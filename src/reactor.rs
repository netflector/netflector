//! Single-threaded reactor: a registration arena dispatched against I/O readiness.
//!
//! Built on a generational-index [`arena`]. Registrations are addressed by a
//! `Copy` [`Key`], never a pointer or reference — which is what lets a handler
//! reach back into the reactor (to register or unregister others, or arm write
//! interest) without aliasing the storage it lives in. A freed slot bumps its
//! generation, so a stale key fails safe (resolves to nothing) instead of
//! dangling.
//!
//! The reactor owns a [`poll::Poller`] and drives the kernel (epoll/kqueue) as
//! registrations come and go; [`Reactor::poll_once`] waits for readiness and
//! dispatches it. Each [`Handler`] **owns its fd** (it is `AsRawFd`); the reactor
//! only watches it. Unregistering removes the kernel interest *first*, then the
//! registration drops and the handler closes the fd — so interest is always gone
//! before the fd closes: no stale-interest window, and no fd the reactor double-owns
//! (a capture socket the handler also needs for I/O stays owned by the handler).
//!
//! Dispatch **takes the handler out of its slot** for the duration of its call,
//! so `&mut Reactor` is free to hand to the handler. The handler can therefore
//! mutate the reactor freely — including registering new fds, which a loop
//! holding an iterator into the registration storage would risk invalidating
//! mid-iteration; here nothing borrows the arena during the call, so it just works.

mod arena;
mod poll;
mod signal;

pub(crate) use self::arena::Key;

use std::io;
use std::num::NonZeroUsize;
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

use self::arena::Arena;
use self::poll::Poller;

/// How many ready fds one [`wait`](poll::Poller::wait) reports. The reflector
/// watches only a handful of fds, so this is ample headroom; level-triggering
/// re-reports any overflow on the next wait, so a small buffer never loses events.
const EVENT_CAPACITY: NonZeroUsize = NonZeroUsize::new(64).unwrap();

/// Callbacks for a registered file descriptor. The handler **owns** the fd (it is
/// `AsRawFd`) and must report the *same* fd for as long as it is registered: the
/// reactor caches it at registration and watches it without closing it, so a handler
/// that swapped its fd mid-registration would leave the reactor watching the old one.
/// To change the fd, unregister and re-register. Unregistering removes the kernel
/// interest, then the handler drops and closes the fd.
///
/// `on_readable` is required; `on_writable` defaults to a no-op and only fires while
/// write interest is armed (see [`Reactor::set_write_interest`]). Each is handed
/// `&mut Reactor`, so a handler can register or unregister others, arm/disarm its
/// own write interest, etc.
pub(crate) trait Handler: AsRawFd {
    /// The owned fd is readable.
    fn on_readable(&mut self, reactor: &mut Reactor);

    /// The owned fd is writable and write interest is armed.
    fn on_writable(&mut self, _reactor: &mut Reactor) {}
}

/// What a registration is ready for in a given dispatch — the event a poll loop
/// (or a test) feeds the reactor.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Readiness {
    /// The fd is readable.
    pub(crate) readable: bool,
    /// The fd is writable.
    pub(crate) writable: bool,
}

/// One registration: the handler owns the fd; the reactor caches its `RawFd` for
/// poll operations, tracks write interest, and holds the handler (taken out only
/// transiently during dispatch).
struct Registration {
    raw: RawFd,
    write_interest: bool,
    handler: Option<Box<dyn Handler>>,
}

/// The single-threaded reactor: owns the registrations and the poller, and
/// dispatches readiness to handlers.
pub(crate) struct Reactor {
    registrations: Arena<Registration>,
    poll: Poller,
    shutdown: bool,
}

impl Reactor {
    /// A new reactor with an empty registration set and a fresh poller.
    ///
    /// # Errors
    /// Returns an error if the poller's backing fd (epoll/kqueue) cannot be created.
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self {
            registrations: Arena::new(),
            poll: Poller::new(EVENT_CAPACITY)?,
            shutdown: false,
        })
    }

    /// Register `handler` (which owns its fd), returning the key that addresses it.
    /// Write interest starts disarmed. The key is the only way to unregister or
    /// re-target the registration later.
    ///
    /// # Errors
    /// Returns an error if the kernel registration fails; the arena insert is
    /// rolled back so no partial registration remains.
    pub(crate) fn register(&mut self, handler: Box<dyn Handler>) -> io::Result<Key> {
        let raw = handler.as_raw_fd();
        let key = self.registrations.insert(Registration {
            raw,
            write_interest: false,
            handler: Some(handler),
        });
        if let Err(e) = self.poll.add(raw, key) {
            // Undo the insert so a failed registration leaves nothing behind.
            self.registrations.remove(key);
            return Err(e);
        }
        log::debug!("registered fd {raw}");
        Ok(key)
    }

    /// Drop the registration `key` addresses: remove its kernel interest and close
    /// the fd. Returns whether it was still live.
    ///
    /// # Errors
    /// Returns an error if removing the kernel interest fails.
    pub(crate) fn unregister(&mut self, key: Key) -> io::Result<bool> {
        let Some(reg) = self.registrations.remove(key) else {
            log::trace!("unregister: {key:?} already gone");
            return Ok(false);
        };
        // `remove` moves the registration into `reg`, which keeps the handler — and
        // its fd — alive until this function returns. Drop the kernel interest now,
        // before `reg` drops at scope end and the handler closes the fd.
        self.poll.remove(reg.raw)?;
        log::debug!("unregistered fd {}", reg.raw);
        Ok(true)
    }

    /// Arm or disarm delivery of write readiness for the registration `key`
    /// addresses. Returns whether the key was live.
    ///
    /// # Errors
    /// Returns an error if updating the kernel's write interest fails.
    pub(crate) fn set_write_interest(&mut self, key: Key, enabled: bool) -> io::Result<bool> {
        let Some(reg) = self.registrations.get_mut(key) else {
            log::trace!("set_write_interest: {key:?} already gone");
            return Ok(false);
        };
        // Program the kernel first; flip the in-memory flag only on success, so the
        // arena and the kernel never disagree about write interest. (`self.poll` and
        // `self.registrations` are disjoint fields, so the `reg` borrow can stay live
        // across the syscall.)
        self.poll.set_write(reg.raw, key, enabled)?;
        reg.write_interest = enabled;
        log::trace!(
            "fd {}: write interest {}",
            reg.raw,
            if enabled { "armed" } else { "disarmed" }
        );
        Ok(true)
    }

    /// Whether `key` still addresses a live registration.
    #[must_use]
    pub(crate) fn is_registered(&self, key: Key) -> bool {
        self.registrations.contains(key)
    }

    /// Wait for readiness (until `timeout`, or block if `None`) and dispatch each
    /// ready fd. The single step a run loop repeats.
    ///
    /// # Errors
    /// Returns an error if the underlying wait fails. An interrupted wait reports
    /// no events rather than erroring.
    pub(crate) fn poll_once(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.poll.wait(timeout)?;
        // `next_event` returns an owned (`Copy`) event, so the `self.poll` borrow
        // ends before `dispatch` needs `&mut self`.
        while let Some(event) = self.poll.next_event() {
            self.dispatch(event.key, event.readiness);
        }
        Ok(())
    }

    /// Run until a shutdown signal (SIGINT/SIGTERM) arrives, dispatching readiness
    /// in between. A self-pipe shutdown handler is installed for the duration and
    /// the previous signal dispositions are restored before returning.
    ///
    /// # Errors
    /// Returns an error if the shutdown handler cannot be installed or a wait fails.
    pub(crate) fn run(&mut self) -> io::Result<()> {
        let (shutdown, pipe) = signal::ShutdownPipe::install()?;
        let key = self.register(Box::new(pipe))?;
        self.shutdown = false;
        let result = self.run_loop();
        // Restore the signal handlers and unpublish the write fd *before* closing
        // the read end, so a late signal can't write to a reader-less pipe.
        drop(shutdown);
        self.unregister(key).ok();
        result
    }

    /// Dispatch readiness until [`request_shutdown`](Self::request_shutdown) is
    /// called. Blocks in each wait, so it idles at zero cost between events.
    fn run_loop(&mut self) -> io::Result<()> {
        while !self.shutdown {
            self.poll_once(None)?;
        }
        Ok(())
    }

    /// Ask the run loop to stop once the current dispatch returns. Handlers call
    /// this (the self-pipe handler does, on a shutdown signal); calling it outside
    /// a run loop just arms the next one to exit immediately.
    pub(crate) fn request_shutdown(&mut self) {
        self.shutdown = true;
    }

    /// Deliver `readiness` to the registration `key` addresses — the seam
    /// [`poll_once`](Self::poll_once) drives the reactor through. A stale key is a
    /// safe no-op.
    fn dispatch(&mut self, key: Key, readiness: Readiness) {
        // Take the handler out so `self` is free to be borrowed for the call. The
        // slot stays put, so `key` stays valid and the handler can be returned.
        let Some(reg) = self.registrations.get_mut(key) else {
            // stale key — the registration is gone
            log::trace!("dispatch: {key:?} is stale, ignored");
            return;
        };
        let raw = reg.raw;
        let Some(mut handler) = reg.handler.take() else {
            // reentrant dispatch of a slot already in flight
            log::trace!("dispatch: fd {raw} already in flight, ignored");
            return;
        };
        // The cached `raw` assumes a handler keeps its fd while registered (see `Handler`).
        debug_assert_eq!(
            handler.as_raw_fd(),
            raw,
            "handler changed its fd while registered"
        );

        log::trace!(
            "dispatch fd {raw}: readable={} writable={}",
            readiness.readable,
            readiness.writable
        );

        if readiness.readable {
            handler.on_readable(self);
        }
        // Write is re-gated after the read phase: the read handler may have
        // unregistered the fd or disarmed write interest in between.
        if readiness.writable {
            if self
                .registrations
                .get(key)
                .is_some_and(|reg| reg.write_interest)
            {
                handler.on_writable(self);
            } else {
                log::trace!("dispatch fd {raw}: write suppressed after read phase");
            }
        }

        // Return the handler — unless the registration was removed during the
        // call, in which case the slot is gone and the handler is dropped.
        if let Some(reg) = self.registrations.get_mut(key) {
            reg.handler = Some(handler);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::io::Write;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::rc::Rc;

    const READABLE: Readiness = Readiness {
        readable: true,
        writable: false,
    };
    const WRITABLE: Readiness = Readiness {
        readable: false,
        writable: true,
    };
    const BOTH: Readiness = Readiness {
        readable: true,
        writable: true,
    };

    fn short() -> Duration {
        Duration::from_millis(50)
    }

    /// A connected socketpair: the owned end (to register) plus its peer (kept
    /// alive; write to it to make the registered end readable).
    fn pair() -> (OwnedFd, UnixStream) {
        let (a, b) = UnixStream::pair().unwrap();
        (OwnedFd::from(a), b)
    }

    /// A handler whose behavior is supplied as closures, so each test wires up only
    /// what it needs. Like any real handler, it owns its fd.
    type Action = Box<dyn FnMut(&mut Reactor)>;

    struct TestHandler {
        fd: OwnedFd,
        on_read: Action,
        on_write: Option<Action>,
    }

    impl TestHandler {
        fn read(fd: OwnedFd, action: impl FnMut(&mut Reactor) + 'static) -> Box<dyn Handler> {
            Box::new(Self {
                fd,
                on_read: Box::new(action),
                on_write: None,
            })
        }

        fn read_write(
            fd: OwnedFd,
            read: impl FnMut(&mut Reactor) + 'static,
            write: impl FnMut(&mut Reactor) + 'static,
        ) -> Box<dyn Handler> {
            Box::new(Self {
                fd,
                on_read: Box::new(read),
                on_write: Some(Box::new(write)),
            })
        }
    }

    impl AsRawFd for TestHandler {
        fn as_raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }
    }

    impl Handler for TestHandler {
        fn on_readable(&mut self, reactor: &mut Reactor) {
            (self.on_read)(reactor);
        }

        fn on_writable(&mut self, reactor: &mut Reactor) {
            if let Some(write) = &mut self.on_write {
                write(reactor);
            }
        }
    }

    #[test]
    fn dispatch_calls_on_readable() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let seen = Rc::new(Cell::new(false));
        let key = reactor
            .register({
                let seen = seen.clone();
                TestHandler::read(a, move |_| seen.set(true))
            })
            .unwrap();
        reactor.dispatch(key, READABLE);
        assert!(seen.get());
    }

    #[test]
    fn handler_can_unregister_itself() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let hits = Rc::new(Cell::new(0u32));
        let self_key = Rc::new(Cell::new(None));
        let key = reactor
            .register({
                let hits = hits.clone();
                let self_key = self_key.clone();
                TestHandler::read(a, move |reactor| {
                    hits.set(hits.get() + 1);
                    if let Some(k) = self_key.get() {
                        reactor.unregister(k).unwrap();
                    }
                })
            })
            .unwrap();
        self_key.set(Some(key));

        reactor.dispatch(key, READABLE);
        assert_eq!(hits.get(), 1);
        assert!(!reactor.is_registered(key));

        // The now-stale key dispatches to nothing.
        reactor.dispatch(key, READABLE);
        assert_eq!(hits.get(), 1);
    }

    #[test]
    fn handler_can_register_during_dispatch() {
        // The classic mid-dispatch hazard: registering a new fd while the loop is
        // iterating the registrations. Here nothing borrows the arena during the
        // call, so it is simply allowed.
        let mut reactor = Reactor::new().unwrap();
        let (a, _pa) = pair();
        let (c, _pc) = pair();
        let added = Rc::new(Cell::new(None));
        // The handler takes ownership of `c` out of this slot when it fires.
        let to_add = Rc::new(RefCell::new(Some(c)));
        let key = reactor
            .register({
                let added = added.clone();
                let to_add = to_add.clone();
                TestHandler::read(a, move |reactor| {
                    let c = to_add.borrow_mut().take().unwrap();
                    let new_key = reactor.register(TestHandler::read(c, |_| {})).unwrap();
                    added.set(Some(new_key));
                })
            })
            .unwrap();
        reactor.dispatch(key, READABLE);
        assert!(reactor.is_registered(added.get().unwrap()));
        assert!(reactor.is_registered(key));
    }

    #[test]
    fn handler_can_unregister_another() {
        let mut reactor = Reactor::new().unwrap();
        let (victim_fd, _pv) = pair();
        let (actor_fd, _pa) = pair();
        let victim_hits = Rc::new(Cell::new(0u32));
        let victim = reactor
            .register({
                let victim_hits = victim_hits.clone();
                TestHandler::read(victim_fd, move |_| victim_hits.set(victim_hits.get() + 1))
            })
            .unwrap();
        let victim_cell = Rc::new(Cell::new(Some(victim)));
        let actor = reactor
            .register({
                let victim_cell = victim_cell.clone();
                TestHandler::read(actor_fd, move |reactor| {
                    if let Some(v) = victim_cell.get() {
                        reactor.unregister(v).unwrap();
                    }
                })
            })
            .unwrap();

        reactor.dispatch(actor, READABLE);
        assert!(!reactor.is_registered(victim));

        // Dispatching the stale victim key is a safe no-op.
        reactor.dispatch(victim, READABLE);
        assert_eq!(victim_hits.get(), 0);
    }

    #[test]
    fn write_interest_gates_on_writable() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let writes = Rc::new(Cell::new(0u32));
        let key = reactor
            .register(TestHandler::read_write(a, |_| {}, {
                let writes = writes.clone();
                move |_| writes.set(writes.get() + 1)
            }))
            .unwrap();

        // Disarmed: writable readiness does nothing.
        reactor.dispatch(key, WRITABLE);
        assert_eq!(writes.get(), 0);

        assert!(reactor.set_write_interest(key, true).unwrap());
        reactor.dispatch(key, WRITABLE);
        assert_eq!(writes.get(), 1);
    }

    #[test]
    fn read_handler_disarming_write_skips_the_write_phase() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let writes = Rc::new(Cell::new(0u32));
        let self_key = Rc::new(Cell::new(None));
        let key = reactor
            .register(TestHandler::read_write(
                a,
                {
                    let self_key = self_key.clone();
                    move |reactor| {
                        if let Some(k) = self_key.get() {
                            reactor.set_write_interest(k, false).unwrap();
                        }
                    }
                },
                {
                    let writes = writes.clone();
                    move |_| writes.set(writes.get() + 1)
                },
            ))
            .unwrap();
        self_key.set(Some(key));
        reactor.set_write_interest(key, true).unwrap();

        // Both ready, but the read handler disarms write before the write phase.
        reactor.dispatch(key, BOTH);
        assert_eq!(writes.get(), 0);
    }

    #[test]
    fn read_handler_unregistering_itself_skips_the_write_phase() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let writes = Rc::new(Cell::new(0u32));
        let self_key = Rc::new(Cell::new(None));
        let key = reactor
            .register(TestHandler::read_write(
                a,
                {
                    let self_key = self_key.clone();
                    move |reactor| {
                        if let Some(k) = self_key.get() {
                            reactor.unregister(k).unwrap();
                        }
                    }
                },
                {
                    let writes = writes.clone();
                    move |_| writes.set(writes.get() + 1)
                },
            ))
            .unwrap();
        self_key.set(Some(key));
        reactor.set_write_interest(key, true).unwrap();

        reactor.dispatch(key, BOTH);
        assert_eq!(writes.get(), 0); // fd gone after read, write skipped
        assert!(!reactor.is_registered(key));
    }

    #[test]
    fn dispatching_a_stale_key_is_a_noop() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let key = reactor
            .register(TestHandler::read(a, |_| panic!("must not fire")))
            .unwrap();
        assert!(reactor.unregister(key).unwrap());
        reactor.dispatch(key, READABLE); // no panic, no effect
    }

    #[test]
    fn poll_once_dispatches_a_ready_fd() {
        let mut reactor = Reactor::new().unwrap();
        let (a, peer) = pair();
        let fired = Rc::new(Cell::new(false));
        reactor
            .register({
                let fired = fired.clone();
                TestHandler::read(a, move |_| fired.set(true))
            })
            .unwrap();

        // Nothing ready yet: poll_once dispatches nothing.
        reactor.poll_once(Some(short())).unwrap();
        assert!(!fired.get());

        // Make the registered fd readable, then poll: the handler fires.
        (&peer).write_all(b"x").unwrap();
        reactor.poll_once(Some(short())).unwrap();
        assert!(fired.get());
    }

    #[test]
    fn run_loop_stops_when_a_handler_requests_shutdown() {
        let mut reactor = Reactor::new().unwrap();
        let (a, peer) = pair();
        reactor
            .register(TestHandler::read(a, Reactor::request_shutdown))
            .unwrap();
        // Readable before looping, so the first (blocking) wait returns at once.
        (&peer).write_all(b"x").unwrap();
        reactor.run_loop().unwrap();
        assert!(reactor.shutdown);
    }
}
