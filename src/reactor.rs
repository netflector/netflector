//! Single-threaded reactor: a registration arena dispatched against I/O readiness.
//!
//! Handlers and watched fds live in generational-index arenas addressed by `Copy`
//! keys; a stale key resolves to nothing.
//!
//! A [`Handler`] owns the fds it [`watch`](Reactor::watch)es. The reactor holds only
//! kernel interest, and drops it before the handler drops and closes the fd.
//!
//! Dispatch takes the handler out of its slot for the call, so it can be handed
//! `&mut Reactor` and watch, unwatch, register or unregister freely.

mod arena;
mod poll;
mod signal;

pub(crate) use self::arena::{Arena, HandlerSlot, Key};

use std::io;
use std::num::NonZeroUsize;
use std::os::fd::RawFd;
use std::time::{Duration, Instant};

use self::poll::Poller;

/// Ready fds per [`wait`](poll::Poller::wait). Level-triggered, so an overflow is
/// re-reported on the next wait, never lost.
const EVENT_CAPACITY: NonZeroUsize = NonZeroUsize::new(64).unwrap();

/// Handle to a registered handler, returned by [`register`](Reactor::register).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct HandlerKey(Key);

/// Handle to one watched fd, returned by [`watch`](Reactor::watch).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct RegKey(Key);

/// Callbacks for a registered handler, which owns the fds it watches and keeps them
/// open while watched.
pub(crate) trait Handler {
    fn on_readable(&mut self, event: ReadyEvent, reactor: &mut Reactor);

    /// Fires only while write interest is armed for the fd.
    fn on_writable(&mut self, _event: ReadyEvent, _reactor: &mut Reactor) {}

    /// When [`on_deadline`](Self::on_deadline) should next fire; `None` for no timer.
    fn next_deadline(&self) -> Option<Instant> {
        None
    }

    /// `now` is the run loop's single clock read; schedule from it, not `Instant::now()`.
    fn on_deadline(&mut self, _now: Instant, _reactor: &mut Reactor) {}

    fn on_control(&mut self, _event: ControlEvent, _reactor: &mut Reactor) {}

    /// Hands the handler its own key at [`register`](Reactor::register); a handler that
    /// watches fds later, or unregisters itself, records it here.
    fn adopt_key(&mut self, _key: HandlerKey) {}
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Readiness {
    pub(crate) readable: bool,
    pub(crate) writable: bool,
}

/// The fd that fired and the opaque `user_data` it was [`watch`](Reactor::watch)ed with.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReadyEvent {
    pub(crate) fd: RawFd,
    pub(crate) user_data: u64,
}

/// A request broadcast to every handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlEvent {
    /// Log diagnostics; raised by SIGUSR1.
    Dump,
}

/// `handler` is `None` only while it is out for a dispatch call.
struct HandlerEntry {
    handler: Option<Box<dyn Handler>>,
    regs: Vec<RegKey>,
}

impl HandlerSlot for HandlerEntry {
    type Handler = dyn Handler;

    fn slot(&self) -> &Option<Box<dyn Handler>> {
        &self.handler
    }

    fn slot_mut(&mut self) -> &mut Option<Box<dyn Handler>> {
        &mut self.handler
    }
}

struct Registration {
    fd: RawFd,
    handler_key: HandlerKey,
    read_interest: bool,
    write_interest: bool,
    user_data: u64,
}

pub(crate) struct Reactor {
    handlers: Arena<HandlerEntry>,
    registrations: Arena<Registration>,
    /// Snapshot buffer for the deadline and control sweeps, kept allocated between them.
    dispatch_keys: Vec<Key>,
    poll: Poller,
    shutdown: bool,
    dump_pending: bool,
}

impl Reactor {
    /// # Errors
    /// If the epoll/kqueue fd cannot be created.
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self {
            handlers: Arena::new(),
            registrations: Arena::new(),
            dispatch_keys: Vec::new(),
            poll: Poller::new(EVENT_CAPACITY)?,
            shutdown: false,
            dump_pending: false,
        })
    }

    pub(crate) fn register(&mut self, mut handler: Box<dyn Handler>) -> HandlerKey {
        HandlerKey(self.handlers.insert_from(|key| {
            handler.adopt_key(HandlerKey(key));
            HandlerEntry {
                handler: Some(handler),
                regs: Vec::new(),
            }
        }))
    }

    /// # Errors
    /// If watching any fd fails; the handler is unregistered again.
    pub(crate) fn register_with_fds(
        &mut self,
        handler: Box<dyn Handler>,
        fds: &[(RawFd, u64)],
    ) -> io::Result<HandlerKey> {
        let handler_key = self.register(handler);
        for &(fd, user_data) in fds {
            if let Err(e) = self.watch(handler_key, fd, user_data) {
                self.unregister(handler_key).ok();
                return Err(e);
            }
        }
        Ok(handler_key)
    }

    /// Watch `fd` for readability under `handler_key`. `user_data` is opaque and comes back
    /// in the [`ReadyEvent`].
    ///
    /// # Errors
    /// If `handler_key` is stale, `fd` is already watched, or the kernel registration fails.
    pub(crate) fn watch(
        &mut self,
        handler_key: HandlerKey,
        fd: RawFd,
        user_data: u64,
    ) -> io::Result<RegKey> {
        let Some(handler_entry) = self.handlers.get_mut(handler_key.0) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "watch: no such handler",
            ));
        };
        // kqueue's EV_ADD silently modifies an existing filter, so the poller can't detect a
        // re-add; reject it here.
        if self.registrations.iter().any(|(_, reg)| reg.fd == fd) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "watch: fd already watched",
            ));
        }
        let reg_key = RegKey(self.registrations.insert(Registration {
            fd,
            handler_key,
            read_interest: true,
            write_interest: false,
            user_data,
        }));
        if let Err(e) = self.poll.add(fd, reg_key.0) {
            self.registrations.remove(reg_key.0);
            return Err(e);
        }
        handler_entry.regs.push(reg_key);
        log::debug!("watch fd {fd} for {handler_key:?} as {reg_key:?}");
        Ok(reg_key)
    }

    /// Returns whether `reg_key` was still live. The fd stays open.
    ///
    /// # Errors
    /// If removing the kernel interest fails.
    pub(crate) fn unwatch(&mut self, reg_key: RegKey) -> io::Result<bool> {
        let Some(registration) = self.registrations.remove(reg_key.0) else {
            log::trace!("unwatch: {reg_key:?} already gone");
            return Ok(false);
        };
        if let Some(handler_entry) = self.handlers.get_mut(registration.handler_key.0) {
            handler_entry.regs.retain(|&r| r != reg_key);
        }
        self.poll.remove(registration.fd)?;
        log::debug!("unwatch fd {} ({reg_key:?})", registration.fd);
        Ok(true)
    }

    /// Drop the handler and unwatch its fds. Returns whether `handler_key` was still live.
    ///
    /// # Errors
    /// The first failure removing kernel interest; the remaining fds are still removed.
    pub(crate) fn unregister(&mut self, handler_key: HandlerKey) -> io::Result<bool> {
        let Some(handler_entry) = self.handlers.remove(handler_key.0) else {
            log::trace!("unregister: {handler_key:?} already gone");
            return Ok(false);
        };
        // `handler_entry` (and the fds its handler owns) must outlive the loop: interest goes
        // before the fd closes.
        let mut first_err = None;
        for reg_key in handler_entry.regs {
            if let Some(registration) = self.registrations.remove(reg_key.0)
                && let Err(e) = self.poll.remove(registration.fd)
            {
                first_err.get_or_insert(e);
            }
        }
        log::debug!("unregistered {handler_key:?}");
        match first_err {
            Some(e) => Err(e),
            None => Ok(true),
        }
    }

    /// Returns whether `reg_key` was live.
    ///
    /// # Errors
    /// If updating the kernel's write interest fails.
    pub(crate) fn set_write_interest(
        &mut self,
        reg_key: RegKey,
        enabled: bool,
    ) -> io::Result<bool> {
        let Some(registration) = self.registrations.get_mut(reg_key.0) else {
            log::trace!("set_write_interest: {reg_key:?} already gone");
            return Ok(false);
        };
        if registration.write_interest == enabled {
            return Ok(true);
        }
        // Kernel first, flag only on success, so the two never disagree.
        self.poll.set_interest(
            registration.fd,
            reg_key.0,
            registration.read_interest,
            enabled,
        )?;
        registration.write_interest = enabled;
        log::trace!(
            "fd {}: write interest {}",
            registration.fd,
            if enabled { "armed" } else { "disarmed" }
        );
        Ok(true)
    }

    /// Arm or disarm read readiness (armed by [`watch`](Self::watch)). Returns whether `reg_key`
    /// was live. Disarmed, epoll still reports a hangup or error as readable; kqueue does not
    /// (`EV_DISABLE` suppresses `EV_EOF`, and the write filter is gone while write interest is
    /// off), so a handler that disarms read must keep write interest armed or a deadline set to
    /// hear from the fd again.
    ///
    /// # Errors
    /// If updating the kernel's read interest fails.
    pub(crate) fn set_read_interest(&mut self, reg_key: RegKey, enabled: bool) -> io::Result<bool> {
        let Some(registration) = self.registrations.get_mut(reg_key.0) else {
            log::trace!("set_read_interest: {reg_key:?} already gone");
            return Ok(false);
        };
        self.poll.set_interest(
            registration.fd,
            reg_key.0,
            enabled,
            registration.write_interest,
        )?;
        registration.read_interest = enabled;
        log::trace!(
            "fd {}: read interest {}",
            registration.fd,
            if enabled { "armed" } else { "disarmed" }
        );
        Ok(true)
    }

    #[must_use]
    pub(crate) fn is_registered(&self, handler_key: HandlerKey) -> bool {
        self.handlers.contains(handler_key.0)
    }

    /// Wait for readiness (`None` blocks) and dispatch it.
    ///
    /// # Errors
    /// If the wait fails; `EINTR` is not an error.
    pub(crate) fn poll_once(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.poll.wait(timeout)?;
        while let Some(event) = self.poll.next_event() {
            self.dispatch(RegKey(event.key), event.readiness);
        }
        Ok(())
    }

    /// Run until SIGINT/SIGTERM. Signal handlers are installed for the duration and restored
    /// on return.
    ///
    /// # Errors
    /// If the signal handlers cannot be installed or a wait fails.
    pub(crate) fn run(&mut self) -> io::Result<()> {
        let (guard, pipe) = signal::SignalGuard::install()?;
        let fd = pipe.read_fd();
        let handler_key = self.register_with_fds(Box::new(pipe), &[(fd, 0)])?;
        self.shutdown = false;
        self.dump_pending = false;
        let result = self.run_loop();
        // Guard first: a signal after the read end closes must find no write fd.
        drop(guard);
        self.unregister(handler_key).ok();
        result
    }

    fn run_loop(&mut self) -> io::Result<()> {
        while !self.shutdown {
            let deadline = self.next_deadline();
            let timeout = deadline.map(|d| d.saturating_duration_since(Instant::now()));
            self.poll_once(timeout)?;
            if self.dump_pending {
                self.dump_pending = false;
                self.dispatch_control(ControlEvent::Dump);
            }
            let now = Instant::now();
            if deadline.is_some_and(|d| now >= d) {
                self.dispatch_deadlines(now);
            }
        }
        Ok(())
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.handlers
            .handlers()
            .filter_map(|(_, handler)| handler.next_deadline())
            .min()
    }

    fn dispatch_deadlines(&mut self, now: Instant) {
        // Indexed, not iterated: each call needs `&mut self`. A handler removed mid-sweep leaves
        // a stale key, which `take_handler` misses.
        self.dispatch_keys.clear();
        self.dispatch_keys.extend(
            self.handlers
                .handlers()
                .filter(|(_, handler)| handler.next_deadline().is_some_and(|d| d <= now))
                .map(|(key, _)| key),
        );
        for i in 0..self.dispatch_keys.len() {
            let key = self.dispatch_keys[i];
            let Some(mut handler) = self.handlers.take_handler(key) else {
                log::trace!("dispatch_deadlines: handler for {key:?} gone mid-sweep, skipped");
                continue;
            };
            log::trace!("deadline fired for {key:?}");
            handler.on_deadline(now, self);
            self.handlers.restore_handler(key, handler);
        }
    }

    /// Shares `dispatch_keys` with the deadline sweep; the two never nest.
    fn dispatch_control(&mut self, event: ControlEvent) {
        self.dispatch_keys.clear();
        self.dispatch_keys
            .extend(self.handlers.iter().map(|(key, _)| key));
        for i in 0..self.dispatch_keys.len() {
            let key = self.dispatch_keys[i];
            let Some(mut handler) = self.handlers.take_handler(key) else {
                log::trace!("dispatch_control: handler for {key:?} gone mid-broadcast, skipped");
                continue;
            };
            handler.on_control(event, self);
            self.handlers.restore_handler(key, handler);
        }
    }

    /// Stop the run loop after the current iteration; the rest of this batch still dispatches.
    pub(crate) fn request_shutdown(&mut self) {
        self.shutdown = true;
    }

    /// Broadcast [`ControlEvent::Dump`] once the current dispatch returns.
    pub(crate) fn request_dump(&mut self) {
        self.dump_pending = true;
    }

    fn dispatch(&mut self, reg_key: RegKey, readiness: Readiness) {
        let Some(registration) = self.registrations.get(reg_key.0) else {
            log::trace!("dispatch: {reg_key:?} is stale, ignored");
            return;
        };
        let handler_key = registration.handler_key;
        let event = ReadyEvent {
            fd: registration.fd,
            user_data: registration.user_data,
        };
        let Some(mut handler) = self.handlers.take_handler(handler_key.0) else {
            if self.handlers.contains(handler_key.0) {
                log::trace!("dispatch: {handler_key:?} already in flight, ignored");
            } else {
                log::trace!("dispatch: {reg_key:?} -> {handler_key:?} gone, ignored");
            }
            return;
        };

        log::trace!(
            "dispatch {reg_key:?} (fd {}): readable={} writable={}",
            event.fd,
            readiness.readable,
            readiness.writable
        );

        if readiness.readable {
            handler.on_readable(event, self);
        }
        // Re-check: the read phase may have unwatched the fd or disarmed write interest.
        if readiness.writable {
            if self
                .registrations
                .get(reg_key.0)
                .is_some_and(|r| r.write_interest)
            {
                handler.on_writable(event, self);
            } else {
                log::trace!("dispatch {reg_key:?}: write suppressed after read phase");
            }
        }

        self.handlers.restore_handler(handler_key.0, handler);
    }
}

#[cfg(test)]
mod tests;
