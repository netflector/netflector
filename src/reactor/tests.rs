
use super::*;
use std::cell::{Cell, RefCell};
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
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

/// A [`TestHandler`] callback: each test supplies behavior as a closure over the
/// [`ReadyEvent`] that fired plus the reactor.
type Action = Box<dyn FnMut(ReadyEvent, &mut Reactor)>;

/// A [`TimerHandler`]'s fire callback, aliased like [`Action`] to keep the field type simple.
type TimerAction = Box<dyn FnMut(Instant, &mut Reactor)>;

struct TestHandler {
    /// Owned only to keep the watched fd open for the handler's life (its `Drop` closes it).
    _fd: OwnedFd,
    on_read: Action,
    on_write: Option<Action>,
}

impl TestHandler {
    fn read(
        fd: OwnedFd,
        action: impl FnMut(ReadyEvent, &mut Reactor) + 'static,
    ) -> Box<dyn Handler> {
        Box::new(Self {
            _fd: fd,
            on_read: Box::new(action),
            on_write: None,
        })
    }

    fn read_write(
        fd: OwnedFd,
        read: impl FnMut(ReadyEvent, &mut Reactor) + 'static,
        write: impl FnMut(ReadyEvent, &mut Reactor) + 'static,
    ) -> Box<dyn Handler> {
        Box::new(Self {
            _fd: fd,
            on_read: Box::new(read),
            on_write: Some(Box::new(write)),
        })
    }
}

impl Handler for TestHandler {
    fn on_readable(&mut self, event: ReadyEvent, reactor: &mut Reactor) {
        (self.on_read)(event, reactor);
    }

    fn on_writable(&mut self, event: ReadyEvent, reactor: &mut Reactor) {
        if let Some(write) = &mut self.on_write {
            write(event, reactor);
        }
    }
}

/// Register a single-fd handler and watch its fd (no user data); return both keys:
/// the handler key (for `is_registered`/`unregister`) and the reg key (for
/// `dispatch`/write interest).
fn watch1(reactor: &mut Reactor, handler: Box<dyn Handler>, fd: RawFd) -> (HandlerKey, RegKey) {
    let hk = reactor.register(handler);
    let rk = reactor.watch(hk, fd, 0).unwrap();
    (hk, rk)
}

#[test]
#[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
fn dispatch_calls_on_readable() {
    let mut reactor = Reactor::new().unwrap();
    let (a, _peer) = pair();
    let raw = a.as_raw_fd();
    let seen = Rc::new(Cell::new(false));
    let handler = {
        let seen = seen.clone();
        TestHandler::read(a, move |_event, _reactor| seen.set(true))
    };
    let (_hk, rk) = watch1(&mut reactor, handler, raw);
    reactor.dispatch(rk, READABLE);
    assert!(seen.get());
}

#[test]
#[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
fn handler_can_unregister_itself() {
    let mut reactor = Reactor::new().unwrap();
    let (a, _peer) = pair();
    let raw = a.as_raw_fd();
    let hits = Rc::new(Cell::new(0u32));
    let self_key: Rc<Cell<Option<HandlerKey>>> = Rc::new(Cell::new(None));
    let handler = {
        let hits = hits.clone();
        let self_key = self_key.clone();
        TestHandler::read(a, move |_event, reactor| {
            hits.set(hits.get() + 1);
            if let Some(k) = self_key.get() {
                reactor.unregister(k).unwrap();
            }
        })
    };
    let (hk, rk) = watch1(&mut reactor, handler, raw);
    self_key.set(Some(hk));

    reactor.dispatch(rk, READABLE);
    assert_eq!(hits.get(), 1);
    assert!(!reactor.is_registered(hk));

    // The now-stale reg dispatches to nothing.
    reactor.dispatch(rk, READABLE);
    assert_eq!(hits.get(), 1);
}

#[test]
#[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
fn handler_can_register_during_dispatch() {
    // The classic mid-dispatch hazard: registering a new handler while dispatching.
    // Nothing borrows the arenas during the call, so it is simply allowed.
    let mut reactor = Reactor::new().unwrap();
    let (a, _pa) = pair();
    let raw = a.as_raw_fd();
    let (c, _pc) = pair();
    let added: Rc<Cell<Option<HandlerKey>>> = Rc::new(Cell::new(None));
    // The handler takes ownership of `c` out of this slot when it fires.
    let to_add = Rc::new(RefCell::new(Some(c)));
    let handler = {
        let added = added.clone();
        let to_add = to_add.clone();
        TestHandler::read(a, move |_event, reactor| {
            let c = to_add.borrow_mut().take().unwrap();
            let c_raw = c.as_raw_fd();
            let new_key = reactor
                .register_with_fds(TestHandler::read(c, |_, _| {}), &[(c_raw, 0)])
                .unwrap();
            added.set(Some(new_key));
        })
    };
    let (hk, rk) = watch1(&mut reactor, handler, raw);
    reactor.dispatch(rk, READABLE);
    assert!(reactor.is_registered(added.get().unwrap()));
    assert!(reactor.is_registered(hk));
}

#[test]
#[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
fn handler_can_unregister_another() {
    let mut reactor = Reactor::new().unwrap();
    let (victim_fd, _pv) = pair();
    let victim_raw = victim_fd.as_raw_fd();
    let (actor_fd, _pa) = pair();
    let actor_raw = actor_fd.as_raw_fd();
    let victim_hits = Rc::new(Cell::new(0u32));
    let victim_handler = {
        let victim_hits = victim_hits.clone();
        TestHandler::read(victim_fd, move |_event, _reactor| {
            victim_hits.set(victim_hits.get() + 1);
        })
    };
    let (victim, victim_rk) = watch1(&mut reactor, victim_handler, victim_raw);
    let victim_cell = Rc::new(Cell::new(Some(victim)));
    let actor_handler = {
        let victim_cell = victim_cell.clone();
        TestHandler::read(actor_fd, move |_event, reactor| {
            if let Some(v) = victim_cell.get() {
                reactor.unregister(v).unwrap();
            }
        })
    };
    let (_actor, actor_rk) = watch1(&mut reactor, actor_handler, actor_raw);

    reactor.dispatch(actor_rk, READABLE);
    assert!(!reactor.is_registered(victim));

    // Dispatching the stale victim reg is a safe no-op.
    reactor.dispatch(victim_rk, READABLE);
    assert_eq!(victim_hits.get(), 0);
}

#[test]
#[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
fn write_interest_gates_on_writable() {
    let mut reactor = Reactor::new().unwrap();
    let (a, _peer) = pair();
    let raw = a.as_raw_fd();
    let writes = Rc::new(Cell::new(0u32));
    let handler = TestHandler::read_write(a, |_, _| {}, {
        let writes = writes.clone();
        move |_event, _reactor| writes.set(writes.get() + 1)
    });
    let (_hk, rk) = watch1(&mut reactor, handler, raw);

    // Disarmed: writable readiness does nothing.
    reactor.dispatch(rk, WRITABLE);
    assert_eq!(writes.get(), 0);

    assert!(reactor.set_write_interest(rk, true).unwrap());
    reactor.dispatch(rk, WRITABLE);
    assert_eq!(writes.get(), 1);
}

#[test]
#[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
fn read_handler_disarming_write_skips_the_write_phase() {
    let mut reactor = Reactor::new().unwrap();
    let (a, _peer) = pair();
    let raw = a.as_raw_fd();
    let writes = Rc::new(Cell::new(0u32));
    let reg: Rc<Cell<Option<RegKey>>> = Rc::new(Cell::new(None));
    // The read phase disarms write interest on its own reg before the write phase.
    let handler = TestHandler::read_write(
        a,
        {
            let reg = reg.clone();
            move |_event, reactor| {
                reactor
                    .set_write_interest(reg.get().unwrap(), false)
                    .unwrap();
            }
        },
        {
            let writes = writes.clone();
            move |_event, _reactor| writes.set(writes.get() + 1)
        },
    );
    let (_hk, rk) = watch1(&mut reactor, handler, raw);
    reg.set(Some(rk));
    reactor.set_write_interest(rk, true).unwrap();

    // Both ready, but the read handler disarms write before the write phase.
    reactor.dispatch(rk, BOTH);
    assert_eq!(writes.get(), 0);
}

#[test]
#[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
fn read_handler_unregistering_itself_skips_the_write_phase() {
    let mut reactor = Reactor::new().unwrap();
    let (a, _peer) = pair();
    let raw = a.as_raw_fd();
    let writes = Rc::new(Cell::new(0u32));
    let self_key: Rc<Cell<Option<HandlerKey>>> = Rc::new(Cell::new(None));
    let handler = TestHandler::read_write(
        a,
        {
            let self_key = self_key.clone();
            move |_event, reactor| {
                if let Some(k) = self_key.get() {
                    reactor.unregister(k).unwrap();
                }
            }
        },
        {
            let writes = writes.clone();
            move |_event, _reactor| writes.set(writes.get() + 1)
        },
    );
    let (hk, rk) = watch1(&mut reactor, handler, raw);
    self_key.set(Some(hk));
    reactor.set_write_interest(rk, true).unwrap();

    reactor.dispatch(rk, BOTH);
    assert_eq!(writes.get(), 0); // handler gone after read, write skipped
    assert!(!reactor.is_registered(hk));
}

#[test]
#[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
fn dispatching_a_stale_reg_is_a_noop() {
    let mut reactor = Reactor::new().unwrap();
    let (a, _peer) = pair();
    let raw = a.as_raw_fd();
    let handler = TestHandler::read(a, |_, _| panic!("must not fire"));
    let (hk, rk) = watch1(&mut reactor, handler, raw);
    assert!(reactor.unregister(hk).unwrap());
    reactor.dispatch(rk, READABLE); // no panic, no effect
}

#[test]
#[cfg_attr(miri, ignore = "needs a real poll backend")]
fn poll_once_dispatches_a_ready_fd() {
    let mut reactor = Reactor::new().unwrap();
    let (a, peer) = pair();
    let raw = a.as_raw_fd();
    let fired = Rc::new(Cell::new(false));
    let handler = {
        let fired = fired.clone();
        TestHandler::read(a, move |_event, _reactor| fired.set(true))
    };
    watch1(&mut reactor, handler, raw);

    // Nothing ready yet: poll_once dispatches nothing.
    reactor.poll_once(Some(short())).unwrap();
    assert!(!fired.get());

    // Make the registered fd readable, then poll: the handler fires.
    (&peer).write_all(b"x").unwrap();
    reactor.poll_once(Some(short())).unwrap();
    assert!(fired.get());
}

#[test]
#[cfg_attr(miri, ignore = "needs a real poll backend")]
fn run_loop_stops_when_a_handler_requests_shutdown() {
    let mut reactor = Reactor::new().unwrap();
    let (a, peer) = pair();
    let raw = a.as_raw_fd();
    let handler = TestHandler::read(a, |_event, reactor| reactor.request_shutdown());
    watch1(&mut reactor, handler, raw);
    // Readable before looping, so the first (blocking) wait returns at once.
    (&peer).write_all(b"x").unwrap();
    reactor.run_loop().unwrap();
    assert!(reactor.shutdown);
}

/// Counts [`Handler::on_control`] broadcasts, for the SIGUSR1 dump fan-out tests.
struct ControlCounter(Rc<Cell<u32>>);

impl Handler for ControlCounter {
    fn on_readable(&mut self, _event: ReadyEvent, _reactor: &mut Reactor) {}
    fn on_control(&mut self, _event: ControlEvent, _reactor: &mut Reactor) {
        self.0.set(self.0.get() + 1);
    }
}

#[test]
#[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
fn dispatch_control_reaches_every_handler() {
    let mut reactor = Reactor::new().unwrap();
    let count = Rc::new(Cell::new(0u32));
    reactor.register(Box::new(ControlCounter(count.clone())));
    reactor.register(Box::new(ControlCounter(count.clone())));
    reactor.dispatch_control(ControlEvent::Dump);
    assert_eq!(
        count.get(),
        2,
        "every registered handler gets the control event"
    );
}

#[test]
#[cfg_attr(miri, ignore = "needs a real poll backend")]
fn run_loop_broadcasts_a_pending_dump() {
    let mut reactor = Reactor::new().unwrap();
    let (a, peer) = pair();
    let raw = a.as_raw_fd();
    // On its read the trigger requests a dump and a shutdown, so the loop broadcasts once and exits.
    let trigger = TestHandler::read(a, |_event, reactor| {
        reactor.request_dump();
        reactor.request_shutdown();
    });
    watch1(&mut reactor, trigger, raw);
    let dumps = Rc::new(Cell::new(0u32));
    reactor.register(Box::new(ControlCounter(dumps.clone())));
    (&peer).write_all(b"x").unwrap();
    reactor.run_loop().unwrap();
    assert_eq!(
        dumps.get(),
        1,
        "the pending dump broadcasts once before the loop stops"
    );
}

#[test]
#[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
fn unwatch_removes_one_fd_and_leaves_the_handler() {
    let mut reactor = Reactor::new().unwrap();
    let (a, _pa) = pair();
    let a_raw = a.as_raw_fd();
    let (b, _pb) = pair();
    let b_raw = b.as_raw_fd();
    let hits = Rc::new(Cell::new(0u32));
    // One handler watching two fds (it owns `a`; the test keeps `b` alive).
    let handler = {
        let hits = hits.clone();
        TestHandler::read(a, move |_event, _reactor| hits.set(hits.get() + 1))
    };
    let hk = reactor.register(handler);
    let reg_a = reactor.watch(hk, a_raw, 0).unwrap();
    let reg_b = reactor.watch(hk, b_raw, 0).unwrap();

    reactor.dispatch(reg_a, READABLE);
    reactor.dispatch(reg_b, READABLE);
    assert_eq!(hits.get(), 2);

    // Unwatch one fd: it goes stale, but the handler and its other fd stay live.
    assert!(reactor.unwatch(reg_a).unwrap());
    reactor.dispatch(reg_a, READABLE); // stale, no-op
    reactor.dispatch(reg_b, READABLE);
    assert_eq!(hits.get(), 3);
    assert!(reactor.is_registered(hk));

    // Unwatching an already-gone reg is a benign false.
    assert!(!reactor.unwatch(reg_a).unwrap());
}

#[test]
#[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
fn watch_hands_back_the_ready_event() {
    let mut reactor = Reactor::new().unwrap();
    let (a, _peer) = pair();
    let raw = a.as_raw_fd();
    let seen: Rc<Cell<Option<ReadyEvent>>> = Rc::new(Cell::new(None));
    let handler = {
        let seen = seen.clone();
        TestHandler::read(a, move |event, _reactor| seen.set(Some(event)))
    };
    let hk = reactor.register(handler);
    let rk = reactor.watch(hk, raw, 0xdead_beef).unwrap();

    reactor.dispatch(rk, READABLE);
    let event = seen.get().expect("handler fired");
    assert_eq!(event.user_data, 0xdead_beef); // the token round-trips
    assert_eq!(event.fd, raw);
}

#[test]
#[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
fn register_hands_the_handler_its_own_key() {
    // A handler that records the key it is adopted with, so we can check it matches `register`'s.
    struct KeyRecorder(Rc<Cell<Option<HandlerKey>>>);
    impl Handler for KeyRecorder {
        fn on_readable(&mut self, _event: ReadyEvent, _reactor: &mut Reactor) {}
        fn adopt_key(&mut self, key: HandlerKey) {
            self.0.set(Some(key));
        }
    }
    let mut reactor = Reactor::new().unwrap();
    let seen = Rc::new(Cell::new(None));
    let key = reactor.register(Box::new(KeyRecorder(seen.clone())));
    assert_eq!(
        seen.get(),
        Some(key),
        "adopt_key received the handler's own key"
    );
}

#[test]
#[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
fn watch_on_a_stale_handler_errors() {
    let mut reactor = Reactor::new().unwrap();
    let (a, _pa) = pair();
    let hk = reactor.register(TestHandler::read(a, |_, _| {}));
    assert!(reactor.unregister(hk).unwrap());
    // A live fd, so the rejection is due to the stale handler key, not a bad fd.
    let (b, _pb) = pair();
    assert!(reactor.watch(hk, b.as_raw_fd(), 0).is_err());
}

#[test]
#[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
fn watch_rejects_a_duplicate_fd() {
    let mut reactor = Reactor::new().unwrap();
    let (a, _pa) = pair();
    let raw = a.as_raw_fd();
    let (hk, _rk) = watch1(&mut reactor, TestHandler::read(a, |_, _| {}), raw);
    // A second watch of the same fd is a caller bug the reactor rejects uniformly: kqueue's
    // EV_ADD can't report the re-add, so without this the BSD backend would retag the fd and a
    // later unwatch would strip both regs' interest.
    assert!(reactor.watch(hk, raw, 0).is_err());
}

#[test]
#[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
fn watch_failure_errors_and_leaves_the_handler_usable() {
    let mut reactor = Reactor::new().unwrap();
    let (a, _pa) = pair();
    let hk = reactor.register(TestHandler::read(a, |_, _| {}));
    // The largest descriptor number is never open, so the kernel add fails with EBADF; a
    // closed one would not do, as another test thread can reuse its number before the watch.
    assert!(reactor.watch(hk, RawFd::MAX, 0).is_err());
    // The handler is intact and can still watch a good fd afterward.
    assert!(reactor.is_registered(hk));
    let (b, _pb) = pair();
    assert!(reactor.watch(hk, b.as_raw_fd(), 0).is_ok());
}

#[test]
#[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
fn setting_interest_on_a_stale_reg_is_a_benign_false() {
    let mut reactor = Reactor::new().unwrap();
    let (a, _peer) = pair();
    let raw = a.as_raw_fd();
    let (hk, rk) = watch1(&mut reactor, TestHandler::read(a, |_, _| {}), raw);
    assert!(reactor.unwatch(rk).unwrap());
    assert!(!reactor.set_write_interest(rk, true).unwrap());
    assert!(!reactor.set_read_interest(rk, true).unwrap());
    assert!(reactor.is_registered(hk)); // the handler itself is untouched
}

/// A handler with no fd that only carries a timer: it reports `deadline` and runs `on_fire`
/// when the reactor sweeps it. Lets the deadline path be tested without a real clock or fds.
struct TimerHandler {
    deadline: Option<Instant>,
    on_fire: TimerAction,
}

impl Handler for TimerHandler {
    fn on_readable(&mut self, _event: ReadyEvent, _reactor: &mut Reactor) {}
    fn next_deadline(&self) -> Option<Instant> {
        self.deadline
    }
    fn on_deadline(&mut self, now: Instant, reactor: &mut Reactor) {
        (self.on_fire)(now, reactor);
    }
}

fn timer(
    deadline: Option<Instant>,
    on_fire: impl FnMut(Instant, &mut Reactor) + 'static,
) -> Box<dyn Handler> {
    Box::new(TimerHandler {
        deadline,
        on_fire: Box::new(on_fire),
    })
}

#[test]
#[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
fn next_deadline_reports_the_soonest_across_handlers() {
    let mut reactor = Reactor::new().unwrap();
    let base = Instant::now();
    reactor.register(timer(Some(base + short() * 2), |_, _| {}));
    reactor.register(timer(Some(base + short()), |_, _| {}));
    reactor.register(timer(None, |_, _| {})); // no timer, ignored by the min
    assert_eq!(reactor.next_deadline(), Some(base + short()));
}

#[test]
#[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
fn dispatch_deadlines_fires_only_the_handlers_that_are_due() {
    let mut reactor = Reactor::new().unwrap();
    let base = Instant::now();
    let due = Rc::new(Cell::new(false));
    let early = Rc::new(Cell::new(false));
    reactor.register(timer(Some(base), {
        let due = due.clone();
        move |_, _| due.set(true)
    }));
    reactor.register(timer(Some(base + short() * 10), {
        let early = early.clone();
        move |_, _| early.set(true)
    }));
    reactor.dispatch_deadlines(base + short());
    assert!(due.get(), "a deadline at or before now fires");
    assert!(!early.get(), "a deadline in the future does not");
}

#[test]
#[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
fn run_loop_wakes_at_a_deadline_and_runs_the_timer() {
    let mut reactor = Reactor::new().unwrap();
    let fired = Rc::new(Cell::new(false));
    reactor.register(timer(Some(Instant::now() + short()), {
        let fired = fired.clone();
        move |_now, reactor| {
            fired.set(true);
            reactor.request_shutdown();
        }
    }));
    // No fds are watched, so nothing but the timer elapsing can end the wait.
    reactor.run_loop().unwrap();
    assert!(fired.get());
}
