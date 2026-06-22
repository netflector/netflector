//! epoll readiness backend for Linux (including the embedded ARM targets).
//!
//! Level-triggered: read interest is added once and stays armed, write interest
//! is toggled per registration via a full-mask `EPOLL_CTL_MOD` (epoll has no
//! per-direction enable). The reactor [`Key`] travels in each event's `u64`
//! field, so a wakeup carries its own routing — no fd-to-handler side table.

use std::io;
use std::mem;
use std::num::NonZeroUsize;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use std::time::Duration;

use super::PollEvent;
use crate::reactor::{Key, Readiness};

// libc's EPOLL* constants are `c_int`; `epoll_event.events` is `u32`, so
// `cast_unsigned` reinterprets the (positive) flag bits without a sign-loss lint.
// READ/WRITE are the interests we register; READABLE/WRITABLE classify a returned
// event. Errors and hangups arrive unsolicited and count as readable, so the next
// read observes them; the write side has no equivalent, hence WRITABLE == WRITE.
const READ: u32 = libc::EPOLLIN.cast_unsigned();
const WRITE: u32 = libc::EPOLLOUT.cast_unsigned();
const READABLE: u32 = (libc::EPOLLIN | libc::EPOLLERR | libc::EPOLLHUP).cast_unsigned();
const WRITABLE: u32 = WRITE;

/// An epoll descriptor and the reusable buffer its waits report into.
pub(crate) struct Poller {
    poll_fd: OwnedFd,
    events: Box<[libc::epoll_event]>,
    ready: usize,
    next: usize,
}

impl Poller {
    /// Create an epoll instance reporting up to `capacity` ready fds per [`wait`](Self::wait).
    pub(crate) fn new(capacity: NonZeroUsize) -> io::Result<Self> {
        // SAFETY: epoll_create1 takes only flags; it returns a fresh fd or -1.
        let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh descriptor we exclusively own.
        let poll_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: an all-zero epoll_event is a valid, inert entry; wait() overwrites it.
        let blank: libc::epoll_event = unsafe { mem::zeroed() };
        log::trace!("epoll poller created (capacity {capacity})");
        Ok(Self {
            poll_fd,
            events: vec![blank; capacity.get()].into_boxed_slice(),
            ready: 0,
            next: 0,
        })
    }

    /// Add level-triggered read interest on `fd`, tagged with `key`. Write
    /// interest starts off; toggle it with [`set_write`](Self::set_write).
    pub(crate) fn add(&self, fd: RawFd, key: Key) -> io::Result<()> {
        // A re-add (EEXIST) is a caller bug; surface it instead of silently
        // modifying. The reactor enforces add-once uniformly (kqueue's EV_ADD
        // can't report a re-add, so the Poller can't catch it on its own).
        self.ctl(libc::EPOLL_CTL_ADD, fd, READ, key)?;
        log::trace!("epoll: armed read on fd {fd}");
        Ok(())
    }

    /// Arm or disarm write interest on `fd` (already [added](Self::add)). epoll
    /// has no per-direction toggle, so this rewrites the full interest mask.
    pub(crate) fn set_write(&self, fd: RawFd, key: Key, enabled: bool) -> io::Result<()> {
        let mask = if enabled { READ | WRITE } else { READ };
        self.ctl(libc::EPOLL_CTL_MOD, fd, mask, key)?;
        log::trace!(
            "epoll: write interest {} on fd {fd}",
            if enabled { "armed" } else { "disarmed" }
        );
        Ok(())
    }

    /// Drop all interest on `fd`. An fd the kernel already dropped (e.g. on close)
    /// reports `ENOENT`, which is benign.
    pub(crate) fn remove(&self, fd: RawFd) -> io::Result<()> {
        // SAFETY: poll_fd is our epoll instance; EPOLL_CTL_DEL ignores the event arg.
        let rc = unsafe {
            libc::epoll_ctl(
                self.poll_fd.as_raw_fd(),
                libc::EPOLL_CTL_DEL,
                fd,
                ptr::null_mut(),
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENOENT) {
                return Err(err);
            }
        }
        log::trace!("epoll: removed fd {fd}");
        Ok(())
    }

    /// Block until at least one fd is ready, or until `timeout` elapses (`None`
    /// blocks indefinitely), recording the ready events. Returns how many there
    /// are; drain them with [`next_event`](Self::next_event). `EINTR` yields
    /// `Ok(0)` so the caller can re-check shutdown state and poll again.
    pub(crate) fn wait(&mut self, timeout: Option<Duration>) -> io::Result<usize> {
        let max_events = libc::c_int::try_from(self.events.len()).unwrap_or(libc::c_int::MAX);
        let timeout_ms = match timeout {
            None => -1,
            Some(d) => libc::c_int::try_from(d.as_millis()).unwrap_or(libc::c_int::MAX),
        };
        // SAFETY: the eventlist is our owned buffer, sized by `max_events`.
        let count = unsafe {
            libc::epoll_wait(
                self.poll_fd.as_raw_fd(),
                self.events.as_mut_ptr(),
                max_events,
                timeout_ms,
            )
        };
        if count < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                self.ready = 0;
                log::trace!("epoll: wait interrupted");
                return Ok(0);
            }
            return Err(err);
        }
        self.ready = usize::try_from(count).expect("epoll_wait count is non-negative");
        self.next = 0; // start draining the new batch from the front
        log::trace!("epoll: {} ready", self.ready);
        Ok(self.ready)
    }

    /// The next event from the last [`wait`](Self::wait), or `None` once the batch
    /// is drained. Advances an internal cursor, so each event is yielded once.
    pub(crate) fn next_event(&mut self) -> Option<PollEvent> {
        if self.next >= self.ready {
            return None;
        }
        // Copy the (packed) epoll_event out so fields are read by value, never by ref.
        let event = self.events[self.next];
        self.next += 1;
        let flags = event.events;
        let token = event.u64;
        Some(PollEvent {
            key: Key::from_u64(token),
            readiness: Readiness {
                readable: flags & READABLE != 0,
                writable: flags & WRITABLE != 0,
            },
        })
    }

    fn ctl(&self, op: libc::c_int, fd: RawFd, mask: u32, key: Key) -> io::Result<()> {
        // SAFETY: a zeroed epoll_event is valid; we then set the meaningful fields.
        let mut event: libc::epoll_event = unsafe { mem::zeroed() };
        event.events = mask;
        event.u64 = key.to_u64();
        // SAFETY: poll_fd is our epoll instance; `event` outlives the call.
        let rc = unsafe { libc::epoll_ctl(self.poll_fd.as_raw_fd(), op, fd, &raw mut event) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    const CAPACITY: NonZeroUsize = NonZeroUsize::new(8).unwrap();

    fn short() -> Duration {
        Duration::from_millis(50)
    }

    #[test]
    fn reports_readable_with_the_registered_key() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut poller = Poller::new(CAPACITY).unwrap();
        let key = Key::from_u64(0x0001_0002_0003_0004);
        poller.add(a.as_raw_fd(), key).unwrap();

        // Nothing written yet: the wait times out with no events.
        assert_eq!(poller.wait(Some(short())).unwrap(), 0);

        (&b).write_all(b"x").unwrap();
        assert_eq!(poller.wait(Some(short())).unwrap(), 1);
        let event = poller.next_event().unwrap();
        assert_eq!(event.key, key);
        assert!(event.readiness.readable);
        assert!(!event.readiness.writable);
    }

    #[test]
    fn write_interest_toggles() {
        let (a, _b) = UnixStream::pair().unwrap();
        let mut poller = Poller::new(CAPACITY).unwrap();
        let key = Key::from_u64(7);
        poller.add(a.as_raw_fd(), key).unwrap();

        // Read-only on an idle socket: nothing ready.
        assert_eq!(poller.wait(Some(short())).unwrap(), 0);

        // Armed: a fresh socket has room to send, so it is writable.
        poller.set_write(a.as_raw_fd(), key, true).unwrap();
        assert_eq!(poller.wait(Some(short())).unwrap(), 1);
        let event = poller.next_event().unwrap();
        assert_eq!(event.key, key);
        assert!(event.readiness.writable);

        // Disarmed again: back to nothing.
        poller.set_write(a.as_raw_fd(), key, false).unwrap();
        assert_eq!(poller.wait(Some(short())).unwrap(), 0);
    }

    #[test]
    fn disarming_unarmed_write_is_ok() {
        let (a, _b) = UnixStream::pair().unwrap();
        let poller = Poller::new(CAPACITY).unwrap();
        let key = Key::from_u64(1);
        poller.add(a.as_raw_fd(), key).unwrap();
        // Disarming write interest that was never armed must succeed.
        poller.set_write(a.as_raw_fd(), key, false).unwrap();
    }

    #[test]
    fn remove_clears_interest() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut poller = Poller::new(CAPACITY).unwrap();
        poller.add(a.as_raw_fd(), Key::from_u64(1)).unwrap();
        (&b).write_all(b"x").unwrap();
        poller.remove(a.as_raw_fd()).unwrap();
        assert_eq!(poller.wait(Some(short())).unwrap(), 0);
    }

    #[test]
    fn remove_unregistered_is_benign() {
        let (a, _b) = UnixStream::pair().unwrap();
        let poller = Poller::new(CAPACITY).unwrap();
        // Never added; the kernel reports ENOENT, which remove() swallows.
        poller.remove(a.as_raw_fd()).unwrap();
    }

    #[test]
    fn re_add_reports_already_registered() {
        let (a, _b) = UnixStream::pair().unwrap();
        let poller = Poller::new(CAPACITY).unwrap();
        let key = Key::from_u64(1);
        poller.add(a.as_raw_fd(), key).unwrap();
        // A second add surfaces EEXIST instead of silently modifying.
        let err = poller.add(a.as_raw_fd(), key).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EEXIST));
    }

    #[test]
    fn reports_each_ready_fd() {
        let (a1, b1) = UnixStream::pair().unwrap();
        let (a2, b2) = UnixStream::pair().unwrap();
        let mut poller = Poller::new(CAPACITY).unwrap();
        let k1 = Key::from_u64(100);
        let k2 = Key::from_u64(200);
        poller.add(a1.as_raw_fd(), k1).unwrap();
        poller.add(a2.as_raw_fd(), k2).unwrap();

        (&b1).write_all(b"x").unwrap();
        (&b2).write_all(b"y").unwrap();
        assert_eq!(poller.wait(Some(short())).unwrap(), 2);
        let keys: Vec<Key> = std::iter::from_fn(|| poller.next_event())
            .map(|e| e.key)
            .collect();
        assert!(keys.contains(&k1));
        assert!(keys.contains(&k2));
    }

    #[test]
    fn level_triggered_refires_until_drained() {
        // No edge mode: a readable fd re-fires every wait until drained, so a
        // handler may read once and trust the next wait to report the rest.
        let (mut a, b) = UnixStream::pair().unwrap();
        let mut poller = Poller::new(CAPACITY).unwrap();
        poller.add(a.as_raw_fd(), Key::from_u64(1)).unwrap();
        (&b).write_all(b"xy").unwrap();

        // Ready now, and still ready next wait because we did not drain it.
        assert_eq!(poller.wait(Some(short())).unwrap(), 1);
        assert_eq!(poller.wait(Some(short())).unwrap(), 1);

        // Drain it; now the fd is quiet.
        let mut buf = [0u8; 2];
        a.read_exact(&mut buf).unwrap();
        assert_eq!(poller.wait(Some(short())).unwrap(), 0);
    }
}
