//! kqueue readiness backend for macOS (the dev host) and FreeBSD.
//!
//! Level-triggered: read interest is added once and stays armed, write interest
//! is toggled per registration. The reactor [`Key`] travels in each event's
//! `udata`, so a wakeup carries its own routing — no fd-to-handler side table.

use std::io;
use std::mem;
use std::num::NonZeroUsize;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use std::time::Duration;

use super::PollEvent;
use crate::reactor::{Key, Readiness};

// The Key rides in kevent's pointer-sized `udata`; a sub-64-bit pointer would
// truncate the generation half and silently alias slots. Our kqueue targets
// (macOS, FreeBSD amd64/arm64) are 64-bit — fail the build loudly otherwise.
const _: () = assert!(
    mem::size_of::<*mut libc::c_void>() >= mem::size_of::<u64>(),
    "kqueue backend needs a 64-bit udata to carry the full Key",
);

/// A kqueue descriptor and the reusable buffer its waits report into.
pub(crate) struct Poller {
    poll_fd: OwnedFd,
    events: Box<[libc::kevent]>,
    ready: usize,
}

impl Poller {
    /// Create a kqueue reporting up to `capacity` ready fds per [`wait`](Self::wait).
    pub(crate) fn new(capacity: NonZeroUsize) -> io::Result<Self> {
        // SAFETY: kqueue() takes no arguments; it returns a fresh fd or -1.
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh descriptor we exclusively own.
        let poll_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: an all-zero kevent is a valid, inert entry; wait() overwrites it.
        let blank: libc::kevent = unsafe { mem::zeroed() };
        log::trace!("kqueue poller created (capacity {capacity})");
        Ok(Self {
            poll_fd,
            events: vec![blank; capacity.get()].into_boxed_slice(),
            ready: 0,
        })
    }

    /// Add level-triggered read interest on `fd`, tagged with `key`. Write
    /// interest starts off; toggle it with [`set_write`](Self::set_write).
    pub(crate) fn add(&self, fd: RawFd, key: Key) -> io::Result<()> {
        self.change(fd, libc::EVFILT_READ, libc::EV_ADD | libc::EV_ENABLE, key)?;
        log::trace!("kqueue: armed read on fd {fd}");
        Ok(())
    }

    /// Arm or disarm write interest on `fd` (already [added](Self::add)).
    pub(crate) fn set_write(&self, fd: RawFd, key: Key, enabled: bool) -> io::Result<()> {
        let flags = if enabled {
            libc::EV_ADD | libc::EV_ENABLE
        } else {
            libc::EV_DELETE
        };
        match self.change(fd, libc::EVFILT_WRITE, flags, key) {
            Ok(()) => {}
            // Disarming a write filter that was never armed is a no-op.
            Err(e) if !enabled && e.raw_os_error() == Some(libc::ENOENT) => {}
            Err(e) => return Err(e),
        }
        log::trace!(
            "kqueue: write interest {} on fd {fd}",
            if enabled { "armed" } else { "disarmed" }
        );
        Ok(())
    }

    /// Drop all interest on `fd`. Filters the kernel already removed (e.g. when
    /// `fd` was closed) report `ENOENT`, which is benign.
    pub(crate) fn remove(&self, fd: RawFd) -> io::Result<()> {
        for filter in [libc::EVFILT_READ, libc::EVFILT_WRITE] {
            match self.change_raw(fd, filter, libc::EV_DELETE, 0) {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
                Err(e) => return Err(e),
            }
        }
        log::trace!("kqueue: removed fd {fd}");
        Ok(())
    }

    /// Block until at least one fd is ready, or until `timeout` elapses (`None`
    /// blocks indefinitely), recording the ready events. Returns how many there
    /// are; read each with [`event`](Self::event). `EINTR` yields `Ok(0)` so the
    /// caller can re-check shutdown state and poll again.
    pub(crate) fn wait(&mut self, timeout: Option<Duration>) -> io::Result<usize> {
        let max_events = libc::c_int::try_from(self.events.len()).unwrap_or(libc::c_int::MAX);
        let ts = timeout.map(to_timespec);
        let ts_ptr = ts.as_ref().map_or(ptr::null(), ptr::from_ref);
        // SAFETY: no changes submitted (null/0); the eventlist is our owned buffer
        // sized by `max_events`; `ts_ptr` is null or points to the live local `ts`.
        let count = unsafe {
            libc::kevent(
                self.poll_fd.as_raw_fd(),
                ptr::null(),
                0,
                self.events.as_mut_ptr(),
                max_events,
                ts_ptr,
            )
        };
        if count < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                self.ready = 0;
                log::trace!("kqueue: wait interrupted");
                return Ok(0);
            }
            return Err(err);
        }
        self.ready = usize::try_from(count).expect("kevent count is non-negative");
        log::trace!("kqueue: {} ready", self.ready);
        Ok(self.ready)
    }

    /// The `i`-th event from the last [`wait`](Self::wait); `i` must be less than
    /// the count it returned.
    pub(crate) fn event(&self, i: usize) -> PollEvent {
        assert!(
            i < self.ready,
            "event index {i} is past the wait count {}",
            self.ready
        );
        // Copy the (packed) kevent out so fields are read by value, never by ref.
        let event = self.events[i];
        let filter = event.filter;
        let token = u64::try_from(event.udata.addr()).expect("udata holds a 64-bit token");
        PollEvent {
            key: Key::from_u64(token),
            readiness: Readiness {
                readable: filter == libc::EVFILT_READ,
                writable: filter == libc::EVFILT_WRITE,
            },
        }
    }

    fn change(&self, fd: RawFd, filter: i16, flags: u16, key: Key) -> io::Result<()> {
        self.change_raw(fd, filter, flags, key.to_u64())
    }

    fn change_raw(&self, fd: RawFd, filter: i16, flags: u16, token: u64) -> io::Result<()> {
        let ident = usize::try_from(fd).expect("registered fd is non-negative");
        // SAFETY: a zeroed kevent is valid; we then set every meaningful field.
        let mut change: libc::kevent = unsafe { mem::zeroed() };
        change.ident = ident;
        change.filter = filter;
        change.flags = flags;
        change.udata = ptr::without_provenance_mut(
            usize::try_from(token).expect("token fits a 64-bit pointer"),
        );
        // SAFETY: submit exactly one change; request no events and do not wait.
        let rc = unsafe {
            libc::kevent(
                self.poll_fd.as_raw_fd(),
                &raw const change,
                1,
                ptr::null_mut(),
                0,
                ptr::null(),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// A relative `timeout` as the `timespec` kqueue expects, clamping an
/// astronomically long duration rather than overflowing.
fn to_timespec(timeout: Duration) -> libc::timespec {
    // SAFETY: an all-zero timespec is valid; the meaningful fields are set below.
    let mut ts: libc::timespec = unsafe { mem::zeroed() };
    ts.tv_sec = libc::time_t::try_from(timeout.as_secs()).unwrap_or(libc::time_t::MAX);
    ts.tv_nsec = timeout.subsec_nanos().into();
    ts
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
        let event = poller.event(0);
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
        let event = poller.event(0);
        assert_eq!(event.key, key);
        assert!(event.readiness.writable);

        // Disarmed again: back to nothing.
        poller.set_write(a.as_raw_fd(), key, false).unwrap();
        assert_eq!(poller.wait(Some(short())).unwrap(), 0);
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
    fn disarming_unarmed_write_is_ok() {
        let (a, _b) = UnixStream::pair().unwrap();
        let poller = Poller::new(CAPACITY).unwrap();
        let key = Key::from_u64(1);
        poller.add(a.as_raw_fd(), key).unwrap();
        // Disarming write interest that was never armed must succeed.
        poller.set_write(a.as_raw_fd(), key, false).unwrap();
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
        let count = poller.wait(Some(short())).unwrap();
        assert_eq!(count, 2);
        let keys: Vec<Key> = (0..count).map(|i| poller.event(i).key).collect();
        assert!(keys.contains(&k1));
        assert!(keys.contains(&k2));
    }

    #[test]
    fn level_triggered_refires_until_drained() {
        // No EV_CLEAR: a readable fd re-fires every wait until drained, so a
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

    #[test]
    fn re_add_is_idempotent() {
        let (a, _b) = UnixStream::pair().unwrap();
        let poller = Poller::new(CAPACITY).unwrap();
        let key = Key::from_u64(1);
        poller.add(a.as_raw_fd(), key).unwrap();
        // kqueue's EV_ADD modifies in place on re-add (it can't report EEXIST),
        // so a second add succeeds — unlike epoll, which surfaces it.
        poller.add(a.as_raw_fd(), key).unwrap();
    }
}
