//! kqueue readiness backend for macOS (the dev host) and FreeBSD.
//!
//! Level-triggered: read and write interest are toggled per registration (independent kqueue
//! filters). The reactor [`Key`] travels in each event's `udata`, so a wakeup carries its own
//! routing — no fd-to-handler side table.

use std::io;
use std::mem;
use std::num::NonZeroUsize;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
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
    next: usize,
}

impl Poller {
    /// Create a kqueue reporting up to `capacity` ready fds per [`wait`](Self::wait).
    pub(crate) fn new(capacity: NonZeroUsize) -> io::Result<Self> {
        // SAFETY: kqueue() takes no arguments; it returns a fresh fd or -1.
        let poll_fd = crate::sys::owned_fd_from(unsafe { libc::kqueue() })?;
        // SAFETY: an all-zero kevent is a valid, inert entry; wait() overwrites it.
        let blank: libc::kevent = unsafe { mem::zeroed() };
        log::trace!("kqueue poller created (capacity {capacity})");
        Ok(Self {
            poll_fd,
            events: vec![blank; capacity.get()].into_boxed_slice(),
            ready: 0,
            next: 0,
        })
    }

    /// Register `fd` with level-triggered read interest, tagged with `key`. Write
    /// interest starts off; change either with [`set_interest`](Self::set_interest).
    pub(crate) fn add(&self, fd: RawFd, key: Key) -> io::Result<()> {
        self.change(fd, libc::EVFILT_READ, libc::EV_ADD | libc::EV_ENABLE, key)?;
        log::trace!("kqueue: armed read on fd {fd}");
        Ok(())
    }

    /// Set `fd`'s interest (already [added](Self::add)) to `read`/`write`. The read filter from
    /// [`add`](Self::add) is toggled with `EV_ENABLE`/`EV_DISABLE` (it stays registered); the write
    /// filter is added/deleted on demand.
    pub(crate) fn set_interest(
        &self,
        fd: RawFd,
        key: Key,
        read: bool,
        write: bool,
    ) -> io::Result<()> {
        let read_flag = if read {
            libc::EV_ENABLE
        } else {
            libc::EV_DISABLE
        };
        self.change(fd, libc::EVFILT_READ, read_flag, key)?;
        let write_flags = if write {
            libc::EV_ADD | libc::EV_ENABLE
        } else {
            libc::EV_DELETE
        };
        match self.change(fd, libc::EVFILT_WRITE, write_flags, key) {
            Ok(()) => {}
            // Deleting a write filter that was never armed is a no-op.
            Err(e) if !write && e.raw_os_error() == Some(libc::ENOENT) => {}
            Err(e) => return Err(e),
        }
        log::trace!("kqueue: interest read={read} write={write} on fd {fd}");
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
    /// are; drain them with [`next_event`](Self::next_event). `EINTR` yields
    /// `Ok(0)` so the caller can re-check shutdown state and poll again.
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
        self.next = 0; // start draining the new batch from the front
        log::trace!("kqueue: {} ready", self.ready);
        Ok(self.ready)
    }

    /// The next event from the last [`wait`](Self::wait), or `None` once the batch
    /// is drained. Advances an internal cursor, so each event is yielded once.
    pub(crate) fn next_event(&mut self) -> Option<PollEvent> {
        if self.next >= self.ready {
            return None;
        }
        // Copy the (packed) kevent out so fields are read by value, never by ref.
        let event = self.events[self.next];
        self.next += 1;
        let filter = event.filter;
        let token = u64::try_from(event.udata.addr()).expect("udata holds a 64-bit token");
        Some(PollEvent {
            key: Key::from_u64(token),
            readiness: Readiness {
                readable: filter == libc::EVFILT_READ,
                writable: filter == libc::EVFILT_WRITE,
            },
        })
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
    use std::os::unix::net::UnixStream;

    const CAPACITY: NonZeroUsize = NonZeroUsize::new(8).unwrap();

    // The shared `Poller` contract tests live in the parent `poll` module; only the
    // kqueue-specific re-add behavior is tested here.
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
