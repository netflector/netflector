//! Readiness backend: an OS-uniform [`Poller`] over the platform's readiness
//! syscalls. A wait reports which registered fds are ready, each tagged with the
//! reactor [`Key`] handed to the kernel, so dispatch needs no fd-to-handler side
//! table. Backends: kqueue (macOS/FreeBSD) and epoll (Linux).

use super::{Key, Readiness};

#[cfg(target_os = "linux")]
mod epoll;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod kqueue;

#[cfg(target_os = "linux")]
pub(crate) use self::epoll::Poller;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) use self::kqueue::Poller;

/// One ready fd from a [`Poller`] wait: the [`Key`] it was registered under and
/// what it is ready for.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PollEvent {
    pub key: Key,
    pub readiness: Readiness,
}

// Tests of the uniform `Poller` contract, run against whichever backend compiles
// (kqueue on macOS/FreeBSD, epoll on Linux). Backend-specific behavior the two
// can't share, like re-adding an fd, is tested in each backend module instead.
#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::num::NonZeroUsize;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use super::{Key, Poller};

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
        poller.set_interest(a.as_raw_fd(), key, true, true).unwrap();
        assert_eq!(poller.wait(Some(short())).unwrap(), 1);
        let event = poller.next_event().unwrap();
        assert_eq!(event.key, key);
        assert!(event.readiness.writable);

        // Disarmed again: back to nothing.
        poller
            .set_interest(a.as_raw_fd(), key, true, false)
            .unwrap();
        assert_eq!(poller.wait(Some(short())).unwrap(), 0);
    }

    #[test]
    fn read_interest_toggles() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut poller = Poller::new(CAPACITY).unwrap();
        let key = Key::from_u64(9);
        poller.add(a.as_raw_fd(), key).unwrap();
        (&b).write_all(b"x").unwrap();

        // Read armed by add(): the byte makes `a` readable.
        assert_eq!(poller.wait(Some(short())).unwrap(), 1);

        // Disarm read: the still-buffered byte no longer wakes us.
        poller
            .set_interest(a.as_raw_fd(), key, false, false)
            .unwrap();
        assert_eq!(poller.wait(Some(short())).unwrap(), 0);

        // Re-arm read: the buffered byte fires again (level-triggered).
        poller
            .set_interest(a.as_raw_fd(), key, true, false)
            .unwrap();
        assert_eq!(poller.wait(Some(short())).unwrap(), 1);
    }

    #[test]
    fn disarming_unarmed_write_is_ok() {
        let (a, _b) = UnixStream::pair().unwrap();
        let poller = Poller::new(CAPACITY).unwrap();
        let key = Key::from_u64(1);
        poller.add(a.as_raw_fd(), key).unwrap();
        // Disarming write interest that was never armed must succeed.
        poller
            .set_interest(a.as_raw_fd(), key, true, false)
            .unwrap();
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
        // Level-triggered (no edge/one-shot mode): a readable fd re-fires every wait until drained, so a
        // handler may read once and trust the next wait for the rest.
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
