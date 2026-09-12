//! Interface change monitoring: a routing socket whose readiness means an interface's
//! addresses (or MAC) changed, or an interface came or went. `NETLINK_ROUTE` on Linux,
//! `PF_ROUTE` on the BSDs. Best-effort: a failed open or a read error degrades to the
//! startup-resolved addresses, never aborts the daemon.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use crate::sys::IoStatus;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod route;
#[cfg(target_os = "linux")]
mod rtnetlink;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
use self::route as backend;
#[cfg(target_os = "linux")]
use self::rtnetlink as backend;

/// The kernel clears the overflow flag on the next recv, so an unbroken run of `ENOBUFS` means
/// the socket is wedged: stop rather than spin; a level-triggered wait re-fires later.
const MAX_CONSECUTIVE_OVERFLOWS: u32 = 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum InterfaceEvent {
    /// An address-level change on this kernel index. BSD `RTM_IFINFO` (link state, MAC) maps
    /// here too: a flap refreshes addresses, it is not a lifecycle change.
    Address(u32),
    /// A link lifecycle event on this kernel index: Linux `RTM_{NEW,DEL}LINK` (creation,
    /// deletion or any link change, netlink doesn't distinguish), FreeBSD `RTM_IFANNOUNCE`.
    /// macOS has no lifecycle message, so this is never constructed there.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    Link(u32),
    /// Notifications were dropped: every interface may be stale.
    Overflow,
}

/// The dispatcher watches the fd and calls [`drain`](Self::drain) on readiness.
pub(crate) struct InterfaceMonitor {
    sock: OwnedFd,
    /// Sized once: each notification is one bounded message, never a coalesced dump.
    buf: Box<[u8]>,
}

impl InterfaceMonitor {
    /// Whether the platform allocates interface indexes monotonically, so a new interface
    /// carries an index above every one seen before (Linux: 31-bit cyclic per netns). The
    /// BSDs reuse indexes (FreeBSD hands out the lowest free, macOS recycles the whole ifnet),
    /// so the dispatcher's unknown-index [`InterfaceEvent::Link`] gate is unsound there. Two
    /// Linux corners slip the gate, a device moved between netns keeping a low index and the
    /// 31-bit wrap; the reconcile tick backstops both.
    pub(crate) const INDEXES_MONOTONIC: bool = backend::INDEXES_MONOTONIC;

    /// Whether the backend delivers [`InterfaceEvent::Link`] at all. Where it does not (macOS:
    /// no `RTM_IFANNOUNCE`), an unknown-index address event is the only signal a recreated
    /// interface ever sends and must stand in as the recreation trigger.
    pub(crate) const LIFECYCLE_EVENTS: bool = backend::LIFECYCLE_EVENTS;

    /// # Errors
    /// The socket could not be opened or subscribed: the caller's cue to run without live
    /// updates, not to abort.
    pub(crate) fn open() -> io::Result<Self> {
        Ok(Self {
            sock: backend::open()?,
            buf: vec![0u8; backend::READ_BUF].into_boxed_slice(),
        })
    }

    pub(crate) fn as_raw_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }

    /// Drain every queued notification. After an overflow, [`InterfaceEvent::Overflow`] once
    /// per burst. Reads to `EAGAIN` so a level-triggered wait won't immediately re-fire.
    ///
    /// # Errors
    /// The first non-recoverable recv failure; `ENOBUFS` reports the overflow and continues.
    pub(crate) fn drain(&mut self, mut on_change: impl FnMut(InterfaceEvent)) -> io::Result<()> {
        let mut overflows = 0u32;
        loop {
            // SAFETY: an all-zero sockaddr_storage is a valid, inert source-address out-param.
            let mut src: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut addrlen = libc::socklen_t::try_from(size_of::<libc::sockaddr_storage>())
                .expect("sockaddr_storage fits socklen_t");
            // SAFETY: `recvfrom` fills up to `buf.len()` bytes of the owned buffer and writes the
            // datagram's source address into the `src`/`addrlen` out-params.
            let n = unsafe {
                libc::recvfrom(
                    self.sock.as_raw_fd(),
                    self.buf.as_mut_ptr().cast(),
                    self.buf.len(),
                    0,
                    (&raw mut src).cast::<libc::sockaddr>(),
                    &raw mut addrlen,
                )
            };
            // ENOBUFS is the drain's own signal; handle it before the generic classifier.
            if n < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOBUFS) {
                overflows += 1;
                // Abnormal (buffer pressure or an event storm), so a warn of its own, not just the
                // dispatcher's debug. Once per burst: the dispatcher re-resolves everything on it.
                if overflows == 1 {
                    log::warn!(
                        "interface monitor overflowed; notifications were dropped, re-resolving every interface"
                    );
                    on_change(InterfaceEvent::Overflow);
                } else if overflows >= MAX_CONSECUTIVE_OVERFLOWS {
                    log::warn!(
                        "interface monitor overflow did not clear after {overflows} reads; ending the drain"
                    );
                    return Ok(());
                }
                continue;
            }
            overflows = 0;
            match IoStatus::from_syscall(n)? {
                // Routing sockets don't EOF; a 0 read is treated as drained.
                IoStatus::WouldBlock | IoStatus::Ready(0) => return Ok(()),
                IoStatus::Ready(len) => {
                    if backend::sender_ok(&src, addrlen) {
                        backend::for_each_change(&self.buf[..len], &mut on_change);
                    } else {
                        log::debug!(
                            "interface monitor: dropping a notification from a non-kernel sender"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A freshly-opened monitor drains at once (the socket is non-blocking) without blocking
    // or erroring. Best-effort: some sandboxes deny the routing socket, where the monitor
    // degrades to no live updates, so there's nothing to drain and we skip.
    #[test]
    #[cfg_attr(miri, ignore = "needs a real routing socket")]
    fn opens_and_drains_without_blocking() {
        let mut monitor = match InterfaceMonitor::open() {
            Ok(monitor) => monitor,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skip: the routing socket could not be opened: {e}");
                return;
            }
            Err(e) => panic!("unexpected monitor open failure: {e}"),
        };
        monitor.drain(|_| {}).expect("drain a quiet monitor");
    }
}
