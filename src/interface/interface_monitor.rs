//! Interface change monitoring: a routing socket whose readiness means some interface's
//! addresses (or MAC) changed, or an interface itself came or went, so the dispatcher should
//! react. `NETLINK_ROUTE` on Linux, `PF_ROUTE` on the BSDs. One [`InterfaceMonitor`] over a
//! per-platform backend, mirroring the resolver's rtnetlink/getifaddrs split.
//!
//! Best-effort: only keeps already-resolved addresses fresh. A failed open (or a read error)
//! degrades to the startup-resolved addresses; it never aborts the daemon.

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

/// Bound on consecutive `ENOBUFS` overflows in a single drain. The kernel clears the overflow
/// flag on the next recv, so an unbroken run of them means the socket is wedged. Stop rather
/// than spin the single-threaded loop forever; a level-triggered wait re-fires to try later.
const MAX_CONSECUTIVE_OVERFLOWS: u32 = 16;

/// What one routing-socket notification reported. The kind drives the dispatcher's trigger
/// policy; the monitor itself attaches no meaning beyond the message-type mapping.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum InterfaceEvent {
    /// An address-level change on the interface with this kernel index (also BSD `RTM_IFINFO`
    /// link-state/MAC updates: a flap refreshes addresses, it doesn't signal a lifecycle change).
    Address(u32),
    /// A link lifecycle event on the interface with this kernel index: Linux
    /// `RTM_{NEW,DEL}LINK` (creation, deletion, or any link change -- netlink doesn't
    /// distinguish), FreeBSD `RTM_IFANNOUNCE` (arrival/departure). macOS has no lifecycle
    /// message, so this variant is never constructed there.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    Link(u32),
    /// The socket overflowed and notifications were dropped: every interface may be stale.
    Overflow,
}

/// A routing-socket monitor for interface address and link changes. The dispatcher watches
/// its fd and calls [`drain`](Self::drain) on readiness.
pub(crate) struct InterfaceMonitor {
    sock: OwnedFd,
    /// Reused across drains, sized once at open and never grown. Each notification is a single
    /// bounded message (not a coalesced dump), so a fixed buffer fits with headroom. No
    /// data-path allocation.
    buf: Box<[u8]>,
}

impl InterfaceMonitor {
    /// Whether this platform allocates interface indexes monotonically (Linux: 31-bit cyclic
    /// per netns), so a newly-created interface always carries an index above every
    /// previously-seen one. The dispatcher gates unknown-index [`InterfaceEvent::Link`]
    /// events on that; the BSDs reuse indexes (FreeBSD hands out the lowest free, macOS
    /// recycles the whole ifnet), so no such gate is sound there. Two Linux corners slip the
    /// gate -- a device moved between netns keeps its (possibly low) index when free, and the
    /// 31-bit wrap -- both backstopped by the reconcile tick.
    pub(crate) const INDEXES_MONOTONIC: bool = backend::INDEXES_MONOTONIC;

    /// Whether this backend delivers [`InterfaceEvent::Link`] lifecycle events at all. Where
    /// it does not (macOS: no `RTM_IFANNOUNCE`), an unknown-index address event is the only
    /// signal a recreated interface ever sends, and must stand in as the recreation trigger.
    pub(crate) const LIFECYCLE_EVENTS: bool = backend::LIFECYCLE_EVENTS;

    /// Open and subscribe a routing socket, non-blocking and close-on-exec.
    ///
    /// # Errors
    /// Returns an error if the socket can't be opened or subscribed. A failure is the
    /// caller's cue to run without live updates, not to abort.
    pub(crate) fn open() -> io::Result<Self> {
        Ok(Self {
            sock: backend::open()?,
            buf: vec![0u8; backend::READ_BUF].into_boxed_slice(),
        })
    }

    /// The fd to watch for readiness.
    pub(crate) fn as_raw_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }

    /// Drain every queued notification, calling `on_change(event)` per affected interface;
    /// the per-interface events carry the kernel index. After an overflow it reports
    /// [`InterfaceEvent::Overflow`] once per burst. Reads to `EAGAIN` so a level-triggered
    /// wait won't immediately re-fire.
    ///
    /// # Errors
    /// The first non-recoverable recv failure. Recoverable: `EAGAIN`/`EWOULDBLOCK` end the
    /// drain, `ENOBUFS` reports the overflow and continues (bailing if it never clears).
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
            // ENOBUFS is the drain's own signal (a dropped-notification overflow → re-resolve
            // everything), so handle it before the generic classifier.
            if n < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOBUFS) {
                overflows += 1;
                if overflows == 1 {
                    // A dropped-notification overflow is abnormal (kernel buffer pressure or an
                    // event storm): warn here, not just the dispatcher's debug. Signal
                    // re-resolve-all once per burst; the dispatcher coalesces the 0, so repeating
                    // it per ENOBUFS is redundant.
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
            overflows = 0; // a successful recv breaks the overflow streak
            match IoStatus::from_syscall(n)? {
                // No more queued notifications (or a defensive empty read; routing sockets
                // don't EOF).
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
