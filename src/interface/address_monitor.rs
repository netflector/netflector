//! Interface address-change monitoring: a routing socket whose readiness means some
//! interface's addresses (or MAC) changed, so the dispatcher should re-resolve it.
//! `NETLINK_ROUTE` on Linux, `PF_ROUTE` on the BSDs. One [`AddressMonitor`] over a
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

/// A routing-socket monitor for interface address and link changes. The dispatcher watches
/// its fd and calls [`drain`](Self::drain) on readiness.
pub(crate) struct AddressMonitor {
    sock: OwnedFd,
    /// Reused across drains, sized once at open and never grown. Each notification is a single
    /// bounded message (not a coalesced dump), so a fixed buffer fits with headroom. No
    /// data-path allocation.
    buf: Box<[u8]>,
}

impl AddressMonitor {
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

    /// Drain every queued notification, calling `on_change(ifindex)` per affected interface.
    /// After an overflow it calls `on_change(0)`, meaning "re-resolve everything" (kernel
    /// indices are >= 1, so 0 is an unambiguous signal). Reads to `EAGAIN` so a level-triggered
    /// wait won't immediately re-fire.
    ///
    /// # Errors
    /// The first non-recoverable recv failure. Recoverable: `EAGAIN`/`EWOULDBLOCK` end the
    /// drain, `ENOBUFS` reports the overflow signal and continues (bailing if it never clears).
    pub(crate) fn drain(&mut self, mut on_change: impl FnMut(u32)) -> io::Result<()> {
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
                        "address monitor overflowed; notifications were dropped, re-resolving every interface"
                    );
                    on_change(0);
                } else if overflows >= MAX_CONSECUTIVE_OVERFLOWS {
                    log::warn!(
                        "address monitor overflow did not clear after {overflows} reads; ending the drain"
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
                            "address monitor: dropping a notification from a non-kernel sender"
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
        let mut monitor = match AddressMonitor::open() {
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
