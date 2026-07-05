//! Multicast group membership for the capture interfaces: the kernel admits a group's frames to the
//! raw capture only once the interface joins it (which also drives the IGMP/MLD join upstream). One
//! unbound `SOCK_DGRAM` socket per family, **per interface** — sharding by interface caps each socket
//! at the few reflected protocols (mDNS + SSDP), so Linux's `net.ipv4.igmp_max_memberships` (default
//! 20, unraisable on a locked-down router) is never reached. Unbound so the kernel queues it no
//! datagrams (UDP demux is by bound port); dropping the socket drops its memberships.

use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, OwnedFd};

use libc::c_void;

use crate::libcex::{GroupReq, MCAST_JOIN_GROUP};
use crate::sys::{open_socket, sockaddr_for, socklen_of};

/// One capture interface's multicast memberships: one unbound `SOCK_DGRAM` fd per family, opened on
/// that family's first join, under a fixed `ifindex`. `desired` records requested groups so they can
/// be re-attempted when the interface re-resolves (a v4 group joined before its address existed
/// becomes joinable then).
pub(crate) struct MulticastJoiner {
    ifindex: u32,
    v4: Option<OwnedFd>,
    v6: Option<OwnedFd>,
    desired: Vec<IpAddr>,
}

impl MulticastJoiner {
    pub(crate) fn new(ifindex: u32) -> Self {
        Self {
            ifindex,
            v4: None,
            v6: None,
            desired: Vec::new(),
        }
    }

    /// Join `group` on this interface and record it, so a later interface change re-attempts it.
    /// Idempotent: the kernel keys memberships by `(group, ifindex)`.
    ///
    /// # Errors
    /// The OS error if the socket can't open or the membership can't be added. `EADDRNOTAVAIL` (no
    /// address of that family yet) is deferrable — the group is recorded and [`rejoin`](Self::rejoin)
    /// retries it on the next address-up event.
    pub(crate) fn join(&mut self, group: IpAddr) -> io::Result<()> {
        if !self.desired.contains(&group) {
            self.desired.push(group);
        }
        self.apply(group)
    }

    /// Re-attempt every recorded membership after the interface re-resolves — a group not joinable
    /// before its address existed succeeds now; an already-held one is a no-op. Best-effort: a
    /// still-unavailable family logs and waits for the next change.
    pub(crate) fn rejoin(&mut self) {
        for i in 0..self.desired.len() {
            let group = self.desired[i];
            if let Err(e) = self.apply(group) {
                log::debug!(
                    "re-join of {group} on ifindex {} deferred: {e}",
                    self.ifindex
                );
            }
        }
    }

    fn apply(&mut self, group: IpAddr) -> io::Result<()> {
        let (slot, family, level) = match group {
            IpAddr::V4(_) => (&mut self.v4, libc::AF_INET, libc::IPPROTO_IP),
            IpAddr::V6(_) => (&mut self.v6, libc::AF_INET6, libc::IPPROTO_IPV6),
        };
        let fd = match slot {
            Some(sock) => sock.as_raw_fd(),
            None => slot
                .insert(open_socket(family, libc::SOCK_DGRAM)?)
                .as_raw_fd(),
        };
        // Zero first: a field-by-field literal would leave the padding after `gr_interface`
        // uninitialised, and `setsockopt` reads the whole struct (Valgrind flags them).
        // SAFETY: `group_req` is plain data; all-zero is valid.
        let mut req: GroupReq = unsafe { std::mem::zeroed() };
        req.gr_interface = self.ifindex;
        // Interface is selected by `gr_interface`, so the group sockaddr carries no scope id.
        req.gr_group = sockaddr_for(group, 0, 0).0;
        // SAFETY: `req` is a fully-initialised `group_req` (padding zeroed), passed by address + size.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                MCAST_JOIN_GROUP,
                (&raw const req).cast::<c_void>(),
                socklen_of::<GroupReq>(),
            )
        };
        if rc != 0 {
            let err = io::Error::last_os_error();
            // Already a member is success — the idempotent re-attempt depends on it.
            if !already_member(&err) {
                return Err(err);
            }
        }
        Ok(())
    }
}

/// Whether a join error means the membership is already held — a benign duplicate. The errno isn't
/// uniform: Linux and the BSDs' IPv4 path return `EADDRINUSE`, FreeBSD's IPv6 path `EINVAL`.
fn already_member(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::EADDRINUSE | libc::EINVAL))
}

/// Whether a join error means the environment can't perform the join at all (vs a real rejection) —
/// the cue for the join tests to self-skip. QEMU user-mode emulation doesn't implement the
/// `MCAST_JOIN_GROUP` setsockopt (returns `ENOPROTOOPT`). Test seam only: at runtime these stay fatal.
#[cfg(test)]
pub(crate) fn join_unsupported(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::ENOPROTOOPT | libc::EOPNOTSUPP | libc::ENOSYS)
    )
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn already_member_only_for_the_duplicate_join_errnos() {
        let of = io::Error::from_raw_os_error;
        assert!(already_member(&of(libc::EADDRINUSE))); // Linux / BSD IPv4 duplicate
        assert!(already_member(&of(libc::EINVAL))); // FreeBSD IPv6 duplicate
        assert!(!already_member(&of(libc::ENOBUFS))); // membership cap — a real failure
        assert!(!already_member(&of(libc::EADDRNOTAVAIL))); // interface transiently down
    }

    fn loopback_ifindex() -> u32 {
        let name =
            std::ffi::CString::new(crate::interface::LOOPBACK_IFACE).expect("iface has no NUL");
        // SAFETY: `name` is a valid C string.
        let idx = unsafe { libc::if_nametoindex(name.as_ptr()) };
        assert_ne!(idx, 0, "loopback must resolve to an index");
        idx
    }

    #[test]
    fn kernel_accepts_a_join_on_loopback() {
        // Exercises the full MCAST_JOIN_GROUP FFI against the kernel (per-OS const, group_req layout,
        // by-index selection; by-index doesn't require the interface's IFF_MULTICAST flag). QEMU
        // doesn't implement the setsockopt, so self-skip there.
        let mut joiner = MulticastJoiner::new(loopback_ifindex());
        for group in [
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)),
        ] {
            match joiner.join(group) {
                Ok(()) => {}
                Err(e) if join_unsupported(&e) => {
                    eprintln!(
                        "skip kernel_accepts_a_join: MCAST_JOIN_GROUP unsupported here ({e})"
                    );
                    return;
                }
                Err(e) => panic!("kernel must accept the {group} group join: {e}"),
            }
        }
    }
}
