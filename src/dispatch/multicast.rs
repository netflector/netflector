//! Multicast group membership for the capture interfaces: the kernel admits a group's frames to the
//! raw capture only once the interface joins it. One unbound `SOCK_DGRAM` socket per family per
//! interface, so Linux's `net.ipv4.igmp_max_memberships` (default 20, unraisable on a locked-down
//! router) is never reached; unbound, the kernel queues it no datagrams.

use std::io;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, OwnedFd};

use crate::libcex::{GroupReq, MCAST_JOIN_GROUP};
use crate::sys::{open_socket, setsockopt, sockaddr_for};

/// How a [`rejoin`](MulticastJoiner::rejoin) landed; the three sum to the desired-group count.
/// Only a deferral (no address of its family yet) has a known trigger that resolves it.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct RejoinCounts {
    pub(crate) joined: usize,
    pub(crate) deferred: usize,
    pub(crate) failed: usize,
}

/// `reported`: the current failure episode has been logged; cleared when the group joins.
struct Desired {
    group: IpAddr,
    reported: bool,
}

/// One interface's memberships: a socket per family, opened on first join. The caller passes the
/// interface's current ifindex per call; the joiner caches none.
pub(crate) struct MulticastJoiner {
    v4: Option<OwnedFd>,
    v6: Option<OwnedFd>,
    desired: Vec<Desired>,
    joins: bool,
}

impl MulticastJoiner {
    pub(crate) fn new() -> Self {
        Self {
            v4: None,
            v6: None,
            desired: Vec::new(),
            joins: true,
        }
    }

    /// Joins nothing: `--no-join`.
    pub(crate) fn inert() -> Self {
        Self {
            joins: false,
            ..Self::new()
        }
    }

    /// Record `group` for a later [`rejoin`](Self::rejoin) without joining: the parked-interface
    /// path. Returns its index in the desired list.
    pub(crate) fn record(&mut self, group: IpAddr) -> usize {
        if let Some(index) = self.desired.iter().position(|d| d.group == group) {
            return index;
        }
        self.desired.push(Desired {
            group,
            reported: false,
        });
        self.desired.len() - 1
    }

    /// Join `group` on `ifindex` and record it for later replays. Idempotent: the kernel keys
    /// memberships by `(group, ifindex)`.
    ///
    /// # Errors
    /// The OS error. `EADDRNOTAVAIL` (no address of that family yet) is deferrable:
    /// [`rejoin`](Self::rejoin) retries on the next address event. Any other error is marked
    /// reported: the caller's log is the report, and the replay repeats it at debug.
    pub(crate) fn join(&mut self, group: IpAddr, ifindex: NonZeroU32) -> io::Result<()> {
        if !self.joins {
            return Ok(());
        }
        let index = self.record(group);
        let result = self.apply(group, ifindex);
        if let Err(e) = &result
            && !join_deferrable(e)
        {
            self.desired[index].reported = true;
        }
        result
    }

    /// Drop the sockets so the next join starts fresh. Memberships keyed to a destroyed
    /// interface's index are never scrubbed from a surviving socket, and on Linux still count
    /// toward `igmp_max_memberships`; dropping the fds releases them all. `desired` survives for
    /// the replay.
    pub(crate) fn reset(&mut self) {
        self.v4 = None;
        self.v6 = None;
    }

    /// Re-attempt every recorded membership. A deferrable failure logs at debug (its address
    /// event is coming); anything else warns once per failure episode and logs info when it
    /// finally joins. `NonZeroU32`: `MCAST_JOIN_GROUP` on index 0 lets the kernel pick an
    /// arbitrary interface by route lookup, so callers skip explicitly while parked.
    pub(crate) fn rejoin(&mut self, ifindex: NonZeroU32) -> RejoinCounts {
        let mut counts = RejoinCounts::default();
        for i in 0..self.desired.len() {
            let group = self.desired[i].group;
            match self.apply(group, ifindex) {
                Ok(()) => {
                    counts.joined += 1;
                    if self.desired[i].reported {
                        self.desired[i].reported = false;
                        log::info!(
                            "re-join of {group} on ifindex {ifindex} succeeded after an \
                             earlier failure"
                        );
                    }
                }
                Err(e) if join_deferrable(&e) => {
                    log::debug!("re-join of {group} on ifindex {ifindex} deferred: {e}");
                    counts.deferred += 1;
                }
                Err(e) => {
                    counts.failed += 1;
                    if self.desired[i].reported {
                        log::debug!("re-join of {group} on ifindex {ifindex} still failing: {e}");
                    } else {
                        self.desired[i].reported = true;
                        log::warn!(
                            "re-join of {group} on ifindex {ifindex} failed; its traffic is \
                             not reflected: {e}"
                        );
                    }
                }
            }
        }
        counts
    }

    fn apply(&mut self, group: IpAddr, ifindex: NonZeroU32) -> io::Result<()> {
        let (slot, family, level) = match group {
            IpAddr::V4(_) => (&mut self.v4, libc::AF_INET, libc::IPPROTO_IP),
            IpAddr::V6(_) => (&mut self.v6, libc::AF_INET6, libc::IPPROTO_IPV6),
        };
        let fd = match slot {
            Some(sock) => sock.as_raw_fd(),
            None => slot
                .insert(open_socket(family, libc::SOCK_DGRAM, 0)?)
                .as_raw_fd(),
        };
        // Zeroed, not a field literal: `setsockopt` reads the padding after `gr_interface` too.
        // SAFETY: `group_req` is plain data; all-zero is valid.
        let mut req: GroupReq = unsafe { std::mem::zeroed() };
        req.gr_interface = ifindex.get();
        // `gr_interface` selects the interface, so the group sockaddr carries no scope id.
        req.gr_group = sockaddr_for(group, 0, 0).0;
        match setsockopt(fd, level, MCAST_JOIN_GROUP, &req) {
            Err(e) if !already_member(&e) => Err(e),
            _ => Ok(()),
        }
    }
}

/// Every target returns `EADDRINUSE` for an any-source re-join of a held membership; the
/// idempotent replay relies on it.
fn already_member(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::EADDRINUSE)
}

/// The environment can't join at all: QEMU user-mode returns `ENOPROTOOPT` for
/// `MCAST_JOIN_GROUP`. The join tests self-skip on it.
#[cfg(test)]
pub(crate) fn join_unsupported(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::ENOPROTOOPT | libc::EOPNOTSUPP | libc::ENOSYS)
    )
}

/// The socket holds as many memberships as the system allows: `ENOBUFS` on Linux
/// (`net.ipv4.igmp_max_memberships`), `ETOOMANYREFS` on the BSDs.
pub(crate) fn join_capped(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::ENOBUFS | libc::ETOOMANYREFS))
}

/// `EADDRNOTAVAIL`: the interface has no address of the group's family yet; the address event
/// that supplies one resolves it.
pub(crate) fn join_deferrable(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::EADDRNOTAVAIL)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn an_inert_joiner_joins_nothing_and_opens_no_socket() {
        let mut joiner = MulticastJoiner::inert();
        let ifindex = NonZeroU32::new(1).unwrap();
        joiner
            .join(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), ifindex)
            .unwrap();
        assert!(joiner.test_socketless());
        assert_eq!(joiner.rejoin(ifindex), RejoinCounts::default());
    }

    #[test]
    fn the_membership_cap_errnos_are_capped_joins() {
        let of = io::Error::from_raw_os_error;
        assert!(join_capped(&of(libc::ENOBUFS)));
        assert!(join_capped(&of(libc::ETOOMANYREFS)));
        assert!(!join_capped(&of(libc::EINVAL)));
        assert!(!join_capped(&of(libc::EADDRNOTAVAIL)));
    }

    #[test]
    fn only_eaddrnotavail_is_a_deferrable_join() {
        let of = io::Error::from_raw_os_error;
        assert!(join_deferrable(&of(libc::EADDRNOTAVAIL))); // an address event will fix it
        assert!(!join_deferrable(&of(libc::ENODEV))); // nothing in particular will
        assert!(!join_deferrable(&of(libc::EINVAL)));
    }

    impl MulticastJoiner {
        /// Whether no family socket is open (nothing joined since the last reset). Reachable
        /// from the interface table's parked-interface tests, hence `pub(in crate::dispatch)`.
        pub(in crate::dispatch) fn test_socketless(&self) -> bool {
            self.v4.is_none() && self.v6.is_none()
        }
    }

    #[test]
    fn already_member_only_for_the_duplicate_join_errno() {
        let of = io::Error::from_raw_os_error;
        assert!(already_member(&of(libc::EADDRINUSE))); // duplicate any-source join, every target
        assert!(!already_member(&of(libc::EINVAL))); // a genuine rejection (bad / non-multicast group)
        assert!(!already_member(&of(libc::ENOBUFS))); // membership cap, a real failure
        assert!(!already_member(&of(libc::EADDRNOTAVAIL))); // interface transiently down
    }

    fn loopback_ifindex() -> NonZeroU32 {
        let name =
            std::ffi::CString::new(crate::interface::LOOPBACK_IFACE).expect("iface has no NUL");
        // SAFETY: `name` is a valid C string.
        let idx = unsafe { libc::if_nametoindex(name.as_ptr()) };
        NonZeroU32::new(idx).expect("loopback must resolve to an index")
    }

    // reset drops the per-family sockets while keeping the desired list, so the next rejoin
    // replays every group on fresh fds (no zombie memberships from a destroyed interface).
    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn reset_keeps_desired_and_rejoin_replays_on_fresh_sockets() {
        let mut joiner = MulticastJoiner::new();
        let ifindex = loopback_ifindex();
        match joiner.join(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), ifindex) {
            Ok(()) => {}
            Err(e) if join_unsupported(&e) => {
                eprintln!("skip reset_keeps_desired: MCAST_JOIN_GROUP unsupported here ({e})");
                return;
            }
            Err(e) => panic!("kernel must accept the loopback join: {e}"),
        }
        assert!(joiner.v4.is_some());
        joiner.reset();
        assert!(joiner.v4.is_none(), "reset drops the family sockets");
        assert_eq!(joiner.desired.len(), 1, "the desired list survives");
        let counts = joiner.rejoin(ifindex);
        assert_eq!(
            (counts.joined, counts.deferred),
            (1, 0),
            "rejoin replays the one recorded group, none deferred"
        );
        assert!(
            joiner.v4.is_some(),
            "rejoin re-opens a fresh socket and re-joins"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real socket")]
    fn a_replayed_hard_failure_reports_once() {
        let mut joiner = MulticastJoiner::new();
        // A unicast address can never join, so every replay fails hard (EINVAL) deterministically.
        joiner.record(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let first = joiner.rejoin(loopback_ifindex());
        assert_eq!((first.joined, first.deferred, first.failed), (0, 0, 1));
        assert!(joiner.desired[0].reported, "the first failure is reported");
        let second = joiner.rejoin(loopback_ifindex());
        assert_eq!(second.failed, 1, "the group is still retried");
        assert!(joiner.desired[0].reported);
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real socket")]
    fn join_marks_a_hard_failure_reported() {
        let mut joiner = MulticastJoiner::new();
        let err = joiner
            .join(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), loopback_ifindex())
            .expect_err("a unicast address cannot join");
        assert!(!join_deferrable(&err));
        assert!(
            joiner.desired[0].reported,
            "the caller logs this error; the replay must not re-report it"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn a_join_clears_the_reported_mark() {
        let mut joiner = MulticastJoiner::new();
        let ifindex = loopback_ifindex();
        match joiner.join(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), ifindex) {
            Ok(()) => {}
            Err(e) if join_unsupported(&e) => {
                eprintln!("skip a_join_clears_the_reported_mark: unsupported here ({e})");
                return;
            }
            Err(e) => panic!("kernel must accept the loopback join: {e}"),
        }
        // As if an earlier replay failed: the next success closes the episode.
        joiner.desired[0].reported = true;
        let counts = joiner.rejoin(ifindex);
        assert_eq!((counts.joined, counts.failed), (1, 0));
        assert!(!joiner.desired[0].reported, "the join cleared the mark");
    }

    // The parked-interface path: record keeps the group for the rebuild's replay without
    // touching the kernel (no index exists to join on; MCAST_JOIN_GROUP on index 0 would let
    // the kernel pick an arbitrary interface, which the NonZeroU32 signatures now forbid).
    #[test]
    fn record_keeps_the_group_for_the_replay_without_joining() {
        let mut joiner = MulticastJoiner::new();
        joiner.record(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)));
        joiner.record(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251))); // deduped
        assert!(joiner.v4.is_none(), "no socket opened, no join attempted");
        assert_eq!(
            joiner.desired.len(),
            1,
            "the group is recorded once for the replay"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn kernel_accepts_a_join_on_loopback() {
        // Exercises the full MCAST_JOIN_GROUP FFI against the kernel (per-OS const, group_req layout,
        // by-index selection; by-index doesn't require the interface's IFF_MULTICAST flag). QEMU
        // doesn't implement the setsockopt, so self-skip there.
        let mut joiner = MulticastJoiner::new();
        let ifindex = loopback_ifindex();
        for group in [
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)),
        ] {
            match joiner.join(group, ifindex) {
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
