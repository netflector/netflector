//! Multicast group membership for the capture interfaces. The kernel admits a group's frames to the
//! raw capture only once the interface joins it, which also drives the IGMP/MLD join upstream. One
//! unbound `SOCK_DGRAM` socket per family, per interface. Sharding by interface caps each socket
//! at the few reflected protocols (mDNS + SSDP), so Linux's `net.ipv4.igmp_max_memberships` (default
//! 20, unraisable on a locked-down router) is never reached. Unbound so the kernel queues it no
//! datagrams (UDP demux is by bound port); dropping the socket drops its memberships.

use std::io;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, OwnedFd};

use libc::c_void;

use crate::libcex::{GroupReq, MCAST_JOIN_GROUP};
use crate::sys::{open_socket, sockaddr_for, socklen_of};

/// How a [`rejoin`](MulticastJoiner::rejoin) replay landed: `joined` groups are members after the
/// call (freshly re-joined, or already member), `deferred` groups have no address of their family
/// yet, `failed` groups hit something else. The three sum to the desired-group count. Every desired
/// group is re-applied on every call, so both failure kinds are retried alike; the split is about
/// what to expect, since only a deferral has a known trigger that resolves it. `joined` (not
/// "rejoined": the parked-return replay is a first join) is the signal a caller uses to tell a real
/// replay from a vacuous one over an empty desired list.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct RejoinCounts {
    pub(crate) joined: usize,
    pub(crate) deferred: usize,
    pub(crate) failed: usize,
}

/// One recorded membership: the group wanted on this interface, and whether its current failure has
/// been reported, so a group that can't join logs once per failure episode rather than on every
/// replay. Cleared when the group joins, so a later relapse reports again.
struct Desired {
    group: IpAddr,
    reported: bool,
}

/// One capture interface's multicast memberships: one unbound `SOCK_DGRAM` fd per family, opened on
/// that family's first join. The joiner holds no ifindex of its own -- the caller passes the
/// interface's current one per call, so the table's [`Interface`](crate::interface::Interface) stays
/// the single cached copy. `desired` records requested groups so they can be re-attempted when the
/// interface re-resolves (a v4 group joined before its address existed becomes joinable then).
pub(crate) struct MulticastJoiner {
    v4: Option<OwnedFd>,
    v6: Option<OwnedFd>,
    desired: Vec<Desired>,
    /// Cleared for an inert joiner, whose joins succeed without a membership.
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

    /// A joiner that joins nothing: `--no-join`. Its joins are successful no-ops and its
    /// rejoins have nothing to replay.
    pub(crate) fn inert() -> Self {
        Self {
            joins: false,
            ..Self::new()
        }
    }

    /// Record `group` for a later [`rejoin`](Self::rejoin) without joining now: the
    /// parked-interface path, where no live index exists to join on. Deduped, like
    /// [`join`](Self::join)'s own recording. Returns the group's index in the desired list.
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

    /// Join `group` on the interface `ifindex` and record it, so a later interface change
    /// re-attempts it. Idempotent: the kernel keys memberships by `(group, ifindex)`.
    /// `NonZeroU32` for the same reason as [`rejoin`](Self::rejoin); a parked caller
    /// [`record`](Self::record)s instead.
    ///
    /// # Errors
    /// The OS error if the socket can't open or the membership can't be added. `EADDRNOTAVAIL` (no
    /// address of that family yet) is deferrable: the group is recorded and [`rejoin`](Self::rejoin)
    /// retries it on the next address-up event. Any other error is marked reported before it
    /// returns -- the caller's log is the report, and the replay repeats it at debug only.
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

    /// Drop the per-family sockets, so the next join starts from fresh ones. For an interface
    /// that was destroyed: memberships keyed to the dead index are never scrubbed from a
    /// surviving socket, and on Linux those zombies still count toward
    /// `igmp_max_memberships` (default 20, unraisable on a locked-down router), so re-joining
    /// on kept sockets would exhaust the cap after a handful of recreations. Dropping the fds
    /// releases every membership at once; `desired` survives for the replay.
    pub(crate) fn reset(&mut self) {
        self.v4 = None;
        self.v6 = None;
    }

    /// Re-attempt every recorded membership after the interface re-resolves, returning the
    /// [`RejoinCounts`] split of joined, deferred and failed. A group not joinable before its
    /// address existed succeeds now; an already-held one is a no-op that still counts as joined.
    /// Best-effort: a [deferrable](join_deferrable) failure logs at debug, since the address event
    /// that resolves it is coming. Anything else logs at warn once per failure episode -- repeats
    /// at debug, since the replay runs on every address event -- and at info when the group
    /// finally joins.
    /// `NonZeroU32` makes the parked case unrepresentable: `MCAST_JOIN_GROUP` on index 0
    /// would let the kernel pick an arbitrary interface by route lookup and advertise our groups
    /// there, so callers skip explicitly while parked.
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
                .insert(open_socket(family, libc::SOCK_DGRAM)?)
                .as_raw_fd(),
        };
        // Zero first: a field-by-field literal would leave the padding after `gr_interface`
        // uninitialised, and `setsockopt` reads the whole struct (Valgrind flags them).
        // SAFETY: `group_req` is plain data; all-zero is valid.
        let mut req: GroupReq = unsafe { std::mem::zeroed() };
        req.gr_interface = ifindex.get();
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
            // Already a member is success: the idempotent re-attempt depends on it.
            if !already_member(&err) {
                return Err(err);
            }
        }
        Ok(())
    }
}

/// Whether a join error means the membership is already held, the benign duplicate the idempotent join
/// relies on. Every target returns `EADDRINUSE` for an any-source re-join of an existing membership.
fn already_member(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::EADDRINUSE)
}

/// Whether a join error means the environment can't perform the join at all (vs a real rejection),
/// the cue for the join tests to self-skip. QEMU user-mode emulation doesn't implement the
/// `MCAST_JOIN_GROUP` setsockopt (returns `ENOPROTOOPT`). Test seam only: at runtime these stay fatal.
#[cfg(test)]
pub(crate) fn join_unsupported(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::ENOPROTOOPT | libc::EOPNOTSUPP | libc::ENOSYS)
    )
}

/// Whether a group-join failure means the socket holds as many memberships as the system allows:
/// `ENOBUFS` on Linux (`net.ipv4.igmp_max_memberships`), `ETOOMANYREFS` on the BSDs.
pub(crate) fn join_capped(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::ENOBUFS | libc::ETOOMANYREFS))
}

/// Whether a group-join failure is deferrable: `EADDRNOTAVAIL` means the interface has no address of
/// the group's family yet, so the group joins on the address event that supplies one. Every other
/// error is replayed just the same, but has no trigger anyone can name, so it reports as a failure
/// rather than a wait.
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
