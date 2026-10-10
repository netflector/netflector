//! Multicast group membership for the capture interfaces: the kernel admits a group's frames to the
//! raw capture only once the interface joins it. One unbound `SOCK_DGRAM` socket per family per
//! interface, so Linux's `net.ipv4.igmp_max_memberships` (default 20, unraisable on a locked-down
//! router) is never reached; unbound, the kernel queues it no datagrams.

use std::io;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Instant;

use crate::interface::{InterfaceName, if_index_checked};
use crate::sys::{open_socket, setsockopt, sockaddr_for};

use super::retry_delay;

/// Why a live interface takes no membership as it is. Re-reading the interface retries the join.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Wait {
    /// macOS joins a group only once the interface has the group's address family, which its
    /// first address of that family attaches.
    NoAddress,
    /// The interface carries no IPv4 or no IPv6 at all: on Linux, an MTU below the family's
    /// minimum (1280 for IPv6).
    NoFamily,
    /// The BSDs give no membership to an interface without `IFF_MULTICAST`.
    NotMulticast,
}

/// How a reflector wants a group.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Wanted {
    /// The protocol, for the logs.
    pub(crate) label: &'static str,
    /// The entry requires the group's address family: [`Wait::NoFamily`] then fails the join.
    pub(crate) required: bool,
    /// The level a wait logs at.
    pub(crate) wait_level: log::Level,
}

#[derive(Debug)]
pub(crate) enum JoinError {
    /// The index names no interface any more.
    Gone,
    /// [`Wait::NoFamily`] for a family the entry requires.
    NoFamily,
    /// `capped`: the socket holds as many memberships as the system allows.
    Failed { source: io::Error, capped: bool },
}

/// The interface a pass joins on. The memberships cache no index.
#[derive(Clone, Copy)]
pub(crate) struct Target<'a> {
    pub(crate) name: &'a InterfaceName,
    pub(crate) ifindex: NonZeroU32,
}

impl Target<'_> {
    /// Whether the name still resolves to the index.
    fn is_live(&self) -> io::Result<bool> {
        if_index_checked(self.name).map(|current| current == Some(self.ifindex))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Not attempted on the sockets held now, or refused by an interface found gone.
    Pending,
    Joined,
    Waiting(Wait),
    /// Any other failure; retried from `retry_at`.
    Failed {
        attempts: u32,
        retry_at: Instant,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Problem {
    Wait(Wait),
    Failed,
}

/// One attempt on a live interface.
#[derive(Debug)]
enum Outcome {
    Joined,
    Waits(Wait),
    Failed { source: io::Error, capped: bool },
}

/// The index names no interface any more.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Gone;

struct Membership {
    group: IpAddr,
    label: &'static str,
    wait_level: log::Level,
    state: State,
    /// The problem last reported. A join clears it, so a problem is reported once until the
    /// group joins, however often the interface is rebuilt in between.
    reported: Option<Problem>,
}

impl Membership {
    /// At the group's level, or at debug when this problem was reported already.
    fn report_wait(&mut self, wait: Wait, name: &InterfaceName) {
        let (group, label) = (self.group, self.label);
        let level = if self.reported == Some(Problem::Wait(wait)) {
            log::Level::Debug
        } else {
            self.wait_level
        };
        let family = if group.is_ipv4() { "IPv4" } else { "IPv6" };
        match wait {
            Wait::NoAddress => log::log!(
                level,
                "{label}: joining {group} on {name} once it has an {family} address"
            ),
            Wait::NoFamily => log::log!(
                level,
                "{label}: {group} is not joined on {name}: the interface has no {family}"
            ),
            Wait::NotMulticast => log::log!(
                level,
                "{label}: {group} is not joined on {name}: the interface takes no multicast \
                 memberships"
            ),
        }
        self.reported = Some(Problem::Wait(wait));
    }

    fn settle(&mut self, outcome: Outcome, name: &InterfaceName, now: Instant) {
        let (group, label) = (self.group, self.label);
        match outcome {
            Outcome::Joined => {
                if self.reported.take().is_some() {
                    log::info!("{label}: joined {group} on {name}");
                } else {
                    log::debug!("{label}: joined {group} on {name}");
                }
                self.state = State::Joined;
            }
            Outcome::Waits(wait) => {
                if self.state == State::Waiting(wait) {
                    return;
                }
                self.report_wait(wait, name);
                self.state = State::Waiting(wait);
            }
            Outcome::Failed { source, .. } => {
                let attempts = match self.state {
                    State::Failed { attempts, .. } => attempts.saturating_add(1),
                    _ => 0,
                };
                if self.reported == Some(Problem::Failed) {
                    log::debug!("{label}: joining {group} on {name} still fails: {source}");
                } else {
                    log::warn!(
                        "{label}: joining {group} on {name} failed; its traffic is not reflected \
                         until a retry succeeds: {source}"
                    );
                }
                self.reported = Some(Problem::Failed);
                self.state = State::Failed {
                    attempts,
                    retry_at: now + retry_delay(attempts),
                };
            }
        }
    }
}

/// A socket per family, opened on first use.
#[derive(Default)]
struct Sockets {
    v4: Option<OwnedFd>,
    v6: Option<OwnedFd>,
}

impl Sockets {
    fn join(&mut self, group: IpAddr, target: Target<'_>) -> Result<Outcome, Gone> {
        let (slot, family, level) = match group {
            IpAddr::V4(_) => (&mut self.v4, libc::AF_INET, libc::IPPROTO_IP),
            IpAddr::V6(_) => (&mut self.v6, libc::AF_INET6, libc::IPPROTO_IPV6),
        };
        let fd = match slot {
            Some(sock) => sock.as_raw_fd(),
            None => match open_socket(family, libc::SOCK_DGRAM, 0) {
                Ok(sock) => slot.insert(sock).as_raw_fd(),
                Err(source) => {
                    return Ok(Outcome::Failed {
                        source,
                        capped: false,
                    });
                }
            },
        };
        // Zeroed, not a field literal: `setsockopt` reads the padding after `gr_interface` too.
        // SAFETY: `group_req` is plain data; all-zero is valid.
        let mut req: libc::group_req = unsafe { std::mem::zeroed() };
        // Never 0: the kernel would pick an interface by route lookup.
        req.gr_interface = target.ifindex.get();
        // `gr_interface` selects the interface, so the group sockaddr carries no scope id.
        req.gr_group = sockaddr_for(group, 0, 0).0;
        match setsockopt(fd, level, libc::MCAST_JOIN_GROUP, &req) {
            Ok(()) => Ok(Outcome::Joined),
            Err(e) => classify(e, group, || target.is_live()),
        }
    }
}

/// One interface's memberships: the groups its reflectors want, each with its state, and the
/// sockets that hold them.
pub(crate) struct Memberships {
    sockets: Sockets,
    groups: Vec<Membership>,
}

impl Memberships {
    pub(crate) fn new() -> Self {
        Self {
            sockets: Sockets::default(),
            groups: Vec::new(),
        }
    }

    /// Want `group` without attempting it: the next [`converge`](Self::converge) does. Returns
    /// its index. A wanter that would log the group's wait more severely raises its level, and a
    /// wait already reported is reported again at that level.
    pub(crate) fn add(&mut self, group: IpAddr, wanted: Wanted) -> usize {
        if let Some(index) = self.groups.iter().position(|known| known.group == group) {
            let known = &mut self.groups[index];
            // `log::Level` orders the more severe level first.
            if wanted.wait_level < known.wait_level {
                known.wait_level = wanted.wait_level;
                if let State::Waiting(_) = known.state {
                    known.reported = None;
                }
            }
            return index;
        }
        self.groups.push(Membership {
            group,
            label: wanted.label,
            wait_level: wanted.wait_level,
            state: State::Pending,
            reported: None,
        });
        self.groups.len() - 1
    }

    /// Want `group` and join it on `target`: the startup path. A group another reflector already
    /// wanted is not attempted again.
    ///
    /// # Errors
    /// Whatever leaves the group neither joined nor waiting. The group stays wanted.
    pub(crate) fn join(
        &mut self,
        group: IpAddr,
        wanted: Wanted,
        target: Target<'_>,
        now: Instant,
    ) -> Result<(), JoinError> {
        let index = self.add(group, wanted);
        let membership = &mut self.groups[index];
        match membership.state {
            State::Pending => {}
            State::Waiting(Wait::NoFamily) if wanted.required => return Err(JoinError::NoFamily),
            State::Waiting(wait) if membership.reported.is_none() => {
                membership.report_wait(wait, target.name);
                return Ok(());
            }
            _ => return Ok(()),
        }
        match self.sockets.join(group, target) {
            Err(Gone) => Err(JoinError::Gone),
            Ok(Outcome::Failed { source, capped }) => Err(JoinError::Failed { source, capped }),
            Ok(Outcome::Waits(Wait::NoFamily)) if wanted.required => Err(JoinError::NoFamily),
            Ok(outcome) => {
                membership.settle(outcome, target.name, now);
                Ok(())
            }
        }
    }

    /// Attempt every group that is not joined, a failed one only once its retry is due.
    ///
    /// # Errors
    /// [`Gone`], leaving the rest to the rebuild.
    pub(crate) fn converge(&mut self, target: Target<'_>, now: Instant) -> Result<(), Gone> {
        for membership in &mut self.groups {
            match membership.state {
                State::Joined => continue,
                State::Failed { retry_at, .. } if now < retry_at => continue,
                _ => {}
            }
            let Ok(outcome) = self.sockets.join(membership.group, target) else {
                let Target { name, ifindex } = target;
                log::debug!("{name} (ifindex {ifindex}) is gone; its groups join when it returns");
                // Off the retry timer: only the rebuild can help.
                membership.state = State::Pending;
                return Err(Gone);
            };
            membership.settle(outcome, target.name, now);
        }
        Ok(())
    }

    /// Drop the sockets, and every membership with them. A socket keeps the memberships of a
    /// destroyed interface: on Linux they still count toward `igmp_max_memberships`, and a
    /// re-join of one answers `EADDRINUSE` although the recreated interface holds none. So every
    /// rebuild starts from fresh sockets, at an unchanged index too.
    pub(crate) fn rebase(&mut self) {
        self.sockets = Sockets::default();
        for membership in &mut self.groups {
            membership.state = State::Pending;
        }
    }

    /// When the earliest failed group is due its retry.
    pub(crate) fn next_retry(&self) -> Option<Instant> {
        self.groups
            .iter()
            .filter_map(|membership| match membership.state {
                State::Failed { retry_at, .. } => Some(retry_at),
                _ => None,
            })
            .min()
    }
}

/// What a refused `MCAST_JOIN_GROUP` means. `live` says whether the interface still exists, and
/// runs only for the errnos a dead index shares with a live interface. An errno listed nowhere
/// here is a failure the caller retries.
fn classify(
    err: io::Error,
    group: IpAddr,
    live: impl FnOnce() -> io::Result<bool>,
) -> Result<Outcome, Gone> {
    let errno = err.raw_os_error();
    let v6 = group.is_ipv6();
    let if_live = match errno {
        // Every target answers an any-source re-join of a held membership with it.
        Some(libc::EADDRINUSE) => return Ok(Outcome::Joined),
        // A dead index on Linux. Live, the interface has none of the family: IPv4 below MTU 68,
        // on FreeBSD an interface IPv6 was never set up on.
        Some(libc::ENODEV) => Wait::NoFamily,
        // A dead index on the BSDs, which answer a live interface without `IFF_MULTICAST` alike.
        Some(libc::EADDRNOTAVAIL) if cfg!(not(target_os = "linux")) => Wait::NotMulticast,
        // Linux creates no IPv6 device below MTU 1280.
        Some(libc::EINVAL) if v6 && cfg!(target_os = "linux") => {
            return Ok(Outcome::Waits(Wait::NoFamily));
        }
        // macOS: IPv6 was never attached to the interface.
        Some(libc::EINVAL) if v6 && cfg!(target_os = "macos") => {
            return Ok(Outcome::Waits(Wait::NoAddress));
        }
        Some(libc::EAFNOSUPPORT) if cfg!(target_os = "macos") => {
            return Ok(Outcome::Waits(Wait::NoAddress));
        }
        _ => {
            // The one cap a socket per interface can reach: `net.ipv4.igmp_max_memberships`.
            let capped = cfg!(target_os = "linux") && !v6 && errno == Some(libc::ENOBUFS);
            return Ok(Outcome::Failed {
                source: err,
                capped,
            });
        }
    };
    match live() {
        Ok(true) => Ok(Outcome::Waits(if_live)),
        Ok(false) => Err(Gone),
        Err(_) => Ok(Outcome::Failed {
            source: err,
            capped: false,
        }),
    }
}

/// The environment can't join at all: QEMU user-mode returns `ENOPROTOOPT` for
/// `MCAST_JOIN_GROUP`. The join tests self-skip on it.
#[cfg(test)]
pub(crate) fn join_unsupported(err: &JoinError) -> bool {
    matches!(
        err,
        JoinError::Failed { source, .. } if matches!(
            source.raw_os_error(),
            Some(libc::ENOPROTOOPT | libc::EOPNOTSUPP | libc::ENOSYS)
        )
    )
}

#[cfg(test)]
pub(in crate::dispatch) mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use super::*;
    use crate::test_support::{Capability, skip};

    const MDNS_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251));
    const MDNS_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb));
    /// A unicast address can never join: `EINVAL` on every target, a plain failure for IPv4.
    const NOT_A_GROUP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    pub(in crate::dispatch) const BEST_EFFORT: Wanted = Wanted {
        label: "test",
        required: false,
        wait_level: log::Level::Info,
    };
    pub(in crate::dispatch) const REQUIRED: Wanted = Wanted {
        required: true,
        ..BEST_EFFORT
    };

    impl Memberships {
        /// Whether no family socket is open (nothing attempted since the last rebase).
        pub(in crate::dispatch) fn test_socketless(&self) -> bool {
            self.sockets.v4.is_none() && self.sockets.v6.is_none()
        }

        pub(in crate::dispatch) fn test_all_joined(&self) -> bool {
            self.groups.iter().all(|group| group.state == State::Joined)
        }

        /// As if `group` had failed once, due its retry at `retry_at`.
        pub(in crate::dispatch) fn test_fail(&mut self, group: IpAddr, retry_at: Instant) {
            let index = self.add(group, BEST_EFFORT);
            self.groups[index].state = State::Failed {
                attempts: 0,
                retry_at,
            };
        }

        pub(in crate::dispatch) fn test_waiting(&self, group: IpAddr) -> Option<Wait> {
            match self.state_of(group) {
                State::Waiting(wait) => Some(wait),
                _ => None,
            }
        }

        fn state_of(&self, group: IpAddr) -> State {
            self.groups
                .iter()
                .find(|known| known.group == group)
                .expect("the group is wanted")
                .state
        }
    }

    fn loopback_target(name: &InterfaceName) -> Target<'_> {
        let ifindex = crate::interface::if_index(name).expect("loopback must resolve to an index");
        Target { name, ifindex }
    }

    /// `None` after a skip note: the environment refuses every join.
    fn joined_on_loopback(groups: &[IpAddr]) -> Option<Memberships> {
        let name = InterfaceName::loopback();
        let mut memberships = Memberships::new();
        for group in groups {
            match memberships.join(*group, BEST_EFFORT, loopback_target(&name), Instant::now()) {
                Ok(()) => {}
                Err(e) if join_unsupported(&e) => {
                    skip(Capability::Membership, format!("{e:?}"));
                    return None;
                }
                Err(e) => panic!("kernel must accept the {group} join on loopback: {e:?}"),
            }
        }
        Some(memberships)
    }

    fn os_error(errno: i32) -> io::Error {
        io::Error::from_raw_os_error(errno)
    }

    fn never_asked() -> io::Result<bool> {
        panic!("this errno says nothing about the interface's existence")
    }

    #[test]
    fn a_held_membership_is_a_join() {
        assert!(matches!(
            classify(os_error(libc::EADDRINUSE), MDNS_V4, never_asked),
            Ok(Outcome::Joined)
        ));
    }

    #[test]
    fn a_dead_index_errno_is_gone_only_when_the_interface_is() {
        let dead = || Ok(false);
        let live = || Ok(true);
        assert_eq!(
            classify(os_error(libc::ENODEV), MDNS_V4, dead).unwrap_err(),
            Gone
        );
        assert!(matches!(
            classify(os_error(libc::ENODEV), MDNS_V4, live),
            Ok(Outcome::Waits(Wait::NoFamily))
        ));
        if cfg!(target_os = "linux") {
            // Not a Linux join errno: a failure like any other, the interface not asked about.
            assert!(matches!(
                classify(os_error(libc::EADDRNOTAVAIL), MDNS_V4, never_asked),
                Ok(Outcome::Failed { capped: false, .. })
            ));
        } else {
            assert_eq!(
                classify(os_error(libc::EADDRNOTAVAIL), MDNS_V4, dead).unwrap_err(),
                Gone
            );
            assert!(matches!(
                classify(os_error(libc::EADDRNOTAVAIL), MDNS_V4, live),
                Ok(Outcome::Waits(Wait::NotMulticast))
            ));
        }
    }

    #[test]
    fn a_liveness_lookup_that_cannot_run_is_a_failure_to_retry() {
        let unknown = || Err(os_error(libc::EMFILE));
        assert!(matches!(
            classify(os_error(libc::ENODEV), MDNS_V4, unknown),
            Ok(Outcome::Failed { source, capped: false })
                if source.raw_os_error() == Some(libc::ENODEV)
        ));
    }

    #[test]
    fn an_interface_without_the_family_waits() {
        let v6_einval = classify(os_error(libc::EINVAL), MDNS_V6, never_asked);
        if cfg!(target_os = "linux") {
            assert!(matches!(v6_einval, Ok(Outcome::Waits(Wait::NoFamily))));
        } else if cfg!(target_os = "macos") {
            assert!(matches!(v6_einval, Ok(Outcome::Waits(Wait::NoAddress))));
        } else {
            assert!(matches!(v6_einval, Ok(Outcome::Failed { .. })));
        }
        // For an IPv4 group it is the kernel refusing the group itself.
        assert!(matches!(
            classify(os_error(libc::EINVAL), MDNS_V4, never_asked),
            Ok(Outcome::Failed { .. })
        ));
        for group in [MDNS_V4, MDNS_V6] {
            let unattached = classify(os_error(libc::EAFNOSUPPORT), group, never_asked);
            if cfg!(target_os = "macos") {
                assert!(matches!(unattached, Ok(Outcome::Waits(Wait::NoAddress))));
            } else {
                assert!(matches!(unattached, Ok(Outcome::Failed { .. })));
            }
        }
    }

    #[test]
    fn only_the_linux_ipv4_cap_is_a_capped_join() {
        let capped = |errno, group| {
            matches!(
                classify(os_error(errno), group, never_asked),
                Ok(Outcome::Failed { capped: true, .. })
            )
        };
        assert_eq!(capped(libc::ENOBUFS, MDNS_V4), cfg!(target_os = "linux"));
        assert!(!capped(libc::ENOBUFS, MDNS_V6));
        assert!(!capped(libc::ENOMEM, MDNS_V4));
        assert!(!capped(libc::ETOOMANYREFS, MDNS_V4));
    }

    #[test]
    fn an_unlisted_errno_is_a_failure_to_retry() {
        for errno in [libc::EPERM, libc::ENOMEM, libc::EMFILE] {
            assert!(matches!(
                classify(os_error(errno), MDNS_V6, never_asked),
                Ok(Outcome::Failed { capped: false, .. })
            ));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn kernel_accepts_a_join_on_loopback() {
        // The full MCAST_JOIN_GROUP FFI against the kernel: per-OS const, group_req layout,
        // by-index selection.
        let Some(memberships) = joined_on_loopback(&[MDNS_V4, MDNS_V6]) else {
            return;
        };
        assert!(memberships.test_all_joined());
        assert!(memberships.sockets.v4.is_some() && memberships.sockets.v6.is_some());
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn a_group_wanted_twice_is_joined_once() {
        let Some(mut memberships) = joined_on_loopback(&[MDNS_V4]) else {
            return;
        };
        let name = InterfaceName::loopback();
        let relay = Wanted {
            label: "relay",
            required: true,
            wait_level: log::Level::Warn,
        };
        memberships
            .join(MDNS_V4, relay, loopback_target(&name), Instant::now())
            .expect("already joined");
        assert_eq!(memberships.groups.len(), 1);
        assert_eq!(memberships.groups[0].label, "test", "the first label stays");
        assert_eq!(
            memberships.groups[0].wait_level,
            log::Level::Warn,
            "the more severe level wins"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn a_louder_wanter_has_a_waiting_group_reported_again() {
        let name = InterfaceName::loopback();
        let target = loopback_target(&name);
        let now = Instant::now();
        let mut memberships = Memberships::new();
        let index = memberships.add(MDNS_V6, BEST_EFFORT);
        memberships.groups[index].state = State::Waiting(Wait::NoAddress);
        memberships.groups[index].reported = Some(Problem::Wait(Wait::NoAddress));

        let relay = Wanted {
            wait_level: log::Level::Warn,
            ..BEST_EFFORT
        };
        memberships.add(MDNS_V6, relay);
        assert_eq!(memberships.groups[index].wait_level, log::Level::Warn);
        assert!(
            memberships.groups[index].reported.is_none(),
            "the wait is due a report at the new level"
        );
        memberships
            .join(MDNS_V6, relay, target, now)
            .expect("the group still waits");
        assert_eq!(
            memberships.groups[index].reported,
            Some(Problem::Wait(Wait::NoAddress)),
            "the wait was reported again"
        );
        assert!(memberships.test_socketless(), "nothing was attempted");
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real socket")]
    fn a_failed_join_is_an_error_at_startup() {
        let name = InterfaceName::loopback();
        let mut memberships = Memberships::new();
        let err = memberships
            .join(
                NOT_A_GROUP,
                BEST_EFFORT,
                loopback_target(&name),
                Instant::now(),
            )
            .expect_err("a unicast address cannot join");
        assert!(
            matches!(err, JoinError::Failed { capped: false, .. }),
            "{err:?}"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn a_required_family_the_interface_lacks_is_an_error_for_a_later_wanter_too() {
        let name = InterfaceName::loopback();
        let mut memberships = Memberships::new();
        let index = memberships.add(MDNS_V6, BEST_EFFORT);
        memberships.groups[index].state = State::Waiting(Wait::NoFamily);
        let target = loopback_target(&name);
        memberships
            .join(MDNS_V6, BEST_EFFORT, target, Instant::now())
            .expect("best effort: the group just waits");
        let err = memberships
            .join(MDNS_V6, REQUIRED, target, Instant::now())
            .expect_err("required");
        assert!(matches!(err, JoinError::NoFamily));
        assert!(memberships.test_socketless(), "nothing was attempted again");
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real socket")]
    fn a_failed_group_is_retried_when_due_with_a_growing_delay() {
        let name = InterfaceName::loopback();
        let target = loopback_target(&name);
        let mut memberships = Memberships::new();
        memberships.add(NOT_A_GROUP, BEST_EFFORT);
        let start = Instant::now();
        assert_eq!(memberships.converge(target, start), Ok(()));
        let after = |attempts, seconds| State::Failed {
            attempts,
            retry_at: start + Duration::from_secs(seconds),
        };
        assert_eq!(memberships.state_of(NOT_A_GROUP), after(0, 1));
        assert_eq!(
            memberships.next_retry(),
            Some(start + Duration::from_secs(1))
        );

        assert_eq!(
            memberships.converge(target, start + Duration::from_millis(999)),
            Ok(())
        );
        assert_eq!(
            memberships.state_of(NOT_A_GROUP),
            after(0, 1),
            "not attempted before it is due"
        );

        assert_eq!(
            memberships.converge(target, start + Duration::from_secs(1)),
            Ok(())
        );
        assert_eq!(memberships.state_of(NOT_A_GROUP), after(1, 3));
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn a_converge_joins_what_is_not_joined() {
        let Some(mut memberships) = joined_on_loopback(&[MDNS_V4]) else {
            return;
        };
        let name = InterfaceName::loopback();
        let target = loopback_target(&name);
        let start = Instant::now();
        let waiting = memberships.add(MDNS_V6, BEST_EFFORT);
        memberships.groups[waiting].state = State::Waiting(Wait::NoAddress);
        memberships.groups[waiting].reported = Some(Problem::Wait(Wait::NoAddress));
        let failed = memberships.add(IpAddr::V4(Ipv4Addr::new(239, 255, 77, 77)), BEST_EFFORT);
        memberships.groups[failed].state = State::Failed {
            attempts: 3,
            retry_at: start,
        };
        memberships.groups[failed].reported = Some(Problem::Failed);

        assert_eq!(memberships.converge(target, start), Ok(()));
        assert!(memberships.test_all_joined());
        assert!(
            memberships
                .groups
                .iter()
                .all(|group| group.reported.is_none()),
            "a join ends the reported problem"
        );
        assert_eq!(memberships.next_retry(), None);
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn a_rebase_drops_the_sockets_and_the_next_converge_joins_again() {
        let Some(mut memberships) = joined_on_loopback(&[MDNS_V4, MDNS_V6]) else {
            return;
        };
        memberships.rebase();
        assert!(memberships.test_socketless());
        assert_eq!(memberships.state_of(MDNS_V4), State::Pending);
        assert_eq!(memberships.state_of(MDNS_V6), State::Pending);

        let name = InterfaceName::loopback();
        assert_eq!(
            memberships.converge(loopback_target(&name), Instant::now()),
            Ok(())
        );
        assert!(memberships.test_all_joined());
        assert!(memberships.sockets.v4.is_some() && memberships.sockets.v6.is_some());
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn a_dead_index_stops_the_converge_and_leaves_its_groups_to_the_rebuild() {
        if joined_on_loopback(&[MDNS_V4]).is_none() {
            return;
        }
        let name = InterfaceName::loopback();
        // No interface has this index, and the loopback name resolves to another.
        let dead = Target {
            name: &name,
            ifindex: NonZeroU32::new(0x7fff_fff0).unwrap(),
        };
        let mut memberships = Memberships::new();
        memberships.add(MDNS_V4, BEST_EFFORT);
        memberships.add(MDNS_V6, BEST_EFFORT);
        let now = Instant::now();
        assert_eq!(memberships.converge(dead, now), Err(Gone));
        assert_eq!(memberships.state_of(MDNS_V4), State::Pending);
        assert_eq!(memberships.state_of(MDNS_V6), State::Pending);
        assert_eq!(memberships.next_retry(), None, "no retry timer spins on it");

        let err = memberships
            .join(MDNS_V4, BEST_EFFORT, dead, now)
            .expect_err("the index names no interface");
        assert!(matches!(err, JoinError::Gone), "{err:?}");
    }

    // stf0 exists on every macOS host and has no IFF_MULTICAST.
    #[cfg(target_os = "macos")]
    #[test]
    fn an_interface_without_iff_multicast_waits() {
        let name: InterfaceName = "stf0".parse().unwrap();
        let Some(ifindex) = crate::interface::if_index(&name) else {
            return;
        };
        let target = Target {
            name: &name,
            ifindex,
        };
        let mut memberships = Memberships::new();
        memberships
            .join(MDNS_V4, REQUIRED, target, Instant::now())
            .expect("the group waits");
        assert_eq!(memberships.test_waiting(MDNS_V4), Some(Wait::NotMulticast));
    }
}
