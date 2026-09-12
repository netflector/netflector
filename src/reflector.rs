//! The reflectors: per-protocol packet handlers that re-emit matched traffic on the opposite
//! interface. Each implements the dispatcher's `PacketHandler` and is registered by `run()`
//! from config.

pub(crate) mod dial;
pub(crate) mod mdns;
pub(crate) mod ssdp;
pub(crate) mod udp;
pub(crate) mod wol;
pub(crate) mod wsd;

mod search;
mod simple;

pub(crate) use search::{SearchProtocol, build_pair};
pub(crate) use simple::{Classify, Emit, SimpleReflector};

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use thiserror::Error;

use crate::config::{AddressFamily, PeerList, Reflector};
use crate::dispatch::{
    CaptureKey, DatagramSource, MessageType, PacketDispatcher, join_capped, join_deferrable,
};
use crate::interface::InterfaceAddresses;
use crate::linear_map::LinearMap;
use crate::logging::WARN_WINDOW;
use crate::net::LinkType;
use crate::net::mac::{MacAddr, MacSet};
use crate::reactor::Reactor;

/// A classifier's verdict on a captured payload. `Reflect`/`Skip` carry the message's own
/// [`MessageType`] so the handler can count it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Reflect(MessageType),
    /// A message for the other direction, dropped silently. This is the loop-breaker atop the
    /// capture's own-egress drop and the dispatcher's echo drop: a reflected query re-emitted on
    /// the egress is still a query, which that side's response-only reflector skips.
    Skip(MessageType),
    /// Recognized but configured out (a wake for a device outside the allow-set); the classifier
    /// already logged why.
    Excluded,
    /// Not a recognizable protocol message; the handler logs the drop.
    Junk,
}

/// Where a leg's re-emits go: onto the link, to each of the entry's peers as unicast (a link
/// without a broadcast domain), or to the one searcher that asked, at its captured frame MAC (no
/// ARP/ND).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Delivery {
    Link,
    Peers(Box<[IpAddr]>),
    Unicast { to: SocketAddr, mac: MacAddr },
}

impl Delivery {
    pub(crate) fn new(peers: Option<&PeerList>) -> Self {
        match peers {
            Some(peers) => Self::Peers(peers.iter().copied().collect()),
            None => Self::Link,
        }
    }

    /// The address a datagram to `dst` actually reaches; a reply must be listened for on a source
    /// of that scope.
    pub(crate) fn destination(&self, dst: IpAddr) -> IpAddr {
        match self {
            Self::Link => dst,
            Self::Peers(peers) => peers
                .iter()
                .copied()
                .find(|peer| peer.is_ipv4() == dst.is_ipv4())
                .unwrap_or(dst),
            Self::Unicast { to, .. } => to.ip(),
        }
    }

    /// # Errors
    /// As the dispatcher send it delegates to; a peers send fails only when no copy went out.
    pub(crate) fn send(
        &self,
        dispatcher: &mut PacketDispatcher,
        egress: CaptureKey,
        dst: SocketAddr,
        source: DatagramSource,
        ttl: u8,
        payload: &[u8],
    ) -> io::Result<()> {
        match self {
            Self::Link => dispatcher.send_udp_group(egress, dst, source, ttl, payload),
            Self::Peers(peers) => {
                dispatcher.send_udp_to_peers(egress, peers, dst, source, ttl, payload)
            }
            Self::Unicast { to, mac } => {
                dispatcher.send_udp(egress, *to, *mac, source, ttl, payload)
            }
        }
    }
}

/// Transforms a payload before re-emit (the SSDP DIAL `LOCATION` rewrite). Returns the rewrite,
/// held in the implementor's own scratch, or `None` to forward `payload` verbatim; the caller also
/// reads `None` as "still advertising the device's own addresses" for the unreachable-advertisement
/// suppression.
/// A trait rather than a closure: the `Fn` traits can't express that lending signature.
pub(crate) trait ReplyRewrite {
    fn rewrite<'a>(
        &'a mut self,
        payload: &[u8],
        egress: CaptureKey,
        dispatcher: &mut PacketDispatcher,
        reactor: &mut Reactor,
    ) -> Option<&'a [u8]>;
}

pub(crate) struct NoRewrite;

impl ReplyRewrite for NoRewrite {
    fn rewrite<'a>(
        &'a mut self,
        _payload: &[u8],
        _egress: CaptureKey,
        _dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) -> Option<&'a [u8]> {
        None
    }
}

/// A concrete IP version, unlike the config's `AddressFamily` policy, which may name both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IpFamily {
    V4,
    V6,
}

impl fmt::Display for IpFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        })
    }
}

/// Interface name → the capture `run()` opened for it; the `build` functions resolve `source_if` /
/// `target_if` through it.
#[derive(Default)]
pub(crate) struct InterfaceMap(LinearMap<String, CaptureKey>);

impl InterfaceMap {
    pub(crate) fn insert(&mut self, name: String, key: CaptureKey) {
        self.0.insert(name, key);
    }

    pub(crate) fn key_for(&self, name: &str) -> Option<CaptureKey> {
        self.0.get(name).copied()
    }

    pub(crate) fn require(&self, name: &str) -> Result<CaptureKey, BuildError> {
        self.key_for(name)
            .ok_or_else(|| BuildError::UnknownInterface(name.to_owned()))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum BuildError {
    /// A wiring bug: `run()` opens a capture for every configured interface.
    #[error("no capture for interface \"{0}\"")]
    UnknownInterface(String),
    /// A startup failure rather than a silent half-run. For a bidirectional reflector the named
    /// interface may be the source or the target.
    #[error("interface \"{interface}\" cannot send {family}, required by the reflector")]
    RequiredFamilyUnavailable { interface: String, family: IpFamily },
    #[error("macs can never match on interface \"{0}\": its link carries no MAC addresses")]
    MacsUnmatchable(String),
    /// For a reason no later event clears; a deferrable failure is retried instead.
    #[error("cannot join {group} on interface \"{interface}\": {reason}")]
    GroupJoin {
        group: IpAddr,
        interface: String,
        reason: String,
    },
}

fn directional_verdict<K: PartialEq + Copy + Into<MessageType>>(
    kind: Option<K>,
    reflect: K,
) -> Verdict {
    match kind {
        Some(kind) if kind == reflect => Verdict::Reflect(kind.into()),
        Some(kind) => Verdict::Skip(kind.into()),
        None => Verdict::Junk,
    }
}

/// [`Filter`](crate::dispatch::Filter)'s MAC fields never match a `DLT_NULL` frame. `WoL` never
/// calls this: it matches the MAC inside the magic packet, not the frame's.
fn require_macs_matchable(
    dispatcher: &PacketDispatcher,
    macs: Option<&MacSet>,
    target: CaptureKey,
    target_if: &str,
) -> Result<(), BuildError> {
    if macs.is_some()
        && matches!(dispatcher.link_type(target), Some(link) if link != LinkType::Ethernet)
    {
        return Err(BuildError::MacsUnmatchable(target_if.to_owned()));
    }
    Ok(())
}

/// The per-packet gate before a re-emit: a family whose address has gone away is dropped rather
/// than mis-sent.
fn egress_sources(dispatcher: &PacketDispatcher, egress: CaptureKey, dst: SocketAddr) -> bool {
    dispatcher
        .egress_addrs(egress)
        .is_some_and(|addrs| match dst {
            SocketAddr::V4(_) => addrs.has_v4(),
            SocketAddr::V6(_) => addrs.has_v6(),
        })
}

/// The family `family` requires but `addrs` cannot source; a v6-best-effort `Default` with no v6
/// passes.
fn missing_required_family(family: AddressFamily, addrs: &InterfaceAddresses) -> Option<IpFamily> {
    if family.requires_ipv4() && !addrs.has_v4() {
        Some(IpFamily::V4)
    } else if family.requires_ipv6() && !addrs.has_v6() {
        Some(IpFamily::V6)
    } else {
        None
    }
}

/// The one-sided family check of a protocol that re-emits on the target alone.
///
/// # Errors
/// [`BuildError::RequiredFamilyUnavailable`].
fn require_egress_family(
    dispatcher: &PacketDispatcher,
    egress: CaptureKey,
    egress_if: &str,
    address_family: AddressFamily,
) -> Result<(), BuildError> {
    let addrs = dispatcher.egress_addrs(egress).copied().unwrap_or_default();
    match missing_required_family(address_family, &addrs) {
        Some(family) => Err(BuildError::RequiredFamilyUnavailable {
            interface: egress_if.to_owned(),
            family,
        }),
        None => Ok(()),
    }
}

/// The two-sided family check of a protocol re-emitting on both interfaces.
///
/// # Errors
/// [`BuildError::RequiredFamilyUnavailable`], blaming the side that lacks the family.
fn require_both_sides_family(
    dispatcher: &PacketDispatcher,
    address_family: AddressFamily,
    source: CaptureKey,
    source_if: &str,
    target: CaptureKey,
    target_if: &str,
) -> Result<(), BuildError> {
    let src = dispatcher.egress_addrs(source).copied().unwrap_or_default();
    let tgt = dispatcher.egress_addrs(target).copied().unwrap_or_default();
    let unavailable = |family, missing_on_source| BuildError::RequiredFamilyUnavailable {
        interface: if missing_on_source {
            source_if
        } else {
            target_if
        }
        .to_owned(),
        family,
    };
    if address_family.requires_ipv4() && !(src.has_v4() && tgt.has_v4()) {
        return Err(unavailable(IpFamily::V4, !src.has_v4()));
    }
    if address_family.requires_ipv6() && !(src.has_v6() && tgt.has_v6()) {
        return Err(unavailable(IpFamily::V6, !src.has_v6()));
    }
    Ok(())
}

/// The build steps mDNS, SSDP and WSD share; returns the two captures.
///
/// # Errors
/// [`BuildError::UnknownInterface`], [`BuildError::RequiredFamilyUnavailable`],
/// [`BuildError::MacsUnmatchable`] or [`BuildError::GroupJoin`].
fn open_pair(
    reflector: &Reflector,
    interfaces: &InterfaceMap,
    dispatcher: &mut PacketDispatcher,
    protocol: &str,
    groups: &[SocketAddr],
) -> Result<(CaptureKey, CaptureKey), BuildError> {
    let source = interfaces.require(reflector.source_if.as_str())?;
    let target = interfaces.require(reflector.target_if.as_str())?;
    require_both_sides_family(
        dispatcher,
        reflector.address_family,
        source,
        reflector.source_if.as_str(),
        target,
        reflector.target_if.as_str(),
    )?;
    require_macs_matchable(
        dispatcher,
        reflector.macs.as_ref(),
        target,
        reflector.target_if.as_str(),
    )?;
    for group in groups {
        for (capture, interface) in [
            (source, &reflector.source_if),
            (target, &reflector.target_if),
        ] {
            require_group_join(
                dispatcher,
                capture,
                group.ip(),
                protocol,
                interface.as_str(),
            )?;
        }
    }
    Ok((source, target))
}

fn group_addrs(family: AddressFamily, port: u16, v4: Ipv4Addr, v6: &[Ipv6Addr]) -> Vec<SocketAddr> {
    let mut groups = Vec::with_capacity(1 + v6.len());
    if family.uses_ipv4() {
        groups.push(SocketAddr::from((v4, port)));
    }
    if family.uses_ipv6() {
        groups.extend(v6.iter().map(|group| SocketAddr::from((*group, port))));
    }
    groups
}

/// A [deferrable](join_deferrable) failure only logs: it retries on the next address change.
///
/// # Errors
/// [`BuildError::GroupJoin`].
fn require_group_join(
    dispatcher: &mut PacketDispatcher,
    capture: CaptureKey,
    group: IpAddr,
    protocol: &str,
    interface: &str,
) -> Result<(), BuildError> {
    match dispatcher.join_group(capture, group) {
        Ok(()) => log::debug!("{protocol}: joined {group} on {interface}"),
        Err(e) if join_deferrable(&e) => {
            log::debug!(
                "{protocol}: join {group} on {interface} deferred (no address of its family yet): {e}"
            );
        }
        Err(e) => {
            let reason = if join_capped(&e) {
                format!(
                    "{e}; the interface holds as many memberships as the system allows \
                     (net.ipv4.igmp_max_memberships on Linux)"
                )
            } else {
                e.to_string()
            };
            return Err(BuildError::GroupJoin {
                group,
                interface: interface.to_owned(),
                reason,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::interface::LOOPBACK_IFACE;
    use crate::net::mac::MacAddr;
    use crate::test_support::{loopback_lock, open_loopback_or_skip};

    #[test]
    fn group_addrs_follows_the_address_family() {
        let v4 = Ipv4Addr::new(239, 255, 255, 250);
        let (link_local, site_local) = (
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xc),
            Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0xc),
        );
        let groups = |family| group_addrs(family, 1900, v4, &[link_local, site_local]);
        let at = |ip: IpAddr| SocketAddr::new(ip, 1900);
        // Default and Dual reflect both families; the single-family policies, only their own.
        assert_eq!(
            groups(AddressFamily::Default),
            [at(v4.into()), at(link_local.into()), at(site_local.into())]
        );
        assert_eq!(groups(AddressFamily::Dual), groups(AddressFamily::Default));
        assert_eq!(groups(AddressFamily::Ipv4), [at(v4.into())]);
        assert_eq!(
            groups(AddressFamily::Ipv6),
            [at(link_local.into()), at(site_local.into())]
        );
    }

    #[test]
    fn delivery_follows_the_entrys_peers() {
        let peers: PeerList = "127.0.0.1".parse().unwrap();
        assert_eq!(
            Delivery::new(Some(&peers)),
            Delivery::Peers(Box::new([IpAddr::V4(Ipv4Addr::LOCALHOST)]))
        );
        assert_eq!(Delivery::new(None), Delivery::Link);
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn macs_matchability_follows_the_target_link_framing() {
        let _serial = loopback_lock();
        let Some(cap) = open_loopback_or_skip() else {
            return;
        };
        let mut dispatcher = PacketDispatcher::new();
        let target = dispatcher
            .add_capture(cap)
            .expect("add the loopback capture");
        // No filter configured: nothing to refuse, whatever the framing.
        assert_eq!(
            require_macs_matchable(&dispatcher, None, target, LOOPBACK_IFACE),
            Ok(())
        );
        let macs = MacSet::from(MacAddr::from([2, 0, 0, 0, 0, 1]));
        let result = require_macs_matchable(&dispatcher, Some(&macs), target, LOOPBACK_IFACE);
        // Linux frames loopback as Ethernet, so MACs match there; the BSDs' loopback is
        // `DLT_NULL`, the framing the check refuses.
        #[cfg(target_os = "linux")]
        assert_eq!(result, Ok(()));
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        assert_eq!(
            result,
            Err(BuildError::MacsUnmatchable(LOOPBACK_IFACE.to_owned()))
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn a_join_failure_no_event_clears_fails_the_build() {
        let _serial = loopback_lock();
        let Some(cap) = open_loopback_or_skip() else {
            return;
        };
        let mut dispatcher = PacketDispatcher::new();
        let capture = dispatcher
            .add_capture(cap)
            .expect("add the loopback capture");
        // A unicast address is no group: the join is refused outright, whatever the platform.
        let not_a_group = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let result = require_group_join(
            &mut dispatcher,
            capture,
            not_a_group,
            "test",
            LOOPBACK_IFACE,
        );
        assert!(matches!(
            result,
            Err(BuildError::GroupJoin { group, ref interface, .. })
                if group == not_a_group && interface == LOOPBACK_IFACE
        ));
    }

    #[test]
    fn missing_required_family_enforces_the_requires_policy() {
        let none = InterfaceAddresses::default();
        let v4_only = InterfaceAddresses::new(None, Some(Ipv4Addr::LOCALHOST), None, None);
        // Default requires v4 only: a v4-less egress fails on v4, a v6-less one passes.
        assert_eq!(
            missing_required_family(AddressFamily::Default, &none),
            Some(IpFamily::V4)
        );
        assert_eq!(
            missing_required_family(AddressFamily::Default, &v4_only),
            None
        );
        // Dual requires both: a v4-only egress still misses v6.
        assert_eq!(
            missing_required_family(AddressFamily::Dual, &v4_only),
            Some(IpFamily::V6)
        );
        // Ipv6 requires v6.
        assert_eq!(
            missing_required_family(AddressFamily::Ipv6, &v4_only),
            Some(IpFamily::V6)
        );
    }
}
