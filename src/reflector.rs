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

/// A reflector's verdict on a captured payload, from its protocol's classifier. `Reflect`/`Skip` carry
/// the message's own [`MessageType`] (the packet's *intrinsic* type) so the handler can count it. See
/// [`From`] impls like `From<MdnsKind>` in each protocol reflector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// A message for this direction. Re-emit it.
    Reflect(MessageType),
    /// A message for the *other* direction; drop it silently. Dropping the opposite direction is
    /// the loop-breaker (atop the capture's own-egress drop and the dispatcher's echo drop): a
    /// reflected query re-emitted on the egress is still a query, which the egress side's
    /// response-only reflector skips.
    Skip(MessageType),
    /// A message this leg recognizes but is configured not to relay (a wake for a device outside
    /// the allow-set). The classifier logged why; drop it silently.
    Excluded,
    /// Not a recognizable protocol message on this dedicated group. Drop it with a debug log.
    Junk,
}

/// Where a leg's re-emits go: group and broadcast ones onto the link, or, behind a link without a
/// broadcast domain, to each of the entry's peers as unicast; a reply leg's to the one searcher
/// that asked, at its captured frame MAC (no ARP/ND).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Delivery {
    Link,
    Peers(Box<[IpAddr]>),
    Unicast { to: SocketAddr, mac: MacAddr },
}

impl Delivery {
    /// The delivery an entry's `source_peers` / `target_peers` value describes.
    pub(crate) fn new(peers: Option<&PeerList>) -> Self {
        match peers {
            Some(peers) => Self::Peers(peers.iter().copied().collect()),
            None => Self::Link,
        }
    }

    /// The address a datagram to `dst` reaches under this delivery: `dst` on the link, the first
    /// peer of its family, or the fixed unicast target. A reply to it must be listened for on a
    /// source of that scope.
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

    /// Send a datagram to `dst` on `egress` where the delivery says; a fixed unicast delivery
    /// ignores `dst`.
    ///
    /// # Errors
    /// As the dispatcher's [`send_udp_group`](PacketDispatcher::send_udp_group),
    /// [`send_udp_to_peers`](PacketDispatcher::send_udp_to_peers) (only when no copy went out)
    /// and [`send_udp`](PacketDispatcher::send_udp).
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

/// Transforms a datagram's payload before it is re-emitted: the SSDP DIAL `LOCATION` rewrite, applied
/// on both the advertisement direction and each search session's reply. Returns the rewrite, held in
/// the implementor's own reused scratch, or `None` to forward `payload` verbatim; the caller also
/// reads `None` as "still advertising the device's own addresses" for the unreachable-advertisement
/// suppression.
/// The `Fn` traits can't express that lending signature, which is why this is a trait rather than a
/// closure.
pub(crate) trait ReplyRewrite {
    fn rewrite<'a>(
        &'a mut self,
        payload: &[u8],
        egress: CaptureKey,
        dispatcher: &mut PacketDispatcher,
        reactor: &mut Reactor,
    ) -> Option<&'a [u8]>;
}

/// The identity transform: forward the payload verbatim. A ZST for the reflectors (mDNS, WSD, and SSDP
/// without DIAL) that re-emit unchanged.
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

/// A concrete IP version: the family a reflector requires of an interface. Distinct from the
/// config's `AddressFamily` policy (which may name both at once).
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

/// Maps each configured interface name to the capture `run()` opened for it, so a reflector's
/// `source_if` / `target_if` resolve to the ingress / egress [`CaptureKey`]s. `run()` opens one
/// capture per distinct interface and records it here; the per-protocol `build` functions look
/// names up.
#[derive(Default)]
pub(crate) struct InterfaceMap(LinearMap<String, CaptureKey>);

impl InterfaceMap {
    /// Record the capture `run()` opened for `name`.
    pub(crate) fn insert(&mut self, name: String, key: CaptureKey) {
        self.0.insert(name, key);
    }

    /// The capture key recorded for `name`, or `None` if none was.
    pub(crate) fn key_for(&self, name: &str) -> Option<CaptureKey> {
        self.0.get(name).copied()
    }

    /// The capture key for `name`, or [`BuildError::UnknownInterface`]. Build functions call this
    /// to resolve a configured interface name to its capture.
    pub(crate) fn require(&self, name: &str) -> Result<CaptureKey, BuildError> {
        self.key_for(name)
            .ok_or_else(|| BuildError::UnknownInterface(name.to_owned()))
    }
}

/// Why a reflector could not be built from its config.
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum BuildError {
    /// Names a `source_if` / `target_if` that `run()` opened no capture for. A wiring bug.
    #[error("no capture for interface \"{0}\"")]
    UnknownInterface(String),
    /// An interface can't currently send a family the reflector requires, so it would reflect
    /// nothing for that family. A startup failure rather than a silent half-run. For a
    /// bidirectional reflector (mDNS/SSDP/WSD) the named interface may be the source or the target.
    #[error("interface \"{interface}\" cannot send {family}, required by the reflector")]
    RequiredFamilyUnavailable { interface: String, family: IpFamily },
    /// A `macs` filter on a target whose link framing carries no MAC addresses: it would match
    /// nothing, silently discarding every device-side packet.
    #[error("macs can never match on interface \"{0}\": its link carries no MAC addresses")]
    MacsUnmatchable(String),
    /// A group the reflector captures could not be joined, for a reason no later event clears,
    /// so its traffic would never arrive. A startup failure rather than a running daemon that
    /// reflects nothing for it.
    #[error("cannot join {group} on interface \"{interface}\": {reason}")]
    GroupJoin {
        group: IpAddr,
        interface: String,
        reason: String,
    },
}

/// The verdict of a two-kind classifier for the leg that reflects `reflect`: a message of that kind
/// is reflected, one of the other kind belongs to the other leg, and no kind is junk.
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

/// Refuse a `macs` filter on a target whose link framing carries no MAC addresses:
/// [`Filter`](crate::dispatch::Filter)'s MAC fields never match a `DLT_NULL` frame. `WoL` never
/// calls this: it matches the MAC inside the magic packet's payload, not the frame's.
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

/// Whether `egress` currently has a source address of `dst`'s family, which `send_udp_group` needs
/// to build the frame. The per-packet gate a reflector applies before re-emitting, so a family
/// whose address has gone away is dropped rather than mis-sent.
fn egress_sources(dispatcher: &PacketDispatcher, egress: CaptureKey, dst: SocketAddr) -> bool {
    dispatcher
        .egress_addrs(egress)
        .is_some_and(|addrs| match dst {
            SocketAddr::V4(_) => addrs.has_v4(),
            SocketAddr::V6(_) => addrs.has_v6(),
        })
}

/// The family `addrs` cannot source but `family` requires, if any: the startup check's verdict.
/// `None` means every required family is available (a v6-best-effort `Default` with no v6 passes).
fn missing_required_family(family: AddressFamily, addrs: &InterfaceAddresses) -> Option<IpFamily> {
    if family.requires_ipv4() && !addrs.has_v4() {
        Some(IpFamily::V4)
    } else if family.requires_ipv6() && !addrs.has_v6() {
        Some(IpFamily::V6)
    } else {
        None
    }
}

/// Enforce that `egress` can source every family `address_family` requires: the one-sided check
/// of a protocol that re-emits on the target alone.
///
/// # Errors
/// [`BuildError::RequiredFamilyUnavailable`] naming the interface and the family it can't send.
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

/// Enforce that a protocol re-emitting on both interfaces (mDNS, SSDP, WSD) can source every
/// required family on BOTH. Checks each required family on both interfaces (v4 before v6, the
/// single-interface policy order) and blames the side that actually lacks it: the source when it's
/// the one missing, otherwise the target.
///
/// # Errors
/// [`BuildError::RequiredFamilyUnavailable`] naming the interface and the family it can't send.
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

/// The build steps mDNS, SSDP and WSD share: resolve both captures, require the families both
/// sides re-emit and a matchable `macs` filter on the target, and join every group on both
/// interfaces. Returns the captures.
///
/// # Errors
/// [`BuildError::UnknownInterface`] for an unopened source/target,
/// [`BuildError::RequiredFamilyUnavailable`], [`BuildError::MacsUnmatchable`], or
/// [`BuildError::GroupJoin`] for a join no later event clears.
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
    // A family with no address yet is recorded and re-attempted on the next address change, so a
    // deferred join logs rather than fails the build.
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

/// The group socket addresses `family` reflects to: `v4` if it uses IPv4, each of `v6` if IPv6.
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

/// Join `group` on `capture`, the capture of `interface`, for `protocol`. A
/// [deferrable](join_deferrable) failure logs at debug (it retries on the next address change);
/// any other fails the build.
///
/// # Errors
/// [`BuildError::GroupJoin`], naming the system's membership cap when that is the cause.
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
