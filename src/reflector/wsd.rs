//! The WSD (WS-Discovery) reflector: reflects WS-Discovery between the source and target interfaces so
//! ONVIF-camera / Windows-device discovery crosses the link. Structurally SSDP-without-DIAL: `Hello` /
//! `Bye` announcements reflect device → client as a stateless multicast re-emit (a [`SimpleReflector`],
//! like mDNS), and `Probe` / `Resolve` searches reflect client → device with their unicast
//! `ProbeMatches` / `ResolveMatches` replies routed back through a per-searcher session (the shared
//! [`SearchReflector`]). Re-emits go to the same group at TTL 1, sourced from the egress interface.

use std::net::SocketAddr;
use std::time::Duration;

use crate::config::{AddressFamily, Reflector};
use crate::dispatch::{Filter, IpSet, MessageType, PacketDispatcher};
use crate::net::wsd::{WSD_GROUP_V4, WSD_GROUP_V6, WSD_PORT, WSD_TTL, WsdKind, classify};

use super::{
    BuildError, InterfaceMap, NoRewrite, ReplyRewrite, SearchReflector, SimpleReflector, Verdict,
    require_bidirectional_families,
};

/// WSD's classifier kind maps to its group message types. The `ProbeMatches`/`ResolveMatches` unicast
/// replies are a separate leg ([`MessageType::WsdResponse`]), carried by the response reflector.
impl From<WsdKind> for MessageType {
    fn from(kind: WsdKind) -> Self {
        match kind {
            WsdKind::Announcement => Self::WsdAnnouncement,
            WsdKind::Search => Self::WsdSearch,
        }
    }
}

/// The directional gate for the announcement direction: reflect `Hello` / `Bye`, skip a search (it
/// flows the other way), and treat anything else on the group as junk.
fn announcement_verdict(payload: &[u8]) -> Verdict {
    match classify(payload) {
        Some(kind @ WsdKind::Announcement) => Verdict::Reflect(kind.into()),
        Some(kind @ WsdKind::Search) => Verdict::Skip(kind.into()),
        None => Verdict::Junk,
    }
}

/// The directional gate for the search direction: the mirror of [`announcement_verdict`].
fn search_verdict(payload: &[u8]) -> Verdict {
    match classify(payload) {
        Some(kind @ WsdKind::Search) => Verdict::Reflect(kind.into()),
        Some(kind @ WsdKind::Announcement) => Verdict::Skip(kind.into()),
        None => Verdict::Junk,
    }
}

/// A `Probe` / `Resolve` carries no MX field, so the reply window is fixed: long enough for a
/// device's unicast match (WS-Discovery caps the reply delay at ~500 ms) plus network slack.
const SESSION_WINDOW: Duration = Duration::from_secs(5);

fn window(_: &[u8]) -> Duration {
    SESSION_WINDOW
}

/// Build the WSD reflector for `reflector` and register both directions on `dispatcher`. A no-op when
/// WSD isn't enabled. For each address family in use it joins the group on BOTH interfaces and
/// registers two handlers: `Hello` / `Bye` announcements target → source (a [`SimpleReflector`]), and
/// `Probe` / `Resolve` searches source → target with their unicast replies (the shared
/// [`SearchReflector`]). A required family must be sendable on BOTH interfaces, since both re-emit.
///
/// # Errors
/// [`BuildError::UnknownInterface`] for an unopened source/target, or
/// [`BuildError::RequiredFamilyUnavailable`] if either interface can't send a required family.
pub(crate) fn build(
    reflector: &Reflector,
    interfaces: &InterfaceMap,
    dispatcher: &mut PacketDispatcher,
) -> Result<(), BuildError> {
    if !reflector.wsd {
        return Ok(());
    }
    let source = interfaces.require(reflector.source_if.as_str())?;
    let target = interfaces.require(reflector.target_if.as_str())?;

    // Announcements re-emit on source, searches and their replies on target, so a required family must
    // be sendable on BOTH.
    require_bidirectional_families(
        dispatcher,
        reflector.address_family,
        source,
        reflector.source_if.as_str(),
        target,
        reflector.target_if.as_str(),
    )?;

    // The reserved-port bind for an IPv6 link-local target source needs the target's scope id; use the
    // ifindex the capture already cached (the same value the joiners use).
    let target_ifindex = dispatcher.capture_ifindex(target).unwrap_or(0);

    // Announcements are captured on target, searches on source, so join the group on both. A family with
    // no address yet is recorded and re-attempted on the next address change.
    let groups = used_groups(reflector.address_family);
    for group in &groups {
        if let Err(e) = dispatcher.join_group(target, group.ip()) {
            log::debug!("WSD: join {} on target deferred: {e}", group.ip());
        }
        if let Err(e) = dispatcher.join_group(source, group.ip()) {
            log::debug!("WSD: join {} on source deferred: {e}", group.ip());
        }
    }
    // One handler per direction spans every group; its filter matches the group set at the WSD port.
    let group_ips: IpSet = groups.iter().map(SocketAddr::ip).collect();
    // target -> source: Hello/Bye announcements, optionally filtered to the configured device's MAC.
    dispatcher.register(
        target,
        Filter {
            dst_ip: Some(group_ips.clone()),
            dst_port: Some(WSD_PORT.into()),
            src_mac: reflector.macs.clone(),
            ..Filter::default()
        },
        Box::new(SimpleReflector::new(
            source,
            "WSD",
            "announcement",
            WSD_PORT,
            WSD_TTL,
            announcement_verdict,
        )),
    );
    // source -> target: Probe/Resolve searches (unfiltered, any source client may search); each
    // searcher's unicast matches route back through a per-searcher session.
    dispatcher.register(
        source,
        Filter {
            dst_ip: Some(group_ips),
            dst_port: Some(WSD_PORT.into()),
            ..Filter::default()
        },
        Box::new(SearchReflector::new(
            source,
            target,
            target_ifindex,
            reflector.macs.clone(),
            "WSD",
            MessageType::WsdResponse,
            WSD_TTL,
            search_verdict,
            window,
            Box::new(|| Box::new(NoRewrite) as Box<dyn ReplyRewrite>),
        )),
    );
    log::info!(
        "WSD reflector \"{}\": {} <-> {} (announcements + searches)",
        reflector.name.as_str(),
        reflector.source_if.as_str(),
        reflector.target_if.as_str()
    );
    Ok(())
}

/// The WSD group socket addresses `family` reflects to: the IPv4 group and the IPv6 link-local group
/// (WSD, unlike SSDP, uses only the link-local IPv6 scope).
fn used_groups(family: AddressFamily) -> Vec<SocketAddr> {
    let mut groups = Vec::with_capacity(2);
    if family.uses_ipv4() {
        groups.push(SocketAddr::from((WSD_GROUP_V4, WSD_PORT)));
    }
    if family.uses_ipv6() {
        groups.push(SocketAddr::from((WSD_GROUP_V6, WSD_PORT)));
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn used_groups_follows_the_address_family() {
        let v4 = SocketAddr::from((WSD_GROUP_V4, WSD_PORT));
        let v6 = SocketAddr::from((WSD_GROUP_V6, WSD_PORT));
        // Default and Dual reflect both families; the single-family policies, only their own.
        assert_eq!(used_groups(AddressFamily::Default), vec![v4, v6]);
        assert_eq!(used_groups(AddressFamily::Dual), vec![v4, v6]);
        assert_eq!(used_groups(AddressFamily::Ipv4), vec![v4]);
        assert_eq!(used_groups(AddressFamily::Ipv6), vec![v6]);
    }

    #[test]
    fn verdicts_gate_by_direction() {
        let hello = b"<a:Action>http://x/Hello</a:Action>";
        let probe = b"<a:Action>http://x/Probe</a:Action>";
        assert_eq!(
            announcement_verdict(hello),
            Verdict::Reflect(MessageType::WsdAnnouncement)
        );
        assert_eq!(
            announcement_verdict(probe),
            Verdict::Skip(MessageType::WsdSearch)
        );
        assert_eq!(announcement_verdict(b"junk"), Verdict::Junk);
        assert_eq!(
            search_verdict(probe),
            Verdict::Reflect(MessageType::WsdSearch)
        );
        assert_eq!(
            search_verdict(hello),
            Verdict::Skip(MessageType::WsdAnnouncement)
        );
        assert_eq!(search_verdict(b"junk"), Verdict::Junk);
    }
}
