//! The mDNS reflector: reflects multicast DNS between the source and target interfaces so service
//! discovery crosses the link. It registers two directional [`SimpleReflector`]s, each spanning
//! every in-use family's group: queries flow source → target, responses target → source. Atop the
//! capture's own-egress drop, this breaks the reflection loop. Each re-emits to the same group at
//! TTL 255 (RFC 6762 §11), sourced from the egress interface. The dispatcher's filter pins the
//! group for queries; for responses it also takes an answer sent to the target interface itself,
//! which a device sends when the query asked for a unicast response (the QU bit, RFC 6762 §5.4)
//! or arrived as unicast (a copy to a peer, §5.5). Such an answer goes out on the source's group.
//!
//! Limitation: a legacy querier asking from an ephemeral port expects its answer there, but the
//! relayed query is sourced from port 5353, so the device answers on the group, which that
//! querier does not listen on. (SSDP and WSD instead proxy each searcher's unicast reply through
//! a per-searcher session; mDNS does not.)

use std::net::SocketAddr;

use crate::config::{AddressFamily, Reflector};
use crate::dispatch::{Filter, IpSet, MessageType, PacketDispatcher};
use crate::net::mdns::{
    MDNS_GROUP_V4, MDNS_GROUP_V6, MDNS_PORT, MDNS_TTL, MdnsKind, advertises_only_unreachable,
    classify,
};

use super::{
    BuildError, Delivery, Emit, InterfaceMap, SimpleReflector, Verdict,
    require_bidirectional_families, require_group_join, require_macs_matchable,
};

/// mDNS's classifier kind *is* its message type: `Query`/`Response` map straight across.
impl From<MdnsKind> for MessageType {
    fn from(kind: MdnsKind) -> Self {
        match kind {
            MdnsKind::Query => Self::MdnsQuery,
            MdnsKind::Response => Self::MdnsResponse,
        }
    }
}

/// The directional gate for the source → target reflector: reflect queries, skip responses (they
/// flow the other way), treat a too-short or non-DNS payload on the group as junk. The verdict
/// carries the packet's message type (via [`From<MdnsKind>`]) for the counters.
fn query_verdict(payload: &[u8]) -> Verdict {
    match classify(payload) {
        Some(kind @ MdnsKind::Query) => Verdict::Reflect(kind.into()),
        Some(kind @ MdnsKind::Response) => Verdict::Skip(kind.into()),
        None => Verdict::Junk,
    }
}

/// The directional gate for the target → source reflector: the mirror of [`query_verdict`].
fn response_verdict(payload: &[u8]) -> Verdict {
    match classify(payload) {
        Some(kind @ MdnsKind::Query) => Verdict::Skip(kind.into()),
        Some(kind @ MdnsKind::Response) => Verdict::Reflect(kind.into()),
        None => Verdict::Junk,
    }
}

/// Build the mDNS reflector for `reflector` and register its directional handlers on `dispatcher`.
/// A no-op when mDNS isn't enabled. It joins each in-use family's group on both interfaces (so each
/// capture is admitted the group's frames), then registers two handlers spanning them: queries
/// source → target, responses target → source. A required family must be sendable on BOTH
/// interfaces, since both re-emit.
///
/// # Errors
/// [`BuildError::UnknownInterface`] for an unopened source/target, or
/// [`BuildError::RequiredFamilyUnavailable`] if either interface can't send a required family.
pub(crate) fn build(
    reflector: &Reflector,
    interfaces: &InterfaceMap,
    dispatcher: &mut PacketDispatcher,
) -> Result<(), BuildError> {
    if !reflector.mdns {
        return Ok(());
    }
    let source = interfaces.require(reflector.source_if.as_str())?;
    let target = interfaces.require(reflector.target_if.as_str())?;

    // Both interfaces re-emit (queries on target, responses on source), so a required family must
    // be sendable on BOTH.
    require_bidirectional_families(
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

    // Join every group on both interfaces. A family with no address yet is recorded and re-attempted
    // on the next address change, so a deferred join logs rather than fails the build.
    let groups = used_groups(reflector.address_family);
    for group in &groups {
        for (capture, interface) in [
            (source, &reflector.source_if),
            (target, &reflector.target_if),
        ] {
            require_group_join(dispatcher, capture, group.ip(), "mDNS", interface.as_str())?;
        }
    }
    // One handler per direction spans every group; its filter matches the group set at the mDNS port.
    let group_ips: IpSet = groups.iter().map(SocketAddr::ip).collect();
    // source → target: reflect queries (any client on source may ask).
    dispatcher.register(
        source,
        Filter {
            dst_ip: Some(group_ips.clone()),
            dst_port: Some(MDNS_PORT.into()),
            ..Filter::default()
        },
        Box::new(SimpleReflector::new(
            target,
            Delivery::new(reflector.target_peers.as_ref()),
            "mDNS",
            "query",
            query_verdict,
            Emit::fixed(MDNS_PORT, MDNS_TTL),
        )),
    );
    // target → source: reflect responses, optionally only from the configured device's MAC. An
    // answer to a query that asked for a unicast response, or that reached a peer as unicast,
    // comes to this host rather than the group (RFC 6762 §5.4, §5.5) and is taken in as well. A
    // response comes from port 5353, and one from elsewhere is ignored by every client (§6).
    dispatcher.register(
        target,
        Filter {
            src_port: Some(MDNS_PORT),
            dst_ip: Some(group_ips),
            dst_port: Some(MDNS_PORT.into()),
            src_mac: reflector.macs.clone(),
            dst_own: Some(reflector.address_family),
            ..Filter::default()
        },
        Box::new(
            SimpleReflector::new(
                source,
                // Never to peers: a client takes a unicast answer only to its own question that
                // asked for one (§5.4); the config refuses peers on this side.
                Delivery::Link,
                "mDNS",
                "response",
                response_verdict,
                Emit::fixed(MDNS_PORT, MDNS_TTL).unicast_to_group(MDNS_GROUP_V4, MDNS_GROUP_V6),
            )
            // A response whose A/AAAA records are all link-local or otherwise never a peer
            // advertises endpoints the source side can never use; queries carry no advertisement,
            // so only this leg checks.
            .with_suppress(advertises_only_unreachable),
        ),
    );
    log::info!(
        "mDNS reflector \"{}\": {} <-> {}",
        reflector.name.as_str(),
        reflector.source_if.as_str(),
        reflector.target_if.as_str()
    );
    Ok(())
}

/// The mDNS group socket addresses `family` reflects to.
fn used_groups(family: AddressFamily) -> Vec<SocketAddr> {
    let mut groups = Vec::with_capacity(2);
    if family.uses_ipv4() {
        groups.push(SocketAddr::from((MDNS_GROUP_V4, MDNS_PORT)));
    }
    if family.uses_ipv6() {
        groups.push(SocketAddr::from((MDNS_GROUP_V6, MDNS_PORT)));
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn used_groups_follows_the_address_family() {
        let v4 = SocketAddr::from((MDNS_GROUP_V4, MDNS_PORT));
        let v6 = SocketAddr::from((MDNS_GROUP_V6, MDNS_PORT));
        // Default and Dual reflect both families; the single-family policies, only their own.
        assert_eq!(used_groups(AddressFamily::Default), vec![v4, v6]);
        assert_eq!(used_groups(AddressFamily::Dual), vec![v4, v6]);
        assert_eq!(used_groups(AddressFamily::Ipv4), vec![v4]);
        assert_eq!(used_groups(AddressFamily::Ipv6), vec![v6]);
    }

    #[test]
    fn verdicts_gate_by_direction() {
        // A 12-byte DNS header: QR bit (offset 2, 0x80) clear = query, set = response; shorter = junk.
        let query = [0u8; 12];
        let mut response = [0u8; 12];
        response[2] = 0x80;
        assert_eq!(
            query_verdict(&query),
            Verdict::Reflect(MessageType::MdnsQuery)
        );
        assert_eq!(
            query_verdict(&response),
            Verdict::Skip(MessageType::MdnsResponse)
        );
        assert_eq!(query_verdict(&[0u8; 4]), Verdict::Junk);
        assert_eq!(
            response_verdict(&query),
            Verdict::Skip(MessageType::MdnsQuery)
        );
        assert_eq!(
            response_verdict(&response),
            Verdict::Reflect(MessageType::MdnsResponse)
        );
        assert_eq!(response_verdict(&[0u8; 4]), Verdict::Junk);
    }
}
