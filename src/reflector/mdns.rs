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

use crate::config::Reflector;
use crate::dispatch::{Filter, IpSet, MessageType, PacketDispatcher};
use crate::net::mdns::{
    MDNS_GROUP_V4, MDNS_GROUP_V6, MDNS_PORT, MDNS_TTL, MdnsKind, advertises_only_unreachable,
    classify,
};

use super::{
    BuildError, Delivery, Emit, InterfaceMap, SimpleReflector, Verdict, directional_verdict,
    group_addrs, open_pair,
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
    directional_verdict(classify(payload), MdnsKind::Query)
}

/// The directional gate for the target → source reflector: the mirror of [`query_verdict`].
fn response_verdict(payload: &[u8]) -> Verdict {
    directional_verdict(classify(payload), MdnsKind::Response)
}

/// Build the mDNS reflector for `reflector` and register its directional handlers on `dispatcher`.
/// A no-op when mDNS isn't enabled. Joins each in-use family's group on both interfaces, then
/// registers two handlers spanning them: queries source → target, responses target → source.
///
/// # Errors
/// As [`open_pair`].
pub(crate) fn build(
    reflector: &Reflector,
    interfaces: &InterfaceMap,
    dispatcher: &mut PacketDispatcher,
) -> Result<(), BuildError> {
    if !reflector.mdns {
        return Ok(());
    }
    let groups = group_addrs(
        reflector.address_family,
        MDNS_PORT,
        MDNS_GROUP_V4,
        &[MDNS_GROUP_V6],
    );
    let (source, target) = open_pair(reflector, interfaces, dispatcher, "mDNS", &groups)?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
