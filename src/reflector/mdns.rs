//! The mDNS reflector: queries flow source → target, responses target → source, each re-emitted to
//! the same group at TTL 255 (RFC 6762 §11) from the egress interface.
//!
//! Limitation: a legacy querier asking from an ephemeral port expects its answer there, but the
//! relayed query is sourced from port 5353, so the device answers on the group, which that
//! querier does not listen on.

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

impl From<MdnsKind> for MessageType {
    fn from(kind: MdnsKind) -> Self {
        match kind {
            MdnsKind::Query => Self::MdnsQuery,
            MdnsKind::Response => Self::MdnsResponse,
        }
    }
}

fn query_verdict(payload: &[u8]) -> Verdict {
    directional_verdict(classify(payload), MdnsKind::Query)
}

fn response_verdict(payload: &[u8]) -> Verdict {
    directional_verdict(classify(payload), MdnsKind::Response)
}

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
    // source → target: queries.
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
    // target → source: responses. `dst_own` takes in an answer sent to this host rather than the
    // group (a QU query, RFC 6762 §5.4, or one that reached a peer as unicast, §5.5). `src_port`:
    // a response from anywhere but 5353 is ignored by every client (§6).
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
            // Queries carry no advertisement, so only this leg checks.
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
