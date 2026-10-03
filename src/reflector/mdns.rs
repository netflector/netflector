//! The mDNS reflector: queries flow source → target, responses target → source, each re-emitted to
//! the same group at TTL 255 (RFC 6762 §11) from the egress interface.
//!
//! Answers bound for a side with peers go to each peer as a unicast copy, on purpose. RFC 6762
//! §5.4 has a client take a unicast answer only to a question it asked with the unicast-response
//! bit: Apple's resolver enforces that (within two seconds of the question, from a source on the
//! interface's subnet; mDNSResponder's `ExpectingUnicastResponseForRecord`), Avahi takes any
//! answer from the link. iOS asks that way when a browse starts, so the copies serve Apple clients
//! for their initial discovery and Avahi ones throughout. The alternative on such a link, a
//! multicast answer, reaches nobody, so the RFC is no reason to refuse the peers here.
//!
//! Limitation: a legacy querier asking from an ephemeral port expects its answer there, but the
//! relayed query is sourced from port 5353, so the device answers on the group, which that
//! querier does not listen on.
//!
//! An entry's `mdns_services` allow-list ([`ServiceFilter`]) is each leg's rewrite, applied once a
//! message has passed the direction check: a query goes out unless every question names a refused
//! service. A response carrying refused services is re-emitted trimmed of them when an answer
//! naming an allowed service remains, or when it has answers and none names a service, and is
//! dropped otherwise; the trim is the one place the relay is not verbatim.

use std::net::SocketAddr;

use crate::config::Reflector;
use crate::dispatch::{CaptureKey, Filter, IpSet, MessageType, PacketDispatcher};
use crate::net::mdns::services::{Decision, ServiceFilter, ServiceList};
use crate::net::mdns::{
    MDNS_GROUP_V4, MDNS_GROUP_V6, MDNS_PORT, MDNS_TTL, MdnsKind, advertises_only_unreachable,
    classify,
};
use crate::net::packet::Packet;
use crate::reactor::Reactor;

use super::{
    BuildError, Delivery, Emit, InterfaceMap, NoRewrite, ReplyRewrite, Rewrite, SimpleReflector,
    Verdict, directional_verdict, group_addrs, open_pair,
};

impl From<MdnsKind> for MessageType {
    fn from(kind: MdnsKind) -> Self {
        match kind {
            MdnsKind::Query => Self::MdnsQuery,
            MdnsKind::Response => Self::MdnsResponse,
        }
    }
}

/// One leg's direction check: its own kind of message is reflected, the other skipped.
fn direction(kind: MdnsKind) -> impl Fn(&[u8]) -> Verdict {
    move |payload| directional_verdict(classify(payload), kind)
}

/// One leg's `mdns_services` allow-list: passes, refuses or trims each message as
/// [`ServiceFilter::decide`] rules.
struct ServiceGate {
    message_type: MessageType,
    filter: ServiceFilter,
}

impl ServiceGate {
    fn new(kind: MdnsKind, services: ServiceList) -> Self {
        Self {
            message_type: kind.into(),
            filter: ServiceFilter::new(services),
        }
    }

    /// [`ReplyRewrite::rewrite`], without the dispatcher and reactor it has no use for.
    fn judge(&mut self, packet: &Packet) -> Rewrite<'_> {
        match self.filter.decide(packet.payload) {
            Decision::Pass => Rewrite::Verbatim,
            Decision::Refuse(refused) => {
                log::debug!(
                    "not reflecting {} from {}: refused by mdns_services ({refused})",
                    self.message_type,
                    packet.source
                );
                Rewrite::Refused
            }
            Decision::Trim {
                payload,
                removed,
                refused,
            } => {
                log::debug!(
                    "trimming {} from {}: removed {removed} record{} of services outside \
                     mdns_services ({refused})",
                    self.message_type,
                    packet.source,
                    if removed == 1 { "" } else { "s" }
                );
                Rewrite::Replaced(payload)
            }
            Decision::Malformed => Rewrite::Unreadable,
        }
    }
}

impl ReplyRewrite for ServiceGate {
    fn rewrite<'a>(
        &'a mut self,
        packet: &Packet,
        _egress: CaptureKey,
        _dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) -> Rewrite<'a> {
        self.judge(packet)
    }
}

/// # Errors
/// As [`open_pair`].
pub(crate) fn build(
    reflector: &Reflector,
    interfaces: &InterfaceMap,
    dispatcher: &mut PacketDispatcher,
) -> Result<(), BuildError> {
    let Some(mdns) = &reflector.mdns else {
        return Ok(());
    };
    let groups = group_addrs(
        reflector.address_family,
        MDNS_PORT,
        MDNS_GROUP_V4,
        &[MDNS_GROUP_V6],
    );
    let (source, target) = open_pair(reflector, interfaces, dispatcher, "mDNS", &groups)?;
    let group_ips: IpSet = groups.iter().map(SocketAddr::ip).collect();
    let gate = |kind| -> Box<dyn ReplyRewrite> {
        match &mdns.services {
            Some(services) => Box::new(ServiceGate::new(kind, services.clone())),
            None => Box::new(NoRewrite),
        }
    };
    // source → target: queries.
    dispatcher.register(
        source,
        Filter {
            dst_ip: Some(group_ips.clone()),
            dst_port: Some(MDNS_PORT.into()),
            ..Filter::default()
        },
        Box::new(
            SimpleReflector::new(
                target,
                Delivery::new(reflector.target_peers.as_ref()),
                "mDNS",
                "query",
                direction(MdnsKind::Query),
                Emit::fixed(MDNS_PORT, MDNS_TTL),
            )
            .with_rewrite(gate(MdnsKind::Query)),
        ),
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
                // To the source's peers as unicast copies, §5.4 notwithstanding: a deliberate
                // choice, reasoned in the module doc. Don't "fix" it back to the link.
                Delivery::new(reflector.source_peers.as_ref()),
                "mDNS",
                "response",
                direction(MdnsKind::Response),
                Emit::fixed(MDNS_PORT, MDNS_TTL).unicast_to_group(MDNS_GROUP_V4, MDNS_GROUP_V6),
            )
            .with_rewrite(gate(MdnsKind::Response))
            // Queries carry no advertisement, so only this leg checks.
            .with_suppress(advertises_only_unreachable),
        ),
    );
    log::info!(
        "mDNS reflector \"{}\": {} <-> {}",
        reflector.name.as_str(),
        reflector.source_if,
        reflector.target_if
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::dns::{TYPE_PTR, name, query, response};

    fn ptr<'a>(owner: &'a str, target: &str) -> (&'a str, u16, Vec<u8>) {
        (owner, TYPE_PTR, name(target))
    }

    fn packet(payload: &[u8]) -> Packet<'_> {
        Packet {
            source: "192.0.2.7:5353".parse().unwrap(),
            dest: "224.0.0.251:5353".parse().unwrap(),
            ttl: 255,
            dst_mac: None,
            src_mac: None,
            payload,
        }
    }

    #[test]
    fn each_leg_reflects_its_own_direction() {
        // A 12-byte DNS header: QR bit (offset 2, 0x80) clear = query, set = response; shorter = junk.
        let query = [0u8; 12];
        let mut response = [0u8; 12];
        response[2] = 0x80;
        let queries = direction(MdnsKind::Query);
        let responses = direction(MdnsKind::Response);
        assert_eq!(queries(&query), Verdict::Reflect(MessageType::MdnsQuery));
        assert_eq!(queries(&response), Verdict::Skip(MessageType::MdnsResponse));
        assert_eq!(queries(&[0u8; 4]), Verdict::Junk);
        assert_eq!(responses(&query), Verdict::Skip(MessageType::MdnsQuery));
        assert_eq!(
            responses(&response),
            Verdict::Reflect(MessageType::MdnsResponse)
        );
        assert_eq!(responses(&[0u8; 4]), Verdict::Junk);
    }

    #[test]
    fn the_allow_list_refuses_trims_or_passes() {
        let services: ServiceList = "_ipp._tcp".parse().unwrap();
        let mut queries = ServiceGate::new(MdnsKind::Query, services.clone());
        let mut responses = ServiceGate::new(MdnsKind::Response, services);
        let refused = query(&["_hap._tcp.local"]);
        assert_eq!(queries.judge(&packet(&refused)), Rewrite::Refused);
        let allowed = query(&["_ipp._tcp.local"]);
        assert_eq!(queries.judge(&packet(&allowed)), Rewrite::Verbatim);
        let refused = response(&[ptr("_hap._tcp.local", "L._hap._tcp.local")]);
        assert_eq!(responses.judge(&packet(&refused)), Rewrite::Refused);
        // A message the allow-list cannot walk is unreadable, not a refusal of some service.
        let mut truncated = response(&[ptr("_ipp._tcp.local", "L._ipp._tcp.local")]);
        truncated.truncate(truncated.len() - 3);
        assert_eq!(responses.judge(&packet(&truncated)), Rewrite::Unreadable);
        // A mixed response goes out without the refused record.
        let mixed = response(&[
            ptr("_hap._tcp.local", "L._hap._tcp.local"),
            ptr("_ipp._tcp.local", "L._ipp._tcp.local"),
        ]);
        let Rewrite::Replaced(trimmed) = responses.judge(&packet(&mixed)) else {
            panic!("a mixed response is trimmed");
        };
        assert_eq!(
            trimmed,
            response(&[ptr("_ipp._tcp.local", "L._ipp._tcp.local")])
        );
    }
}
