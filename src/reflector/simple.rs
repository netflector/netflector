//! The shared stateless reflector: classify the payload and, if it's a message for this leg,
//! re-emit it on the egress, verbatim or through a [`ReplyRewrite`]. What differs per protocol
//! enters as the [`Classify`] gate and the [`Emit`] policy. The stateful search directions use
//! `SearchReflector` instead.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::dispatch::{CaptureKey, DatagramSource, Outcome, PacketDispatcher, PacketHandler};
use crate::interface::InterfaceAddresses;
use crate::logging::log_rate;
use crate::net::packet::Packet;
use crate::reactor::Reactor;

use super::{Delivery, NoRewrite, ReplyRewrite, Verdict, WARN_WINDOW, egress_sources};

/// A leg's ingress gate: is this packet a message for it?
pub(crate) trait Classify {
    fn classify(&self, packet: &Packet) -> Verdict;
}

impl<F: Fn(&[u8]) -> Verdict> Classify for F {
    fn classify(&self, packet: &Packet) -> Verdict {
        self(packet.payload)
    }
}

/// The IP source a re-emit carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    Egress(SourcePort),
    /// The captured sender's own ip:port: the transparent relay, whose peers read the sender off
    /// the datagram.
    Captured,
}

impl Source {
    fn resolve(self, packet: &Packet) -> DatagramSource {
        match self {
            Self::Egress(port) => DatagramSource::Egress {
                port: port.resolve(packet),
            },
            Self::Captured => DatagramSource::Exact(packet.source),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourcePort {
    Fixed(u16),
    Captured,
}

impl SourcePort {
    fn resolve(self, packet: &Packet) -> u16 {
        match self {
            Self::Fixed(port) => port,
            Self::Captured => packet.source.port(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ttl {
    Fixed(u8),
    Captured,
}

impl Ttl {
    fn resolve(self, packet: &Packet) -> u8 {
        match self {
            Self::Fixed(ttl) => ttl,
            Self::Captured => packet.ttl,
        }
    }
}

/// Where a re-emit whose captured destination is unicast goes; a group or broadcast destination
/// keeps its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnicastTo {
    /// The leg's filter pins a group, so a unicast destination is not its traffic.
    Nowhere,
    /// A directed broadcast (which reads as unicast without the mask) or a wake sent to a sleeping
    /// device's own address goes to the egress link's broadcast.
    Broadcast,
    /// An answer a peer sent to this host's own address goes to the protocol's group.
    Group { v4: Ipv4Addr, v6: Ipv6Addr },
}

/// How a re-emit is stamped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Emit {
    pub(crate) source: Source,
    pub(crate) ttl: Ttl,
    pub(crate) unicast: UnicastTo,
}

impl Emit {
    /// The multicast-discovery protocols.
    pub(crate) const fn fixed(port: u16, ttl: u8) -> Self {
        Self {
            source: Source::Egress(SourcePort::Fixed(port)),
            ttl: Ttl::Fixed(ttl),
            unicast: UnicastTo::Nowhere,
        }
    }

    pub(crate) const fn captured_from_egress() -> Self {
        Self {
            source: Source::Egress(SourcePort::Captured),
            ttl: Ttl::Captured,
            unicast: UnicastTo::Nowhere,
        }
    }

    /// A search reply relayed back to its searcher from the responding device's own port.
    pub(crate) const fn reply(ttl: u8) -> Self {
        Self {
            source: Source::Egress(SourcePort::Captured),
            ttl: Ttl::Fixed(ttl),
            unicast: UnicastTo::Nowhere,
        }
    }

    pub(crate) const fn captured() -> Self {
        Self {
            source: Source::Captured,
            ttl: Ttl::Captured,
            unicast: UnicastTo::Nowhere,
        }
    }

    pub(crate) const fn unicast_to_broadcast(self) -> Self {
        Self {
            unicast: UnicastTo::Broadcast,
            ..self
        }
    }

    pub(crate) const fn unicast_to_group(self, v4: Ipv4Addr, v6: Ipv6Addr) -> Self {
        Self {
            unicast: UnicastTo::Group { v4, v6 },
            ..self
        }
    }
}

/// One stateless leg of one protocol: re-emits each packet `classify` accepts onto `egress`,
/// stamped per `emit`.
pub(crate) struct SimpleReflector<C> {
    egress: CaptureKey,
    delivery: Delivery,
    /// For logs, e.g. `"mDNS"`.
    name: &'static str,
    /// For logs, e.g. `"query"`.
    kind: &'static str,
    classify: C,
    emit: Emit,
    rewrite: Box<dyn ReplyRewrite>,
    /// The unreachable-advertisement check, consulted only for payloads `rewrite` left untouched.
    suppress: fn(&[u8]) -> bool,
}

impl<C: Classify> SimpleReflector<C> {
    pub(crate) fn new(
        egress: CaptureKey,
        delivery: Delivery,
        name: &'static str,
        kind: &'static str,
        classify: C,
        emit: Emit,
    ) -> Self {
        Self {
            egress,
            delivery,
            name,
            kind,
            classify,
            emit,
            rewrite: Box::new(NoRewrite),
            suppress: |_| false,
        }
    }

    pub(crate) fn with_rewrite(mut self, rewrite: Box<dyn ReplyRewrite>) -> Self {
        self.rewrite = rewrite;
        self
    }

    pub(crate) fn with_suppress(mut self, suppress: fn(&[u8]) -> bool) -> Self {
        self.suppress = suppress;
        self
    }

    fn destination(&self, packet: &Packet, dispatcher: &PacketDispatcher) -> Option<SocketAddr> {
        match &self.delivery {
            Delivery::Unicast { to, .. } => Some(*to),
            Delivery::Link | Delivery::Peers(_) => link_destination(
                packet.dest,
                dispatcher
                    .egress_addrs(self.egress)
                    .and_then(InterfaceAddresses::v4_directed_broadcast),
                self.emit.unicast,
            ),
        }
    }
}

impl<C: Classify> PacketHandler for SimpleReflector<C> {
    fn on_packet(
        &mut self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        reactor: &mut Reactor,
    ) -> Outcome {
        let message_type = match self.classify.classify(packet) {
            Verdict::Reflect(message_type) => message_type,
            Verdict::Skip(message_type) => return Outcome::Skipped(message_type),
            Verdict::Excluded => return Outcome::Filtered,
            Verdict::Junk => {
                log::debug!(
                    "{}: dropping unrecognized payload ({} B) to {} from {}",
                    self.name,
                    packet.payload.len(),
                    packet.dest,
                    packet.source
                );
                return Outcome::Filtered;
            }
        };

        let Some(dest) = self.destination(packet, dispatcher) else {
            log::debug!(
                "{}: dropping {} to {} from {}: not for this leg",
                self.name,
                self.kind,
                packet.dest,
                packet.source
            );
            return Outcome::Filtered;
        };

        // Address loss is transient: a Stalled, not a send failure.
        if !egress_sources(dispatcher, self.egress, dest) {
            log::debug!(
                "{}: egress has no source for {dest} yet; dropping {} from {}",
                self.name,
                self.kind,
                packet.source
            );
            return Outcome::Stalled(message_type);
        }

        let rewritten = self
            .rewrite
            .rewrite(packet.payload, self.egress, dispatcher, reactor);

        // A rewritten payload is exempt: it now names our own egress-side listener, reachable from
        // that link whatever its address class. Only an untouched payload still advertises the far
        // link's addresses.
        if rewritten.is_none() && (self.suppress)(packet.payload) {
            log::debug!(
                "{}: suppressing {} from {}: advertises only unreachable addresses",
                self.name,
                self.kind,
                packet.source
            );
            return Outcome::Dropped(message_type);
        }
        let payload = rewritten.unwrap_or(packet.payload);

        match self.delivery.send(
            dispatcher,
            self.egress,
            dest,
            self.emit.source.resolve(packet),
            self.emit.ttl.resolve(packet),
            payload,
        ) {
            Ok(()) => {
                log::debug!(
                    "reflected {} {} from {} to {dest}",
                    self.name,
                    self.kind,
                    packet.source
                );
                Outcome::Reflected(message_type)
            }
            Err(e) => {
                log_rate!(
                    log::Level::Warn,
                    WARN_WINDOW,
                    "{}: cannot reflect {} from {} to {dest}: {e}",
                    self.name,
                    self.kind,
                    packet.source
                );
                Outcome::Dropped(message_type)
            }
        }
    }
}

/// The v6 stand-in for the IPv4 limited broadcast.
const V6_ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// Where a re-emit of a packet captured to `dest` goes, at the captured port: a group or the
/// limited broadcast keeps it, anything else goes where `unicast` says.
fn link_destination(
    dest: SocketAddr,
    directed_broadcast: Option<Ipv4Addr>,
    unicast: UnicastTo,
) -> Option<SocketAddr> {
    let port = dest.port();
    Some(match (dest, unicast) {
        (SocketAddr::V4(v4), _) if v4.ip().is_multicast() || v4.ip().is_broadcast() => dest,
        (SocketAddr::V6(v6), _) if v6.ip().is_multicast() => dest,
        (_, UnicastTo::Nowhere) => return None,
        (SocketAddr::V4(_), UnicastTo::Broadcast) => {
            SocketAddr::from((directed_broadcast.unwrap_or(Ipv4Addr::BROADCAST), port))
        }
        (SocketAddr::V6(_), UnicastTo::Broadcast) => SocketAddr::from((V6_ALL_NODES, port)),
        (SocketAddr::V4(_), UnicastTo::Group { v4, .. }) => SocketAddr::from((v4, port)),
        (SocketAddr::V6(_), UnicastTo::Group { v6, .. }) => SocketAddr::from((v6, port)),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::dispatch::MessageType;
    use crate::test_support::{ReplaceRewrite, loopback_lock, open_loopback_or_skip};

    fn reflect_all(_: &[u8]) -> Verdict {
        Verdict::Reflect(MessageType::MdnsResponse)
    }

    type LoopbackRig = (
        SimpleReflector<fn(&[u8]) -> Verdict>,
        PacketDispatcher,
        Reactor,
    );

    /// A reflector with the given transform and suppression check, plus the dispatcher/reactor it
    /// runs against, over a real loopback egress (`None` = skip, no `CAP_NET_RAW`).
    fn reflector_over_loopback(
        rewrite: Box<dyn ReplyRewrite>,
        suppress: fn(&[u8]) -> bool,
    ) -> Option<LoopbackRig> {
        let cap = open_loopback_or_skip()?;
        let mut dispatcher = PacketDispatcher::new();
        let egress = dispatcher
            .add_capture(cap)
            .expect("add the loopback capture");
        let reactor = Reactor::new().expect("reactor");
        let reflector = SimpleReflector::new(
            egress,
            Delivery::Link,
            "TEST",
            "response",
            reflect_all as fn(&[u8]) -> Verdict,
            Emit::fixed(5353, 255),
        )
        .with_rewrite(rewrite)
        .with_suppress(suppress);
        Some((reflector, dispatcher, reactor))
    }

    fn group_packet() -> Packet<'static> {
        Packet {
            source: "127.0.0.1:5353".parse().unwrap(),
            dest: "224.0.0.251:5353".parse().unwrap(),
            ttl: 255,
            dst_mac: None,
            src_mac: None,
            payload: b"response",
        }
    }

    /// A packet from an ephemeral port at a non-default TTL, so a captured policy reads apart from a
    /// fixed one.
    fn packet_to(dest: &str) -> Packet<'static> {
        Packet {
            source: "10.0.0.1:40000".parse().unwrap(),
            dest: dest.parse().unwrap(),
            ttl: 7,
            dst_mac: None,
            src_mac: None,
            payload: b"",
        }
    }

    #[test]
    fn link_destination_keeps_groups_and_broadcasts_the_rest() {
        let dest = |s: &str| s.parse::<SocketAddr>().unwrap();
        let egress = Some(Ipv4Addr::new(192, 0, 2, 255));
        let to_broadcast = Emit::captured_from_egress().unicast_to_broadcast().unicast;
        for group in ["224.0.0.251:5353", "[ff02::fb]:5353"] {
            assert_eq!(
                Some(dest(group)),
                link_destination(dest(group), egress, to_broadcast)
            );
        }
        // The limited broadcast stays limited; a directed broadcast or a wake sent to a device's
        // own address goes to the egress's own directed broadcast, at the captured port.
        assert_eq!(
            Some(dest("255.255.255.255:9")),
            link_destination(dest("255.255.255.255:9"), egress, to_broadcast)
        );
        for captured in ["10.0.0.255:9", "10.0.0.2:9"] {
            assert_eq!(
                Some(dest("192.0.2.255:9")),
                link_destination(dest(captured), egress, to_broadcast)
            );
            // Without the egress prefix, link-wide still means the limited broadcast.
            assert_eq!(
                Some(dest("255.255.255.255:9")),
                link_destination(dest(captured), None, to_broadcast)
            );
        }
        assert_eq!(
            Some(dest("[ff02::1]:9")),
            link_destination(dest("[fe80::2]:9"), egress, to_broadcast)
        );
    }

    #[test]
    fn link_destination_drops_a_unicast_destination_by_default() {
        let dest = |s: &str| s.parse::<SocketAddr>().unwrap();
        let egress = Some(Ipv4Addr::new(192, 0, 2, 255));
        let nowhere = Emit::fixed(5353, 255).unicast;
        assert_eq!(None, link_destination(dest("10.0.0.2:9"), egress, nowhere));
        assert_eq!(None, link_destination(dest("[fe80::2]:9"), egress, nowhere));
        // Groups and broadcasts still go out.
        for kept in ["224.0.0.251:5353", "[ff02::fb]:5353", "255.255.255.255:9"] {
            assert_eq!(
                Some(dest(kept)),
                link_destination(dest(kept), egress, nowhere)
            );
        }
    }

    #[test]
    fn link_destination_sends_a_unicast_answer_to_the_group() {
        let dest = |s: &str| s.parse::<SocketAddr>().unwrap();
        let egress = Some(Ipv4Addr::new(192, 0, 2, 255));
        let to_group = Emit::fixed(5353, 255)
            .unicast_to_group(Ipv4Addr::new(224, 0, 0, 251), "ff02::fb".parse().unwrap())
            .unicast;
        // An answer to this host's own address, in either family, goes to that family's group.
        assert_eq!(
            Some(dest("224.0.0.251:5353")),
            link_destination(dest("10.0.0.1:5353"), egress, to_group)
        );
        assert_eq!(
            Some(dest("[ff02::fb]:5353")),
            link_destination(dest("[fd00::1]:5353"), egress, to_group)
        );
        // Groups and broadcasts keep their destination.
        for kept in [
            "224.0.0.251:5353",
            "[ff02::fb]:5353",
            "255.255.255.255:5353",
        ] {
            assert_eq!(
                Some(dest(kept)),
                link_destination(dest(kept), egress, to_group)
            );
        }
    }

    #[test]
    fn source_port_and_ttl_policies_resolve_fixed_or_captured() {
        let packet = packet_to("10.0.0.2:9");
        assert_eq!(SourcePort::Fixed(1900).resolve(&packet), 1900);
        assert_eq!(SourcePort::Captured.resolve(&packet), 40000);
        assert_eq!(Ttl::Fixed(2).resolve(&packet), 2);
        assert_eq!(Ttl::Captured.resolve(&packet), 7);
    }

    #[test]
    fn a_function_classifies_by_payload_alone() {
        fn by_length(payload: &[u8]) -> Verdict {
            if payload.is_empty() {
                Verdict::Junk
            } else {
                Verdict::Reflect(MessageType::MdnsQuery)
            }
        }
        assert_eq!(by_length.classify(&packet_to("10.0.0.2:9")), Verdict::Junk);
        assert_eq!(
            by_length.classify(&group_packet()),
            Verdict::Reflect(MessageType::MdnsQuery)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn a_fixed_unicast_delivery_ignores_the_captured_destination() {
        let _serial = loopback_lock();
        let Some(cap) = open_loopback_or_skip() else {
            return;
        };
        let mut dispatcher = PacketDispatcher::new();
        let egress = dispatcher
            .add_capture(cap)
            .expect("add the loopback capture");
        let mut reactor = Reactor::new().expect("reactor");
        let mut reflector = SimpleReflector::new(
            egress,
            Delivery::Unicast {
                to: "127.0.0.1:4000".parse().unwrap(),
                mac: crate::net::mac::MacAddr::from([0x02, 0, 0, 0, 0, 1]),
            },
            "TEST",
            "response",
            reflect_all as fn(&[u8]) -> Verdict,
            Emit::reply(2),
        );
        // A unicast captured destination is dropped under the link deliveries; the fixed
        // delivery relays regardless of it.
        let outcome = reflector.on_packet(&packet_to("127.0.0.1:9"), &mut dispatcher, &mut reactor);
        assert_eq!(outcome, Outcome::Reflected(MessageType::MdnsResponse));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn a_suppressed_payload_is_dropped_before_the_send() {
        let _serial = loopback_lock();
        // The Dropped outcome proves the early return: a completed loopback send would be Reflected.
        let Some((mut reflector, mut dispatcher, mut reactor)) =
            reflector_over_loopback(Box::new(NoRewrite), |_| true)
        else {
            return;
        };
        assert_eq!(
            reflector.on_packet(&group_packet(), &mut dispatcher, &mut reactor),
            Outcome::Dropped(MessageType::MdnsResponse)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn a_rewritten_payload_is_exempt_from_suppression() {
        // The rewrite spliced in our own egress-side listener, reachable from that link whatever
        // its address class, so the gate must not even be consulted. The tracking fn (would-be
        // suppressing) proves it: a fn pointer can't capture, hence the static.
        static SUPPRESS_CONSULTED: AtomicBool = AtomicBool::new(false);
        fn tracking_suppress(_: &[u8]) -> bool {
            SUPPRESS_CONSULTED.store(true, Ordering::Relaxed);
            true
        }
        let _serial = loopback_lock();
        let Some((mut reflector, mut dispatcher, mut reactor)) =
            reflector_over_loopback(Box::new(ReplaceRewrite), tracking_suppress)
        else {
            return;
        };
        let outcome = reflector.on_packet(&group_packet(), &mut dispatcher, &mut reactor);
        assert!(
            !SUPPRESS_CONSULTED.load(Ordering::Relaxed),
            "the gate ran on a rewritten payload"
        );
        // And the exempt payload completed the reflect: it was sent, not merely spared the gate.
        assert_eq!(outcome, Outcome::Reflected(MessageType::MdnsResponse));
    }
}
