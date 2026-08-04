//! A shared stateless reflector for the multicast-discovery protocols.
//!
//! mDNS (both directions), the WSD Hello/Bye announcements, and SSDP's `NOTIFY` advertisements are the
//! same operation: classify the payload and, if it's a message for this direction, re-emit it to its
//! own group on the egress interface, verbatim or through an optional [`ReplyRewrite`] (SSDP's
//! advertisement direction rewrites the DIAL `LOCATION`). The search directions are stateful
//! (per-searcher sessions), so they use the shared `SearchReflector` instead.

use crate::dispatch::{CaptureKey, Outcome, PacketDispatcher, PacketHandler};
use crate::net::packet::Packet;
use crate::reactor::Reactor;

use super::{NoRewrite, ReplyRewrite, Verdict, egress_sources};

/// One direction of one multicast-discovery protocol: re-emits each accepted message captured on its
/// ingress onto `egress`, to the message's own destination (the dispatcher's filter pins that to the
/// group). The `classify` fn is the directional gate; an optional [`ReplyRewrite`] transforms the
/// payload before re-emit (default: forward verbatim).
pub(crate) struct SimpleReflector {
    egress: CaptureKey,
    /// Protocol tag for logs, e.g. `"mDNS"`.
    name: &'static str,
    /// The message kind/direction this reflector handles, for logs, e.g. `"query"`.
    kind: &'static str,
    /// The UDP source port to emit from: a protocol's well-known port. The destination comes from
    /// `packet.dest`.
    src_port: u16,
    ttl: u8,
    classify: fn(&[u8]) -> Verdict,
    /// Transforms the payload before re-emit; [`NoRewrite`] (the default) forwards verbatim.
    rewrite: Box<dyn ReplyRewrite>,
    /// The link-local suppression check for payloads `rewrite` left untouched (default: none).
    suppress: fn(&[u8]) -> bool,
}

impl SimpleReflector {
    pub(crate) fn new(
        egress: CaptureKey,
        name: &'static str,
        kind: &'static str,
        src_port: u16,
        ttl: u8,
        classify: fn(&[u8]) -> Verdict,
    ) -> Self {
        Self {
            egress,
            name,
            kind,
            src_port,
            ttl,
            classify,
            rewrite: Box::new(NoRewrite),
            suppress: |_| false,
        }
    }

    /// Apply `rewrite` to the payload before re-emit (e.g. SSDP's DIAL `LOCATION` rewrite); without it
    /// the payload is forwarded verbatim.
    pub(crate) fn with_rewrite(mut self, rewrite: Box<dyn ReplyRewrite>) -> Self {
        self.rewrite = rewrite;
        self
    }

    /// Drop (rather than re-emit) any payload `suppress` flags: the protocol's
    /// `advertises_only_link_local` check.
    pub(crate) fn with_suppress(mut self, suppress: fn(&[u8]) -> bool) -> Self {
        self.suppress = suppress;
        self
    }
}

impl PacketHandler for SimpleReflector {
    fn on_packet(
        &mut self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        reactor: &mut Reactor,
    ) -> Outcome {
        let message_type = match (self.classify)(packet.payload) {
            Verdict::Reflect(message_type) => message_type,
            Verdict::Skip(message_type) => return Outcome::Skipped(message_type),
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

        // A family the egress can't currently source is a quiet, transient drop (address
        // loss): a Stalled, not a genuine send failure.
        if !egress_sources(dispatcher, self.egress, packet.dest) {
            log::debug!(
                "{}: egress has no source for {} yet; dropping {} from {}",
                self.name,
                packet.dest,
                self.kind,
                packet.source
            );
            return Outcome::Stalled(message_type);
        }

        let rewritten = self
            .rewrite
            .rewrite(packet.payload, self.egress, dispatcher, reactor);

        // A rewritten payload is exempt: the rewrite inserts netflector's own egress-side listener,
        // reachable from the egress link even when that interface's address is itself link-local.
        // Only an untouched payload still advertises the far link's addresses.
        if rewritten.is_none() && (self.suppress)(packet.payload) {
            log::debug!(
                "{}: suppressing {} from {}: advertises only link-local addresses",
                self.name,
                self.kind,
                packet.source
            );
            return Outcome::Dropped(message_type);
        }
        let payload = rewritten.unwrap_or(packet.payload);

        match dispatcher.send_udp_group(self.egress, packet.dest, self.src_port, self.ttl, payload)
        {
            Ok(()) => {
                log::debug!(
                    "reflected {} {} from {} to {}",
                    self.name,
                    self.kind,
                    packet.source,
                    packet.dest
                );
                Outcome::Reflected(message_type)
            }
            Err(e) => {
                log::warn!(
                    "{}: cannot reflect {} from {} to {}: {e}",
                    self.name,
                    self.kind,
                    packet.source,
                    packet.dest
                );
                Outcome::Dropped(message_type)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::capture::Capture;
    use crate::dispatch::MessageType;

    /// Open a loopback capture, or `None` (skip) without `CAP_NET_RAW`. A real capture gives the
    /// egress a source address, so `on_packet` reaches the suppression gate.
    fn open_loopback_or_skip() -> Option<Capture> {
        match Capture::open(crate::interface::LOOPBACK_IFACE) {
            Ok(cap) => Some(cap),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skip: no CAP_NET_RAW to open a loopback capture ({e})");
                None
            }
            Err(e) => panic!("unexpected loopback capture open failure: {e}"),
        }
    }

    fn reflect_all(_: &[u8]) -> Verdict {
        Verdict::Reflect(MessageType::MdnsResponse)
    }

    /// A reflector with the given transform and suppression check, plus the dispatcher/reactor it
    /// runs against, over a real loopback egress (`None` = skip, no `CAP_NET_RAW`).
    fn reflector_over_loopback(
        rewrite: Box<dyn ReplyRewrite>,
        suppress: fn(&[u8]) -> bool,
    ) -> Option<(SimpleReflector, PacketDispatcher, Reactor)> {
        let cap = open_loopback_or_skip()?;
        let mut dispatcher = PacketDispatcher::new();
        let egress = dispatcher
            .add_capture(cap)
            .expect("add the loopback capture");
        let reactor = Reactor::new().expect("reactor");
        let reflector = SimpleReflector::new(egress, "TEST", "response", 5353, 255, reflect_all)
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

    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn a_suppressed_payload_is_dropped_before_the_send() {
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

    /// A rewrite that replaces the payload wholesale, standing in for a DIAL rewrite that spliced
    /// in the proxy's own listener.
    struct ReplaceRewrite;

    impl ReplyRewrite for ReplaceRewrite {
        fn rewrite<'a>(
            &'a mut self,
            _: &[u8],
            _: CaptureKey,
            _: &mut PacketDispatcher,
            _: &mut Reactor,
        ) -> Option<&'a [u8]> {
            Some(b"REWRITTEN")
        }
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
