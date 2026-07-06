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
        }
    }

    /// Apply `rewrite` to the payload before re-emit (e.g. SSDP's DIAL `LOCATION` rewrite); without it
    /// the payload is forwarded verbatim.
    pub(crate) fn with_rewrite(mut self, rewrite: Box<dyn ReplyRewrite>) -> Self {
        self.rewrite = rewrite;
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

        let payload = self
            .rewrite
            .rewrite(packet.payload, self.egress, dispatcher, reactor);

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
