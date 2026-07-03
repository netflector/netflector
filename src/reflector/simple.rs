//! A shared stateless reflector for the multicast-discovery protocols.
//!
//! mDNS (both directions) and the WSD Hello/Bye announcements are the same operation: classify the
//! payload, and if it's a message for this direction, re-emit it verbatim to its own group on the
//! egress interface. [`SimpleReflector`] captures that. SSDP's advertisement direction is similar but
//! stays its own handler (its DIAL rewrite is a side effect), and the search directions are stateful
//! (per-searcher sessions) — so neither uses [`SimpleReflector`].

use crate::dispatch::{CaptureKey, PacketDispatcher, PacketHandler};
use crate::net::packet::Packet;
use crate::reactor::Reactor;

use super::egress_sources;

/// A reflector's verdict on a captured payload, from its protocol's classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// A message for this direction — re-emit it.
    Reflect,
    /// A message for the *other* direction — drop it silently. Dropping the opposite direction is
    /// the loop-breaker (atop the capture's own-egress drop): a reflected query re-emitted on the
    /// egress is still a query, which the egress side's response-only reflector skips.
    Skip,
    /// Not a recognizable protocol message on this dedicated group — drop it with a debug log.
    Junk,
}

/// One direction of one multicast-discovery protocol: re-emits each accepted message captured on its
/// ingress onto `egress`, to the message's own destination (the dispatcher's filter pins that to the
/// group). Stateless — the `classify` fn is the entire directional gate.
pub(crate) struct SimpleReflector {
    egress: CaptureKey,
    /// Protocol tag for logs, e.g. `"mDNS"`.
    name: &'static str,
    /// The message kind/direction this reflector handles, for logs, e.g. `"query"`.
    kind: &'static str,
    /// The UDP source port to emit from (a protocol's well-known port; `dst` carries the dest port).
    src_port: u16,
    ttl: u8,
    classify: fn(&[u8]) -> Verdict,
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
        }
    }
}

impl PacketHandler for SimpleReflector {
    fn on_packet(
        &mut self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) {
        match (self.classify)(packet.payload) {
            Verdict::Reflect => {
                // A family the egress can't currently source is a quiet drop (transient address
                // loss), so send_udp_group's error stays a genuine failure.
                if !egress_sources(dispatcher, self.egress, packet.dest) {
                    log::debug!(
                        "{}: egress has no source for {} yet; dropping {} from {}",
                        self.name,
                        packet.dest,
                        self.kind,
                        packet.source
                    );
                    return;
                }
                match dispatcher.send_udp_group(
                    self.egress,
                    packet.dest,
                    self.src_port,
                    self.ttl,
                    packet.payload,
                ) {
                    Ok(()) => log::debug!(
                        "reflected {} {} from {} to {}",
                        self.name,
                        self.kind,
                        packet.source,
                        packet.dest
                    ),
                    Err(e) => log::warn!(
                        "{}: cannot reflect {} from {} to {}: {e}",
                        self.name,
                        self.kind,
                        packet.source,
                        packet.dest
                    ),
                }
            }
            Verdict::Skip => {}
            Verdict::Junk => log::debug!(
                "{}: dropping unrecognized payload ({} B) to {} from {}",
                self.name,
                packet.payload.len(),
                packet.dest,
                packet.source
            ),
        }
    }
}
