//! The SSDP advertisement direction: reflect `NOTIFY` announcements target → source.

use crate::dispatch::{CaptureKey, PacketDispatcher, PacketHandler};
use crate::net::packet::Packet;
use crate::net::ssdp::{SSDP_PORT, SSDP_TTL, SsdpKind, classify};
use crate::reactor::Reactor;
use crate::reflector::{ReplyRewrite, egress_sources};

use super::DialRewrite;

/// Reflects SSDP advertisements (`NOTIFY`) target → source, onto `egress`, to the message's own
/// destination — the dispatcher's filter pins that to the group. Searches (`M-SEARCH`) flow the other
/// way through the shared `SearchReflector`, so this handler only ever reflects advertisements.
pub(super) struct SsdpAdvertisementReflector {
    egress: CaptureKey,
    /// DIAL `LOCATION` rewriting; `None` leaves advertisements verbatim.
    dial: Option<DialRewrite>,
}

impl SsdpAdvertisementReflector {
    /// A reflector re-emitting advertisements onto `egress` (the source), with optional DIAL rewriting.
    pub(super) fn new(egress: CaptureKey, dial: Option<DialRewrite>) -> Self {
        Self { egress, dial }
    }
}

impl PacketHandler for SsdpAdvertisementReflector {
    fn on_packet(
        &mut self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        reactor: &mut Reactor,
    ) {
        match classify(packet.payload) {
            Some(SsdpKind::Advertisement) => {
                // A family the egress can't currently source is a quiet drop (transient address
                // loss), so send_udp_group's error stays a genuine failure.
                if !egress_sources(dispatcher, self.egress, packet.dest) {
                    log::debug!(
                        "SSDP: egress has no source for {} yet; dropping advertisement from {}",
                        packet.dest,
                        packet.source
                    );
                    return;
                }
                let payload = match self.dial.as_mut() {
                    Some(dial) => dial.rewrite(packet.payload, self.egress, dispatcher, reactor),
                    None => packet.payload,
                };
                match dispatcher.send_udp_group(
                    self.egress,
                    packet.dest,
                    SSDP_PORT,
                    SSDP_TTL,
                    payload,
                ) {
                    Ok(()) => log::debug!(
                        "reflected SSDP advertisement from {} to {}",
                        packet.source,
                        packet.dest
                    ),
                    Err(e) => log::warn!(
                        "SSDP: cannot reflect from {} to {}: {e}",
                        packet.source,
                        packet.dest
                    ),
                }
            }
            // Searches flow source → target through the search reflector, not this direction.
            Some(SsdpKind::Search) => {}
            // Non-SSDP payload on the group: anomalous but harmless, drop quietly.
            None => log::debug!(
                "SSDP: dropping non-SSDP payload ({} B) to {} from {}",
                packet.payload.len(),
                packet.dest,
                packet.source
            ),
        }
    }
}
