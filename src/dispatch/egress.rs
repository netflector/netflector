//! The egress path: assembling a UDP datagram for an interface into one reused frame buffer and
//! injecting it, each distinct frame once per routed packet.

use std::io;
use std::net::{IpAddr, SocketAddr};

use crate::capture::Capture;
use crate::interface::InterfaceAddresses;
use crate::logging::{WARN_WINDOW, log_rate};
use crate::net::mac::MacAddr;

use super::CaptureKey;
use super::datagram::{DatagramSource, build_udp, ethernet_dst};
use super::interface_table::InterfaceTable;

/// A UDP datagram to inject: its destination, IP source, TTL and payload. The L2 destination is
/// separate, since it is derived from `dst` for a group send and given for a unicast one.
#[derive(Clone, Copy)]
pub(super) struct Datagram<'a> {
    pub(super) dst: SocketAddr,
    pub(super) source: DatagramSource,
    pub(super) ttl: u8,
    pub(super) payload: &'a [u8],
}

/// The frame-build scratch and the duplicate-send scope of the packet being routed. One scratch
/// serves every reflector: the single-threaded loop runs one send at a time.
pub(super) struct Egress {
    scratch: Box<[u8]>,
    /// The number of the packet being routed, from 1.
    packet: u64,
    /// Whether a packet is being routed; a send outside routing (a timer, a session) is never a
    /// duplicate of a packet's re-emit.
    routing: bool,
}

impl Egress {
    pub(super) fn new() -> Self {
        Self {
            scratch: vec![0u8; crate::net::MAX_FRAME_LEN].into_boxed_slice(),
            packet: 0,
            routing: false,
        }
    }

    /// Open the duplicate-send scope of the next routed packet.
    pub(super) fn begin_packet(&mut self) {
        self.packet += 1;
        self.routing = true;
    }

    pub(super) fn end_packet(&mut self) {
        self.routing = false;
    }

    /// Build `datagram` with `dst_mac` as the L2 destination and inject it on `egress`; the link
    /// framing follows the egress's link type. An unknown or draining egress is a logged drop.
    ///
    /// # Errors
    /// A send failure, or a frame that can't be built from the egress's current state: no source
    /// address/MAC for the datagram, a source of the other family, or a payload that overflows
    /// the scratch or the datagram length fields.
    pub(super) fn send_udp(
        &mut self,
        table: &mut InterfaceTable,
        egress: CaptureKey,
        dst_mac: MacAddr,
        datagram: Datagram<'_>,
    ) -> io::Result<()> {
        if let Some(len) = self.build_frame(table, egress, dst_mac, datagram)? {
            self.send_built(table, egress, len)?;
        }
        Ok(())
    }

    /// Inject a broadcast/multicast `datagram` on `egress`, deriving the L2 destination from its
    /// address class. A unicast destination has no derivable group MAC and is a
    /// [`DatagramError::UnicastDestination`](super::datagram::DatagramError::UnicastDestination).
    ///
    /// # Errors
    /// As [`send_udp`](Self::send_udp), plus the unicast rejection.
    pub(super) fn send_udp_group(
        &mut self,
        table: &mut InterfaceTable,
        egress: CaptureKey,
        datagram: Datagram<'_>,
    ) -> io::Result<()> {
        let dst_mac = ethernet_dst(
            datagram.dst.ip(),
            table
                .egress_addrs(egress)
                .and_then(InterfaceAddresses::v4_directed_broadcast),
        )
        .map_err(io::Error::other)?;
        self.send_udp(table, egress, dst_mac, datagram)
    }

    /// Deliver a group or broadcast `datagram` to `peers` instead: one unicast copy per peer of
    /// its family, at its port. Each copy is checked against the packet's earlier sends on its
    /// own, so two entries whose lists share a peer deliver to it once.
    ///
    /// # Errors
    /// As [`send_udp`](Self::send_udp) when no copy went out at all. A peer the link cannot reach
    /// (a `WireGuard` peer without an endpoint) costs only its own copy, logged.
    pub(super) fn send_udp_to_peers(
        &mut self,
        table: &mut InterfaceTable,
        egress: CaptureKey,
        peers: &[IpAddr],
        datagram: Datagram<'_>,
    ) -> io::Result<()> {
        let mut delivered = false;
        let mut failure = None;
        let dst = datagram.dst;
        for &peer in peers.iter().filter(|peer| peer.is_ipv4() == dst.is_ipv4()) {
            // Nothing here resolves neighbours: on a link with MACs the copy travels in a
            // broadcast frame, and only the addressed host keeps it.
            let copy = Datagram {
                dst: SocketAddr::new(peer, dst.port()),
                ..datagram
            };
            let Some(len) = self.build_frame(table, egress, MacAddr::broadcast(), copy)? else {
                return Ok(());
            };
            match self.send_built(table, egress, len) {
                Ok(_) => delivered = true,
                Err(e) => {
                    log_rate!(
                        log::Level::Warn,
                        WARN_WINDOW,
                        "{}: cannot send to peer {peer}: {e}",
                        egress_name(table, egress)
                    );
                    failure = Some(e);
                }
            }
        }
        match failure {
            Some(e) if !delivered => Err(e),
            _ => Ok(()),
        }
    }

    /// Assemble `datagram` for `egress` into the scratch. `None` (logged) when the egress is
    /// unknown or taken out for its drain.
    fn build_frame(
        &mut self,
        table: &InterfaceTable,
        egress: CaptureKey,
        dst_mac: MacAddr,
        datagram: Datagram<'_>,
    ) -> io::Result<Option<usize>> {
        let (Some(addrs), Some(link)) = (
            table.egress_addrs(egress).copied(),
            table.capture(egress).map(Capture::link_type),
        ) else {
            log::warn!("egress {egress:?} unavailable (drained or unknown); datagram dropped");
            return Ok(None);
        };
        build_udp(
            &addrs,
            link,
            datagram.dst,
            dst_mac,
            datagram.source,
            datagram.ttl,
            datagram.payload,
            &mut self.scratch,
        )
        .map(Some)
        .map_err(io::Error::other)
    }

    /// Send the frame in the scratch on `egress`, unless an equal one already went out there for
    /// the packet being routed: two entries whose legs coincide (per-device entries on one pair,
    /// whose query legs carry no MAC filter) both relay a packet, and the second's frame equals
    /// the first's. Noted only once sent, so a failed send leaves the second to try. Returns
    /// whether the frame went out.
    fn send_built(
        &mut self,
        table: &mut InterfaceTable,
        egress: CaptureKey,
        len: usize,
    ) -> io::Result<bool> {
        let frame = &self.scratch[..len];
        if self.routing && table.was_sent(egress, self.packet, frame) {
            log::trace!("egress {egress:?}: an equal frame already went out for this packet");
            return Ok(false);
        }
        send(table, egress, frame)?;
        if self.routing {
            table.record_sent(egress, self.packet, frame);
        }
        Ok(true)
    }
}

/// Inject `frame` on the capture `egress` addresses. A key resolving to a drained (taken-out) or
/// out-of-range capture is a logged drop, not an error.
pub(super) fn send(table: &InterfaceTable, egress: CaptureKey, frame: &[u8]) -> io::Result<()> {
    if let Some(capture) = table.capture(egress) {
        capture
            .send(frame)
            .map_err(|e| oversize_context(e, capture.if_name(), frame.len(), table.mtu_of(egress)))
    } else {
        log::warn!("egress {egress:?} unavailable (drained or unknown); frame dropped");
        Ok(())
    }
}

/// The name of the interface behind `egress`, for a message; `?` for an unknown key.
fn egress_name(table: &InterfaceTable, egress: CaptureKey) -> &str {
    table
        .interface_of(egress)
        .and_then(|interface| table.interface_name(interface))
        .unwrap_or("?")
}

/// Re-word an `EMSGSIZE` send failure to name the frame, the interface, and its MTU (as of the
/// interface's last resolution); the bare "Message too long" names none of them. Any other error
/// passes through.
fn oversize_context(e: io::Error, if_name: &str, frame_len: usize, mtu: Option<u32>) -> io::Error {
    if e.raw_os_error() != Some(libc::EMSGSIZE) {
        return e;
    }
    let mtu = mtu.map_or_else(String::new, |mtu| format!(" (MTU {mtu})"));
    io::Error::new(
        e.kind(),
        format!("a frame of {frame_len} bytes exceeds what {if_name}{mtu} can carry"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversize_context_rewords_only_emsgsize() {
        // The reworded message is the feature: it must name the frame length, the interface, and
        // the MTU when known.
        let e = oversize_context(
            io::Error::from_raw_os_error(libc::EMSGSIZE),
            "vxlan0",
            1500,
            Some(1370),
        );
        let text = e.to_string();
        assert!(
            text.contains("1500") && text.contains("vxlan0") && text.contains("1370"),
            "{text}"
        );
        // The custom message costs the errno representation (std's `io::Error` carries one or the
        // other, never both). Deliberate: nothing matches on EMSGSIZE downstream, and the message
        // is the only surface an operator sees.
        assert_eq!(e.raw_os_error(), None);
        // Any other error passes through untouched: its message is the plain strerror text, and
        // it keeps its errno (rewording builds a custom error, whose `raw_os_error` is `None`).
        let other = oversize_context(io::Error::from_raw_os_error(libc::ENETDOWN), "x0", 9, None);
        assert_eq!(
            other.to_string(),
            io::Error::from_raw_os_error(libc::ENETDOWN).to_string()
        );
        assert_eq!(other.raw_os_error(), Some(libc::ENETDOWN));
    }
}
