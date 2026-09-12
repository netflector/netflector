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

/// The L2 destination is separate: derived from `dst` for a group send, given for a unicast one.
#[derive(Clone, Copy)]
pub(super) struct Datagram<'a> {
    pub(super) dst: SocketAddr,
    pub(super) source: DatagramSource,
    pub(super) ttl: u8,
    pub(super) payload: &'a [u8],
}

pub(super) struct Egress {
    scratch: Box<[u8]>,
    /// The number of the packet being routed, from 1.
    packet: u64,
    /// A send outside routing (a timer, a session) is never a duplicate.
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

    pub(super) fn begin_packet(&mut self) {
        self.packet += 1;
        self.routing = true;
    }

    pub(super) fn end_packet(&mut self) {
        self.routing = false;
    }

    /// # Errors
    /// A send failure, or a frame that can't be built from the egress's current state.
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

    /// # Errors
    /// As [`send_udp`](Self::send_udp), plus a unicast `dst`, whose group MAC can't be derived.
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

    /// One unicast copy per peer of `dst`'s family, at its port; a peer already sent to for this
    /// packet is skipped.
    ///
    /// # Errors
    /// As [`send_udp`](Self::send_udp), only when no copy went out.
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
            // No neighbour resolution: the copy travels in a broadcast frame and only the
            // addressed host keeps it.
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

    /// `None` (logged): the egress is unknown or taken out for its drain. The latter needs
    /// `egress == ingress`, which no reflector configures (A -> B, never A -> A).
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

    /// Skip a frame equal to one already sent for this packet: two entries whose legs coincide
    /// (per-device entries on one pair) both relay it. Recorded only once sent, so a failed send
    /// leaves the second to try.
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

/// A drained or unknown egress is a logged drop, not an error.
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

fn egress_name(table: &InterfaceTable, egress: CaptureKey) -> &str {
    table
        .interface_of(egress)
        .and_then(|interface| table.interface_name(interface))
        .unwrap_or("?")
}

/// Re-word `EMSGSIZE` to name the frame, the interface and its MTU; the bare "Message too long"
/// names none.
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
