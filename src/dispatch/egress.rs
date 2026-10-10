//! The egress path: assembling a UDP datagram for an interface and injecting it through one
//! reused frame buffer, as IP fragments past the MTU, each distinct datagram once per routed
//! packet.

use std::hash::{BuildHasher, DefaultHasher, Hash, Hasher, RandomState};
use std::io;
use std::net::{IpAddr, SocketAddr};

use crate::capture::Capture;
use crate::interface::InterfaceAddresses;
use crate::logging::{WARN_WINDOW, log_rate};
use crate::net::MAX_MTU;
use crate::net::frame::UdpFrames;
use crate::net::mac::MacAddr;

use super::CaptureKey;
use super::datagram::{DatagramSource, build_udp, ethernet_dst};
use super::interface_table::InterfaceTable;

/// For an interface whose MTU is unreadable: IPv6's minimum link MTU.
const FALLBACK_MTU: usize = 1280;

/// The L2 destination is separate: derived from `dst` for a group send, given for a unicast one.
#[derive(Clone, Copy, Hash)]
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
    /// The IP identification of the next datagram.
    next_id: u32,
}

impl Egress {
    pub(super) fn new() -> Self {
        // A random start, so a restart doesn't reuse identifications a receiver may still hold
        // fragments under. std keys `RandomState` from the OS.
        let seed = RandomState::new().hash_one(());
        Self {
            scratch: vec![0u8; crate::net::MAX_FRAME_LEN].into_boxed_slice(),
            packet: 0,
            routing: false,
            next_id: u32::try_from(seed >> 32).expect("the high half of a u64 fits a u32"),
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
    /// A send failure, or a datagram that can't be built from the egress's current state.
    pub(super) fn send_udp(
        &mut self,
        table: &mut InterfaceTable,
        egress: CaptureKey,
        dst_mac: MacAddr,
        datagram: Datagram<'_>,
    ) -> io::Result<()> {
        let digest = digest(dst_mac, datagram);
        if self.already_sent(table, egress, digest) {
            return Ok(());
        }
        if let Some(frames) = self.plan(table, egress, dst_mac, datagram)? {
            self.transmit(table, egress, &frames, digest)?;
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
        // No neighbour resolution: each copy travels in a broadcast frame and only the addressed
        // host keeps it.
        let dst_mac = MacAddr::broadcast();
        let mut delivered = false;
        let mut failure = None;
        let dst = datagram.dst;
        for &peer in peers.iter().filter(|peer| peer.is_ipv4() == dst.is_ipv4()) {
            let copy = Datagram {
                dst: SocketAddr::new(peer, dst.port()),
                ..datagram
            };
            let digest = digest(dst_mac, copy);
            if self.already_sent(table, egress, digest) {
                delivered = true;
                continue;
            }
            let Some(frames) = self.plan(table, egress, dst_mac, copy)? else {
                return Ok(());
            };
            match self.transmit(table, egress, &frames, digest) {
                Ok(()) => delivered = true,
                Err(e) => {
                    log_rate!(
                        log::Level::Warn,
                        WARN_WINDOW,
                        "{}: cannot send to peer {peer}: {e}",
                        table.capture_name(egress)
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

    /// A datagram equal to one already sent for this packet: two entries whose legs coincide
    /// (per-device entries on one pair) both relay it.
    fn already_sent(&self, table: &InterfaceTable, egress: CaptureKey, digest: u64) -> bool {
        let sent = self.routing && table.was_sent(egress, self.packet, digest);
        if sent {
            log::trace!("egress {egress:?}: an equal datagram already went out for this packet");
        }
        sent
    }

    /// `None` (logged): the egress is unknown or taken out for its drain. The latter needs
    /// `egress == ingress`, which no reflector configures (A -> B, never A -> A).
    fn plan<'a>(
        &mut self,
        table: &InterfaceTable,
        egress: CaptureKey,
        dst_mac: MacAddr,
        datagram: Datagram<'a>,
    ) -> io::Result<Option<UdpFrames<'a>>> {
        let (Some(addrs), Some(link)) = (
            table.egress_addrs(egress).copied(),
            table.capture(egress).map(Capture::link_type),
        ) else {
            log::warn!("egress {egress:?} unavailable (drained or unknown); datagram dropped");
            return Ok(None);
        };
        // A parked or unbound interface's capture can still be attached to some interface.
        if table.ifindex_of(egress).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("interface {} is not bound", table.capture_name(egress)),
            ));
        }
        let id = self.next_id;
        self.next_id = id.wrapping_add(1);
        build_udp(
            &addrs,
            link,
            datagram.dst,
            dst_mac,
            datagram.source,
            datagram.ttl,
            id,
            datagram.payload,
            frame_mtu(table.mtu_of(egress)),
        )
        .map(Some)
        .map_err(io::Error::other)
    }

    /// Recorded only once every frame is out, so a failed send leaves the second entry to try.
    fn transmit(
        &mut self,
        table: &mut InterfaceTable,
        egress: CaptureKey,
        frames: &UdpFrames<'_>,
        digest: u64,
    ) -> io::Result<()> {
        for index in 0..frames.count() {
            let len = frames
                .write(index, &mut self.scratch)
                .map_err(io::Error::other)?;
            send(table, egress, &self.scratch[..len])?;
        }
        if self.routing {
            table.record_sent(egress, self.packet, digest);
        }
        Ok(())
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

/// Everything a datagram's frames are built from on one egress, for the per-packet dedupe: the
/// frames themselves differ in their identification.
fn digest(dst_mac: MacAddr, datagram: Datagram<'_>) -> u64 {
    let mut hasher = DefaultHasher::new();
    (dst_mac, datagram).hash(&mut hasher);
    hasher.finish()
}

fn frame_mtu(mtu: Option<u32>) -> usize {
    mtu.map_or(FALLBACK_MTU, |mtu| usize::try_from(mtu).unwrap_or(MAX_MTU))
        .min(MAX_MTU)
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
