//! Parse a captured frame into a [`Packet`], or a [`Fragment`] of one: link header, then IP and
//! UDP, borrowing the payload from the capture buffer. The kernel filter already restricts capture
//! to IP/UDP; the validation here is defense in depth, so a malformed frame is a [`ParseError`] to
//! log and skip.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use thiserror::Error;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
use super::DLT_NULL_HEADER_SIZE;
use super::checksum;
use super::mac::MacAddr;
use super::{
    ETHERNET_HEADER_SIZE, FRAGMENT_UNIT, IP_PROTO_UDP, IPV4_HEADER_SIZE, IPV6_FRAGMENT_HEADER_SIZE,
    IPV6_HEADER_SIZE, IPV6_NEXT_FRAGMENT, LinkType, UDP_HEADER_SIZE,
};

/// A parsed UDP datagram, its payload borrowed from the capture buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Packet<'a> {
    pub(crate) source: SocketAddr,
    pub(crate) dest: SocketAddr,
    /// IPv4 TTL or IPv6 hop limit, as captured.
    pub(crate) ttl: u8,
    /// `None` on a link without MACs (`DLT_NULL`, raw IP).
    pub(crate) dst_mac: Option<MacAddr>,
    pub(crate) src_mac: Option<MacAddr>,
    pub(crate) payload: &'a [u8],
}

impl<'a> Packet<'a> {
    /// A datagram put back together from fragments: `datagram` is its UDP header and payload,
    /// `first` the header of its fragment at offset 0. The UDP length must span `datagram` and
    /// the checksum must hold, since reassembly is where a datagram can come out wrong.
    ///
    /// # Errors
    /// A length or checksum that doesn't match `datagram`.
    pub(crate) fn reassembled(
        first: &FragmentHeader,
        datagram: &'a [u8],
    ) -> Result<Self, ParseError> {
        let (src_port, dst_port, payload) = parse_udp(datagram)?;
        let (&header, _) = datagram.split_first_chunk().ok_or(ParseError::Truncated)?;
        if UDP_HEADER_SIZE + payload.len() != datagram.len() {
            return Err(ParseError::BadLength);
        }
        let stored = u16::from_be_bytes([header[6], header[7]]);
        let valid = match (first.source, first.dest) {
            // IPv4 lets a sender leave the checksum out (RFC 768); IPv6 requires it (RFC 8200).
            (IpAddr::V4(_), IpAddr::V4(_)) if stored == 0 => true,
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                checksum::udp_v4(src, dst, header, payload) == stored
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                checksum::udp_v6(src, dst, header, payload) == stored
            }
            _ => false,
        };
        if !valid {
            return Err(ParseError::BadChecksum);
        }
        Ok(Packet {
            source: SocketAddr::new(first.source, src_port),
            dest: SocketAddr::new(first.dest, dst_port),
            ttl: first.ttl,
            dst_mac: first.dst_mac,
            src_mac: first.src_mac,
            payload,
        })
    }

    /// On a link with MACs the all-ones destination is decisive: it carries a directed broadcast
    /// of any subnet on the link as well as the limited one. Without MACs only the address is left:
    /// the limited broadcast, or `directed_broadcast`, the link's own subnet's.
    pub(crate) fn is_broadcast(&self, directed_broadcast: Option<Ipv4Addr>) -> bool {
        match (self.dest.ip(), self.dst_mac) {
            (IpAddr::V4(v4), Some(mac)) => !v4.is_multicast() && mac == MacAddr::broadcast(),
            (IpAddr::V4(v4), None) => v4.is_broadcast() || Some(v4) == directed_broadcast,
            (IpAddr::V6(_), _) => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FragmentHeader {
    pub(crate) source: IpAddr,
    pub(crate) dest: IpAddr,
    /// IPv4's 16-bit identification, widened, or IPv6's.
    pub(crate) id: u32,
    /// In bytes, into the datagram's UDP header and payload.
    pub(crate) offset: usize,
    /// Another fragment follows.
    pub(crate) more: bool,
    pub(crate) ttl: u8,
    pub(crate) dst_mac: Option<MacAddr>,
    pub(crate) src_mac: Option<MacAddr>,
}

/// One IP fragment of a UDP datagram, its data borrowed from the capture buffer. Only the first,
/// at offset 0, holds the UDP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Fragment<'a> {
    pub(crate) header: FragmentHeader,
    pub(crate) data: &'a [u8],
}

impl Fragment<'_> {
    /// The datagram's addressing as a payload-less [`Packet`], all a routing filter reads. `None`
    /// past the first fragment, or for a first one too short to hold the UDP header.
    pub(crate) fn headers(&self) -> Option<Packet<'static>> {
        if self.header.offset != 0 {
            return None;
        }
        let udp = self.data.first_chunk::<UDP_HEADER_SIZE>()?;
        Some(Packet {
            source: SocketAddr::new(self.header.source, u16::from_be_bytes([udp[0], udp[1]])),
            dest: SocketAddr::new(self.header.dest, u16::from_be_bytes([udp[2], udp[3]])),
            ttl: self.header.ttl,
            dst_mac: self.header.dst_mac,
            src_mac: self.header.src_mac,
            payload: &[],
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Parsed<'a> {
    Datagram(Packet<'a>),
    Fragment(Fragment<'a>),
}

impl<'a> Parsed<'a> {
    /// # Errors
    /// The frame is truncated, not IPv4/IPv6 UDP, or carries an inconsistent length field.
    pub(crate) fn parse(link_type: LinkType, frame: &'a [u8]) -> Result<Self, ParseError> {
        let link = parse_link_header(link_type, frame)?;
        // The version nibble, not the ethertype or `DLT_NULL` family, governs the header layout.
        let &first = link.l3.first().ok_or(ParseError::Truncated)?;
        match first >> 4 {
            4 => parse_ipv4(link),
            6 => parse_ipv6(link),
            version => Err(ParseError::BadIpVersion(version)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum ParseError {
    #[error("frame is truncated")]
    Truncated,
    #[error("unsupported IP version {0}")]
    BadIpVersion(u8),
    #[error("not a UDP datagram (IP protocol {0})")]
    NotUdp(u8),
    #[error("inconsistent length field")]
    BadLength,
    #[error("UDP checksum mismatch")]
    BadChecksum,
    #[error("frame tagged for VLAN {0}")]
    VlanTagged(u16),
}

#[derive(Clone, Copy)]
struct LinkHeader<'a> {
    dst_mac: Option<MacAddr>,
    src_mac: Option<MacAddr>,
    l3: &'a [u8],
}

fn parse_link_header(link_type: LinkType, frame: &[u8]) -> Result<LinkHeader<'_>, ParseError> {
    match link_type {
        LinkType::Ethernet => {
            let l3 = ethernet_l3(frame)?;
            // `ethernet_l3` proved all 14 header bytes are present: the MAC slices can't panic.
            Ok(LinkHeader {
                dst_mac: Some(read_mac(&frame[0..6])?),
                src_mac: Some(read_mac(&frame[6..12])?),
                l3,
            })
        }
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        LinkType::DltNull => Ok(LinkHeader {
            dst_mac: None,
            src_mac: None,
            l3: frame
                .get(DLT_NULL_HEADER_SIZE..)
                .ok_or(ParseError::Truncated)?,
        }),
        #[cfg(target_os = "linux")]
        LinkType::RawIp => Ok(LinkHeader {
            dst_mac: None,
            src_mac: None,
            l3: frame,
        }),
    }
}

const ETHERTYPE_VLAN: u16 = 0x8100;
const VLAN_ID_MASK: u16 = 0x0fff;

/// The bytes past the Ethernet header. An 802.1Q tag with VLAN ID 0 carries only a priority: the
/// frame belongs to the untagged network, so the tag is skipped. A frame tagged for a VLAN is
/// refused.
fn ethernet_l3(frame: &[u8]) -> Result<&[u8], ParseError> {
    let (header, rest) = frame
        .split_at_checked(ETHERNET_HEADER_SIZE)
        .ok_or(ParseError::Truncated)?;
    if header[12..] != ETHERTYPE_VLAN.to_be_bytes() {
        return Ok(rest);
    }
    let ([tci_hi, tci_lo, _, _], l3) = rest.split_first_chunk().ok_or(ParseError::Truncated)?;
    match u16::from_be_bytes([*tci_hi, *tci_lo]) & VLAN_ID_MASK {
        0 => Ok(l3),
        vid => Err(ParseError::VlanTagged(vid)), // Cannot really happen due to BPF filter
    }
}

fn parse_ipv4(link: LinkHeader<'_>) -> Result<Parsed<'_>, ParseError> {
    let l3 = link.l3;
    if l3.len() < IPV4_HEADER_SIZE {
        return Err(ParseError::Truncated);
    }

    // IHL is in 32-bit words and covers the options.
    let header_len = usize::from(l3[0] & 0x0f) * 4;
    if header_len < IPV4_HEADER_SIZE || header_len > l3.len() {
        return Err(ParseError::BadLength);
    }

    if l3[9] != IP_PROTO_UDP {
        return Err(ParseError::NotUdp(l3[9]));
    }

    // Trust the total length over the captured slice: it trims trailing link padding (Ethernet
    // min-frame, capture slack).
    let total_len = usize::from(u16::from_be_bytes([l3[2], l3[3]]));
    if total_len < header_len || total_len > l3.len() {
        return Err(ParseError::BadLength);
    }

    let source = IpAddr::V4(ipv4_addr(&l3[12..16])?);
    let dest = IpAddr::V4(ipv4_addr(&l3[16..20])?);
    let ttl = l3[8];
    let body = &l3[header_len..total_len];
    // Bit 13 is More Fragments, bits 0-12 the offset; Don't Fragment (bit 14) is ignored.
    let flags_offset = u16::from_be_bytes([l3[6], l3[7]]);
    let offset = usize::from(flags_offset & 0x1fff) * FRAGMENT_UNIT;
    let more = flags_offset & 0x2000 != 0;
    if offset == 0 && !more {
        return datagram(link, source, dest, ttl, body);
    }
    Ok(Parsed::Fragment(Fragment {
        header: FragmentHeader {
            source,
            dest,
            id: u32::from(u16::from_be_bytes([l3[4], l3[5]])),
            offset,
            more,
            ttl,
            dst_mac: link.dst_mac,
            src_mac: link.src_mac,
        },
        data: body,
    }))
}

/// Of the extension headers only a Fragment header directly after the base header is read; any
/// other next header than UDP is rejected.
fn parse_ipv6(link: LinkHeader<'_>) -> Result<Parsed<'_>, ParseError> {
    let l3 = link.l3;
    if l3.len() < IPV6_HEADER_SIZE {
        return Err(ParseError::Truncated);
    }

    let payload_len = usize::from(u16::from_be_bytes([l3[4], l3[5]]));
    let total_len = IPV6_HEADER_SIZE + payload_len;
    if total_len > l3.len() {
        return Err(ParseError::BadLength);
    }

    let source = IpAddr::V6(ipv6_addr(&l3[8..24])?);
    let dest = IpAddr::V6(ipv6_addr(&l3[24..40])?);
    let hop_limit = l3[7];
    let body = &l3[IPV6_HEADER_SIZE..total_len];
    match l3[6] {
        IP_PROTO_UDP => datagram(link, source, dest, hop_limit, body),
        IPV6_NEXT_FRAGMENT => {
            let (fragment, data) = body
                .split_first_chunk::<IPV6_FRAGMENT_HEADER_SIZE>()
                .ok_or(ParseError::Truncated)?;
            if fragment[0] != IP_PROTO_UDP {
                return Err(ParseError::NotUdp(fragment[0]));
            }
            // The offset is the high 13 bits, More Fragments the lowest.
            let offset_more = u16::from_be_bytes([fragment[2], fragment[3]]);
            let offset = usize::from(offset_more >> 3) * FRAGMENT_UNIT;
            let more = offset_more & 1 != 0;
            // An atomic fragment (RFC 6946) is the whole datagram.
            if offset == 0 && !more {
                return datagram(link, source, dest, hop_limit, data);
            }
            Ok(Parsed::Fragment(Fragment {
                header: FragmentHeader {
                    source,
                    dest,
                    id: u32::from_be_bytes([fragment[4], fragment[5], fragment[6], fragment[7]]),
                    offset,
                    more,
                    ttl: hop_limit,
                    dst_mac: link.dst_mac,
                    src_mac: link.src_mac,
                },
                data,
            }))
        }
        next => Err(ParseError::NotUdp(next)),
    }
}

fn datagram<'a>(
    link: LinkHeader<'a>,
    source: IpAddr,
    dest: IpAddr,
    ttl: u8,
    l4: &'a [u8],
) -> Result<Parsed<'a>, ParseError> {
    let (src_port, dst_port, payload) = parse_udp(l4)?;
    Ok(Parsed::Datagram(Packet {
        source: SocketAddr::new(source, src_port),
        dest: SocketAddr::new(dest, dst_port),
        ttl,
        dst_mac: link.dst_mac,
        src_mac: link.src_mac,
        payload,
    }))
}

fn parse_udp(l4: &[u8]) -> Result<(u16, u16, &[u8]), ParseError> {
    if l4.len() < UDP_HEADER_SIZE {
        return Err(ParseError::Truncated);
    }
    let src_port = u16::from_be_bytes([l4[0], l4[1]]);
    let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
    let udp_len = usize::from(u16::from_be_bytes([l4[4], l4[5]]));
    if udp_len < UDP_HEADER_SIZE || udp_len > l4.len() {
        return Err(ParseError::BadLength);
    }
    Ok((src_port, dst_port, &l4[UDP_HEADER_SIZE..udp_len]))
}

fn ipv4_addr(bytes: &[u8]) -> Result<Ipv4Addr, ParseError> {
    <[u8; 4]>::try_from(bytes)
        .map(Ipv4Addr::from)
        .map_err(|_| ParseError::Truncated)
}

fn ipv6_addr(bytes: &[u8]) -> Result<Ipv6Addr, ParseError> {
    <[u8; 16]>::try_from(bytes)
        .map(Ipv6Addr::from)
        .map_err(|_| ParseError::Truncated)
}

fn read_mac(bytes: &[u8]) -> Result<MacAddr, ParseError> {
    <[u8; 6]>::try_from(bytes)
        .map(MacAddr::from)
        .map_err(|_| ParseError::Truncated)
}

#[cfg(test)]
mod tests {
    use std::net::{SocketAddrV4, SocketAddrV6};

    use super::*;
    use crate::net::frame::{LinkHeader as FrameLink, UdpFrames};
    use crate::net::mac::MacAddr;
    use crate::test_support::frame;

    impl<'a> Parsed<'a> {
        /// The whole datagram a test frame carries.
        pub(crate) fn datagram(self) -> Packet<'a> {
            match self {
                Parsed::Datagram(packet) => packet,
                Parsed::Fragment(fragment) => panic!("expected a whole datagram: {fragment:?}"),
            }
        }
    }

    // Round-trip: what the frame builder writes, the parser reads back. The two are
    // each other's inverse, so a single test exercises every header field.
    #[test]
    fn round_trips_ethernet_ipv4() {
        let src = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 10), 5353);
        let dst = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 20), 5354);
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let mut buf = [0u8; 64];
        // Distinct dst/src MACs so a swapped read would fail.
        let dst_mac = MacAddr::from([0x02, 0, 0, 0, 0, 0xaa]);
        let src_mac = MacAddr::from([0x02, 0, 0, 0, 0, 0xbb]);
        let n =
            frame::ethernet_ipv4_udp(dst_mac, src_mac, src, dst, 64, &payload, &mut buf).unwrap();

        let packet = Parsed::parse(LinkType::Ethernet, &buf[..n])
            .unwrap()
            .datagram();
        assert_eq!(packet.source, SocketAddr::V4(src));
        assert_eq!(packet.dest, SocketAddr::V4(dst));
        assert_eq!(packet.ttl, 64);
        assert_eq!(packet.dst_mac, Some(dst_mac));
        assert_eq!(packet.src_mac, Some(src_mac));
        assert_eq!(packet.payload, &payload);
    }

    #[test]
    fn round_trips_ethernet_ipv6() {
        let src = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5353, 0, 0);
        let dst = SocketAddrV6::new(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb), 5354, 0, 0);
        let payload = [0xaa, 0xbb, 0xcc];
        let mut buf = [0u8; 80];
        let dst_mac = MacAddr::from([0x33, 0x33, 0, 0, 0, 0xfb]);
        let src_mac = MacAddr::from([0x02, 0, 0, 0, 0, 0xbb]);
        let n =
            frame::ethernet_ipv6_udp(dst_mac, src_mac, src, dst, 255, &payload, &mut buf).unwrap();

        let packet = Parsed::parse(LinkType::Ethernet, &buf[..n])
            .unwrap()
            .datagram();
        assert_eq!(packet.source, SocketAddr::V6(src));
        assert_eq!(packet.dest, SocketAddr::V6(dst));
        assert_eq!(packet.ttl, 255);
        assert_eq!(packet.dst_mac, Some(dst_mac));
        assert_eq!(packet.src_mac, Some(src_mac));
        assert_eq!(packet.payload, &payload);
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn round_trips_dlt_null_ipv4() {
        let src = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5353);
        let dst = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5354);
        let payload = [0x01, 0x02];
        let mut buf = [0u8; 64];
        let n = frame::dlt_null_ipv4_udp(src, dst, 64, &payload, &mut buf).unwrap();

        let packet = Parsed::parse(LinkType::DltNull, &buf[..n])
            .unwrap()
            .datagram();
        assert_eq!(packet.source, SocketAddr::V4(src));
        assert_eq!(packet.dest, SocketAddr::V4(dst));
        assert_eq!(packet.ttl, 64);
        // DLT_NULL has no L2 header, so no MACs to report.
        assert_eq!(packet.dst_mac, None);
        assert_eq!(packet.src_mac, None);
        assert_eq!(packet.payload, &payload);
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn round_trips_dlt_null_ipv6() {
        let src = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5353, 0, 0);
        let dst = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5354, 0, 0);
        let payload = [0x09];
        let mut buf = [0u8; 80];
        let n = frame::dlt_null_ipv6_udp(src, dst, 255, &payload, &mut buf).unwrap();

        let packet = Parsed::parse(LinkType::DltNull, &buf[..n])
            .unwrap()
            .datagram();
        assert_eq!(packet.source, SocketAddr::V6(src));
        assert_eq!(packet.dest, SocketAddr::V6(dst));
        assert_eq!(packet.ttl, 255);
        assert_eq!(packet.payload, &payload);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn round_trips_raw_ip_ipv4() {
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 10, 10, 2), 5353);
        let dst = SocketAddrV4::new(Ipv4Addr::new(10, 10, 10, 1), 5354);
        let payload = [0x01, 0x02];
        let mut buf = [0u8; 64];
        let n = frame::ipv4_udp(src, dst, 64, &payload, &mut buf).unwrap();

        let packet = Parsed::parse(LinkType::RawIp, &buf[..n])
            .unwrap()
            .datagram();
        assert_eq!(packet.source, SocketAddr::V4(src));
        assert_eq!(packet.dest, SocketAddr::V4(dst));
        assert_eq!(packet.ttl, 64);
        // No link header, so no MACs to report.
        assert_eq!(packet.dst_mac, None);
        assert_eq!(packet.src_mac, None);
        assert_eq!(packet.payload, &payload);
        assert_eq!(
            Parsed::parse(LinkType::RawIp, &[]),
            Err(ParseError::Truncated)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn round_trips_raw_ip_ipv6() {
        let src = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5353, 0, 0);
        let dst = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5354, 0, 0);
        let payload = [0x09];
        let mut buf = [0u8; 80];
        let n = frame::ipv6_udp(src, dst, 255, &payload, &mut buf).unwrap();

        let packet = Parsed::parse(LinkType::RawIp, &buf[..n])
            .unwrap()
            .datagram();
        assert_eq!(packet.source, SocketAddr::V6(src));
        assert_eq!(packet.dest, SocketAddr::V6(dst));
        assert_eq!(packet.ttl, 255);
        assert_eq!(packet.payload, &payload);
    }

    // A captured frame can carry trailing link padding (Ethernet min-frame, BPF slack)
    // past the datagram; the declared IP total length must trim it off the payload.
    #[test]
    fn trims_trailing_link_padding() {
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1);
        let dst = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 2);
        let payload = [0x11, 0x22, 0x33];
        let mut buf = [0u8; 64]; // zero-filled tail stands in for padding
        let mac = MacAddr::broadcast();
        let n = frame::ethernet_ipv4_udp(mac, mac, src, dst, 64, &payload, &mut buf).unwrap();

        let packet = Parsed::parse(LinkType::Ethernet, &buf[..n + 10])
            .unwrap()
            .datagram();
        assert_eq!(packet.payload, &payload);
    }

    // IPv4 options: a header longer than 20 bytes (IHL > 5) must be skipped to find L4.
    // The builder never emits options, so this frame is laid out by hand.
    #[test]
    fn parses_ipv4_with_options() {
        let mut frame = [0u8; 50]; // 14 Ethernet + 24 IPv4 (IHL 6) + 8 UDP + 4 payload
        frame[14] = 0x46; // version 4, IHL 6 (24-byte header, 4 option bytes)
        frame[16..18].copy_from_slice(&36u16.to_be_bytes()); // total length (IP + UDP + payload)
        frame[22] = 64; // ttl
        frame[23] = IP_PROTO_UDP;
        frame[26..30].copy_from_slice(&[10, 1, 2, 3]); // src IP
        frame[30..34].copy_from_slice(&[10, 4, 5, 6]); // dst IP
        // frame[34..38] are the 4 option bytes (left zero; the parser skips them).
        frame[38..40].copy_from_slice(&1111u16.to_be_bytes()); // src port
        frame[40..42].copy_from_slice(&2222u16.to_be_bytes()); // dst port
        frame[42..44].copy_from_slice(&12u16.to_be_bytes()); // UDP length
        frame[46..50].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // payload

        let packet = Parsed::parse(LinkType::Ethernet, &frame)
            .unwrap()
            .datagram();
        assert_eq!(packet.source, "10.1.2.3:1111".parse().unwrap());
        assert_eq!(packet.dest, "10.4.5.6:2222".parse().unwrap());
        assert_eq!(packet.ttl, 64);
        assert_eq!(packet.payload, &[0xde, 0xad, 0xbe, 0xef]);
    }

    /// Build a valid Ethernet IPv4 UDP frame into `buf`, returning its length. The
    /// rejection tests corrupt one field of this baseline.
    fn valid_ethernet_ipv4(buf: &mut [u8]) -> usize {
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1234);
        let dst = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 5678);
        let mac = MacAddr::broadcast();
        frame::ethernet_ipv4_udp(mac, mac, src, dst, 64, &[0xab; 4], buf).unwrap()
    }

    #[test]
    fn rejects_frame_shorter_than_link_header() {
        assert_eq!(
            Parsed::parse(LinkType::Ethernet, &[0u8; 10]),
            Err(ParseError::Truncated)
        );
    }

    #[test]
    fn rejects_truncated_ip_header() {
        // Ethernet header, then a valid IPv4 version nibble but only a few L3 bytes.
        let mut frame = [0u8; 18];
        frame[14] = 0x45;
        assert_eq!(
            Parsed::parse(LinkType::Ethernet, &frame),
            Err(ParseError::Truncated)
        );
    }

    #[test]
    fn rejects_unsupported_ip_version() {
        let mut buf = [0u8; 64];
        let n = valid_ethernet_ipv4(&mut buf);
        buf[14] = 0x55; // version 5
        assert_eq!(
            Parsed::parse(LinkType::Ethernet, &buf[..n]),
            Err(ParseError::BadIpVersion(5))
        );
    }

    fn written(frames: &UdpFrames) -> Vec<Vec<u8>> {
        (0..frames.count())
            .map(|index| {
                let mut frame = vec![0u8; 2048];
                let n = frames.write(index, &mut frame).unwrap();
                frame.truncate(n);
                frame
            })
            .collect()
    }

    fn fragment_of(frame: &[u8]) -> Fragment<'_> {
        match Parsed::parse(LinkType::Ethernet, frame).unwrap() {
            Parsed::Fragment(fragment) => fragment,
            Parsed::Datagram(packet) => panic!("expected a fragment: {packet:?}"),
        }
    }

    fn link() -> FrameLink {
        FrameLink::Ethernet {
            dst: MacAddr::from([0x02, 0, 0, 0, 0, 0xaa]),
            src: MacAddr::from([0x02, 0, 0, 0, 0, 0xbb]),
        }
    }

    #[test]
    fn parses_ipv4_fragments() {
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 3702);
        let dst = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 40000);
        let payload: Vec<u8> = (0..100).collect();
        // A 68-byte MTU leaves 48 bytes per fragment: 108 datagram bytes are 48 + 48 + 12.
        let frames = UdpFrames::ipv4(link(), src, dst, 64, 0xbeef, &payload, 68).unwrap();
        let written = written(&frames);
        let parsed: Vec<_> = written.iter().map(|frame| fragment_of(frame)).collect();
        assert_eq!(parsed.len(), 3);
        for (index, fragment) in parsed.iter().enumerate() {
            let header = fragment.header;
            assert_eq!(header.source, IpAddr::V4(*src.ip()));
            assert_eq!(header.dest, IpAddr::V4(*dst.ip()));
            assert_eq!(header.id, 0xbeef);
            assert_eq!(header.offset, index * 48);
            assert_eq!(header.more, index < 2);
            assert_eq!(header.ttl, 64);
            assert_eq!(
                header.src_mac,
                Some(MacAddr::from([0x02, 0, 0, 0, 0, 0xbb]))
            );
        }
        assert_eq!(parsed[0].data.len(), 48);
        assert_eq!(parsed[0].data[8..], payload[..40]);
        assert_eq!(parsed[2].data, &payload[88..]);
        // Only the first fragment knows the ports.
        let headers = parsed[0].headers().unwrap();
        assert_eq!(headers.source, SocketAddr::V4(src));
        assert_eq!(headers.dest, SocketAddr::V4(dst));
        assert_eq!(headers.payload, []);
        assert_eq!(parsed[1].headers(), None);
    }

    #[test]
    fn parses_ipv6_fragments() {
        let src = SocketAddrV6::new("fe80::1".parse().unwrap(), 3702, 0, 0);
        let dst = SocketAddrV6::new("fe80::2".parse().unwrap(), 40000, 0, 0);
        let payload: Vec<u8> = (0..100).collect();
        // 96 leaves 48 bytes per fragment behind the 40 + 8 header bytes.
        let frames = UdpFrames::ipv6(link(), src, dst, 255, 0x0102_0304, &payload, 96).unwrap();
        let written = written(&frames);
        let parsed: Vec<_> = written.iter().map(|frame| fragment_of(frame)).collect();
        assert_eq!(parsed.len(), 3);
        for (index, fragment) in parsed.iter().enumerate() {
            assert_eq!(fragment.header.id, 0x0102_0304);
            assert_eq!(fragment.header.offset, index * 48);
            assert_eq!(fragment.header.more, index < 2);
            assert_eq!(fragment.header.ttl, 255);
        }
        assert_eq!(parsed[2].data, &payload[88..]);
        assert_eq!(parsed[0].headers().unwrap().dest, SocketAddr::V6(dst));
    }

    /// A whole IPv6 frame with a Fragment header carrying `offset_more` spliced in after the base
    /// header, its next header set to `next`.
    fn with_fragment_header(offset_more: u16, next: u8) -> Vec<u8> {
        let mut buf = [0u8; 80];
        let n = valid_ethernet_ipv6(&mut buf);
        let l3 = ETHERNET_HEADER_SIZE;
        let mut frame = buf[..l3 + IPV6_HEADER_SIZE].to_vec();
        frame[l3 + 6] = IPV6_NEXT_FRAGMENT;
        let payload_len = u16::from_be_bytes([frame[l3 + 4], frame[l3 + 5]]) + 8;
        frame[l3 + 4..l3 + 6].copy_from_slice(&payload_len.to_be_bytes());
        let [hi, lo] = offset_more.to_be_bytes();
        frame.extend_from_slice(&[next, 0, hi, lo, 0, 0, 0, 7]);
        frame.extend_from_slice(&buf[l3 + IPV6_HEADER_SIZE..n]);
        frame
    }

    #[test]
    fn an_ipv6_atomic_fragment_is_the_whole_datagram() {
        let mut buf = [0u8; 80];
        let n = valid_ethernet_ipv6(&mut buf);
        let whole = Parsed::parse(LinkType::Ethernet, &buf[..n]).unwrap();
        let atomic = with_fragment_header(0, IP_PROTO_UDP);
        assert_eq!(Parsed::parse(LinkType::Ethernet, &atomic), Ok(whole));
    }

    #[test]
    fn rejects_an_ipv6_fragment_of_another_protocol() {
        let frame = with_fragment_header(1, 6);
        assert_eq!(
            Parsed::parse(LinkType::Ethernet, &frame),
            Err(ParseError::NotUdp(6))
        );
    }

    /// The UDP header and payload of a whole IPv4 datagram, and the header of its one fragment.
    fn reassembled_v4(payload: &[u8]) -> (Vec<u8>, FragmentHeader) {
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 3702);
        let dst = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 40000);
        let mut buf = vec![0u8; 2048];
        let n = UdpFrames::ipv4(link(), src, dst, 64, 1, payload, 1500)
            .unwrap()
            .write(0, &mut buf)
            .unwrap();
        let first = FragmentHeader {
            source: IpAddr::V4(*src.ip()),
            dest: IpAddr::V4(*dst.ip()),
            id: 1,
            offset: 0,
            more: true,
            ttl: 64,
            dst_mac: None,
            src_mac: None,
        };
        (
            buf[ETHERNET_HEADER_SIZE + IPV4_HEADER_SIZE..n].to_vec(),
            first,
        )
    }

    #[test]
    fn a_reassembled_datagram_must_hold_its_length_and_checksum() {
        let payload = [0x5a; 40];
        let (datagram, first) = reassembled_v4(&payload);
        let packet = Packet::reassembled(&first, &datagram).unwrap();
        assert_eq!(packet.source, "10.0.0.1:3702".parse().unwrap());
        assert_eq!(packet.dest, "10.0.0.2:40000".parse().unwrap());
        assert_eq!(packet.payload, payload);

        let mut corrupt = datagram.clone();
        corrupt[20] ^= 1;
        assert_eq!(
            Packet::reassembled(&first, &corrupt),
            Err(ParseError::BadChecksum)
        );
        // A zero checksum means none: IPv4 accepts that, IPv6 does not.
        let mut unchecked = datagram.clone();
        unchecked[6..8].fill(0);
        assert!(Packet::reassembled(&first, &unchecked).is_ok());
        let first_v6 = FragmentHeader {
            source: IpAddr::V6(Ipv6Addr::LOCALHOST),
            dest: IpAddr::V6(Ipv6Addr::LOCALHOST),
            ..first
        };
        assert_eq!(
            Packet::reassembled(&first_v6, &unchecked),
            Err(ParseError::BadChecksum)
        );
        // A UDP length short of the reassembled bytes, or past them.
        let mut longer = datagram.clone();
        longer.extend_from_slice(&[0; 8]);
        assert_eq!(
            Packet::reassembled(&first, &longer),
            Err(ParseError::BadLength)
        );
        assert_eq!(
            Packet::reassembled(&first, &datagram[..datagram.len() - 1]),
            Err(ParseError::BadLength)
        );
    }

    #[test]
    fn rejects_non_udp() {
        let mut buf = [0u8; 64];
        let n = valid_ethernet_ipv4(&mut buf);
        buf[23] = 6; // IP protocol TCP
        assert_eq!(
            Parsed::parse(LinkType::Ethernet, &buf[..n]),
            Err(ParseError::NotUdp(6))
        );
    }

    #[test]
    fn rejects_oversized_total_length() {
        let mut buf = [0u8; 64];
        let n = valid_ethernet_ipv4(&mut buf);
        buf[16..18].copy_from_slice(&u16::MAX.to_be_bytes()); // total length past the frame
        assert_eq!(
            Parsed::parse(LinkType::Ethernet, &buf[..n]),
            Err(ParseError::BadLength)
        );
    }

    #[test]
    fn rejects_oversized_udp_length() {
        let mut buf = [0u8; 64];
        let n = valid_ethernet_ipv4(&mut buf);
        // UDP length field sits at the start of L4 + 4: Ethernet(14) + IPv4(20) + 4.
        buf[38..40].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            Parsed::parse(LinkType::Ethernet, &buf[..n]),
            Err(ParseError::BadLength)
        );
    }

    #[test]
    fn rejects_ipv4_header_length_below_minimum() {
        let mut buf = [0u8; 64];
        let n = valid_ethernet_ipv4(&mut buf);
        buf[14] = 0x44; // version 4, IHL 4: a 16-byte header, below the 20-byte minimum
        assert_eq!(
            Parsed::parse(LinkType::Ethernet, &buf[..n]),
            Err(ParseError::BadLength)
        );
    }

    // Don't-Fragment (0x4000) alone is a whole datagram, not a fragment.
    #[test]
    fn accepts_dont_fragment_flag() {
        let mut buf = [0u8; 64];
        let n = valid_ethernet_ipv4(&mut buf);
        buf[20] = 0x40; // DF set, MF and fragment offset clear
        buf[21] = 0x00;
        let packet = Parsed::parse(LinkType::Ethernet, &buf[..n])
            .unwrap()
            .datagram();
        assert_eq!(packet.payload, &[0xab; 4]);
    }

    #[test]
    fn accepts_empty_udp_payload() {
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1);
        let dst = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 2);
        let mac = MacAddr::broadcast();
        let mut buf = [0u8; 64];
        let n = frame::ethernet_ipv4_udp(mac, mac, src, dst, 64, &[], &mut buf).unwrap();
        let packet = Parsed::parse(LinkType::Ethernet, &buf[..n])
            .unwrap()
            .datagram();
        assert_eq!(packet.payload, []);
    }

    /// Build a valid Ethernet IPv6 UDP frame into `buf`, returning its length. The
    /// IPv6 counterpart of [`valid_ethernet_ipv4`] for the rejection tests.
    fn valid_ethernet_ipv6(buf: &mut [u8]) -> usize {
        let src = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1234, 0, 0);
        let dst = SocketAddrV6::new(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb), 5678, 0, 0);
        let mac = MacAddr::broadcast();
        frame::ethernet_ipv6_udp(mac, mac, src, dst, 64, &[0xab; 4], buf).unwrap()
    }

    #[test]
    fn rejects_truncated_ipv6_header() {
        // Ethernet header, then a valid IPv6 version nibble but fewer than 40 L3 bytes.
        let mut frame = [0u8; 30];
        frame[14] = 0x60;
        assert_eq!(
            Parsed::parse(LinkType::Ethernet, &frame),
            Err(ParseError::Truncated)
        );
    }

    #[test]
    fn rejects_ipv6_non_udp() {
        let mut buf = [0u8; 80];
        let n = valid_ethernet_ipv6(&mut buf);
        buf[20] = 6; // IPv6 next header (L3 offset 6) -> TCP
        assert_eq!(
            Parsed::parse(LinkType::Ethernet, &buf[..n]),
            Err(ParseError::NotUdp(6))
        );
    }

    #[test]
    fn rejects_oversized_ipv6_payload_length() {
        let mut buf = [0u8; 80];
        let n = valid_ethernet_ipv6(&mut buf);
        buf[18..20].copy_from_slice(&u16::MAX.to_be_bytes()); // payload length past the frame
        assert_eq!(
            Parsed::parse(LinkType::Ethernet, &buf[..n]),
            Err(ParseError::BadLength)
        );
    }

    #[test]
    fn rejects_udp_length_below_minimum() {
        let mut buf = [0u8; 64];
        let n = valid_ethernet_ipv4(&mut buf);
        buf[38..40].copy_from_slice(&4u16.to_be_bytes()); // UDP length below the 8-byte header
        assert_eq!(
            Parsed::parse(LinkType::Ethernet, &buf[..n]),
            Err(ParseError::BadLength)
        );
    }

    #[test]
    fn rejects_l4_region_smaller_than_the_udp_header() {
        let mut buf = [0u8; 64];
        let n = valid_ethernet_ipv4(&mut buf);
        buf[16..18].copy_from_slice(&24u16.to_be_bytes()); // total length leaves 4 bytes for L4
        assert_eq!(
            Parsed::parse(LinkType::Ethernet, &buf[..n]),
            Err(ParseError::Truncated)
        );
    }

    #[test]
    fn rejects_ethernet_frame_with_no_l3_bytes() {
        assert_eq!(
            Parsed::parse(LinkType::Ethernet, &[0u8; ETHERNET_HEADER_SIZE]),
            Err(ParseError::Truncated)
        );
    }

    /// `frame` with an 802.1Q tag carrying `tci` inserted after the MACs.
    fn tagged(frame: &[u8], tci: u16) -> Vec<u8> {
        let [tci_hi, tci_lo] = tci.to_be_bytes();
        [&frame[..12], &[0x81, 0x00, tci_hi, tci_lo], &frame[12..]].concat()
    }

    #[test]
    fn reads_a_priority_tagged_frame_past_its_tag() {
        let mut buf = [0u8; 64];
        let n = valid_ethernet_ipv4(&mut buf);
        let untagged = Parsed::parse(LinkType::Ethernet, &buf[..n]).unwrap();
        let frame = tagged(&buf[..n], 0xa000); // PCP 5, VID 0
        assert_eq!(Parsed::parse(LinkType::Ethernet, &frame), Ok(untagged));
    }

    #[test]
    fn rejects_a_frame_tagged_for_a_vlan() {
        let mut buf = [0u8; 64];
        let n = valid_ethernet_ipv4(&mut buf);
        let frame = tagged(&buf[..n], 0xa01e); // PCP 5, VID 30
        assert_eq!(
            Parsed::parse(LinkType::Ethernet, &frame),
            Err(ParseError::VlanTagged(30))
        );
    }

    #[test]
    fn rejects_a_vlan_tag_cut_short() {
        let mut frame = [0u8; ETHERNET_HEADER_SIZE + 2];
        frame[12..14].copy_from_slice(&[0x81, 0x00]);
        assert_eq!(
            Parsed::parse(LinkType::Ethernet, &frame),
            Err(ParseError::Truncated)
        );
    }
}
