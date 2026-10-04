//! Build the link-layer frames injected on the egress path, into a caller-provided buffer with
//! the checksums filled. A datagram larger than the MTU leaves as IP fragments, one per frame.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use thiserror::Error;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
use super::DLT_NULL_HEADER_SIZE;
use super::checksum;
use super::mac::MacAddr;
use super::{
    ETHERNET_HEADER_SIZE, FRAGMENT_UNIT, IP_PROTO_UDP, IPV4_HEADER_SIZE, IPV6_FRAGMENT_HEADER_SIZE,
    IPV6_HEADER_SIZE, IPV6_NEXT_FRAGMENT, UDP_HEADER_SIZE,
};

const IPV4_ETHERTYPE: u16 = 0x0800;
const IPV6_ETHERTYPE: u16 = 0x86dd;
const IPV4_FLAG_MF: u16 = 0x2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum FrameError {
    #[error("output buffer too small: need {needed} bytes, have {available}")]
    BufferTooSmall { needed: usize, available: usize },
    #[error("payload of {payload} bytes is too large for a UDP datagram")]
    PayloadTooLarge { payload: usize },
    #[error("an MTU of {mtu} bytes leaves no room for a fragment")]
    MtuTooSmall { mtu: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkHeader {
    Ethernet {
        dst: MacAddr,
        src: MacAddr,
    },
    /// BSD `DLT_NULL`: the address family in host byte order.
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    DltNull,
    /// A Linux raw IP link (`WireGuard`, tun) takes the bare datagram.
    #[cfg(target_os = "linux")]
    RawIp,
}

impl LinkHeader {
    fn size(self) -> usize {
        match self {
            Self::Ethernet { .. } => ETHERNET_HEADER_SIZE,
            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            Self::DltNull => DLT_NULL_HEADER_SIZE,
            #[cfg(target_os = "linux")]
            Self::RawIp => 0,
        }
    }

    fn write(self, out: &mut [u8], ipv6: bool) {
        match self {
            Self::Ethernet { dst, src } => {
                let ethertype = if ipv6 { IPV6_ETHERTYPE } else { IPV4_ETHERTYPE };
                out[0..6].copy_from_slice(&dst.octets());
                out[6..12].copy_from_slice(&src.octets());
                out[12..14].copy_from_slice(&ethertype.to_be_bytes());
            }
            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            Self::DltNull => {
                let family = if ipv6 { libc::AF_INET6 } else { libc::AF_INET };
                out[0..4].copy_from_slice(&family.cast_unsigned().to_ne_bytes());
            }
            #[cfg(target_os = "linux")]
            Self::RawIp => {}
        }
    }
}

/// Where a fragment's data sits in its datagram.
#[derive(Clone, Copy)]
struct Placement {
    offset: usize,
    /// Another fragment follows.
    more: bool,
}

impl Placement {
    /// The offset in [`FRAGMENT_UNIT`]s, as both headers store it.
    fn units(self) -> u16 {
        u16::try_from(self.offset / FRAGMENT_UNIT).expect("a datagram's offsets fit 13 bits")
    }
}

#[derive(Clone, Copy)]
enum IpHeader {
    V4 {
        src: Ipv4Addr,
        dst: Ipv4Addr,
        ttl: u8,
        id: u16,
    },
    V6 {
        src: Ipv6Addr,
        dst: Ipv6Addr,
        hop_limit: u8,
        id: u32,
    },
}

impl IpHeader {
    fn size(self, fragmented: bool) -> usize {
        match self {
            Self::V4 { .. } => IPV4_HEADER_SIZE,
            Self::V6 { .. } if fragmented => IPV6_HEADER_SIZE + IPV6_FRAGMENT_HEADER_SIZE,
            Self::V6 { .. } => IPV6_HEADER_SIZE,
        }
    }

    /// `out` is exactly the header, `data_len` the datagram bytes after it.
    fn write(self, out: &mut [u8], data_len: usize, placement: Option<Placement>) {
        out.fill(0);
        match self {
            Self::V4 { src, dst, ttl, id } => {
                let total_length = u16::try_from(IPV4_HEADER_SIZE + data_len)
                    .expect("UdpFrames bounds a datagram by the total-length field");
                let flags_offset = placement.map_or(0, |placement| {
                    placement.units() | if placement.more { IPV4_FLAG_MF } else { 0 }
                });
                out[0] = 0x45; // version 4, IHL 5 (no options)
                out[2..4].copy_from_slice(&total_length.to_be_bytes());
                out[4..6].copy_from_slice(&id.to_be_bytes());
                out[6..8].copy_from_slice(&flags_offset.to_be_bytes());
                out[8] = ttl;
                out[9] = IP_PROTO_UDP;
                out[12..16].copy_from_slice(&src.octets());
                out[16..20].copy_from_slice(&dst.octets());
                let checksum = checksum::ipv4_header(out);
                out[10..12].copy_from_slice(&checksum.to_be_bytes());
            }
            Self::V6 {
                src,
                dst,
                hop_limit,
                id,
            } => {
                // The payload length counts any extension header.
                let payload_length = u16::try_from(out.len() - IPV6_HEADER_SIZE + data_len)
                    .expect("UdpFrames bounds a datagram by the UDP length field");
                out[0] = 0x60; // version 6, zero traffic class / flow label
                out[4..6].copy_from_slice(&payload_length.to_be_bytes());
                out[6] = IP_PROTO_UDP;
                out[7] = hop_limit;
                out[8..24].copy_from_slice(&src.octets());
                out[24..40].copy_from_slice(&dst.octets());
                if let Some(placement) = placement {
                    out[6] = IPV6_NEXT_FRAGMENT;
                    let fragment = &mut out[IPV6_HEADER_SIZE..];
                    fragment[0] = IP_PROTO_UDP;
                    let offset_more = (placement.units() << 3) | u16::from(placement.more);
                    fragment[2..4].copy_from_slice(&offset_more.to_be_bytes());
                    fragment[4..8].copy_from_slice(&id.to_be_bytes());
                }
            }
        }
    }
}

/// A UDP datagram laid out for one link: a single frame when it fits the MTU, otherwise one IP
/// fragment per frame.
pub(crate) struct UdpFrames<'a> {
    link: LinkHeader,
    ip: IpHeader,
    udp: [u8; UDP_HEADER_SIZE],
    /// The caller's bytes; the UDP header stays apart in `udp`.
    payload: &'a [u8],
    /// The datagram bytes each frame carries: all of them, or a multiple of [`FRAGMENT_UNIT`].
    chunk: usize,
    fragmented: bool,
}

impl<'a> UdpFrames<'a> {
    /// `mtu` bounds each frame's IP packet.
    ///
    /// # Errors
    /// [`FrameError::PayloadTooLarge`] or [`FrameError::MtuTooSmall`].
    pub(crate) fn ipv4(
        link: LinkHeader,
        src: SocketAddrV4,
        dst: SocketAddrV4,
        ttl: u8,
        id: u16,
        payload: &'a [u8],
        mtu: usize,
    ) -> Result<Self, FrameError> {
        let mut udp = udp_header(src.port(), dst.port(), payload, IPV4_HEADER_SIZE)?;
        let checksum = checksum::udp_v4(*src.ip(), *dst.ip(), udp, payload);
        udp[6..8].copy_from_slice(&checksum.to_be_bytes());
        let ip = IpHeader::V4 {
            src: *src.ip(),
            dst: *dst.ip(),
            ttl,
            id,
        };
        Self::new(link, ip, udp, payload, mtu)
    }

    /// As [`ipv4`](Self::ipv4); a fragmented datagram carries a Fragment header in every frame.
    ///
    /// # Errors
    /// [`FrameError::PayloadTooLarge`] or [`FrameError::MtuTooSmall`].
    pub(crate) fn ipv6(
        link: LinkHeader,
        src: SocketAddrV6,
        dst: SocketAddrV6,
        hop_limit: u8,
        id: u32,
        payload: &'a [u8],
        mtu: usize,
    ) -> Result<Self, FrameError> {
        let mut udp = udp_header(src.port(), dst.port(), payload, 0)?;
        let checksum = checksum::udp_v6(*src.ip(), *dst.ip(), udp, payload);
        udp[6..8].copy_from_slice(&checksum.to_be_bytes());
        let ip = IpHeader::V6 {
            src: *src.ip(),
            dst: *dst.ip(),
            hop_limit,
            id,
        };
        Self::new(link, ip, udp, payload, mtu)
    }

    fn new(
        link: LinkHeader,
        ip: IpHeader,
        udp: [u8; UDP_HEADER_SIZE],
        payload: &'a [u8],
        mtu: usize,
    ) -> Result<Self, FrameError> {
        let datagram = UDP_HEADER_SIZE + payload.len();
        let (chunk, fragmented) = if ip.size(false) + datagram <= mtu {
            (datagram, false)
        } else {
            let room = mtu.saturating_sub(ip.size(true));
            match room - room % FRAGMENT_UNIT {
                0 => return Err(FrameError::MtuTooSmall { mtu }),
                chunk => (chunk, true),
            }
        };
        Ok(Self {
            link,
            ip,
            udp,
            payload,
            chunk,
            fragmented,
        })
    }

    pub(crate) fn count(&self) -> usize {
        self.datagram_len().div_ceil(self.chunk)
    }

    /// Write frame `index`, counting from 0, into `out`; returns its length.
    ///
    /// # Errors
    /// [`FrameError::BufferTooSmall`].
    ///
    /// # Panics
    /// `index` not below [`count`](Self::count).
    pub(crate) fn write(&self, index: usize, out: &mut [u8]) -> Result<usize, FrameError> {
        let datagram_len = self.datagram_len();
        let start = index * self.chunk;
        assert!(start < datagram_len, "frame {index} of {}", self.count());
        let end = (start + self.chunk).min(datagram_len);
        let (link_len, ip_len) = (self.link.size(), self.ip.size(self.fragmented));
        let frame_len = link_len + ip_len + (end - start);
        let available = out.len();
        let out = out.get_mut(..frame_len).ok_or(FrameError::BufferTooSmall {
            needed: frame_len,
            available,
        })?;
        let (link, rest) = out.split_at_mut(link_len);
        let (header, body) = rest.split_at_mut(ip_len);
        self.link
            .write(link, matches!(self.ip, IpHeader::V6 { .. }));
        let placement = self.fragmented.then_some(Placement {
            offset: start,
            more: end < datagram_len,
        });
        self.ip.write(header, body.len(), placement);
        let (body, from) = if start == 0 {
            let (udp, rest) = body.split_at_mut(UDP_HEADER_SIZE);
            udp.copy_from_slice(&self.udp);
            (rest, 0)
        } else {
            (body, start - UDP_HEADER_SIZE)
        };
        body.copy_from_slice(&self.payload[from..from + body.len()]);
        Ok(frame_len)
    }

    fn datagram_len(&self) -> usize {
        UDP_HEADER_SIZE + self.payload.len()
    }
}

/// The checksum field is left zero. IPv4 passes its header size: the reassembled datagram,
/// header included, must fit the 16-bit total length.
fn udp_header(
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    ipv4_header: usize,
) -> Result<[u8; UDP_HEADER_SIZE], FrameError> {
    let length = UDP_HEADER_SIZE + payload.len();
    if u16::try_from(ipv4_header + length).is_err() {
        return Err(FrameError::PayloadTooLarge {
            payload: payload.len(),
        });
    }
    let length = u16::try_from(length).expect("no longer than the bound just checked");
    let mut udp = [0u8; UDP_HEADER_SIZE];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&length.to_be_bytes());
    Ok(udp)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0xaa];
    const SRC_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0xbb];

    fn v4_endpoints() -> (SocketAddrV4, SocketAddrV4) {
        (
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), 3702),
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 30), 49503),
        )
    }

    fn v6_endpoints() -> (SocketAddrV6, SocketAddrV6) {
        (
            SocketAddrV6::new("fe80::1".parse().unwrap(), 3702, 0, 0),
            SocketAddrV6::new("fe80::30".parse().unwrap(), 49503, 0, 0),
        )
    }

    fn ethernet() -> LinkHeader {
        LinkHeader::Ethernet {
            dst: MacAddr::from(DST_MAC),
            src: MacAddr::from(SRC_MAC),
        }
    }

    /// Every frame of `frames`, written into its own buffer. The sentinel fill shows any byte the
    /// builder leaves unwritten.
    fn written(frames: &UdpFrames) -> Vec<Vec<u8>> {
        (0..frames.count())
            .map(|index| {
                let mut buf = vec![0xAAu8; 1 << 17];
                let n = frames.write(index, &mut buf).unwrap();
                buf[..n].to_vec()
            })
            .collect()
    }

    /// `payload` bytes of a counting pattern, so a misplaced slice shows.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    #[test]
    fn an_ipv4_datagram_that_fits_is_one_frame() {
        let (src, dst) = v4_endpoints();
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let frames = UdpFrames::ipv4(ethernet(), src, dst, 1, 0x1234, &payload, 1500).unwrap();
        let [frame] = written(&frames).try_into().unwrap();
        assert_eq!(frame.len(), 14 + 20 + 8 + payload.len());
        assert_eq!(frame[0..6], DST_MAC);
        assert_eq!(frame[6..12], SRC_MAC);
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), IPV4_ETHERTYPE);

        // IPv4 header: every byte.
        let ip = &frame[14..];
        assert_eq!(ip[0], 0x45); // version 4, IHL 5
        assert_eq!(ip[1], 0); // DSCP / ECN
        assert_eq!(u16::from_be_bytes([ip[2], ip[3]]), 32); // total length
        assert_eq!(u16::from_be_bytes([ip[4], ip[5]]), 0x1234); // identification
        assert_eq!(u16::from_be_bytes([ip[6], ip[7]]), 0); // no DF, no MF, offset 0
        assert_eq!(ip[8], 1); // ttl
        assert_eq!(ip[9], IP_PROTO_UDP);
        assert_eq!(
            u16::from_be_bytes([ip[10], ip[11]]),
            checksum::ipv4_header(&ip[..20])
        );
        assert_eq!(&ip[12..16], src.ip().octets().as_slice());
        assert_eq!(&ip[16..20], dst.ip().octets().as_slice());

        // UDP header + payload: every byte.
        let udp: &[u8; 8] = ip[20..28].try_into().unwrap();
        assert_eq!(u16::from_be_bytes([udp[0], udp[1]]), src.port());
        assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), dst.port());
        assert_eq!(u16::from_be_bytes([udp[4], udp[5]]), 12); // UDP length
        assert_eq!(
            u16::from_be_bytes([udp[6], udp[7]]),
            checksum::udp_v4(*src.ip(), *dst.ip(), *udp, &payload)
        );
        assert_eq!(&ip[28..], &payload);
    }

    #[test]
    fn an_ipv6_datagram_that_fits_is_one_frame() {
        let (src, dst) = v6_endpoints();
        let payload = [0xaa, 0xbb, 0xcc];
        let frames = UdpFrames::ipv6(ethernet(), src, dst, 255, 7, &payload, 1500).unwrap();
        let [frame] = written(&frames).try_into().unwrap();
        assert_eq!(frame.len(), 14 + 40 + 8 + payload.len());
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), IPV6_ETHERTYPE);

        // IPv6 header: every byte. No Fragment header on a datagram that fits.
        let ip = &frame[14..];
        assert_eq!(ip[0], 0x60); // version 6
        assert_eq!(&ip[1..4], [0u8; 3].as_slice()); // traffic class + flow label
        assert_eq!(u16::from_be_bytes([ip[4], ip[5]]), 11); // payload length
        assert_eq!(ip[6], IP_PROTO_UDP); // next header
        assert_eq!(ip[7], 255); // hop limit
        assert_eq!(&ip[8..24], src.ip().octets().as_slice());
        assert_eq!(&ip[24..40], dst.ip().octets().as_slice());

        let udp: &[u8; 8] = ip[40..48].try_into().unwrap();
        assert_eq!(u16::from_be_bytes([udp[0], udp[1]]), src.port());
        assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), dst.port());
        assert_eq!(u16::from_be_bytes([udp[4], udp[5]]), 11);
        assert_eq!(
            u16::from_be_bytes([udp[6], udp[7]]),
            checksum::udp_v6(*src.ip(), *dst.ip(), *udp, &payload)
        );
        assert_eq!(&ip[48..], &payload);
    }

    #[test]
    fn an_ipv4_datagram_over_the_mtu_leaves_in_fragments() {
        let (src, dst) = v4_endpoints();
        let payload = pattern(2595);
        let whole = written(
            &UdpFrames::ipv4(ethernet(), src, dst, 64, 0x4242, &payload, usize::MAX).unwrap(),
        );
        let frames = UdpFrames::ipv4(ethernet(), src, dst, 64, 0x4242, &payload, 1500).unwrap();
        let fragments = written(&frames);
        // 2603 datagram bytes: 1480 + 1123.
        assert_eq!(fragments.len(), 2);

        let mut data = Vec::new();
        for (index, frame) in fragments.iter().enumerate() {
            let ip = &frame[14..];
            let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
            assert_eq!(total, ip.len());
            assert!(total <= 1500, "fragment {index} is {total} bytes");
            assert_eq!(u16::from_be_bytes([ip[4], ip[5]]), 0x4242);
            let flags_offset = u16::from_be_bytes([ip[6], ip[7]]);
            let more = index + 1 < fragments.len();
            assert_eq!(flags_offset & IPV4_FLAG_MF != 0, more);
            assert_eq!(usize::from(flags_offset & 0x1fff) * 8, data.len());
            assert_eq!(
                u16::from_be_bytes([ip[10], ip[11]]),
                checksum::ipv4_header(&ip[..20])
            );
            data.extend_from_slice(&ip[20..]);
        }
        // The fragments carry exactly the datagram the unfragmented frame does, UDP checksum
        // included.
        assert_eq!(data, whole[0][14 + 20..]);
    }

    #[test]
    fn an_ipv6_datagram_over_the_mtu_leaves_in_fragments() {
        let (src, dst) = v6_endpoints();
        let payload = pattern(2595);
        let whole = written(
            &UdpFrames::ipv6(ethernet(), src, dst, 255, 0xdead_beef, &payload, usize::MAX).unwrap(),
        );
        let frames =
            UdpFrames::ipv6(ethernet(), src, dst, 255, 0xdead_beef, &payload, 1500).unwrap();
        let fragments = written(&frames);
        // 2603 datagram bytes: 1448 + 1155, each behind 40 + 8 header bytes.
        assert_eq!(fragments.len(), 2);

        let mut data = Vec::new();
        for (index, frame) in fragments.iter().enumerate() {
            let ip = &frame[14..];
            assert!(ip.len() <= 1500, "fragment {index} is {} bytes", ip.len());
            assert_eq!(
                usize::from(u16::from_be_bytes([ip[4], ip[5]])),
                ip.len() - 40
            );
            assert_eq!(ip[6], IPV6_NEXT_FRAGMENT);
            let fragment = &ip[40..48];
            assert_eq!(fragment[0], IP_PROTO_UDP);
            assert_eq!(fragment[1], 0);
            let offset_more = u16::from_be_bytes([fragment[2], fragment[3]]);
            assert_eq!(offset_more & 1 != 0, index + 1 < fragments.len());
            assert_eq!(offset_more & 0b110, 0); // reserved
            assert_eq!(usize::from(offset_more >> 3) * 8, data.len());
            assert_eq!(
                u32::from_be_bytes(fragment[4..8].try_into().unwrap()),
                0xdead_beef
            );
            data.extend_from_slice(&ip[48..]);
        }
        assert_eq!(data, whole[0][14 + 40..]);
    }

    #[test]
    fn a_datagram_exactly_at_the_mtu_stays_whole() {
        let (src, dst) = v4_endpoints();
        let fits = pattern(1500 - 20 - 8);
        let frames = UdpFrames::ipv4(ethernet(), src, dst, 64, 1, &fits, 1500).unwrap();
        assert_eq!(frames.count(), 1);
        let over = pattern(1500 - 20 - 8 + 1);
        let frames = UdpFrames::ipv4(ethernet(), src, dst, 64, 1, &over, 1500).unwrap();
        assert_eq!(frames.count(), 2);
    }

    #[test]
    fn every_link_carries_the_same_ip_packet() {
        let (src, dst) = v4_endpoints();
        let payload = pattern(100);
        let frame = |link| {
            let frames = UdpFrames::ipv4(link, src, dst, 64, 9, &payload, 1500).unwrap();
            let [frame] = written(&frames).try_into().unwrap();
            frame
        };
        let reference = frame(ethernet())[ETHERNET_HEADER_SIZE..].to_vec();
        assert_eq!(reference[0], 0x45);
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        {
            let frame = frame(LinkHeader::DltNull);
            assert_eq!(
                u32::from_ne_bytes(frame[0..4].try_into().unwrap()),
                libc::AF_INET.cast_unsigned()
            );
            assert_eq!(frame[DLT_NULL_HEADER_SIZE..], reference);
        }
        #[cfg(target_os = "linux")]
        assert_eq!(frame(LinkHeader::RawIp), reference);
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn dlt_null_prefixes_the_host_family() {
        let (src, dst) = v6_endpoints();
        let frames = UdpFrames::ipv6(LinkHeader::DltNull, src, dst, 255, 0, &[1], 1500).unwrap();
        let [frame] = written(&frames).try_into().unwrap();
        assert_eq!(
            u32::from_ne_bytes(frame[0..4].try_into().unwrap()),
            libc::AF_INET6.cast_unsigned()
        );
        assert_eq!(frame[DLT_NULL_HEADER_SIZE], 0x60);
    }

    #[test]
    fn a_short_buffer_is_reported_with_the_link_header_counted() {
        let (src, dst) = v4_endpoints();
        let frames = UdpFrames::ipv4(ethernet(), src, dst, 1, 0, &[], 1500).unwrap();
        let mut buf = [0u8; 20];
        assert_eq!(
            frames.write(0, &mut buf),
            Err(FrameError::BufferTooSmall {
                needed: 42,
                available: 20
            })
        );
    }

    // IPv4 trips the total-length field (header + datagram), IPv6 the UDP length field alone.
    #[test]
    fn a_payload_past_the_length_fields_is_too_large() {
        let (src4, dst4) = v4_endpoints();
        let payload = vec![0u8; 65_508];
        assert!(matches!(
            UdpFrames::ipv4(ethernet(), src4, dst4, 1, 0, &payload, 1500),
            Err(FrameError::PayloadTooLarge { payload: 65_508 })
        ));
        assert!(UdpFrames::ipv4(ethernet(), src4, dst4, 1, 0, &payload[1..], 1500).is_ok());
        let (src6, dst6) = v6_endpoints();
        let payload = vec![0u8; 65_528];
        assert!(matches!(
            UdpFrames::ipv6(ethernet(), src6, dst6, 1, 0, &payload, 1500),
            Err(FrameError::PayloadTooLarge { payload: 65_528 })
        ));
        assert!(UdpFrames::ipv6(ethernet(), src6, dst6, 1, 0, &payload[1..], 1500).is_ok());
    }

    #[test]
    fn an_mtu_without_room_for_a_fragment_is_refused() {
        let (src, dst) = v4_endpoints();
        let payload = pattern(100);
        assert!(matches!(
            UdpFrames::ipv4(ethernet(), src, dst, 1, 0, &payload, 27),
            Err(FrameError::MtuTooSmall { mtu: 27 })
        ));
        assert_eq!(
            UdpFrames::ipv4(ethernet(), src, dst, 1, 0, &payload, 28)
                .unwrap()
                .count(),
            14
        );
    }
}
