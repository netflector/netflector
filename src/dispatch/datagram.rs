//! Assembling a UDP datagram for an egress: the L2 destination and the frame builder for its link
//! type. The dispatcher's adapter over [`net::frame`](crate::net::frame).

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use thiserror::Error;

use crate::interface::{InterfaceAddresses, Ipv6Scope};
use crate::net::LinkType;
use crate::net::frame::{self, FrameError};
use crate::net::mac::MacAddr;

/// Each case is one the reflector's family and MAC gating makes unreachable in practice; they
/// stay typed so the builder is unit-testable and a stray one logs precisely.
#[derive(Debug, Error, PartialEq, Eq)]
pub(super) enum DatagramError {
    #[error("egress has no source address for the datagram's family")]
    NoSourceAddress,
    #[error("egress has no source MAC for an Ethernet frame")]
    NoSourceMac,
    #[error("destination is unicast; only broadcast/multicast is injected")]
    UnicastDestination,
    #[error("source and destination are of different address families")]
    SourceFamilyMismatch,
    #[error(transparent)]
    Frame(#[from] FrameError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DatagramSource {
    /// The egress's own address of the destination's family, at `port`.
    Egress {
        port: u16,
    },
    Exact(SocketAddr),
}

/// Broadcast for the IPv4 limited broadcast and the egress's own directed broadcast, the group
/// MAC for multicast. A unicast `dst` would need resolving, so it is an error.
pub(super) fn ethernet_dst(
    dst: IpAddr,
    v4_directed_broadcast: Option<Ipv4Addr>,
) -> Result<MacAddr, DatagramError> {
    match dst {
        IpAddr::V4(v4) if v4.is_broadcast() || Some(v4) == v4_directed_broadcast => {
            Ok(MacAddr::broadcast())
        }
        _ if dst.is_multicast() => Ok(MacAddr::multicast_for(dst)),
        _ => Err(DatagramError::UnicastDestination),
    }
}

/// A link without L2 addresses (BSD `DLT_NULL`, a Linux raw IP tunnel) ignores `dst_mac` and
/// needs no source MAC.
// The whole wire spec; bundling any of it would obscure more than the arg count costs.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_udp(
    addrs: &InterfaceAddresses,
    link: LinkType,
    dst: SocketAddr,
    dst_mac: MacAddr,
    source: DatagramSource,
    ttl: u8,
    payload: &[u8],
    scratch: &mut [u8],
) -> Result<usize, DatagramError> {
    match dst {
        SocketAddr::V4(dst) => {
            let src = match source {
                DatagramSource::Egress { port } => {
                    SocketAddrV4::new(addrs.v4().ok_or(DatagramError::NoSourceAddress)?, port)
                }
                DatagramSource::Exact(SocketAddr::V4(src)) => src,
                DatagramSource::Exact(SocketAddr::V6(_)) => {
                    return Err(DatagramError::SourceFamilyMismatch);
                }
            };
            match link {
                LinkType::Ethernet => Ok(frame::ethernet_ipv4_udp(
                    dst_mac,
                    addrs.mac().ok_or(DatagramError::NoSourceMac)?,
                    src,
                    dst,
                    ttl,
                    payload,
                    scratch,
                )?),
                #[cfg(any(target_os = "macos", target_os = "freebsd"))]
                LinkType::DltNull => Ok(frame::dlt_null_ipv4_udp(src, dst, ttl, payload, scratch)?),
                #[cfg(target_os = "linux")]
                LinkType::RawIp => Ok(frame::ipv4_udp(src, dst, ttl, payload, scratch)?),
            }
        }
        SocketAddr::V6(dst) => {
            let src = match source {
                // Match the destination's scope: ff05::c must not be sourced from a link-local.
                DatagramSource::Egress { port } => {
                    let src_ip = addrs
                        .v6(Ipv6Scope::of(*dst.ip()))
                        .ok_or(DatagramError::NoSourceAddress)?;
                    SocketAddrV6::new(src_ip, port, 0, 0)
                }
                DatagramSource::Exact(SocketAddr::V6(src)) => src,
                DatagramSource::Exact(SocketAddr::V4(_)) => {
                    return Err(DatagramError::SourceFamilyMismatch);
                }
            };
            match link {
                LinkType::Ethernet => Ok(frame::ethernet_ipv6_udp(
                    dst_mac,
                    addrs.mac().ok_or(DatagramError::NoSourceMac)?,
                    src,
                    dst,
                    ttl,
                    payload,
                    scratch,
                )?),
                #[cfg(any(target_os = "macos", target_os = "freebsd"))]
                LinkType::DltNull => Ok(frame::dlt_null_ipv6_udp(src, dst, ttl, payload, scratch)?),
                #[cfg(target_os = "linux")]
                LinkType::RawIp => Ok(frame::ipv6_udp(src, dst, ttl, payload, scratch)?),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    /// A fully-populated egress: a MAC, v4, a link-local v6, and a routable v6.
    fn full_addrs() -> InterfaceAddresses {
        InterfaceAddresses::new(
            Some(MacAddr::from([0x02, 0, 0, 0, 0, 0x01])),
            Some(Ipv4Addr::new(192, 168, 0, 2)),
            Some("fe80::2".parse().unwrap()),
            Some("2001:db8::2".parse().unwrap()),
        )
    }

    #[test]
    fn build_udp_sources_a_site_local_group_from_the_routable_address() {
        // A site-local SSDP group (ff05::c) must source from the routable address, not the link-local.
        let addrs = full_addrs();
        let dst = SocketAddr::from((Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0x0c), 1900));
        let mut scratch = [0u8; 2048];
        let n = build_udp(
            &addrs,
            LinkType::Ethernet,
            dst,
            MacAddr::multicast_for(dst.ip()),
            DatagramSource::Egress { port: 4000 },
            2,
            b"ssdp",
            &mut scratch,
        )
        .unwrap();
        // The IPv6 source address sits at bytes [22..38] of the frame (14 Ethernet + offset 8 into
        // the v6 header).
        assert_eq!(
            &scratch[22..38],
            "2001:db8::2"
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets()
                .as_slice(),
            "ff05::c sourced from the routable address"
        );
        assert!(n > 38);
    }

    #[test]
    fn build_udp_keeps_a_captured_source_verbatim() {
        // A relay re-emit carries the sender's own ip:port, not the egress's; the frame's source
        // sits at bytes [26..30] (14 Ethernet + offset 12) and its port at [34..36].
        let addrs = full_addrs();
        let dst = SocketAddr::from((Ipv4Addr::BROADCAST, 9003));
        let captured: SocketAddr = "192.0.2.7:40001".parse().unwrap();
        let mut scratch = [0u8; 2048];
        let n = build_udp(
            &addrs,
            LinkType::Ethernet,
            dst,
            MacAddr::broadcast(),
            DatagramSource::Exact(captured),
            32,
            b"sood",
            &mut scratch,
        )
        .unwrap();
        assert_eq!(&scratch[26..30], &[192, 0, 2, 7]);
        assert_eq!(&scratch[34..36], &40001u16.to_be_bytes());
        assert!(n > 36);
        // A source of the other family cannot be framed.
        assert_eq!(
            build_udp(
                &addrs,
                LinkType::Ethernet,
                dst,
                MacAddr::broadcast(),
                DatagramSource::Exact("[fe80::7]:40001".parse().unwrap()),
                32,
                b"sood",
                &mut scratch,
            ),
            Err(DatagramError::SourceFamilyMismatch)
        );
    }

    #[test]
    fn ethernet_dst_maps_address_classes() {
        assert_eq!(
            ethernet_dst(IpAddr::V4(Ipv4Addr::BROADCAST), None),
            Ok(MacAddr::broadcast())
        );
        let v4_group: IpAddr = "224.0.0.251".parse().unwrap();
        assert_eq!(
            ethernet_dst(v4_group, None),
            Ok(MacAddr::multicast_for(v4_group))
        );
        let v6_group: IpAddr = "ff02::1".parse().unwrap();
        assert_eq!(
            ethernet_dst(v6_group, None),
            Ok(MacAddr::multicast_for(v6_group))
        );
        // A unicast destination (either family) has no injectable L2 address.
        assert_eq!(
            ethernet_dst("192.168.0.1".parse().unwrap(), None),
            Err(DatagramError::UnicastDestination)
        );
        assert_eq!(
            ethernet_dst("fe80::1".parse().unwrap(), None),
            Err(DatagramError::UnicastDestination)
        );
        // The egress's own directed broadcast is a broadcast; any other subnet's is not ours to
        // resolve.
        let directed = Ipv4Addr::new(192, 0, 2, 255);
        assert_eq!(
            ethernet_dst(IpAddr::V4(directed), Some(directed)),
            Ok(MacAddr::broadcast())
        );
        assert_eq!(
            ethernet_dst(IpAddr::V4(directed), Some(Ipv4Addr::new(10, 0, 0, 255))),
            Err(DatagramError::UnicastDestination)
        );
    }

    #[test]
    fn build_udp_v4_broadcast_sources_from_the_egress() {
        let addrs = full_addrs();
        let dst = SocketAddr::from((Ipv4Addr::BROADCAST, 9));
        let mut scratch = [0u8; 2048];
        let n = build_udp(
            &addrs,
            LinkType::Ethernet,
            dst,
            MacAddr::broadcast(),
            DatagramSource::Egress { port: 4000 },
            64,
            b"wol",
            &mut scratch,
        )
        .unwrap();
        // L2 header: the supplied destination MAC, the egress's own MAC as source.
        assert_eq!(&scratch[0..6], MacAddr::broadcast().octets().as_slice());
        assert_eq!(&scratch[6..12], addrs.mac().unwrap().octets().as_slice());
        assert!(n > 12, "frame must extend past the L2 header");
    }

    #[test]
    fn build_udp_v6_writes_the_supplied_mac() {
        let addrs = full_addrs();
        let group = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        let dst = SocketAddr::from((group, 9));
        let mut scratch = [0u8; 2048];
        build_udp(
            &addrs,
            LinkType::Ethernet,
            dst,
            MacAddr::multicast_for(IpAddr::V6(group)),
            DatagramSource::Egress { port: 4000 },
            64,
            b"wol",
            &mut scratch,
        )
        .unwrap();
        // 33:33 + the low 32 bits of ff02::1 (the supplied MAC), then the egress's own MAC.
        assert_eq!(&scratch[0..6], [0x33, 0x33, 0, 0, 0, 0x01].as_slice());
        assert_eq!(&scratch[6..12], addrs.mac().unwrap().octets().as_slice());
    }

    #[test]
    fn build_udp_assembles_a_unicast_frame() {
        // The unicast path the M-SEARCH 200-OK reply will use: an explicit dst MAC and a unicast
        // dst. build_udp doesn't derive the MAC, so unicast works here (unlike send_udp_group).
        let addrs = full_addrs();
        let searcher_mac = MacAddr::from([0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
        let dst = SocketAddr::from((Ipv4Addr::new(192, 168, 0, 5), 9));
        let mut scratch = [0u8; 2048];
        let n = build_udp(
            &addrs,
            LinkType::Ethernet,
            dst,
            searcher_mac,
            DatagramSource::Egress { port: 4000 },
            64,
            b"ok",
            &mut scratch,
        )
        .unwrap();
        // The supplied unicast MAC is the L2 destination; the egress's own MAC is the source.
        assert_eq!(&scratch[0..6], searcher_mac.octets().as_slice());
        assert_eq!(&scratch[6..12], addrs.mac().unwrap().octets().as_slice());
        assert!(n > 12);
    }

    #[test]
    fn build_udp_needs_a_source_address_for_the_family() {
        // A v6-less egress cannot source a v6 datagram.
        let v4_only = InterfaceAddresses::new(
            Some(MacAddr::from([0x02, 0, 0, 0, 0, 0x01])),
            Some(Ipv4Addr::new(192, 168, 0, 2)),
            None,
            None,
        );
        let dst = SocketAddr::from((Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), 9));
        let mut scratch = [0u8; 2048];
        assert_eq!(
            build_udp(
                &v4_only,
                LinkType::Ethernet,
                dst,
                MacAddr::broadcast(),
                DatagramSource::Egress { port: 4000 },
                64,
                b"x",
                &mut scratch
            ),
            Err(DatagramError::NoSourceAddress)
        );
    }

    #[test]
    fn build_udp_ethernet_needs_a_source_mac() {
        let no_mac = InterfaceAddresses::new(
            None,
            Some(Ipv4Addr::new(192, 168, 0, 2)),
            Some("fe80::2".parse().unwrap()),
            Some("2001:db8::2".parse().unwrap()),
        );
        let dst = SocketAddr::from((Ipv4Addr::BROADCAST, 9));
        let mut scratch = [0u8; 2048];
        assert_eq!(
            build_udp(
                &no_mac,
                LinkType::Ethernet,
                dst,
                MacAddr::broadcast(),
                DatagramSource::Egress { port: 4000 },
                64,
                b"x",
                &mut scratch
            ),
            Err(DatagramError::NoSourceMac)
        );
    }

    #[test]
    fn build_udp_surfaces_a_frame_error() {
        // A scratch too small for the frame is a typed DatagramError::Frame, not a panic. The
        // `#[from] FrameError` conversion send_udp then maps onto io::Error.
        let dst = SocketAddr::from((Ipv4Addr::BROADCAST, 9));
        let mut tiny = [0u8; 16];
        assert!(matches!(
            build_udp(
                &full_addrs(),
                LinkType::Ethernet,
                dst,
                MacAddr::broadcast(),
                DatagramSource::Egress { port: 4000 },
                64,
                b"x",
                &mut tiny
            ),
            Err(DatagramError::Frame(FrameError::BufferTooSmall { .. }))
        ));
    }

    // DLT_NULL (BSD loopback) carries no L2 header, so a MAC-less egress still builds. The frame
    // opens with the 4-byte host-order address family, not a MAC, and the supplied dst MAC is
    // ignored (there is no L2 header to place it in).
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn build_udp_dlt_null_needs_no_mac() {
        let no_mac = InterfaceAddresses::new(
            None,
            Some(Ipv4Addr::new(192, 168, 0, 2)),
            Some("fe80::2".parse().unwrap()),
            Some("2001:db8::2".parse().unwrap()),
        );
        let dst = SocketAddr::from((Ipv4Addr::BROADCAST, 9));
        let mut scratch = [0u8; 2048];
        build_udp(
            &no_mac,
            LinkType::DltNull,
            dst,
            MacAddr::broadcast(),
            DatagramSource::Egress { port: 4000 },
            64,
            b"wol",
            &mut scratch,
        )
        .unwrap();
        assert_eq!(
            u32::from_ne_bytes(scratch[0..4].try_into().unwrap()),
            libc::AF_INET.cast_unsigned()
        );
    }
}
