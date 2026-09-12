//! The wire layer: on-the-wire packet formats. Link-layer framing, IP/UDP
//! checksums, building and parsing frames.

use std::net::IpAddr;

mod checksum;
pub(crate) mod frame;
pub(crate) mod http;
pub(crate) mod mac;
pub(crate) mod mdns;
pub(crate) mod packet;
pub(crate) mod port_reservation;
#[cfg(target_os = "freebsd")]
pub(crate) mod route_query;
pub(crate) mod ssdp;
pub(crate) mod stream_buffer;
pub(crate) mod tcp;
pub(crate) mod wsd;

/// Link-layer framing of a captured or injected frame, reported per interface by the capture
/// layer. Ethernet; BSD `DLT_NULL` (loopback/tunnel interfaces); on Linux the bare IP packet a
/// tunnel (`WireGuard`, tun) carries, with no link header at all. Linux frames loopback as
/// Ethernet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinkType {
    Ethernet,
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    DltNull,
    #[cfg(target_os = "linux")]
    RawIp,
}

const IP_PROTO_UDP: u8 = 17;

/// Ethernet link header: dst MAC(6) + src MAC(6) + ethertype(2).
const ETHERNET_HEADER_SIZE: usize = 14;
/// BSD `DLT_NULL` link header: a 4-byte address family in host byte order (`lo0`).
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
const DLT_NULL_HEADER_SIZE: usize = 4;
/// IPv4 without options (the minimum); the IPv6 base header and UDP header are fixed.
const IPV4_HEADER_SIZE: usize = 20;
const IPV6_HEADER_SIZE: usize = 40;
const UDP_HEADER_SIZE: usize = 8;

/// The largest frame the daemon builds, captures or forwards; every frame-path buffer is sized
/// from it. Clears a 1514-byte Ethernet frame (the FCS is stripped before capture) with headroom
/// for a baby-jumbo MTU; true 9000-byte jumbo is out of reach.
pub(crate) const MAX_FRAME_LEN: usize = 2048;

/// The largest UDP payload that still fits [`MAX_FRAME_LEN`] under the worst-case header stack.
/// IPv6 is fixed at 40: the builders emit no extension headers.
pub(crate) const MAX_UDP_PAYLOAD_LEN: usize =
    MAX_FRAME_LEN - (ETHERNET_HEADER_SIZE + IPV6_HEADER_SIZE + UDP_HEADER_SIZE);

/// The largest interface MTU whose full-size packets still fit [`MAX_FRAME_LEN`] once framed. An
/// MTU counts L3 bytes; Ethernet's link header is the binding case.
pub(crate) const MAX_MTU: usize = MAX_FRAME_LEN - ETHERNET_HEADER_SIZE;

pub(crate) fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.is_link_local(),
            None => v6.is_unicast_link_local(),
        },
    }
}

/// Whether `ip` can never name another single host: loopback, unspecified, multicast, the IPv4
/// limited broadcast. A v4-mapped IPv6 address is judged by its IPv4 rules (std's
/// `Ipv6Addr::is_loopback` misses `::ffff:127.0.0.1`). A directed IPv4 broadcast is
/// indistinguishable from a host address without the mask and reads as `false`.
pub(crate) fn is_never_a_peer(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast()
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_never_a_peer(IpAddr::V4(v4)),
            None => v6.is_loopback() || v6.is_unspecified() || v6.is_multicast(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_local_covers_both_families_and_nothing_routable() {
        assert!(is_link_local("169.254.7.9".parse().unwrap()));
        assert!(is_link_local("fe80::1".parse().unwrap()));
        assert!(!is_link_local("192.168.1.1".parse().unwrap()));
        assert!(!is_link_local("2001:db8::1".parse().unwrap()));
        // A v4-mapped address is judged by its IPv4 rules.
        assert!(is_link_local("::ffff:169.254.7.9".parse().unwrap()));
        assert!(!is_link_local("::ffff:192.168.1.1".parse().unwrap()));
        // Adjacent special ranges don't leak in: loopback and unique-local are not link-local.
        assert!(!is_link_local("127.0.0.1".parse().unwrap()));
        assert!(!is_link_local("fd00::1".parse().unwrap()));
    }

    #[test]
    fn never_a_peer_covers_the_non_host_classes_and_nothing_else() {
        assert!(is_never_a_peer("127.0.0.1".parse().unwrap()));
        assert!(is_never_a_peer("0.0.0.0".parse().unwrap()));
        assert!(is_never_a_peer("239.255.255.250".parse().unwrap()));
        assert!(is_never_a_peer("255.255.255.255".parse().unwrap()));
        assert!(is_never_a_peer("::1".parse().unwrap()));
        assert!(is_never_a_peer("::".parse().unwrap()));
        assert!(is_never_a_peer("ff02::c".parse().unwrap()));
        // A v4-mapped address is judged by its IPv4 rules.
        assert!(is_never_a_peer("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!is_never_a_peer("::ffff:192.168.1.1".parse().unwrap()));
        // Host addresses stay peers, link-local and a maskless directed broadcast included.
        assert!(!is_never_a_peer("192.168.1.1".parse().unwrap()));
        assert!(!is_never_a_peer("169.254.7.9".parse().unwrap()));
        assert!(!is_never_a_peer("fe80::1".parse().unwrap()));
        assert!(!is_never_a_peer("192.168.1.255".parse().unwrap()));
    }
}
