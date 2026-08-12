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
mod route_query;
pub(crate) mod ssdp;
pub(crate) mod stream_buffer;
pub(crate) mod tcp;
pub(crate) mod uninit_buf;
pub(crate) mod wsd;

/// Link-layer framing of a captured or injected frame. The capture layer reports
/// it per interface; [`frame`] adds the matching link header and [`packet`] strips
/// it before parsing L3. Either a 14-byte Ethernet header, or on BSD `DLT_NULL`'s
/// 4-byte host-order address family (loopback/tunnel interfaces). Linux frames every
/// interface as Ethernet, loopback included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinkType {
    Ethernet,
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    DltNull,
}

/// IANA protocol number for UDP.
const IP_PROTO_UDP: u8 = 17;

/// Ethernet link header: dst MAC(6) + src MAC(6) + ethertype(2).
const ETHERNET_HEADER_SIZE: usize = 14;
/// BSD `DLT_NULL` link header: a 4-byte address family in host byte order (`lo0`).
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
const DLT_NULL_HEADER_SIZE: usize = 4;
/// IPv4 header without options (the minimum), the fixed IPv6 base header, and the
/// fixed UDP header.
const IPV4_HEADER_SIZE: usize = 20;
const IPV6_HEADER_SIZE: usize = 40;
const UDP_HEADER_SIZE: usize = 8;

/// The largest frame the daemon builds, captures or forwards. Every buffer on the frame path is
/// sized from this: the dispatcher's send scratch, and each capture backend's read buffer, so
/// anything captured can be re-emitted. Clears a standard 1514-byte Ethernet frame (the FCS is
/// stripped before capture) with headroom for a baby-jumbo MTU. True 9000-byte jumbo is out of
/// reach, and no discovery protocol comes near it.
pub(crate) const MAX_FRAME_LEN: usize = 2048;

/// The largest UDP payload that still fits [`MAX_FRAME_LEN`] once framed, so anything built within
/// it is forwardable. The worst-case header stack: Ethernet (over `DLT_NULL`) plus IPv6 (over
/// IPv4, and fixed at 40 since the builders emit no extension headers) plus UDP.
pub(crate) const MAX_UDP_PAYLOAD_LEN: usize =
    MAX_FRAME_LEN - (ETHERNET_HEADER_SIZE + IPV6_HEADER_SIZE + UDP_HEADER_SIZE);

/// The largest interface MTU whose full-size packets still fit [`MAX_FRAME_LEN`] once framed (an
/// MTU counts L3 bytes; the frame adds the link header). Ethernet is the binding case; a
/// `DLT_NULL` link's 4-byte header leaves a little more room, accepted as slack.
pub(crate) const MAX_MTU: usize = MAX_FRAME_LEN - ETHERNET_HEADER_SIZE;

/// Whether `ip` is link-local (IPv4 `169.254.0.0/16`, IPv6 `fe80::/10`). A v4-mapped IPv6 address
/// is judged by its IPv4 rules, like [`is_never_a_peer`].
pub(crate) fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.is_link_local(),
            None => v6.is_unicast_link_local(),
        },
    }
}

/// Whether `ip` can never name another single host: loopback is the connecting host itself,
/// unspecified is no host, and multicast / IPv4 limited broadcast are groups. Unlike link-local,
/// which is a valid peer on its own link, such an address names no device from any segment. A
/// v4-mapped IPv6 address is judged by its IPv4 rules (`::ffff:127.0.0.1` reaches `127.0.0.1`,
/// and std's `Ipv6Addr::is_loopback` would miss it). A directed IPv4 broadcast is
/// indistinguishable from a host address without the subnet mask and reads as `false`.
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
