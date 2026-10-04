//! Classic-BPF filter programs.
//!
//! The instruction encoding is shared between Linux (`SO_ATTACH_FILTER`) and the
//! BSD BPF device (`BIOCSETF`): [`BpfInsn`] aliases libc's per-OS name (`sock_filter` /
//! `bpf_insn`), so the same array installs on either backend.

#[cfg(target_os = "linux")]
pub(crate) type BpfInsn = libc::sock_filter;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) type BpfInsn = libc::bpf_insn;

const fn insn(code: u16, jt: u8, jf: u8, k: u32) -> BpfInsn {
    BpfInsn { code, jt, jf, k }
}

/// Accept IPv4 UDP or IPv6 UDP on an Ethernet link, drop everything else in-kernel. Of the IPv6
/// extension headers only a Fragment header directly after the base header is read. A priority
/// tag (802.1Q with VLAN ID 0) belongs to the untagged network and is read past, the index
/// register holding its length; a frame tagged for a VLAN is dropped.
///
/// ```text
///  0 ldx #0                   no tag
///  1 ldh [12]                 ethertype
///  2 jeq 0x8100 -> 3          else -> 6
///  3 ldh [14]                 tag control information
///  4 jset 0x0fff -> drop@17   else fall through: VLAN ID 0
///  5 ldx #4                   the tag's length
///  6 ldh [x+12]               ethertype past any tag
///  7 jeq 0x0800 -> IPv4@14    else fall through
///  8 jeq 0x86dd -> IPv6 fall  else drop@17
///  9 ldb [x+20]               IPv6 next-header
/// 10 jeq 17     -> accept@16  else fall through
/// 11 jeq 44     -> fall       else drop@17
/// 12 ldb [x+54]               the Fragment header's next header
/// 13 jeq 17     -> accept@16  else drop@17
/// 14 ldb [x+23]               IPv4 protocol
/// 15 jeq 17     -> accept@16  else drop@17
/// 16 ret 0xffffffff           accept
/// 17 ret 0                    drop
/// ```
pub(crate) const ETHERNET_UDP_FILTER: [BpfInsn; 18] = [
    insn(0x0001, 0, 0, 0x0000_0000),  // BPF_LDX|BPF_W|BPF_IMM X = 0
    insn(0x0028, 0, 0, 0x0000_000c),  // BPF_LD|BPF_H|BPF_ABS  [12] ethertype
    insn(0x0015, 0, 3, 0x0000_8100),  // BPF_JMP|BPF_JEQ|BPF_K 0x8100 802.1Q
    insn(0x0028, 0, 0, 0x0000_000e),  // BPF_LD|BPF_H|BPF_ABS  [14] tag control information
    insn(0x0045, 12, 0, 0x0000_0fff), // BPF_JMP|BPF_JSET|BPF_K a VLAN ID
    insn(0x0001, 0, 0, 0x0000_0004),  // BPF_LDX|BPF_W|BPF_IMM X = 4
    insn(0x0048, 0, 0, 0x0000_000c),  // BPF_LD|BPF_H|BPF_IND  [x+12] ethertype
    insn(0x0015, 6, 0, 0x0000_0800),  // BPF_JMP|BPF_JEQ|BPF_K 0x0800 IPv4
    insn(0x0015, 0, 8, 0x0000_86dd),  // BPF_JMP|BPF_JEQ|BPF_K 0x86dd IPv6
    insn(0x0050, 0, 0, 0x0000_0014),  // BPF_LD|BPF_B|BPF_IND  [x+20] IPv6 next-header
    insn(0x0015, 5, 0, 0x0000_0011),  // BPF_JMP|BPF_JEQ|BPF_K 17 UDP
    insn(0x0015, 0, 5, 0x0000_002c),  // BPF_JMP|BPF_JEQ|BPF_K 44 Fragment
    insn(0x0050, 0, 0, 0x0000_0036),  // BPF_LD|BPF_B|BPF_IND  [x+54] fragment next-header
    insn(0x0015, 2, 3, 0x0000_0011),  // BPF_JMP|BPF_JEQ|BPF_K 17 UDP
    insn(0x0050, 0, 0, 0x0000_0017),  // BPF_LD|BPF_B|BPF_IND  [x+23] IPv4 protocol
    insn(0x0015, 0, 1, 0x0000_0011),  // BPF_JMP|BPF_JEQ|BPF_K 17 UDP
    insn(0x0006, 0, 0, 0xffff_ffff),  // BPF_RET|BPF_K accept
    insn(0x0006, 0, 0, 0x0000_0000),  // BPF_RET|BPF_K drop
];

/// Prepended to a classifier on Linux kernels without `PACKET_IGNORE_OUTGOING`: the
/// `SKF_AD_PKTTYPE` ancillary load reads `skb->pkt_type`, and frames we sent
/// (`PACKET_OUTGOING`) are dropped.
///
/// ```text
/// ldb #pkttype                  skb->pkt_type via the ancillary offset
/// jeq PACKET_OUTGOING -> drop@2    else fall through to the classifier
/// ret 0                         drop
/// ```
#[cfg(target_os = "linux")]
pub(crate) const DROP_OUTGOING_PROLOGUE: [BpfInsn; 3] = [
    // BPF_LD|BPF_B|BPF_ABS: A = pkt_type, from the negative ancillary offset.
    insn(
        0x0030,
        0,
        0,
        (libc::SKF_AD_OFF + libc::SKF_AD_PKTTYPE).cast_unsigned(),
    ),
    // Our TX (PACKET_OUTGOING): jt=0 -> drop; else jf=1 -> the classifier below.
    // `u32::from` isn't const.
    insn(0x0015, 0, 1, libc::PACKET_OUTGOING as u32),
    insn(0x0006, 0, 0, 0x0000_0000), // BPF_RET|BPF_K drop
];

/// Prepended to the Ethernet classifier on Linux. The kernel moves an 802.1Q tag into
/// `skb->vlan_tci` before packet sockets on the parent interface see the frame, so without this
/// the classifier reads the inner ethertype and takes another VLAN's traffic as the parent's.
/// Untagged and priority-tagged (VID 0) frames fall through.
///
/// ```text
/// ld #vlan_tci             skb->vlan_tci via the ancillary offset
/// and 0x0fff               keep the VLAN ID
/// jeq 0 -> classifier      else fall through
/// ret 0                    drop
/// ```
#[cfg(target_os = "linux")]
pub(crate) const DROP_VLAN_TAGGED_PROLOGUE: [BpfInsn; 4] = [
    // BPF_LD|BPF_W|BPF_ABS: A = vlan_tci, from the negative ancillary offset.
    insn(
        0x0020,
        0,
        0,
        (libc::SKF_AD_OFF + libc::SKF_AD_VLAN_TAG).cast_unsigned(),
    ),
    insn(0x0054, 0, 0, 0x0000_0fff), // BPF_ALU|BPF_AND|BPF_K the VLAN ID
    insn(0x0015, 1, 0, 0x0000_0000), // BPF_JMP|BPF_JEQ|BPF_K 0: jt=1 -> the classifier
    insn(0x0006, 0, 0, 0x0000_0000), // BPF_RET|BPF_K drop
];

/// Accept IPv4 UDP or IPv6 UDP on a raw IP link (a Linux tunnel), IPv6 behind a Fragment header
/// too. No link header: the IP version nibble at offset 0 picks the layout.
///
/// ```text
///  0 ldb [0]                  version nibble + IHL / traffic class
///  1 and 0xf0                 keep the version
///  2 jeq 0x40 -> IPv4@9       else fall through
///  3 jeq 0x60 -> IPv6 fall    else drop@12
///  4 ldb [6]                  IPv6 next-header
///  5 jeq 17   -> accept@11    else fall through
///  6 jeq 44   -> fall         else drop@12
///  7 ldb [40]                 the Fragment header's next header
///  8 jeq 17   -> accept@11    else drop@12
///  9 ldb [9]                  IPv4 protocol
/// 10 jeq 17   -> accept@11    else drop@12
/// 11 ret 0xffffffff           accept
/// 12 ret 0                    drop
/// ```
#[cfg(target_os = "linux")]
pub(crate) const RAW_IP_UDP_FILTER: [BpfInsn; 13] = [
    insn(0x0030, 0, 0, 0x0000_0000), // BPF_LD|BPF_B|BPF_ABS  [0] version nibble + IHL
    insn(0x0054, 0, 0, 0x0000_00f0), // BPF_ALU|BPF_AND|BPF_K 0xf0 keep the version
    insn(0x0015, 6, 0, 0x0000_0040), // BPF_JMP|BPF_JEQ|BPF_K 4 IPv4
    insn(0x0015, 0, 8, 0x0000_0060), // BPF_JMP|BPF_JEQ|BPF_K 6 IPv6
    insn(0x0030, 0, 0, 0x0000_0006), // BPF_LD|BPF_B|BPF_ABS  [6] IPv6 next-header
    insn(0x0015, 5, 0, 0x0000_0011), // BPF_JMP|BPF_JEQ|BPF_K 17 UDP
    insn(0x0015, 0, 5, 0x0000_002c), // BPF_JMP|BPF_JEQ|BPF_K 44 Fragment
    insn(0x0030, 0, 0, 0x0000_0028), // BPF_LD|BPF_B|BPF_ABS  [40] fragment next-header
    insn(0x0015, 2, 3, 0x0000_0011), // BPF_JMP|BPF_JEQ|BPF_K 17 UDP
    insn(0x0030, 0, 0, 0x0000_0009), // BPF_LD|BPF_B|BPF_ABS  [9] IPv4 protocol
    insn(0x0015, 0, 1, 0x0000_0011), // BPF_JMP|BPF_JEQ|BPF_K 17 UDP
    insn(0x0006, 0, 0, 0xffff_ffff), // BPF_RET|BPF_K accept
    insn(0x0006, 0, 0, 0x0000_0000), // BPF_RET|BPF_K drop
];

/// The classic-BPF VM loads a word big-endian regardless of host, while a `DLT_NULL` frame
/// stores the family in host order, so the `jeq` constant is the family byte-swapped on a
/// little-endian host.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
const fn host_af_to_bpf_be(af: libc::c_int) -> u32 {
    af.cast_unsigned().to_be()
}

/// Accept IPv4 UDP or IPv6 UDP on a `DLT_NULL` link (BSD `lo0`), IPv6 behind a Fragment header
/// too. The link header is a 4-byte host-order address family, so the offsets differ from
/// Ethernet's.
///
/// ```text
///  0 ld  [0]                  load the 4-byte address family
///  1 jeq AF_INET  -> IPv4@8   else fall through
///  2 jeq AF_INET6 -> IPv6 fall  else drop@11
///  3 ldb [10]                 IPv6 next-header (4 + 6)
///  4 jeq 17       -> accept@10  else fall through
///  5 jeq 44       -> fall     else drop@11
///  6 ldb [44]                 the Fragment header's next header (4 + 40)
///  7 jeq 17       -> accept@10  else drop@11
///  8 ldb [13]                 IPv4 protocol (4 + 9)
///  9 jeq 17       -> accept@10  else drop@11
/// 10 ret 0xffffffff           accept
/// 11 ret 0                    drop
/// ```
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) const DLT_NULL_UDP_FILTER: [BpfInsn; 12] = [
    insn(0x0020, 0, 0, 0x0000_0000), // BPF_LD|BPF_W|BPF_ABS  [0] address family
    insn(0x0015, 6, 0, host_af_to_bpf_be(libc::AF_INET)), // BPF_JMP|BPF_JEQ|BPF_K AF_INET
    insn(0x0015, 0, 8, host_af_to_bpf_be(libc::AF_INET6)), // BPF_JMP|BPF_JEQ|BPF_K AF_INET6
    insn(0x0030, 0, 0, 0x0000_000a), // BPF_LD|BPF_B|BPF_ABS  [10] IPv6 next-header
    insn(0x0015, 5, 0, 0x0000_0011), // BPF_JMP|BPF_JEQ|BPF_K 17 UDP
    insn(0x0015, 0, 5, 0x0000_002c), // BPF_JMP|BPF_JEQ|BPF_K 44 Fragment
    insn(0x0030, 0, 0, 0x0000_002c), // BPF_LD|BPF_B|BPF_ABS  [44] fragment next-header
    insn(0x0015, 2, 3, 0x0000_0011), // BPF_JMP|BPF_JEQ|BPF_K 17 UDP
    insn(0x0030, 0, 0, 0x0000_000d), // BPF_LD|BPF_B|BPF_ABS  [13] IPv4 protocol
    insn(0x0015, 0, 1, 0x0000_0011), // BPF_JMP|BPF_JEQ|BPF_K 17 UDP
    insn(0x0006, 0, 0, 0xffff_ffff), // BPF_RET|BPF_K accept
    insn(0x0006, 0, 0, 0x0000_0000), // BPF_RET|BPF_K drop
];

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    use super::*;
    use crate::net::frame::{LinkHeader, UdpFrames};
    use crate::net::mac::MacAddr;

    const ACCEPT: u32 = u32::MAX;

    /// Run a classifier over `frame` as the kernel would: loads are big-endian, and one past the
    /// end drops the frame. Only the opcodes the classifiers use are modeled.
    fn run(program: &[BpfInsn], frame: &[u8]) -> u32 {
        let (mut a, mut x) = (0u32, 0u32);
        let mut pc = 0;
        loop {
            let BpfInsn { code, jt, jf, k } = program[pc];
            pc += 1;
            let load = |offset: u32, size: usize| {
                let start = usize::try_from(offset).ok()?;
                let bytes = frame.get(start..start + size)?;
                Some(
                    bytes
                        .iter()
                        .fold(0, |word, &byte| word << 8 | u32::from(byte)),
                )
            };
            let loaded = match code {
                0x0020 => load(k, 4),
                0x0028 => load(k, 2),
                0x0030 => load(k, 1),
                0x0048 => load(x + k, 2),
                0x0050 => load(x + k, 1),
                0x0001 => {
                    x = k;
                    continue;
                }
                0x0054 => Some(a & k),
                0x0015 => {
                    pc += usize::from(if a == k { jt } else { jf });
                    continue;
                }
                0x0045 => {
                    pc += usize::from(if a & k != 0 { jt } else { jf });
                    continue;
                }
                0x0006 => return k,
                _ => panic!("opcode {code:#06x} is not modeled"),
            };
            let Some(loaded) = loaded else {
                return 0;
            };
            a = loaded;
        }
    }

    /// Whole and fragmented UDP datagrams of both families on `link`.
    fn udp_frames(link: LinkHeader) -> Vec<Vec<u8>> {
        let payload = [0x42; 1000];
        let v4_src = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 3702);
        let v4_dst = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 40000);
        let v6_src = SocketAddrV6::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 3702, 0, 0);
        let v6_dst = SocketAddrV6::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2), 40000, 0, 0);
        let mut frames = Vec::new();
        for mtu in [1500, 600] {
            let datagrams = [
                UdpFrames::ipv4(link, v4_src, v4_dst, 64, 1, &payload, mtu).unwrap(),
                UdpFrames::ipv6(link, v6_src, v6_dst, 64, 1, &payload, mtu).unwrap(),
            ];
            for datagram in datagrams {
                for index in 0..datagram.count() {
                    let mut frame = vec![0u8; 2048];
                    let n = datagram.write(index, &mut frame).unwrap();
                    frame.truncate(n);
                    frames.push(frame);
                }
            }
        }
        assert_eq!(frames.len(), 6, "a whole and two fragments per family");
        frames
    }

    /// `frames` carrying another protocol than UDP: TCP in the IPv4 protocol, the IPv6 next
    /// header, or the Fragment header's next header; or a hop-by-hop header ahead of UDP.
    fn not_udp(frames: &[Vec<u8>], l3: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for frame in frames {
            let mut tcp = frame.clone();
            match frame[l3] >> 4 {
                4 => tcp[l3 + 9] = 6,
                _ if frame[l3 + 6] == 44 => tcp[l3 + 40] = 6,
                _ => {
                    tcp[l3 + 6] = 6;
                    let mut hop_by_hop = frame.clone();
                    hop_by_hop[l3 + 6] = 0;
                    out.push(hop_by_hop);
                }
            }
            out.push(tcp);
        }
        out
    }

    fn check(program: &[BpfInsn], link: LinkHeader, l3: usize) {
        let frames = udp_frames(link);
        for frame in &frames {
            assert_eq!(run(program, frame), ACCEPT, "dropped {frame:02x?}");
        }
        for frame in not_udp(&frames, l3) {
            assert_eq!(run(program, &frame), 0, "accepted {frame:02x?}");
        }
    }

    #[test]
    fn the_ethernet_classifier_takes_udp_and_its_fragments() {
        let link = LinkHeader::Ethernet {
            dst: MacAddr::broadcast(),
            src: MacAddr::broadcast(),
        };
        check(&ETHERNET_UDP_FILTER, link, 14);
        // Behind a priority tag still; behind a VLAN's, never.
        for frame in udp_frames(link) {
            let tagged = |tci: u16| {
                let [hi, lo] = tci.to_be_bytes();
                [&frame[..12], &[0x81, 0x00, hi, lo], &frame[12..]].concat()
            };
            assert_eq!(run(&ETHERNET_UDP_FILTER, &tagged(0xa000)), ACCEPT);
            assert_eq!(run(&ETHERNET_UDP_FILTER, &tagged(0xa01e)), 0);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_raw_ip_classifier_takes_udp_and_its_fragments() {
        check(&RAW_IP_UDP_FILTER, LinkHeader::RawIp, 0);
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn the_dlt_null_classifier_takes_udp_and_its_fragments() {
        check(&DLT_NULL_UDP_FILTER, LinkHeader::DltNull, 4);
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn dlt_null_family_constants_match_a_bpf_word_load() {
        // The DLT_NULL frame stores the family in host byte order; the BPF VM loads
        // that word big-endian. The filter's jeq constant must equal that view, or
        // it matches no frame at all.
        for af in [libc::AF_INET, libc::AF_INET6] {
            let as_the_vm_loads_it = u32::from_be_bytes(af.cast_unsigned().to_ne_bytes());
            assert_eq!(host_af_to_bpf_be(af), as_the_vm_loads_it);
        }
    }
}
