//! Raw L2 packet capture: a per-interface handle the reactor can poll. BPF on
//! macOS/FreeBSD, `AF_PACKET` on Linux; frames are read into a reused buffer,
//! no per-frame allocation.

mod filter;

#[cfg(target_os = "linux")]
mod af_packet;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod bpf;

#[cfg(target_os = "linux")]
pub(crate) use self::af_packet::Capture;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) use self::bpf::Capture;

/// One read of a capture.
#[derive(Debug)]
pub(crate) enum Read<'a> {
    Frame(&'a [u8]),
    /// A frame too large to forward, dropped and counted.
    Oversized,
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};

    use super::Read;
    use crate::interface::InterfaceName;
    use crate::net::{LinkType, MAX_DATAGRAM_LEN};
    use crate::test_support::{Capability, loopback_lock, open_or_skip, skip};

    // Live capture against a real interface (`NETFLECTOR_TEST_IFACE`). Backend-neutral
    // because a real interface is Ethernet-framed on both backends: BPF reports
    // DLT_EN10MB, AF_PACKET delivers the Ethernet header.
    #[test]
    fn live_capture_decodes_real_frames() -> std::io::Result<()> {
        let Some(iface) = std::env::var_os("NETFLECTOR_TEST_IFACE") else {
            eprintln!("skip live_capture: set NETFLECTOR_TEST_IFACE to an Ethernet interface");
            return Ok(());
        };
        let iface: InterfaceName = iface
            .to_string_lossy()
            .parse()
            .expect("NETFLECTOR_TEST_IFACE is an interface name");
        let Some(mut capture) = open_or_skip(&iface)? else {
            return Ok(());
        };
        assert_eq!(capture.link_type(), LinkType::Ethernet);

        // Every frame the kernel filter passed must be an IPv4/IPv6 Ethernet frame, so a
        // mis-sliced header would corrupt these.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut validated = 0u32;
        while validated < 8 && std::time::Instant::now() < deadline {
            match capture.next_frame()? {
                Some(Read::Oversized) => {}
                Some(Read::Frame(frame)) => {
                    assert!(frame.len() >= 14, "frame shorter than an Ethernet header");
                    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
                    assert!(
                        ethertype == 0x0800 || ethertype == 0x86dd,
                        "filter passed a non-IP ethertype {ethertype:#06x}",
                    );
                    validated += 1;
                }
                None => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
        eprintln!("live_capture: validated {validated} frame(s) on {iface}");
        Ok(())
    }

    // A kernel can hand its own tap a datagram it reassembled, past the link MTU: a Linux bridge
    // whose br_netfilter hook runs conntrack defrag does. Loopback carries one whole the same
    // way, and the largest one the reassembler takes is read, not dropped as oversized.
    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn a_datagram_at_the_reassembly_limit_is_read_whole() -> std::io::Result<()> {
        let _serial = loopback_lock();
        let Some(mut capture) = open_or_skip(&InterfaceName::loopback())? else {
            return Ok(());
        };
        let payload = vec![0x5a; MAX_DATAGRAM_LEN - 8]; // the limit counts the UDP header
        for local in ["127.0.0.1:0", "[::1]:0"] {
            let Ok(receiver) = UdpSocket::bind(local) else {
                skip(Capability::Ipv6, "::1 unavailable");
                continue;
            };
            let sender = UdpSocket::bind(local)?;
            sender.send_to(&payload, receiver.local_addr()?)?;
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut oversized = 0;
            loop {
                match capture.next_frame()? {
                    Some(Read::Frame(frame)) if frame.ends_with(&payload) => break,
                    Some(Read::Frame(_)) => {}
                    Some(Read::Oversized) => oversized += 1,
                    None if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    None => panic!(
                        "the datagram to {} was not read whole ({oversized} oversized)",
                        receiver.local_addr()?
                    ),
                }
            }
        }
        Ok(())
    }
}
