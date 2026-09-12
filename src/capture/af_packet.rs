//! `AF_PACKET` packet capture (Linux).
//!
//! Init order matters: the socket opens with protocol 0 and captures nothing, so the filter
//! and the loop-prevention option go in before `bind` sets the real protocol and starts
//! delivery; no unfiltered frame (an IGMP from a multicast join, say) ever queues. The BSD
//! backend binds first and relies on `BIOCSETF` flushing the kernel buffer.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use libc::{c_int, c_void};

use super::Read;
use super::filter::{BpfInsn, DROP_OUTGOING_PROLOGUE, ETHERNET_UDP_FILTER, RAW_IP_UDP_FILTER};
use crate::interface::if_index;
use crate::logging::{WARN_WINDOW, log_rate};
use crate::net::LinkType;
use crate::sys::{IoStatus, check, open_socket, setsockopt, socklen_of};

/// A raw-capture handle on one interface. No cached ifindex: the bind holds it, so nothing
/// here goes stale when the index changes.
pub(crate) struct Capture {
    fd: OwnedFd,
    buf: Box<[u8]>,
    link_type: LinkType,
    name: String,
}

impl Capture {
    /// Open an `AF_PACKET` capture bound to `if_name`.
    ///
    /// # Errors
    /// An unknown interface, a hardware type neither Ethernet nor raw IP, or a failed
    /// socket/filter/bind.
    pub(crate) fn open(if_name: &str) -> io::Result<Self> {
        // Protocol 0: nothing is captured until the bind.
        let fd = open_socket(libc::AF_PACKET, libc::SOCK_RAW, 0)?;
        let link_type = attach(&fd, if_name)?;
        log::debug!(
            "opened AF_PACKET capture on {if_name} (fd {}, {link_type:?})",
            fd.as_raw_fd()
        );
        Ok(Self {
            fd,
            buf: vec![0u8; crate::net::MAX_FRAME_LEN].into_boxed_slice(),
            link_type,
            name: if_name.into(),
        })
    }

    /// Re-attach to the interface named at open, after it was recreated. Same fd, so the
    /// reactor's watch stays valid.
    ///
    /// # Errors
    /// [`io::ErrorKind::NotFound`] while no interface bears the name; otherwise the attach
    /// failure.
    pub(crate) fn rebind(&mut self) -> io::Result<()> {
        self.link_type = attach(&self.fd, &self.name)?;
        // The kernel parked ENETDOWN on the socket when the old interface died; consume it so
        // the first post-rebind recv surfaces frames, not the stale failure.
        match crate::sys::so_error(self.fd.as_raw_fd()) {
            Ok(0) => {}
            Ok(errno) => log::debug!(
                "cleared a pending error on the re-bound capture for {}: {}",
                self.name,
                io::Error::from_raw_os_error(errno)
            ),
            // Can't fail on a live fd (SO_ERROR is generic); if it does, the next read surfaces
            // the stale error.
            Err(e) => log::warn!(
                "could not clear the pending error on the re-bound capture for {}: {e}",
                self.name
            ),
        }
        log::debug!(
            "re-bound AF_PACKET capture to {} ({:?})",
            self.name,
            self.link_type
        );
        Ok(())
    }

    /// Whether the socket is still bound to the live interface `ifindex`. The kernel resets the
    /// bound index to -1 when the interface is unregistered, so a destroyed or recreated
    /// interface compares unequal.
    pub(crate) fn attached(&self, ifindex: u32) -> bool {
        // SAFETY: an all-zero sockaddr_ll is a valid out-param; the kernel fills it up to `len`.
        let mut addr: libc::sockaddr_ll = unsafe { core::mem::zeroed() };
        let mut len = socklen_of::<libc::sockaddr_ll>();
        // SAFETY: `addr`/`len` are valid out-params for the socket's own address.
        let rc = unsafe {
            libc::getsockname(
                self.fd.as_raw_fd(),
                (&raw mut addr).cast::<libc::sockaddr>(),
                &raw mut len,
            )
        };
        rc == 0 && u32::try_from(addr.sll_ifindex).is_ok_and(|bound| bound == ifindex)
    }

    pub(crate) fn link_type(&self) -> LinkType {
        self.link_type
    }

    pub(crate) fn if_name(&self) -> &str {
        &self.name
    }

    /// `Ok(None)` when a read would block.
    ///
    /// # Errors
    /// A `recv` failure other than would-block.
    pub(crate) fn next_frame(&mut self) -> io::Result<Option<Read<'_>>> {
        let Some(bytes) = self.recv_once()? else {
            return Ok(None);
        };
        // MSG_TRUNC reports the frame's real length even past the buffer, so an oversized
        // frame is dropped instead of silently cut.
        if bytes > self.buf.len() {
            // A remote peer can flood oversized frames.
            log_rate!(
                log::Level::Warn,
                WARN_WINDOW,
                "{}: dropping oversized frame: {bytes} bytes exceeds the {}-byte receive \
                 buffer",
                self.name,
                self.buf.len()
            );
            return Ok(Some(Read::Oversized));
        }
        Ok(Some(Read::Frame(&self.buf[..bytes])))
    }

    /// Never: each `recv` is one frame, so a level-triggered wait re-fires while the socket
    /// has more.
    #[allow(clippy::unused_self)] // uniform Capture API; the BPF backend reads self
    pub(crate) fn has_buffered(&self) -> bool {
        false
    }

    /// The kernel parks `ENETDOWN` on a packet socket whose interface was unregistered.
    pub(crate) fn lost_interface(err: &io::Error) -> bool {
        err.raw_os_error() == Some(libc::ENETDOWN)
    }

    /// Inject a fully-built link-layer `frame` on this interface.
    ///
    /// # Errors
    /// A failed or short send.
    pub(crate) fn send(&self, frame: &[u8]) -> io::Result<()> {
        // A plain `send` on the bound SOCK_RAW socket suffices, no `sockaddr_ll`. On a raw IP
        // link the kernel reads the protocol off the IP version (Linux 5.8+).
        // SAFETY: `frame` is a valid readable slice of `frame.len()` bytes.
        let sent = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                frame.as_ptr().cast::<c_void>(),
                frame.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if usize::try_from(sent).expect("send result is non-negative") != frame.len() {
            return Err(io::Error::other("short send to AF_PACKET socket"));
        }
        Ok(())
    }

    /// One `recv` into the buffer; `Ok(None)` when it would block.
    fn recv_once(&mut self) -> io::Result<Option<usize>> {
        // SAFETY: `recv` writes up to `buf.len()` bytes into our own buffer.
        let n = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                self.buf.as_mut_ptr().cast::<c_void>(),
                self.buf.len(),
                libc::MSG_TRUNC,
            )
        };
        match IoStatus::from_syscall(n)? {
            IoStatus::Ready(len) => Ok(Some(len)),
            IoStatus::WouldBlock => Ok(None),
        }
    }
}

impl AsRawFd for Capture {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// The filter goes in before the bind, so no frame is ever delivered unfiltered.
fn attach(fd: &OwnedFd, if_name: &str) -> io::Result<LinkType> {
    let ifindex = resolve_ifindex(if_name)?;
    let link_type = link_type_of(fd, if_name)?;
    install_filter(fd, link_type)?;
    bind_interface(fd, link_addr(ifindex))?;
    Ok(link_type)
}

/// Ethernet (a loopback is framed the same) or raw IP (`ARPHRD_NONE`: `WireGuard`, tun).
fn link_type_of(fd: &OwnedFd, if_name: &str) -> io::Result<LinkType> {
    // SAFETY: an all-zero `ifreq` is valid (a zeroed name and union).
    let mut ifr: libc::ifreq = unsafe { core::mem::zeroed() };
    let n = if_name.len().min(libc::IFNAMSIZ - 1);
    // SAFETY: copy `n` name bytes into the zeroed `c_char` buffer (same layout as `u8`);
    // the trailing zero keeps it NUL-terminated.
    unsafe {
        std::ptr::copy_nonoverlapping(if_name.as_ptr(), ifr.ifr_name.as_mut_ptr().cast::<u8>(), n);
    }
    let request =
        libc::Ioctl::try_from(libc::SIOCGIFHWADDR).expect("SIOCGIFHWADDR fits the request type");
    // SAFETY: the ioctl reads the name and writes the hardware address back into the union; any
    // socket serves it.
    check(unsafe { libc::ioctl(fd.as_raw_fd(), request, &raw mut ifr) })?;
    // SAFETY: a successful ioctl wrote `ifru_hwaddr`, whose family is the hardware type.
    match unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_family } {
        libc::ARPHRD_ETHER | libc::ARPHRD_LOOPBACK => Ok(LinkType::Ethernet),
        libc::ARPHRD_NONE => Ok(LinkType::RawIp),
        other => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("hardware type {other} is neither Ethernet nor a raw IP link"),
        )),
    }
}

/// The UDP classifier plus loop prevention. `PACKET_IGNORE_OUTGOING` is Linux 4.20+ and
/// user-mode QEMU rejects it; without it an in-filter drop precedes the classifier. A hairpin
/// bridge port returns our frames as received ones and gets past both; the dispatcher's echo
/// drop catches those.
fn install_filter(fd: &OwnedFd, link_type: LinkType) -> io::Result<()> {
    let classifier: &[BpfInsn] = match link_type {
        LinkType::Ethernet => &ETHERNET_UDP_FILTER,
        LinkType::RawIp => &RAW_IP_UDP_FILTER,
    };
    match set_ignore_outgoing(fd) {
        Ok(()) => attach_filter(fd, classifier),
        Err(e) => {
            log::info!(
                "PACKET_IGNORE_OUTGOING unavailable ({e}); dropping our own frames in the BPF \
                 filter"
            );
            attach_filter(fd, &drop_outgoing_filter(classifier))
        }
    }
}

fn drop_outgoing_filter(classifier: &[BpfInsn]) -> Vec<BpfInsn> {
    DROP_OUTGOING_PROLOGUE
        .iter()
        .chain(classifier)
        .copied()
        .collect()
}

fn resolve_ifindex(if_name: &str) -> io::Result<c_int> {
    let ifindex = if_index(if_name).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface {if_name} not found"),
        )
    })?;
    c_int::try_from(ifindex).map_err(|_| io::Error::other("interface index too large"))
}

fn link_addr(ifindex: c_int) -> libc::sockaddr_ll {
    // SAFETY: all-zero is a valid `sockaddr_ll`: integer and byte-array fields only.
    let mut addr: libc::sockaddr_ll = unsafe { core::mem::zeroed() };
    addr.sll_family = u16::try_from(libc::AF_PACKET).expect("AF_PACKET fits u16");
    addr.sll_ifindex = ifindex;
    addr
}

fn set_ignore_outgoing(fd: &OwnedFd) -> io::Result<()> {
    setsockopt(
        fd.as_raw_fd(),
        libc::SOL_PACKET,
        libc::PACKET_IGNORE_OUTGOING,
        &1 as &c_int,
    )
}

fn attach_filter(fd: &OwnedFd, filter: &[BpfInsn]) -> io::Result<()> {
    let program = libc::sock_fprog {
        len: u16::try_from(filter.len()).expect("filter length fits u16"),
        // The kernel only reads the program, so the const-to-mut cast is sound.
        filter: filter.as_ptr().cast_mut(),
    };
    setsockopt(
        fd.as_raw_fd(),
        libc::SOL_SOCKET,
        libc::SO_ATTACH_FILTER,
        &program,
    )
}

fn bind_interface(fd: &OwnedFd, mut addr: libc::sockaddr_ll) -> io::Result<()> {
    addr.sll_protocol = u16::try_from(libc::ETH_P_ALL)
        .expect("ETH_P_ALL fits u16")
        .to_be();
    // SAFETY: `addr` is a fully-initialized `sockaddr_ll` of the given length.
    check(unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&raw const addr).cast::<libc::sockaddr>(),
            socklen_of::<libc::sockaddr_ll>(),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6, UdpSocket};
    use std::time::{Duration, Instant};

    use super::*;
    use crate::net::frame;
    use crate::net::mac::MacAddr;
    use crate::test_support::{Tun, loopback_lock, open_or_skip};

    /// How long a live tun test waits for a packet to cross the device.
    const WAIT_BUDGET: Duration = Duration::from_secs(2);

    /// `BpfInsn` is libc's type, which derives no `PartialEq`/`Debug`; compare as field tuples.
    fn as_tuples(insns: &[BpfInsn]) -> Vec<(u16, u8, u8, u32)> {
        insns.iter().map(|i| (i.code, i.jt, i.jf, i.k)).collect()
    }

    #[test]
    fn drop_outgoing_filter_prepends_the_prologue() {
        for classifier in [&ETHERNET_UDP_FILTER[..], &RAW_IP_UDP_FILTER[..]] {
            let filter = drop_outgoing_filter(classifier);
            assert_eq!(
                as_tuples(&filter[..DROP_OUTGOING_PROLOGUE.len()]),
                as_tuples(&DROP_OUTGOING_PROLOGUE)
            );
            assert_eq!(
                as_tuples(&filter[DROP_OUTGOING_PROLOGUE.len()..]),
                as_tuples(classifier)
            );
        }
    }

    /// A bare IPv4 UDP datagram and a bare IPv6 one, each carrying `payload`.
    fn bare_datagrams(payload: &[u8]) -> [Vec<u8>; 2] {
        let mut buf = [0u8; 128];
        let v4 = frame::ipv4_udp(
            SocketAddrV4::new(Ipv4Addr::new(10, 99, 200, 2), 40000),
            SocketAddrV4::new(Ipv4Addr::new(10, 99, 200, 1), 40001),
            64,
            payload,
            &mut buf,
        )
        .expect("build the IPv4 datagram");
        let v4 = buf[..v4].to_vec();
        let v6 = frame::ipv6_udp(
            SocketAddrV6::new("fd00:99::2".parse().unwrap(), 40000, 0, 0),
            SocketAddrV6::new("fd00:99::1".parse().unwrap(), 40001, 0, 0),
            64,
            payload,
            &mut buf,
        )
        .expect("build the IPv6 datagram");
        [v4, buf[..v6].to_vec()]
    }

    /// Whether `capture` yields a frame equal to `want` within [`WAIT_BUDGET`].
    fn captures(capture: &mut Capture, want: &[u8]) -> io::Result<bool> {
        let deadline = Instant::now() + WAIT_BUDGET;
        while Instant::now() < deadline {
            while let Some(read) = capture.next_frame()? {
                if matches!(read, Read::Frame(frame) if frame == want) {
                    return Ok(true);
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(false)
    }

    // Live raw IP link, receive side: a tun device is `ARPHRD_NONE`, so a packet its far end
    // writes is captured as the bare IP packet it is, in either family.
    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn a_tun_link_captures_bare_ip_packets() -> io::Result<()> {
        let Some(mut tun) = Tun::create() else {
            return Ok(());
        };
        let mut capture = Capture::open(&tun.name)?;
        assert_eq!(capture.link_type(), LinkType::RawIp);
        for packet in bare_datagrams(b"netflector-tun-in") {
            tun.far_end.write_all(&packet)?;
            assert!(
                captures(&mut capture, &packet)?,
                "did not capture the IPv{} packet written to {}",
                packet[0] >> 4,
                tun.name
            );
        }
        Ok(())
    }

    // Live raw IP link, send side: a packet sent on the capture comes out of the tun's far end
    // as the bare IP packet it was built as, in either family.
    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn a_tun_link_sends_bare_ip_packets() -> io::Result<()> {
        let Some(tun) = Tun::create() else {
            return Ok(());
        };
        let capture = Capture::open(&tun.name)?;
        for packet in bare_datagrams(b"netflector-tun-out") {
            capture.send(&packet)?;
            assert!(
                tun.read_until(&packet)?,
                "the IPv{} packet sent on {} did not reach its far end",
                packet[0] >> 4,
                tun.name
            );
        }
        Ok(())
    }

    // Live capture against the real kernel: send UDP to 127.0.0.1 and capture the
    // looped frame off `lo`. Validates the open/filter/bind/recv path and that lo
    // is Ethernet-framed. PACKET_IGNORE_OUTGOING drops the TX copy; we see the RX one.
    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn captures_a_known_frame_on_lo() -> io::Result<()> {
        const PROBE: &[u8] = b"netflector-afpacket-capture-probe";
        let _serial = loopback_lock();
        let Some(mut capture) = open_or_skip("lo", "afpacket_capture")? else {
            return Ok(());
        };
        assert_eq!(capture.link_type(), LinkType::Ethernet);

        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = receiver.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();

        // An lo frame is [14-byte Ethernet][IPv4][UDP][payload]; finding our payload
        // at the tail behind an IPv4/IPv6 ethertype proves the layout decoded. The
        // capture is armed before the send, and the looped frame waits in the socket
        // buffer until drained, so one send then polling captures it.
        sender.send_to(PROBE, target).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut decoded = false;
        while !decoded && std::time::Instant::now() < deadline {
            while let Some(read) = capture.next_frame()? {
                let Read::Frame(frame) = read else {
                    continue;
                };
                if frame.len() >= 14 && frame.ends_with(PROBE) {
                    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
                    assert!(ethertype == 0x0800 || ethertype == 0x86dd);
                    decoded = true;
                    break;
                }
            }
            if !decoded {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
        assert!(decoded, "did not capture our UDP probe on lo");
        Ok(())
    }

    // A frame past the receive buffer is dropped, but it still costs a read, so the drain
    // budget counts it: one oversized datagram on lo yields one `Read::Oversized`.
    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn an_oversized_frame_costs_a_read() -> io::Result<()> {
        let _serial = loopback_lock();
        let Some(mut capture) = open_or_skip("lo", "afpacket_oversized")? else {
            return Ok(());
        };
        let receiver = UdpSocket::bind("127.0.0.1:0")?;
        let sender = UdpSocket::bind("127.0.0.1:0")?;
        // lo's MTU carries it whole, so it arrives as one frame past MAX_FRAME_LEN.
        sender.send_to(
            &[0u8; 2 * crate::net::MAX_FRAME_LEN],
            receiver.local_addr()?,
        )?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match capture.next_frame()? {
                Some(Read::Oversized) => break,
                Some(Read::Frame(_)) => {} // unrelated loopback traffic
                None if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                None => panic!("did not capture the oversized datagram on lo"),
            }
        }
        Ok(())
    }

    // Live send: inject a built Ethernet frame on `lo` via send(), then capture it
    // back. lo loops every transmitted frame to its input tap, and we keep the RX
    // copy (PACKET_IGNORE_OUTGOING drops only the TX copy), so this validates that
    // send() actually puts the frame on the wire. (Whether the local IP stack then
    // delivers a raw-injected loopback frame to a socket is kernel-specific, and not
    // what send() is for: on a real interface it reaches other hosts, not us.)
    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn send_loops_back_on_lo() -> io::Result<()> {
        const PROBE: &[u8] = b"netflector-afpacket-send-probe";
        let _serial = loopback_lock();
        let Some(mut capture) = open_or_skip("lo", "afpacket_send")? else {
            return Ok(());
        };

        let src = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40000);
        let dst = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40001);
        let mac = MacAddr::broadcast();
        let mut buf = [0u8; 256];
        let n = frame::ethernet_ipv4_udp(mac, mac, src, dst, 64, PROBE, &mut buf)
            .expect("build Ethernet frame");

        // The injected frame loops to the input tap and waits there until drained, so
        // one send then polling captures it.
        capture.send(&buf[..n]).expect("send on lo");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut looped = false;
        while !looped && std::time::Instant::now() < deadline {
            while let Some(read) = capture.next_frame()? {
                let Read::Frame(frame) = read else {
                    continue;
                };
                if frame.ends_with(PROBE) {
                    looped = true;
                    break;
                }
            }
            if !looped {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
        assert!(
            looped,
            "did not capture our injected frame looped back on lo"
        );
        Ok(())
    }
}
