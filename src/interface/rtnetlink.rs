//! Linux address resolution over rtnetlink (`NETLINK_ROUTE`): one `RTM_GETADDR` dump for the
//! v4/v6 addresses (each carrying its `IFA_FLAGS`, so tentative/deprecated/dadfailed are
//! filtered inline) and one `RTM_GETLINK` dump for the MAC. The netlink message framing is
//! hand-rolled: `libc` exposes it for Android only, not glibc/musl.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::ptr;

use libc::{c_int, socklen_t};

use super::{InterfaceAddresses, V6Pick, v6_rank};
use crate::libcex::{
    IfAddrMsg, NETLINK_ROUTE, NLM_F_DUMP, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, NlMsgHdr, RtAttr,
    SockAddrNl, nl_align,
};
use crate::net::mac::MacAddr;

/// `IFA_F_*` bits that disqualify an address as a source.
const IFA_F_UNUSABLE: u32 = libc::IFA_F_TENTATIVE | libc::IFA_F_DEPRECATED | libc::IFA_F_DADFAILED;

/// Iterator over the `rtattr` TLVs of a message: yields `(attr_type, value)`, stopping at the
/// first malformed length (as the kernel's own walk does).
struct RtAttrs<'a> {
    msg: &'a [u8],
    at: usize,
}

/// The `rtattr` TLVs of `msg` starting at byte offset `from`.
fn rtattrs(msg: &[u8], from: usize) -> RtAttrs<'_> {
    RtAttrs { msg, at: from }
}

impl<'a> Iterator for RtAttrs<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let rta = read_at::<RtAttr>(self.msg, self.at)?;
        let rta_len = rta.len as usize;
        if rta_len < size_of::<RtAttr>() || self.at + rta_len > self.msg.len() {
            return None;
        }
        let data = &self.msg[self.at + size_of::<RtAttr>()..self.at + rta_len];
        self.at += nl_align(rta_len);
        Some((rta.attr_type, data))
    }
}

/// Read a `repr(C)` POD `T` at `off` in `buf`, or `None` if `buf` is too short (or `off`
/// overflows). Tolerates any alignment. `T` must be a plain wire struct: no padding-sensitive
/// invariants, no `Drop`. The netlink headers/bodies all qualify.
pub(super) fn read_at<T>(buf: &[u8], off: usize) -> Option<T> {
    if off.checked_add(size_of::<T>())? > buf.len() {
        return None;
    }
    // SAFETY: the bound check guarantees a full `T` lies within `buf`; `read_unaligned` imposes
    // no alignment requirement, and `T` is a plain wire struct.
    Some(unsafe { ptr::read_unaligned(buf.as_ptr().add(off).cast::<T>()) })
}

/// Resolve interface `ifindex`'s current source addresses with two netlink dumps:
/// `RTM_GETADDR` for v4/v6 (flag-filtered, link-local > ULA > global) and `RTM_GETLINK` for
/// the MAC. `if_name` is for tracing only; the dumps are filtered by `ifindex`. A `0`
/// `ifindex` (the caller's "unknown interface" sentinel) skips the dumps.
///
/// # Errors
/// Returns an error if a netlink socket, request, or reply fails.
pub(super) fn resolve(if_name: &str, ifindex: u32) -> io::Result<InterfaceAddresses> {
    if ifindex == 0 {
        return Ok(InterfaceAddresses::default());
    }

    let sock = netlink_socket()?;
    let mut addrs = InterfaceAddresses::default();

    let mut v6_pick = V6Pick::default();
    dump(
        &sock,
        libc::RTM_GETADDR,
        libc::RTM_NEWADDR,
        IfAddrMsg::default(),
        |msg| {
            scan_addr(msg, if_name, ifindex, &mut addrs, &mut v6_pick);
        },
    )?;
    // SAFETY: a zeroed `ifinfomsg` (an all-integer POD) is a valid `AF_UNSPEC` link-dump request body.
    let link_req: libc::ifinfomsg = unsafe { std::mem::zeroed() };
    dump(
        &sock,
        libc::RTM_GETLINK,
        libc::RTM_NEWLINK,
        link_req,
        |msg| {
            scan_link(msg, if_name, ifindex, &mut addrs);
        },
    )?;

    Ok(addrs)
}

fn netlink_socket() -> io::Result<OwnedFd> {
    // SAFETY: `socket` returns a fresh fd or -1.
    crate::sys::owned_fd_from(unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_ROUTE,
        )
    })
}

/// Send a dump request (`request_type` + `body`) and feed every reply of `reply_type` to
/// `on_msg`, until `NLMSG_DONE`.
fn dump<B>(
    sock: &OwnedFd,
    request_type: u16,
    reply_type: u16,
    body: B,
    mut on_msg: impl FnMut(&[u8]),
) -> io::Result<()> {
    #[repr(C)]
    struct Request<B> {
        hdr: NlMsgHdr,
        body: B,
    }
    let req = Request {
        hdr: NlMsgHdr {
            len: u32::try_from(size_of::<Request<B>>()).expect("request fits a u32"),
            msg_type: request_type,
            flags: NLM_F_REQUEST | NLM_F_DUMP,
            seq: 1,
            pid: 0,
        },
        body,
    };
    // SAFETY: `req` is fully initialized; send its bytes to the netlink socket.
    let sent = unsafe {
        libc::send(
            sock.as_raw_fd(),
            (&raw const req).cast(),
            size_of::<Request<B>>(),
            0,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    // Grows to whatever the largest datagram needs (see the peek below); reused across
    // datagrams, so it reallocates at most a few times over a dump.
    let mut buf: Vec<u8> = Vec::new();
    loop {
        // Size the next datagram before reading it: MSG_PEEK leaves it queued while MSG_TRUNC
        // reports its true length. Reading into a zero-length buffer learns the size; an
        // oversized message then grows `buf` rather than being silently truncated.
        // SAFETY: a zero-length read dereferences nothing, so the null pointer is never read.
        let size = unsafe {
            libc::recv(
                sock.as_raw_fd(),
                ptr::null_mut(),
                0,
                libc::MSG_PEEK | libc::MSG_TRUNC,
            )
        };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        // Infallible: the negative (error) case returned above, and a non-negative `isize`
        // always fits `usize`.
        let size = usize::try_from(size).expect("recv count is non-negative");
        buf.resize(size, 0);

        let mut src = SockAddrNl::default();
        let mut addrlen =
            socklen_t::try_from(size_of::<SockAddrNl>()).expect("sockaddr_nl fits socklen_t");
        // SAFETY: `recvfrom` fills up to `buf.len()` bytes of the owned buffer (now the whole
        // datagram) and writes the source address into the `src`/`addrlen` out-params.
        let received = unsafe {
            libc::recvfrom(
                sock.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                (&raw mut src).cast::<libc::sockaddr>(),
                &raw mut addrlen,
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        // Only the kernel (nl_pid == 0) may answer the dump; a local process could unicast a spoofed
        // reply to inject a bogus address. Discard anything else and read the next datagram.
        if src.pid != 0 {
            log::debug!(
                "netlink dump: ignoring a reply from a non-kernel sender (pid {})",
                src.pid
            );
            continue;
        }
        let received = usize::try_from(received).expect("recv count is non-negative");

        match walk_dump(&buf[..received], reply_type, &mut on_msg) {
            DumpStep::Done => return Ok(()),
            DumpStep::Failed(e) => return Err(e),
            DumpStep::More => {} // read the next datagram
        }
    }
}

/// One dump datagram's outcome from [`walk_dump`].
enum DumpStep {
    /// `NLMSG_DONE`: the dump is complete.
    Done,
    /// `NLMSG_ERROR`: the kernel reported a dump error (carrying its errno).
    Failed(io::Error),
    /// The datagram was fully walked; read the next one.
    More,
}

/// Walk one dump datagram, feeding each `reply_type` message to `on_msg`, and report whether the dump is
/// done, failed, or needs another datagram. Split from [`dump`]'s socket loop so the message walk (and
/// its bounds handling) is unit-testable.
fn walk_dump(buf: &[u8], reply_type: u16, on_msg: &mut impl FnMut(&[u8])) -> DumpStep {
    let mut offset = 0;
    while let Some(hdr) = read_at::<NlMsgHdr>(buf, offset) {
        let len = hdr.len as usize;
        // checked_add: a crafted len must not wrap `offset + len` past the bound on a 32-bit usize,
        // which would then panic the `&buf[offset..offset + len]` slice (start > end) below.
        if len < size_of::<NlMsgHdr>() || offset.checked_add(len).is_none_or(|end| end > buf.len())
        {
            break;
        }
        match hdr.msg_type {
            NLMSG_DONE => return DumpStep::Done,
            NLMSG_ERROR => return DumpStep::Failed(nlmsg_error(buf, offset)),
            t if t == reply_type => on_msg(&buf[offset..offset + len]),
            _ => {}
        }
        offset += nl_align(len);
    }
    DumpStep::More
}

/// The error for an `NLMSG_ERROR` reply at `offset`. Its payload is `struct nlmsgerr { int error; ... }`
/// where `error` is a negative errno, or 0 for an ACK (which our dumps never request).
fn nlmsg_error(buf: &[u8], offset: usize) -> io::Error {
    match read_at::<c_int>(buf, offset + nl_align(size_of::<NlMsgHdr>())) {
        Some(errno) if errno != 0 => io::Error::from_raw_os_error(errno.saturating_neg()),
        _ => io::Error::other("netlink dump failed (NLMSG_ERROR without an errno)"),
    }
}

/// Parse one `RTM_NEWADDR` message; if it carries a usable address of `ifindex`, record it
/// (v4: first wins; v6: highest-ranked usable wins). `msg` spans one netlink message.
fn scan_addr(
    msg: &[u8],
    if_name: &str,
    ifindex: u32,
    addrs: &mut InterfaceAddresses,
    v6_pick: &mut V6Pick,
) {
    let body_at = nl_align(size_of::<NlMsgHdr>());
    let Some(body) = read_at::<IfAddrMsg>(msg, body_at) else {
        return;
    };
    let family = c_int::from(body.family);
    if body.index != ifindex || (family != libc::AF_INET && family != libc::AF_INET6) {
        return;
    }

    // Prefer `IFA_LOCAL` (the local address) over `IFA_ADDRESS` (the peer on point-to-point
    // links); they coincide on broadcast links. `IFA_FLAGS`, when present, is the full
    // 32-bit set and supersedes the 8-bit `ifa_flags`.
    let mut local: Option<&[u8]> = None;
    let mut address: Option<&[u8]> = None;
    let mut flags = u32::from(body.flags);
    for (attr_type, data) in rtattrs(msg, body_at + nl_align(size_of::<IfAddrMsg>())) {
        match attr_type {
            libc::IFA_ADDRESS => address = Some(data),
            libc::IFA_LOCAL => local = Some(data),
            libc::IFA_FLAGS => {
                // `IFA_FLAGS` is a `u32`; ignore a malformed attribute of any other length.
                if let Ok(bytes) = <[u8; 4]>::try_from(data) {
                    flags = u32::from_ne_bytes(bytes);
                }
            }
            _ => {}
        }
    }

    let Some(bytes) = local.or(address) else {
        return;
    };
    if family == libc::AF_INET {
        // First usable address wins: skip a tentative/deprecated/DAD-failed v4 (the same
        // IFA_F_UNUSABLE mask the v6 branch applies) so it is never chosen as the reflection source.
        if addrs.v4.is_none()
            && flags & IFA_F_UNUSABLE == 0
            && let Ok(octets) = <[u8; 4]>::try_from(bytes)
        {
            let v4 = Ipv4Addr::from(octets);
            log::trace!("{if_name}: v4 {v4}");
            addrs.v4 = Some(v4);
        }
    } else if let Ok(octets) = <[u8; 16]>::try_from(bytes) {
        let addr = Ipv6Addr::from(octets);
        let rank = v6_rank(addr);
        let usable = flags & IFA_F_UNUSABLE == 0;
        log::trace!(
            "{if_name}: v6 {addr} flags {flags:#06x} rank {rank:?} -> {}",
            if usable { "usable" } else { "filtered" }
        );
        if usable {
            v6_pick.consider(addrs, addr);
        }
    }
}

/// Parse one `RTM_NEWLINK` message; if it is `ifindex` and carries a 6-byte `IFLA_ADDRESS`,
/// record it as the MAC. `msg` spans one netlink message.
fn scan_link(msg: &[u8], if_name: &str, ifindex: u32, addrs: &mut InterfaceAddresses) {
    let body_at = nl_align(size_of::<NlMsgHdr>());
    let Some(body) = read_at::<libc::ifinfomsg>(msg, body_at) else {
        return;
    };
    if u32::try_from(body.ifi_index).ok() != Some(ifindex) {
        return;
    }

    for (attr_type, data) in rtattrs(msg, body_at + nl_align(size_of::<libc::ifinfomsg>())) {
        if attr_type == libc::IFLA_ADDRESS
            && let Ok(mac) = <[u8; 6]>::try_from(data)
        {
            let mac = MacAddr::from(mac);
            log::trace!("{if_name}: mac {mac}");
            addrs.mac = Some(mac);
            // A link has a single L2 address; the rest of the message is irrelevant.
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize `[len:u16][type:u16][value]` rtattr TLVs, each padded to 4 bytes, onto `buf`.
    fn push_attrs(buf: &mut Vec<u8>, attrs: &[(u16, &[u8])]) {
        for &(attr_type, value) in attrs {
            let len = u16::try_from(size_of::<RtAttr>() + value.len()).unwrap();
            buf.extend_from_slice(&len.to_ne_bytes());
            buf.extend_from_slice(&attr_type.to_ne_bytes());
            buf.extend_from_slice(value);
            while !buf.len().is_multiple_of(4) {
                buf.push(0);
            }
        }
    }

    /// An `RTM_NEWADDR` message: a zeroed nlmsghdr, an ifaddrmsg (family/flags/index), then `attrs`.
    fn addr_msg(family: c_int, index: u32, flags: u8, attrs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut m = vec![0u8; nl_align(size_of::<NlMsgHdr>())];
        m.push(u8::try_from(family).unwrap()); // family
        m.extend_from_slice(&[0, flags, 0]); // prefixlen, flags, scope
        m.extend_from_slice(&index.to_ne_bytes()); // index
        push_attrs(&mut m, attrs);
        m
    }

    /// An `RTM_NEWLINK` message: a zeroed nlmsghdr, an ifinfomsg (index), then `attrs`.
    fn link_msg(index: i32, attrs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut m = vec![0u8; nl_align(size_of::<NlMsgHdr>())];
        m.extend_from_slice(&[0, 0]); // family, pad
        m.extend_from_slice(&0u16.to_ne_bytes()); // dev_type
        m.extend_from_slice(&index.to_ne_bytes()); // index (i32)
        m.extend_from_slice(&[0u8; 8]); // flags, change
        push_attrs(&mut m, attrs);
        m
    }

    /// A netlink message with its `nlmsghdr` len/type set from `body`, length-padded.
    fn nl_message(msg_type: u16, body: &[u8]) -> Vec<u8> {
        let len = size_of::<NlMsgHdr>() + body.len();
        let mut m = vec![0u8; nl_align(len)];
        m[0..4].copy_from_slice(&u32::try_from(len).unwrap().to_ne_bytes());
        m[4..6].copy_from_slice(&msg_type.to_ne_bytes());
        m[size_of::<NlMsgHdr>()..size_of::<NlMsgHdr>() + body.len()].copy_from_slice(body);
        m
    }

    #[test]
    fn nl_align_rounds_up_to_four() {
        assert_eq!(nl_align(0), 0);
        assert_eq!(nl_align(1), 4);
        assert_eq!(nl_align(4), 4);
        assert_eq!(nl_align(5), 8);
    }

    #[test]
    fn read_at_bounds_checks_the_read() {
        let buf = [1u8, 2, 3, 4, 5];
        assert_eq!(
            read_at::<u32>(&buf, 1),
            Some(u32::from_ne_bytes([2, 3, 4, 5]))
        );
        assert_eq!(read_at::<u32>(&buf, 2), None); // 2 + 4 > 5
        assert_eq!(read_at::<u16>(&buf, usize::MAX), None); // offset overflow
    }

    #[test]
    fn walk_dump_stops_at_a_length_that_would_overflow_the_offset() {
        // A crafted second message with len ~usize::MAX (u32::MAX on the 32-bit targets) must not wrap
        // `offset + len` past the bound and panic the `&buf[offset..offset + len]` slice (start > end);
        // the walk delivers the valid first message, then breaks and asks for the next datagram.
        let mut buf = nl_message(libc::RTM_NEWADDR, &[0u8; size_of::<IfAddrMsg>()]);
        let second = buf.len();
        buf.extend(nl_message(
            libc::RTM_NEWADDR,
            &[0u8; size_of::<IfAddrMsg>()],
        ));
        buf[second..second + 4].copy_from_slice(&u32::MAX.to_ne_bytes());
        let mut count = 0;
        let step = walk_dump(&buf, libc::RTM_NEWADDR, &mut |_| count += 1);
        assert!(matches!(step, DumpStep::More));
        assert_eq!(count, 1); // only the valid first message was delivered
    }

    #[test]
    fn walk_dump_surfaces_the_nlmsg_error_errno() {
        // NLMSG_ERROR's first payload word is a negative errno; the walk must report it, not a blank
        // failure. -EPERM here.
        let buf = nl_message(NLMSG_ERROR, &(-libc::EPERM).to_ne_bytes());
        match walk_dump(&buf, libc::RTM_NEWADDR, &mut |_| {}) {
            DumpStep::Failed(e) => assert_eq!(e.raw_os_error(), Some(libc::EPERM)),
            _ => panic!("expected DumpStep::Failed carrying the errno"),
        }
    }

    #[test]
    fn rtattrs_walks_tlvs_and_stops_at_a_bad_length() {
        let mut buf = Vec::new();
        push_attrs(&mut buf, &[(1, &[0xaa, 0xbb]), (2, &[0xcc])]);
        let got: Vec<(u16, Vec<u8>)> = rtattrs(&buf, 0).map(|(t, v)| (t, v.to_vec())).collect();
        assert_eq!(got, vec![(1, vec![0xaa, 0xbb]), (2, vec![0xcc])]);

        // A final header whose length runs past the buffer ends the walk after the good attrs.
        let mut bad = buf.clone();
        bad.extend_from_slice(&[0xff, 0xff, 0x00, 0x00]); // len = 0xffff
        assert_eq!(rtattrs(&bad, 0).count(), 2);
    }

    #[test]
    fn scan_addr_records_a_usable_v4() {
        let msg = addr_msg(libc::AF_INET, 5, 0, &[(libc::IFA_ADDRESS, &[10, 0, 0, 1])]);
        let mut addrs = InterfaceAddresses::default();
        scan_addr(&msg, "eth0", 5, &mut addrs, &mut V6Pick::default());
        assert_eq!(addrs.v4, Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn scan_addr_prefers_ifa_local_over_ifa_address() {
        // On point-to-point links IFA_ADDRESS is the peer; IFA_LOCAL is ours.
        let msg = addr_msg(
            libc::AF_INET,
            5,
            0,
            &[
                (libc::IFA_ADDRESS, &[10, 0, 0, 2]),
                (libc::IFA_LOCAL, &[10, 0, 0, 1]),
            ],
        );
        let mut addrs = InterfaceAddresses::default();
        scan_addr(&msg, "eth0", 5, &mut addrs, &mut V6Pick::default());
        assert_eq!(addrs.v4, Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn scan_addr_skips_an_unusable_v4() {
        // IFA_FLAGS carrying TENTATIVE (0x40) supersedes the 8-bit flags and disqualifies it.
        let msg = addr_msg(
            libc::AF_INET,
            5,
            0,
            &[
                (libc::IFA_ADDRESS, &[10, 0, 0, 1]),
                (libc::IFA_FLAGS, &0x40u32.to_ne_bytes()),
            ],
        );
        let mut addrs = InterfaceAddresses::default();
        scan_addr(&msg, "eth0", 5, &mut addrs, &mut V6Pick::default());
        assert_eq!(addrs.v4, None);
    }

    #[test]
    fn scan_addr_ignores_a_different_ifindex() {
        let msg = addr_msg(libc::AF_INET, 99, 0, &[(libc::IFA_ADDRESS, &[10, 0, 0, 1])]);
        let mut addrs = InterfaceAddresses::default();
        scan_addr(&msg, "eth0", 5, &mut addrs, &mut V6Pick::default());
        assert_eq!(addrs.v4, None);
    }

    #[test]
    fn scan_addr_records_a_usable_v6() {
        let v6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let msg = addr_msg(libc::AF_INET6, 5, 0, &[(libc::IFA_ADDRESS, &v6.octets())]);
        let mut addrs = InterfaceAddresses::default();
        scan_addr(&msg, "eth0", 5, &mut addrs, &mut V6Pick::default());
        assert_eq!(addrs.v6, Some(v6));
    }

    #[test]
    fn scan_link_records_the_mac_only_for_the_right_index() {
        let mac = [0x02, 0, 0, 0, 0, 0x2a];
        let msg = link_msg(5, &[(libc::IFLA_ADDRESS, &mac)]);
        let mut addrs = InterfaceAddresses::default();
        scan_link(&msg, "eth0", 5, &mut addrs);
        assert_eq!(addrs.mac, Some(MacAddr::from(mac)));

        let mut other = InterfaceAddresses::default();
        scan_link(&msg, "eth0", 6, &mut other);
        assert_eq!(other.mac, None);
    }
}
