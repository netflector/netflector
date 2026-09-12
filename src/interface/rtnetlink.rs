//! Linux address resolution over rtnetlink: one `RTM_GETADDR` dump for the v4/v6 addresses
//! (filtered by their `IFA_FLAGS`) and one `RTM_GETLINK` dump for the MAC and MTU.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::ptr;
use std::time::{Duration, Instant};

use libc::{c_int, socklen_t};

use super::{InterfaceAddresses, V6Pick, v6_rank};
use crate::libcex::nl_align;
use crate::net::mac::MacAddr;
use crate::sys::{IoStatus, blocking_socket};

/// `IFA_F_*` bits that disqualify an address as a source.
const IFA_F_UNUSABLE: u32 = libc::IFA_F_TENTATIVE | libc::IFA_F_DEPRECATED | libc::IFA_F_DADFAILED;

/// The kernel answers inside our own `sendmsg`/`recvmsg`, so these are not normal waits: they cap
/// a reply dropped in the socket's `ENOBUFS` state, or a local process feeding us datagrams we
/// discard, either of which would park the reactor for good.
const READ_TIMEOUT: Duration = Duration::from_secs(1);
const DUMP_DEADLINE: Duration = Duration::from_secs(5);

/// The `rtattr` TLVs of a message, stopping at the first malformed length as the kernel's own
/// walk does.
struct RtAttrs<'a> {
    msg: &'a [u8],
    at: usize,
}

fn rtattrs(msg: &[u8], from: usize) -> RtAttrs<'_> {
    RtAttrs { msg, at: from }
}

impl<'a> Iterator for RtAttrs<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let rta = read_at::<libc::rtattr>(self.msg, self.at)?;
        let rta_len = rta.rta_len as usize;
        if rta_len < size_of::<libc::rtattr>() || self.at + rta_len > self.msg.len() {
            return None;
        }
        let data = &self.msg[self.at + size_of::<libc::rtattr>()..self.at + rta_len];
        self.at += nl_align(rta_len);
        Some((rta.rta_type, data))
    }
}

/// A wire struct [`read_at`] may copy out of a byte buffer.
///
/// # Safety
/// Every bit pattern must be a valid value of the type: all-integer `repr(C)` fields, no `Drop`.
pub(super) unsafe trait Pod: Copy {}

// SAFETY: all-integer repr(C) kernel structs.
unsafe impl Pod for libc::nlmsghdr {}
// SAFETY: as above.
unsafe impl Pod for libc::ifaddrmsg {}
// SAFETY: as above.
unsafe impl Pod for libc::ifinfomsg {}
// SAFETY: as above.
unsafe impl Pod for libc::rtattr {}
// SAFETY: an integer.
unsafe impl Pod for c_int {}
// SAFETY: an integer.
unsafe impl Pod for u32 {}
// SAFETY: an integer.
unsafe impl Pod for u16 {}

/// `None` if `buf` is too short. Any alignment.
pub(super) fn read_at<T: Pod>(buf: &[u8], off: usize) -> Option<T> {
    if off.checked_add(size_of::<T>())? > buf.len() {
        return None;
    }
    // SAFETY: the bound check guarantees a full `T` lies within `buf`; `read_unaligned` imposes
    // no alignment requirement, and `Pod` makes every bit pattern a valid `T`.
    Some(unsafe { ptr::read_unaligned(buf.as_ptr().add(off).cast::<T>()) })
}

/// `if_name` is for tracing only; the dumps filter by `ifindex`. A 0 `ifindex` skips the dumps.
///
/// # Errors
/// A failed netlink socket, request or reply.
pub(super) fn resolve(
    if_name: &str,
    ifindex: u32,
) -> io::Result<(InterfaceAddresses, Option<u32>)> {
    if ifindex == 0 {
        log::debug!("{if_name}: no kernel ifindex; skipping the address dump");
        return Ok((InterfaceAddresses::default(), None));
    }

    let sock = netlink_socket()?;
    let mut addrs = InterfaceAddresses::default();
    let mut mtu = None;

    let mut v6_pick = V6Pick::default();
    // SAFETY: a zeroed `ifaddrmsg` (an all-integer POD) is a valid `AF_UNSPEC` address-dump
    // request body.
    let addr_req: libc::ifaddrmsg = unsafe { std::mem::zeroed() };
    dump(
        &sock,
        libc::RTM_GETADDR,
        libc::RTM_NEWADDR,
        addr_req,
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
            scan_link(msg, if_name, ifindex, &mut addrs, &mut mtu);
        },
    )?;

    Ok((addrs, mtu))
}

fn netlink_socket() -> io::Result<OwnedFd> {
    let sock = blocking_socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE)?;
    crate::sys::set_recv_timeout(sock.as_raw_fd(), READ_TIMEOUT)?;
    Ok(sock)
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
        hdr: libc::nlmsghdr,
        body: B,
    }
    let req = Request {
        hdr: libc::nlmsghdr {
            nlmsg_len: u32::try_from(size_of::<Request<B>>()).expect("request fits a u32"),
            nlmsg_type: request_type,
            nlmsg_flags: nl_u16(libc::NLM_F_REQUEST | libc::NLM_F_DUMP),
            nlmsg_seq: 1,
            nlmsg_pid: 0,
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

    let mut buf: Vec<u8> = Vec::new();
    let deadline = Instant::now() + DUMP_DEADLINE;
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::other(
                "the netlink dump did not finish within its deadline",
            ));
        }
        // MSG_PEEK|MSG_TRUNC on a zero-length read reports the queued datagram's true length
        // without consuming it.
        // SAFETY: a zero-length read dereferences nothing, so the null pointer is never read.
        let size = unsafe {
            libc::recv(
                sock.as_raw_fd(),
                ptr::null_mut(),
                0,
                libc::MSG_PEEK | libc::MSG_TRUNC,
            )
        };
        // A blocking read only reports would-block once READ_TIMEOUT expires.
        let IoStatus::Ready(size) = IoStatus::from_syscall(size)? else {
            return Err(io::Error::other("the netlink dump went unanswered"));
        };
        buf.resize(size, 0);

        // SAFETY: a zeroed `sockaddr_nl` (an all-integer POD; libc keeps its padding field
        // private, so there is no literal to write) is a valid recvfrom out-param.
        let mut src: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut addrlen = socklen_t::try_from(size_of::<libc::sockaddr_nl>())
            .expect("sockaddr_nl fits socklen_t");
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
        let IoStatus::Ready(received) = IoStatus::from_syscall(received)? else {
            return Err(io::Error::other("the netlink dump went unanswered"));
        };
        // Only the kernel (nl_pid 0) may answer: a local process could unicast a spoofed reply to
        // inject a bogus address.
        if src.nl_pid != 0 {
            log::debug!(
                "netlink dump: ignoring a reply from a non-kernel sender (pid {})",
                src.nl_pid
            );
            continue;
        }

        match walk_dump(&buf[..received], reply_type, &mut on_msg) {
            DumpStep::Done => return Ok(()),
            DumpStep::Failed(e) => return Err(e),
            DumpStep::More => {}
        }
    }
}

enum DumpStep {
    /// `NLMSG_DONE`.
    Done,
    /// `NLMSG_ERROR`, carrying its errno.
    Failed(io::Error),
    /// The datagram was fully walked; read the next one.
    More,
}

/// libc types the `NLMSG_*` kinds and `NLM_F_*` flags `c_int`, but the wire fields are `u16` and
/// a const of another type can't pattern-match `nlmsg_type`.
// guarded: the assert rejects any negative or truncating value
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
const fn nl_u16(value: libc::c_int) -> u16 {
    assert!(0 <= value && value <= 0xffff);
    value as u16
}

const NLMSG_DONE: u16 = nl_u16(libc::NLMSG_DONE);
const NLMSG_ERROR: u16 = nl_u16(libc::NLMSG_ERROR);

/// Walk one dump datagram, feeding each `reply_type` message to `on_msg`.
fn walk_dump(buf: &[u8], reply_type: u16, on_msg: &mut impl FnMut(&[u8])) -> DumpStep {
    let mut offset = 0;
    while let Some(hdr) = read_at::<libc::nlmsghdr>(buf, offset) {
        let len = hdr.nlmsg_len as usize;
        // checked_add: a crafted len must not wrap `offset + len` on a 32-bit usize; the slice
        // below would then panic.
        if len < size_of::<libc::nlmsghdr>()
            || offset.checked_add(len).is_none_or(|end| end > buf.len())
        {
            // Debug, not warn: the next refresh re-reads everything.
            log::debug!(
                "netlink dump walk stopped at offset {offset}: len {len}, buffer {} B \
                 (truncated or malformed); remaining messages skipped",
                buf.len()
            );
            break;
        }
        match hdr.nlmsg_type {
            NLMSG_DONE => return DumpStep::Done,
            NLMSG_ERROR => return DumpStep::Failed(nlmsg_error(buf, offset)),
            t if t == reply_type => on_msg(&buf[offset..offset + len]),
            _ => {}
        }
        offset += nl_align(len);
    }
    DumpStep::More
}

/// The payload is `struct nlmsgerr { int error; ... }`: a negative errno, or 0 for an ACK (which
/// our dumps never request).
fn nlmsg_error(buf: &[u8], offset: usize) -> io::Error {
    match read_at::<c_int>(buf, offset + nl_align(size_of::<libc::nlmsghdr>())) {
        Some(errno) if errno != 0 => io::Error::from_raw_os_error(errno.saturating_neg()),
        _ => io::Error::other("netlink dump failed (NLMSG_ERROR without an errno)"),
    }
}

/// Record a usable address of `ifindex` from one `RTM_NEWADDR` (v4: first wins; v6: highest
/// rank wins).
fn scan_addr(
    msg: &[u8],
    if_name: &str,
    ifindex: u32,
    addrs: &mut InterfaceAddresses,
    v6_pick: &mut V6Pick,
) {
    let body_at = nl_align(size_of::<libc::nlmsghdr>());
    let Some(body) = read_at::<libc::ifaddrmsg>(msg, body_at) else {
        return;
    };
    let family = c_int::from(body.ifa_family);
    if body.ifa_index != ifindex || (family != libc::AF_INET && family != libc::AF_INET6) {
        return;
    }

    // Prefer `IFA_LOCAL` (the local address) over `IFA_ADDRESS` (the peer on point-to-point
    // links); they coincide on broadcast links. `IFA_FLAGS`, when present, is the full
    // 32-bit set and supersedes the 8-bit `ifa_flags`.
    let mut local: Option<&[u8]> = None;
    let mut address: Option<&[u8]> = None;
    let mut flags = u32::from(body.ifa_flags);
    for (attr_type, data) in rtattrs(msg, body_at + nl_align(size_of::<libc::ifaddrmsg>())) {
        match attr_type {
            libc::IFA_ADDRESS => address = Some(data),
            libc::IFA_LOCAL => local = Some(data),
            libc::IFA_FLAGS => {
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
        let Ok(octets) = <[u8; 4]>::try_from(bytes) else {
            return;
        };
        let v4 = Ipv4Addr::from(octets);
        if flags & IFA_F_UNUSABLE != 0 {
            log::trace!("{if_name}: v4 {v4} flags {flags:#06x} -> filtered");
        } else if addrs.v4.is_some() {
            log::trace!("{if_name}: v4 {v4} (ignored; already have one)");
        } else {
            log::trace!("{if_name}: v4 {v4}/{}", body.ifa_prefixlen);
            addrs.v4 = Some(v4);
            addrs.v4_prefix = Some(body.ifa_prefixlen);
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

/// Record the MAC (`IFLA_ADDRESS`) and MTU of `ifindex` from one `RTM_NEWLINK`.
fn scan_link(
    msg: &[u8],
    if_name: &str,
    ifindex: u32,
    addrs: &mut InterfaceAddresses,
    mtu: &mut Option<u32>,
) {
    let body_at = nl_align(size_of::<libc::nlmsghdr>());
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
        } else if attr_type == libc::IFLA_MTU
            && let Ok(bytes) = <[u8; 4]>::try_from(data)
        {
            let value = u32::from_ne_bytes(bytes);
            log::trace!("{if_name}: mtu {value}");
            *mtu = Some(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize `[len:u16][type:u16][value]` rtattr TLVs, each padded to 4 bytes, onto `buf`.
    fn push_attrs(buf: &mut Vec<u8>, attrs: &[(u16, &[u8])]) {
        for &(attr_type, value) in attrs {
            let len = u16::try_from(size_of::<libc::rtattr>() + value.len()).unwrap();
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
        addr_msg_prefixed(family, index, 0, flags, attrs)
    }

    /// [`addr_msg`] with the ifaddrmsg's prefix length set.
    fn addr_msg_prefixed(
        family: c_int,
        index: u32,
        prefixlen: u8,
        flags: u8,
        attrs: &[(u16, &[u8])],
    ) -> Vec<u8> {
        let mut m = vec![0u8; nl_align(size_of::<libc::nlmsghdr>())];
        m.push(u8::try_from(family).unwrap()); // family
        m.extend_from_slice(&[prefixlen, flags, 0]); // prefixlen, flags, scope
        m.extend_from_slice(&index.to_ne_bytes()); // index
        push_attrs(&mut m, attrs);
        m
    }

    /// An `RTM_NEWLINK` message: a zeroed nlmsghdr, an ifinfomsg (index), then `attrs`.
    fn link_msg(index: i32, attrs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut m = vec![0u8; nl_align(size_of::<libc::nlmsghdr>())];
        m.extend_from_slice(&[0, 0]); // family, pad
        m.extend_from_slice(&0u16.to_ne_bytes()); // dev_type
        m.extend_from_slice(&index.to_ne_bytes()); // index (i32)
        m.extend_from_slice(&[0u8; 8]); // flags, change
        push_attrs(&mut m, attrs);
        m
    }

    /// A netlink message with its `nlmsghdr` len/type set from `body`, length-padded.
    fn nl_message(msg_type: u16, body: &[u8]) -> Vec<u8> {
        let len = size_of::<libc::nlmsghdr>() + body.len();
        let mut m = vec![0u8; nl_align(len)];
        m[0..4].copy_from_slice(&u32::try_from(len).unwrap().to_ne_bytes());
        m[4..6].copy_from_slice(&msg_type.to_ne_bytes());
        m[size_of::<libc::nlmsghdr>()..size_of::<libc::nlmsghdr>() + body.len()]
            .copy_from_slice(body);
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
        let mut buf = nl_message(libc::RTM_NEWADDR, &[0u8; size_of::<libc::ifaddrmsg>()]);
        let second = buf.len();
        buf.extend(nl_message(
            libc::RTM_NEWADDR,
            &[0u8; size_of::<libc::ifaddrmsg>()],
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
    fn scan_addr_records_the_v4_prefix() {
        let msg = addr_msg_prefixed(
            libc::AF_INET,
            5,
            24,
            0,
            &[(libc::IFA_ADDRESS, &[192, 0, 2, 2])],
        );
        let mut addrs = InterfaceAddresses::default();
        scan_addr(&msg, "eth0", 5, &mut addrs, &mut V6Pick::default());
        assert_eq!(
            addrs.v4_directed_broadcast(),
            Some(Ipv4Addr::new(192, 0, 2, 255))
        );
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
        let mut mtu = None;
        scan_link(&msg, "eth0", 5, &mut addrs, &mut mtu);
        assert_eq!(addrs.mac, Some(MacAddr::from(mac)));

        let mut other = InterfaceAddresses::default();
        scan_link(&msg, "eth0", 6, &mut other, &mut mtu);
        assert_eq!(other.mac, None);
    }

    #[test]
    fn scan_link_records_the_mtu_beside_the_mac() {
        let mac = [0x02, 0, 0, 0, 0, 0x2a];
        let msg = link_msg(
            5,
            &[
                (libc::IFLA_ADDRESS, &mac),
                (libc::IFLA_MTU, &1500u32.to_ne_bytes()),
            ],
        );
        let mut addrs = InterfaceAddresses::default();
        let mut mtu = None;
        scan_link(&msg, "eth0", 5, &mut addrs, &mut mtu);
        assert_eq!(addrs.mac, Some(MacAddr::from(mac)));
        assert_eq!(mtu, Some(1500));
    }
}
