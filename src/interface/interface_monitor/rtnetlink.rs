//! Linux: an rtnetlink (`NETLINK_ROUTE`) socket subscribed to the address and link change
//! multicast groups. The message layer (header walk, `ifaddrmsg`/`ifinfomsg` bodies) is the
//! resolver's, reused from [`super::super::rtnetlink`].

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use libc::socklen_t;

use super::super::rtnetlink::read_at;
use super::InterfaceEvent;
use crate::libcex::{IfAddrMsg, NETLINK_ROUTE, NlMsgHdr, SockAddrNl, nl_align};

/// Holds one notification. Multicast delivers one message per datagram, never a coalesced
/// dump. Sized for the largest: an `RTM_NEWLINK` carries the interface's whole attribute set
/// (stats, `IFLA_AF_SPEC`, VF info) at ~1 KB; addresses are far smaller. 8 KiB is roomy.
pub(super) const READ_BUF: usize = 8192;

/// Subscribe v4/v6 address adds+removes and link (MAC/state) changes. A MAC change arrives
/// as `RTM_NEWLINK`, not an address event, so `RTMGRP_LINK` is needed to catch it.
const SUBSCRIBED_GROUPS: u32 =
    (libc::RTMGRP_IPV4_IFADDR | libc::RTMGRP_IPV6_IFADDR | libc::RTMGRP_LINK) as u32;

/// Open a `NETLINK_ROUTE` socket bound to the change groups, non-blocking + close-on-exec.
pub(super) fn open() -> io::Result<OwnedFd> {
    // SAFETY: `socket` returns a fresh fd or -1; the type arg carries CLOEXEC|NONBLOCK
    // (Linux applies both atomically, with no fcntl race).
    let sock = crate::sys::owned_fd_from(unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            NETLINK_ROUTE,
        )
    })?;
    let addr = SockAddrNl {
        family: u16::try_from(libc::AF_NETLINK).expect("AF_NETLINK fits a u16"),
        groups: SUBSCRIBED_GROUPS,
        ..SockAddrNl::default()
    };
    // SAFETY: a fully-initialized `sockaddr_nl` of its own size; `bind` reads it and
    // subscribes the multicast groups.
    let rc = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            (&raw const addr).cast::<libc::sockaddr>(),
            socklen_t::try_from(size_of::<SockAddrNl>()).expect("sockaddr_nl fits socklen_t"),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sock)
}

/// Walk every netlink message in one datagram; report the interface index and event kind of
/// each `RTM_{NEW,DEL}ADDR` ([`InterfaceEvent::Address`], from its `ifaddrmsg`) and
/// `RTM_{NEW,DEL}LINK` ([`InterfaceEvent::Link`], from its `ifinfomsg`).
pub(super) fn for_each_change(buf: &[u8], on_change: &mut impl FnMut(InterfaceEvent)) {
    let mut offset = 0;
    while let Some(hdr) = read_at::<NlMsgHdr>(buf, offset) {
        let len = hdr.len as usize;
        // checked_add: a crafted len must not wrap `offset + len` past the bound on a 32-bit usize
        // (which would also make `nl_align(len)` wrap to 0 and spin the walk forever).
        if len < size_of::<NlMsgHdr>() || offset.checked_add(len).is_none_or(|end| end > buf.len())
        {
            // Not a normal end (that's the `while` running out): a message claims an
            // impossible length (truncated datagram or corruption), so a change is dropped.
            log::warn!(
                "netlink message walk stopped at offset {offset}: len {len}, buffer {} B \
                 (truncated or malformed); a change may be missed",
                buf.len()
            );
            break;
        }
        let body_at = offset + nl_align(size_of::<NlMsgHdr>());
        let end = offset + len;
        match hdr.msg_type {
            libc::RTM_NEWADDR | libc::RTM_DELADDR => {
                if let Some(body) = read_at::<IfAddrMsg>(&buf[..end], body_at) {
                    report(body.index, InterfaceEvent::Address, on_change);
                }
            }
            libc::RTM_NEWLINK | libc::RTM_DELLINK => {
                if let Some(body) = read_at::<libc::ifinfomsg>(&buf[..end], body_at) {
                    // `ifi_index` is i32 but always a positive kernel index; a negative one is
                    // as malformed as 0, so fold it in for report's drop-and-warn.
                    report(
                        u32::try_from(body.ifi_index).unwrap_or(0),
                        InterfaceEvent::Link,
                        on_change,
                    );
                }
            }
            _ => {}
        }
        offset += nl_align(len);
    }
}

/// Whether a notification came from the kernel. The kernel's netlink source address has `nl_pid == 0`;
/// a user process's carries its port id, so a non-zero pid is a locally-spoofed datagram (netlink
/// user-to-user unicast needs no privilege) and is dropped.
pub(super) fn sender_ok(src: &libc::sockaddr_storage, len: socklen_t) -> bool {
    if usize::try_from(len).unwrap_or(0) < size_of::<SockAddrNl>() {
        return false;
    }
    // SAFETY: the len check guarantees the storage holds a full sockaddr_nl; read its prefix unaligned.
    let nl = unsafe { std::ptr::read_unaligned((&raw const *src).cast::<SockAddrNl>()) };
    nl.pid == 0
}

/// Forward an `event(index)` change; `event` is a variant constructor
/// ([`InterfaceEvent::Address`] or [`InterfaceEvent::Link`]). Kernel indices are >= 1, so a 0
/// (including a folded-in negative `ifi_index`) is a malformed message: dropped with a warn
/// rather than forwarded as nonsense.
fn report(
    index: u32,
    event: fn(u32) -> InterfaceEvent,
    on_change: &mut impl FnMut(InterfaceEvent),
) {
    if index == 0 {
        log::warn!("interface monitor: dropping a change with no valid interface index");
        return;
    }
    let event = event(index);
    log::trace!("interface monitor: {event:?}");
    on_change(event);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A netlink message: a `nlmsghdr` (len, type) followed by `body`, length-padded.
    fn message(msg_type: u16, body: &[u8]) -> Vec<u8> {
        let len = size_of::<NlMsgHdr>() + body.len();
        let mut m = vec![0u8; nl_align(len)];
        m[0..4].copy_from_slice(
            &u32::try_from(len)
                .expect("test message fits u32")
                .to_ne_bytes(),
        );
        m[4..6].copy_from_slice(&msg_type.to_ne_bytes());
        m[size_of::<NlMsgHdr>()..size_of::<NlMsgHdr>() + body.len()].copy_from_slice(body);
        m
    }

    /// An `ifaddrmsg` body carrying `ifa_index` (a `u32` at body offset 4).
    fn ifaddrmsg(index: u32) -> Vec<u8> {
        let mut b = vec![0u8; size_of::<IfAddrMsg>()];
        b[4..8].copy_from_slice(&index.to_ne_bytes());
        b
    }

    /// An `ifinfomsg` body carrying `ifi_index` (an `i32` at body offset 4).
    fn ifinfomsg(index: i32) -> Vec<u8> {
        let mut b = vec![0u8; size_of::<libc::ifinfomsg>()];
        b[4..8].copy_from_slice(&index.to_ne_bytes());
        b
    }

    /// A `sockaddr_storage` holding a `sockaddr_nl` with `pid` as its `nl_pid`.
    fn storage_with_pid(pid: u32) -> libc::sockaddr_storage {
        let nl = SockAddrNl {
            pid,
            ..SockAddrNl::default()
        };
        // SAFETY: an all-zero sockaddr_storage is valid, and it is large enough and aligned to hold a
        // sockaddr_nl written into its prefix.
        unsafe {
            let mut ss: libc::sockaddr_storage = std::mem::zeroed();
            std::ptr::write((&raw mut ss).cast::<SockAddrNl>(), nl);
            ss
        }
    }

    #[test]
    fn sender_ok_accepts_only_the_kernel() {
        let full = socklen_t::try_from(size_of::<SockAddrNl>()).unwrap();
        assert!(sender_ok(&storage_with_pid(0), full)); // the kernel (nl_pid 0)
        assert!(!sender_ok(&storage_with_pid(1234), full)); // a user process's port id
        assert!(!sender_ok(&storage_with_pid(0), 4)); // a too-short source address
    }

    #[test]
    fn reports_index_of_addr_and_link_messages() {
        let mut buf = message(libc::RTM_NEWADDR, &ifaddrmsg(7));
        buf.extend(message(libc::RTM_DELLINK, &ifinfomsg(9)));
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |e| seen.push(e));
        assert_eq!(seen, [InterfaceEvent::Address(7), InterfaceEvent::Link(9)]);
    }

    #[test]
    fn ignores_other_message_types() {
        // NLMSG_DONE (3) and any non-addr/link type carry no interface index for us.
        let buf = message(3, &ifaddrmsg(5));
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |e| seen.push(e));
        assert!(seen.is_empty());
    }

    #[test]
    fn skips_a_body_too_short_for_its_struct() {
        // A truncated ifaddrmsg (claimed type, body shorter than ifaddrmsg) yields nothing.
        let buf = message(libc::RTM_NEWADDR, &[0u8; 2]);
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |e| seen.push(e));
        assert!(seen.is_empty());
    }

    #[test]
    fn never_forwards_index_zero() {
        // 0 names no interface and is the parent's overflow sentinel, so a message carrying it
        // must not be reported (which would trigger a spurious re-resolve of everything).
        let buf = message(libc::RTM_NEWADDR, &ifaddrmsg(0));
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |e| seen.push(e));
        assert!(seen.is_empty());
    }

    #[test]
    fn stops_at_a_message_claiming_a_length_past_the_buffer() {
        let mut buf = message(libc::RTM_NEWADDR, &ifaddrmsg(7));
        buf[0..4].copy_from_slice(&9999u32.to_ne_bytes()); // len past the datagram
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |e| seen.push(e));
        assert!(seen.is_empty());
    }

    #[test]
    fn stops_at_a_length_that_would_overflow_the_offset() {
        // A crafted second message with len ~usize::MAX (u32::MAX on the 32-bit targets) must not wrap
        // `offset + len` past the bound check and spin the walk forever (the wrap needs a non-zero
        // offset); the walk reports the valid first message, then breaks.
        let mut buf = message(libc::RTM_NEWADDR, &ifaddrmsg(7));
        let second = buf.len();
        buf.extend(message(libc::RTM_NEWADDR, &ifaddrmsg(9)));
        buf[second..second + 4].copy_from_slice(&u32::MAX.to_ne_bytes());
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |e| seen.push(e));
        assert_eq!(seen, [InterfaceEvent::Address(7)]);
    }
}
