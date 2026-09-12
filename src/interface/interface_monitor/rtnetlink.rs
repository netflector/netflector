//! Linux: an rtnetlink socket subscribed to the address and link change groups. The message
//! layer is the resolver's, [`super::super::rtnetlink`].

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use libc::socklen_t;

use super::super::rtnetlink::read_at;
use super::InterfaceEvent;
use crate::libcex::nl_align;
use crate::sys::{check, open_socket};

/// One message per datagram, never a coalesced dump; the largest, an `RTM_NEWLINK` with the
/// interface's whole attribute set, is ~1 KB.
pub(super) const READ_BUF: usize = 8192;

/// See [`InterfaceMonitor::INDEXES_MONOTONIC`](super::InterfaceMonitor::INDEXES_MONOTONIC).
pub(super) const INDEXES_MONOTONIC: bool = true;

/// See [`InterfaceMonitor::LIFECYCLE_EVENTS`](super::InterfaceMonitor::LIFECYCLE_EVENTS).
pub(super) const LIFECYCLE_EVENTS: bool = true;

/// A MAC change arrives as `RTM_NEWLINK`, not an address event, so `RTMGRP_LINK` is needed to
/// catch it.
const SUBSCRIBED_GROUPS: u32 =
    (libc::RTMGRP_IPV4_IFADDR | libc::RTMGRP_IPV6_IFADDR | libc::RTMGRP_LINK) as u32;

pub(super) fn open() -> io::Result<OwnedFd> {
    let sock = open_socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE)?;
    // SAFETY: a zeroed `sockaddr_nl` is an all-integer POD (libc keeps its padding field
    // private, so there is no literal to write); the two meaningful fields are set below.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = u16::try_from(libc::AF_NETLINK).expect("AF_NETLINK fits a u16");
    addr.nl_groups = SUBSCRIBED_GROUPS;
    // SAFETY: a fully-initialized `sockaddr_nl` of its own size; `bind` reads it and
    // subscribes the multicast groups.
    check(unsafe {
        libc::bind(
            sock.as_raw_fd(),
            (&raw const addr).cast::<libc::sockaddr>(),
            socklen_t::try_from(size_of::<libc::sockaddr_nl>())
                .expect("sockaddr_nl fits socklen_t"),
        )
    })?;
    Ok(sock)
}

/// Report the interface index of each `RTM_{NEW,DEL}ADDR` and `RTM_{NEW,DEL}LINK` in one
/// datagram.
pub(super) fn for_each_change(buf: &[u8], on_change: &mut impl FnMut(InterfaceEvent)) {
    let mut offset = 0;
    while let Some(hdr) = read_at::<libc::nlmsghdr>(buf, offset) {
        let len = hdr.nlmsg_len as usize;
        // checked_add: a crafted len must not wrap `offset + len` on a 32-bit usize, which
        // would also make `nl_align(len)` wrap to 0 and spin the walk forever.
        if len < size_of::<libc::nlmsghdr>()
            || offset.checked_add(len).is_none_or(|end| end > buf.len())
        {
            log::warn!(
                "netlink message walk stopped at offset {offset}: len {len}, buffer {} B \
                 (truncated or malformed); a change may be missed",
                buf.len()
            );
            break;
        }
        let body_at = offset + nl_align(size_of::<libc::nlmsghdr>());
        let end = offset + len;
        match hdr.nlmsg_type {
            libc::RTM_NEWADDR | libc::RTM_DELADDR => {
                if let Some(body) = read_at::<libc::ifaddrmsg>(&buf[..end], body_at) {
                    report(body.ifa_index, InterfaceEvent::Address, on_change);
                }
            }
            libc::RTM_NEWLINK | libc::RTM_DELLINK => {
                if let Some(body) = read_at::<libc::ifinfomsg>(&buf[..end], body_at) {
                    // A negative `ifi_index` is as malformed as 0; fold it in.
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

/// The kernel's netlink source address has `nl_pid == 0`; a non-zero pid is a locally spoofed
/// datagram (netlink user-to-user unicast needs no privilege).
pub(super) fn sender_ok(src: &libc::sockaddr_storage, len: socklen_t) -> bool {
    if usize::try_from(len).unwrap_or(0) < size_of::<libc::sockaddr_nl>() {
        return false;
    }
    // SAFETY: the len check guarantees the storage holds a full sockaddr_nl; read its prefix unaligned.
    let nl = unsafe { std::ptr::read_unaligned((&raw const *src).cast::<libc::sockaddr_nl>()) };
    nl.nl_pid == 0
}

/// Kernel indices are >= 1; a 0 is malformed and dropped with a warn.
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
        let len = size_of::<libc::nlmsghdr>() + body.len();
        let mut m = vec![0u8; nl_align(len)];
        m[0..4].copy_from_slice(
            &u32::try_from(len)
                .expect("test message fits u32")
                .to_ne_bytes(),
        );
        m[4..6].copy_from_slice(&msg_type.to_ne_bytes());
        m[size_of::<libc::nlmsghdr>()..size_of::<libc::nlmsghdr>() + body.len()]
            .copy_from_slice(body);
        m
    }

    /// An `ifaddrmsg` body carrying `ifa_index` (a `u32` at body offset 4).
    fn ifaddrmsg(index: u32) -> Vec<u8> {
        let mut b = vec![0u8; size_of::<libc::ifaddrmsg>()];
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
        // SAFETY: an all-zero sockaddr_storage is valid, and it is large enough and aligned to hold a
        // sockaddr_nl written into its prefix.
        unsafe {
            let mut nl: libc::sockaddr_nl = std::mem::zeroed();
            nl.nl_pid = pid;
            let mut ss: libc::sockaddr_storage = std::mem::zeroed();
            std::ptr::write((&raw mut ss).cast::<libc::sockaddr_nl>(), nl);
            ss
        }
    }

    #[test]
    fn sender_ok_accepts_only_the_kernel() {
        let full = socklen_t::try_from(size_of::<libc::sockaddr_nl>()).unwrap();
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
        // Kernel indices start at 1, so a 0 is malformed. Forwarding it would match the first
        // parked table entry, which caches 0, and re-resolve the wrong interface.
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
