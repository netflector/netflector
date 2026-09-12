//! macOS/FreeBSD: a `PF_ROUTE` socket. Only the interface index is read, at its fixed header
//! offset: the `ifa_msghdr`/`if_msghdr` tails diverge across the BSDs.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use libc::c_int;

use super::InterfaceEvent;

/// A routing message is a fixed header plus a few small sockaddrs, a few hundred bytes.
pub(super) const READ_BUF: usize = 2048;

/// See [`InterfaceMonitor::INDEXES_MONOTONIC`](super::InterfaceMonitor::INDEXES_MONOTONIC).
pub(super) const INDEXES_MONOTONIC: bool = false;

/// See [`InterfaceMonitor::LIFECYCLE_EVENTS`](super::InterfaceMonitor::LIFECYCLE_EVENTS):
/// FreeBSD announces arrival/departure via `RTM_IFANNOUNCE`; macOS has no lifecycle message.
pub(super) const LIFECYCLE_EVENTS: bool = cfg!(target_os = "freebsd");

/// The route socket's default receive queue is ~8 KiB. Best-effort and kernel-clamped;
/// FreeBSD's `SO_RERROR` still recovers from an overflow, macOS (no `SO_RERROR`) relies on this
/// alone.
const RECV_BUFFER: c_int = 256 * 1024;

/// `ifam_index` (`ifa_msghdr`) and `ifm_index` (`if_msghdr`) are both a `u16` at this offset.
const INDEX_OFFSET: usize = 12;
const _: () = assert!(std::mem::offset_of!(libc::ifa_msghdr, ifam_index) == INDEX_OFFSET);
const _: () = assert!(std::mem::offset_of!(libc::if_msghdr, ifm_index) == INDEX_OFFSET);

/// `ifan_index` sits earlier: the announce header has no `ifam_addrs`/`ifm_data` before it.
#[cfg(target_os = "freebsd")]
const ANNOUNCE_INDEX_OFFSET: usize = 4;
#[cfg(target_os = "freebsd")]
const _: () =
    assert!(std::mem::offset_of!(libc::if_announcemsghdr, ifan_index) == ANNOUNCE_INDEX_OFFSET);

pub(super) fn open() -> io::Result<OwnedFd> {
    let sock = crate::sys::open_socket(libc::PF_ROUTE, libc::SOCK_RAW, 0)?;
    crate::sys::increase_recv_buffer(sock.as_raw_fd(), RECV_BUFFER);
    // Without SO_RERROR the drain's ENOBUFS recovery never fires; macOS has no equivalent.
    #[cfg(target_os = "freebsd")]
    crate::sys::set_recv_error_reporting(sock.as_raw_fd())?;
    Ok(sock)
}

/// Every routing message begins with `u16 msglen; u8 version; u8 type`. `RTM_IFINFO` (a flap
/// or MAC change) maps to [`InterfaceEvent::Address`], not a lifecycle event.
pub(super) fn for_each_change(buf: &[u8], on_change: &mut impl FnMut(InterfaceEvent)) {
    let mut offset = 0;
    while offset + 4 <= buf.len() {
        let msglen = usize::from(u16::from_ne_bytes([buf[offset], buf[offset + 1]]));
        let msg_type = c_int::from(buf[offset + 3]);
        if msglen < 4 || offset + msglen > buf.len() {
            log::warn!(
                "routing message walk stopped at offset {offset}: msglen {msglen}, buffer {} B \
                 (truncated or malformed); a change may be missed",
                buf.len()
            );
            break;
        }
        let hit = match msg_type {
            libc::RTM_NEWADDR | libc::RTM_DELADDR | libc::RTM_IFINFO => Some((
                INDEX_OFFSET,
                InterfaceEvent::Address as fn(u32) -> InterfaceEvent,
            )),
            #[cfg(target_os = "freebsd")]
            libc::RTM_IFANNOUNCE => Some((
                ANNOUNCE_INDEX_OFFSET,
                InterfaceEvent::Link as fn(u32) -> InterfaceEvent,
            )),
            _ => {
                // PF_ROUTE is unfiltered; this trace is the only trail of what a drain saw.
                log::trace!("interface monitor: ignoring routing message type {msg_type}");
                None
            }
        };
        if let Some((index_offset, event)) = hit
            && msglen >= index_offset + 2
        {
            let index =
                u16::from_ne_bytes([buf[offset + index_offset], buf[offset + index_offset + 1]]);
            if index == 0 {
                // Kernel indices are >= 1.
                log::warn!("interface monitor: dropping a change with no valid interface index");
            } else {
                let event = event(u32::from(index));
                log::trace!("interface monitor: {event:?}");
                on_change(event);
            }
        }
        offset += msglen;
    }
}

/// `PF_ROUTE` carries no sender identity and echoes local processes' requests to every listener.
/// Accept all: an injected message only picks which interface to re-resolve, and the re-resolve
/// reads the kernel.
pub(super) fn sender_ok(_src: &libc::sockaddr_storage, _len: libc::socklen_t) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A routing message of `msglen` bytes: header (msglen, type) plus `index` at its fixed
    /// offset, the rest zero.
    fn message(msg_type: c_int, index: u16, msglen: usize) -> Vec<u8> {
        let mut m = vec![0u8; msglen];
        m[0..2].copy_from_slice(
            &u16::try_from(msglen)
                .expect("test msglen fits u16")
                .to_ne_bytes(),
        );
        m[3] = u8::try_from(msg_type).expect("test rtm_type fits u8");
        m[INDEX_OFFSET..INDEX_OFFSET + 2].copy_from_slice(&index.to_ne_bytes());
        m
    }

    #[test]
    fn reports_index_of_address_and_link_messages() {
        let mut buf = message(libc::RTM_NEWADDR, 7, 20);
        buf.extend(message(libc::RTM_IFINFO, 9, 24));
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |e| seen.push(e));
        // RTM_IFINFO is a flap/MAC change, not a lifecycle event, so both report Address.
        assert_eq!(
            seen,
            [InterfaceEvent::Address(7), InterfaceEvent::Address(9)]
        );
    }

    /// FreeBSD announces interface arrival/departure; the walk maps both to a Link event,
    /// reading `ifan_index` at its own (earlier) offset.
    #[cfg(target_os = "freebsd")]
    #[test]
    fn announce_messages_report_a_link_event() {
        let mut m = vec![0u8; 24];
        m[0..2].copy_from_slice(&24u16.to_ne_bytes());
        m[3] = u8::try_from(libc::RTM_IFANNOUNCE).expect("RTM_IFANNOUNCE fits u8");
        m[ANNOUNCE_INDEX_OFFSET..ANNOUNCE_INDEX_OFFSET + 2].copy_from_slice(&7u16.to_ne_bytes());
        let mut seen = Vec::new();
        for_each_change(&m, &mut |e| seen.push(e));
        assert_eq!(seen, [InterfaceEvent::Link(7)]);
    }

    #[test]
    fn ignores_unsubscribed_types() {
        // RTM_ADD (a route was added) is neither an address nor a link change.
        let buf = message(libc::RTM_ADD, 5, 20);
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |e| seen.push(e));
        assert!(seen.is_empty());
    }

    #[test]
    fn ignores_message_too_short_for_the_index() {
        // A subscribed type whose length stops before the index field (offset 12) must not
        // be read past. Built by hand: the helper would write an index this message can't hold.
        let mut buf = vec![0u8; INDEX_OFFSET];
        buf[0..2].copy_from_slice(&u16::try_from(INDEX_OFFSET).unwrap().to_ne_bytes());
        buf[3] = u8::try_from(libc::RTM_NEWADDR).unwrap();
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |e| seen.push(e));
        assert!(seen.is_empty());
    }

    #[test]
    fn never_forwards_index_zero() {
        // Kernel indices start at 1, so a 0 is malformed. Forwarding it would match the first
        // parked table entry, which caches 0, and re-resolve the wrong interface.
        let buf = message(libc::RTM_NEWADDR, 0, 20);
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |e| seen.push(e));
        assert!(seen.is_empty());
    }

    #[test]
    fn stops_at_a_message_claiming_a_length_past_the_buffer() {
        let mut buf = message(libc::RTM_NEWADDR, 7, 20);
        buf[0..2].copy_from_slice(&9999u16.to_ne_bytes()); // msglen past the datagram
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |e| seen.push(e));
        assert!(seen.is_empty());
    }
}
