//! macOS/FreeBSD: a `PF_ROUTE` socket delivers routing messages; the address and link ones
//! carry the affected interface's index. We read only that index, at its fixed offset in the
//! message. Same "trust the offset, not the whole libc struct" approach as
//! [`super::super::getifaddrs`]'s MAC read: the `ifa_msghdr`/`if_msghdr` tails diverge across
//! the BSDs.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use libc::c_int;

/// Holds one routing message: a fixed header plus a few small sockaddrs (the `RTAX_*` slots),
/// a few hundred bytes. No rtnetlink-style attribute lists, so smaller than the `rtnetlink`
/// backend's 8 KiB suffices.
pub(super) const READ_BUF: usize = 2048;

/// Requested `SO_RCVBUF` for the route socket, whose default receive queue is only ~8 KiB. Enlarge it so
/// a burst of routing messages is far less likely to overflow it and drop changes. Best-effort and
/// kernel-clamped; FreeBSD's `SO_RERROR` still recovers from an overflow, and macOS (no `SO_RERROR`)
/// relies on this alone. Linux's netlink monitor already defaults to the system max, so it isn't grown.
const RECV_BUFFER: c_int = 256 * 1024;

/// `ifam_index` (in `ifa_msghdr`) and `ifm_index` (in `if_msghdr`) are both a `u16` at this
/// offset; the asserts pin it against the libc layout.
const INDEX_OFFSET: usize = 12;
const _: () = assert!(std::mem::offset_of!(libc::ifa_msghdr, ifam_index) == INDEX_OFFSET);
const _: () = assert!(std::mem::offset_of!(libc::if_msghdr, ifm_index) == INDEX_OFFSET);

/// Open a `PF_ROUTE` socket, non-blocking + close-on-exec.
pub(super) fn open() -> io::Result<OwnedFd> {
    // FreeBSD accepts CLOEXEC|NONBLOCK in the socket type; macOS needs a follow-up fcntl.
    #[cfg(target_os = "freebsd")]
    let socktype = libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    #[cfg(target_os = "macos")]
    let socktype = libc::SOCK_RAW;
    // SAFETY: `socket` returns a fresh fd or -1.
    let sock = crate::sys::owned_fd_from(unsafe { libc::socket(libc::PF_ROUTE, socktype, 0) })?;
    #[cfg(target_os = "macos")]
    crate::sys::set_cloexec_nonblock(sock.as_raw_fd())?;
    crate::sys::set_recv_buffer(sock.as_raw_fd(), RECV_BUFFER);
    // FreeBSD only: without SO_RERROR a receive-buffer overflow is dropped silently, so the drain's
    // ENOBUFS re-resolve-all recovery never fires and address changes are lost under pressure. Enabling
    // it surfaces the overflow as ENOBUFS on the next recv; Linux netlink already reports it. macOS has
    // the same silent drop but no SO_RERROR (a FreeBSD 13.0+ option) or equivalent, so the
    // overflow-recovery gap is unfixable there.
    #[cfg(target_os = "freebsd")]
    {
        let on: c_int = 1;
        // SAFETY: setsockopt reads `on` (a c_int of the given length) on a valid socket fd.
        let rc = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                crate::libcex::SO_RERROR,
                (&raw const on).cast(),
                libc::socklen_t::try_from(size_of::<c_int>()).expect("c_int fits socklen_t"),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(sock)
}

/// Walk every routing message in `buf`; report the interface index of each `RTM_NEWADDR` /
/// `RTM_DELADDR` (address change) and `RTM_IFINFO` (link/MAC change). Every routing message
/// begins with `u16 msglen; u8 version; u8 type`.
pub(super) fn for_each_change(buf: &[u8], on_change: &mut impl FnMut(u32)) {
    let mut offset = 0;
    while offset + 4 <= buf.len() {
        let msglen = usize::from(u16::from_ne_bytes([buf[offset], buf[offset + 1]]));
        let msg_type = c_int::from(buf[offset + 3]);
        if msglen < 4 || offset + msglen > buf.len() {
            // Not the normal end (the `while` running out): a message claims an impossible
            // length, so a change may be dropped.
            log::warn!(
                "routing message walk stopped at offset {offset}: msglen {msglen}, buffer {} B \
                 (truncated or malformed); a change may be missed",
                buf.len()
            );
            break;
        }
        if matches!(
            msg_type,
            libc::RTM_NEWADDR | libc::RTM_DELADDR | libc::RTM_IFINFO
        ) && msglen >= INDEX_OFFSET + 2
        {
            let index =
                u16::from_ne_bytes([buf[offset + INDEX_OFFSET], buf[offset + INDEX_OFFSET + 1]]);
            // 0 names no interface (kernel indices are >= 1) and is the parent's "re-resolve
            // everything" overflow signal, so a stray 0 must never be forwarded.
            if index != 0 {
                log::trace!("address monitor: change for ifindex {index}");
                on_change(u32::from(index));
            }
        }
        offset += msglen;
    }
}

/// `PF_ROUTE` messages have no per-message sender identity; every one is the kernel's, so accept all.
/// (Mirrors the netlink backend's `sender_ok`, which rejects locally-spoofed datagrams.)
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
        for_each_change(&buf, &mut |i| seen.push(i));
        assert_eq!(seen, [7, 9]);
    }

    #[test]
    fn ignores_unsubscribed_types() {
        // RTM_ADD (a route was added) is neither an address nor a link change.
        let buf = message(libc::RTM_ADD, 5, 20);
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |i| seen.push(i));
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
        for_each_change(&buf, &mut |i| seen.push(i));
        assert!(seen.is_empty());
    }

    #[test]
    fn never_forwards_index_zero() {
        // 0 names no interface and is the parent's overflow sentinel, so a message carrying it
        // must not be reported (which would trigger a spurious re-resolve of everything).
        let buf = message(libc::RTM_NEWADDR, 0, 20);
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |i| seen.push(i));
        assert!(seen.is_empty());
    }

    #[test]
    fn stops_at_a_message_claiming_a_length_past_the_buffer() {
        let mut buf = message(libc::RTM_NEWADDR, 7, 20);
        buf[0..2].copy_from_slice(&9999u16.to_ne_bytes()); // msglen past the datagram
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |i| seen.push(i));
        assert!(seen.is_empty());
    }
}
