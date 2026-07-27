//! Which interface would the kernel route a destination through? A `PF_ROUTE` `RTM_GET` query.
//!
//! FreeBSD has no `SO_BINDTODEVICE`/`IP_BOUND_IF`, so the DIAL proxy checks the route instead of
//! pinning the connect. Weaker than a pin: it can't hold an established connection in place, and
//! under multipath the kernel reports the first nexthop while the connect hashes independently.

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use libc::{c_int, c_void};

use crate::libcex::RtMsgHdr;
use crate::sys::IoStatus;

/// One routing message: a fixed header plus a few small sockaddrs.
const READ_BUF: usize = 2048;

/// Bound on one blocking read, and on the whole exchange. The kernel hands the reply to a software
/// interrupt rather than queueing it inline, so some wait is normal; these only cap the cases where
/// it was dropped (the netisr queue and the receive buffer both discard silently) or where the
/// socket's own broadcasts keep arriving faster than we step over them.
const READ_TIMEOUT: Duration = Duration::from_secs(1);
const REPLY_DEADLINE: Duration = Duration::from_secs(5);

/// The default `rts_recvspace` is 8 KiB, small enough that a burst of the kernel's routing
/// broadcasts can crowd out the reply we are waiting for.
const RECV_BUFFER: c_int = 256 * 1024;

/// Marks our request in the reply; the kernel's broadcasts carry 0.
const REQUEST_SEQ: c_int = 1;

/// An `RTM_GET` request: the header followed by the one sockaddr it names. A routing message carries
/// a variable set of sockaddrs, so `<net/route.h>` declares no struct for one; `route(8)` appends
/// them to a byte blob through a cursor. Asking for a single `RTA_DST` needs only this.
#[repr(C)]
struct RouteRequest {
    hdr: RtMsgHdr,
    dst: libc::sockaddr_in,
}

// A trailing sockaddr occupies `SA_SIZE` bytes: `sa_len` rounded up to a multiple of `sizeof(long)`.
// A 16-byte `sockaddr_in` is already a multiple, so a plain field lands where the cursor would.
const _: () = assert!(size_of::<RouteRequest>() == size_of::<RtMsgHdr>() + 16);

/// The index of the interface the kernel would route `dst` through.
///
/// # Errors
/// No route, a route that discards traffic, or a routing-socket failure. Anything that leaves the
/// answer unknown is an error: the caller refuses the connect on one.
pub(crate) fn egress_ifindex(dst: Ipv4Addr) -> io::Result<u32> {
    let sock = open_route_socket()?;
    let request = build_request(dst);
    // SAFETY: `request` is a live, fully initialized `RouteRequest` of exactly this size.
    let written = unsafe {
        libc::write(
            sock.as_raw_fd(),
            (&raw const request).cast::<c_void>(),
            size_of::<RouteRequest>(),
        )
    };
    if written < 0 {
        let err = io::Error::last_os_error();
        // The kernel reports an unroutable destination by failing the write, not by replying.
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Err(io::Error::other(format!("no route to {dst}")));
        }
        return Err(err);
    }
    read_reply(sock.as_raw_fd(), dst)
}

/// A socket for one query: blocking, like the netlink dump's, since this is a synchronous exchange
/// rather than something the reactor polls. `AF_INET` narrows the broadcasts it also receives.
fn open_route_socket() -> io::Result<OwnedFd> {
    // SAFETY: `socket` returns a fresh fd or -1.
    let sock = crate::sys::owned_fd_from(unsafe {
        libc::socket(
            libc::PF_ROUTE,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::AF_INET,
        )
    })?;
    crate::sys::set_recv_timeout(sock.as_raw_fd(), READ_TIMEOUT)?;
    crate::sys::increase_recv_buffer(sock.as_raw_fd(), RECV_BUFFER);
    // A reply the buffer had no room for then reports ENOBUFS rather than looking like silence.
    crate::sys::set_recv_error_reporting(sock.as_raw_fd())?;
    Ok(sock)
}

/// `RTA_DST` alone, without `RTA_NETMASK`, selects the longest-prefix match: the lookup a forwarded
/// packet gets rather than an exact-match one.
fn build_request(dst: Ipv4Addr) -> RouteRequest {
    RouteRequest {
        hdr: RtMsgHdr {
            msglen: u16::try_from(size_of::<RouteRequest>())
                .expect("the request fits a u16 length"),
            version: u8::try_from(libc::RTM_VERSION).expect("RTM_VERSION fits a u8"),
            msg_type: u8::try_from(libc::RTM_GET).expect("RTM_GET fits a u8"),
            addrs: libc::RTA_DST,
            pid: our_pid(),
            seq: REQUEST_SEQ,
            ..RtMsgHdr::default()
        },
        dst: libc::sockaddr_in {
            sin_len: u8::try_from(size_of::<libc::sockaddr_in>())
                .expect("sockaddr_in fits a u8 length"),
            sin_family: u8::try_from(libc::AF_INET).expect("AF_INET fits a u8 family"),
            sin_port: 0, // a route has no port
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(dst.octets()),
            },
            sin_zero: [0; 8],
        },
    }
}

/// Read past the kernel's broadcasts to our own reply. An unanswered query is an error, so the
/// caller refuses the connect rather than allowing it.
fn read_reply(fd: RawFd, dst: Ipv4Addr) -> io::Result<u32> {
    let mut buf = [0u8; READ_BUF];
    let deadline = Instant::now() + REPLY_DEADLINE;
    // Counted so the deadline message can tell a flooded socket from a silent one.
    let mut skipped = 0_u32;
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::other(format!(
                "no answer for {dst} in {REPLY_DEADLINE:?}, after {skipped} other messages"
            )));
        }
        // SAFETY: `buf` is a valid writable buffer of its own length.
        let read = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<c_void>(), buf.len()) };
        // A blocking read only reports would-block once READ_TIMEOUT expires.
        let IoStatus::Ready(n) = IoStatus::from_syscall(read)? else {
            return Err(io::Error::other(format!(
                "the routing socket did not answer which interface reaches {dst}"
            )));
        };
        if n < size_of::<RtMsgHdr>() {
            skipped += 1;
            continue;
        }
        // SAFETY: `buf` holds at least a whole header, checked above. Unaligned because the read
        // landed in a byte buffer, and `RtMsgHdr` is plain data with no invalid bit patterns.
        let hdr = unsafe { buf.as_ptr().cast::<RtMsgHdr>().read_unaligned() };
        if !is_our_reply(&hdr) {
            skipped += 1;
            continue;
        }
        if hdr.errno != 0 {
            return Err(io::Error::from_raw_os_error(hdr.errno));
        }
        if hdr.flags & (libc::RTF_REJECT | libc::RTF_BLACKHOLE) != 0 {
            return Err(io::Error::other(format!(
                "the route to {dst} discards traffic"
            )));
        }
        return Ok(u32::from(hdr.index));
    }
}

/// Whether `hdr` answers our own request rather than being one of the kernel's broadcasts.
fn is_our_reply(hdr: &RtMsgHdr) -> bool {
    hdr.version == u8::try_from(libc::RTM_VERSION).expect("RTM_VERSION fits a u8")
        && hdr.msg_type == u8::try_from(libc::RTM_GET).expect("RTM_GET fits a u8")
        && hdr.pid == our_pid()
        && hdr.seq == REQUEST_SEQ
}

fn our_pid() -> c_int {
    // SAFETY: `getpid` takes no arguments and cannot fail.
    unsafe { libc::getpid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore = "needs a real routing socket")]
    fn loopback_routes_via_lo0() {
        // A live exchange: the header layout and size have to be right or the kernel rejects the
        // request or the reply is read from the wrong place.
        let want = crate::interface::if_index("lo0").expect("lo0 exists");
        assert_eq!(egress_ifindex(Ipv4Addr::LOCALHOST).expect("a route"), want);
    }

    /// A header matching every field [`is_our_reply`] keys on. Each rejection test below changes
    /// exactly one of them, so it exercises its own clause rather than tripping an earlier one.
    fn our_reply() -> RtMsgHdr {
        RtMsgHdr {
            version: u8::try_from(libc::RTM_VERSION).unwrap(),
            msg_type: u8::try_from(libc::RTM_GET).unwrap(),
            pid: our_pid(),
            seq: REQUEST_SEQ,
            ..RtMsgHdr::default()
        }
    }

    #[test]
    fn recognises_our_own_reply() {
        assert!(is_our_reply(&our_reply()));
    }

    #[test]
    fn skips_another_process_reply() {
        // Every routing socket sees every reply, including other processes' RTM_GETs.
        let hdr = RtMsgHdr {
            pid: our_pid() + 1,
            ..our_reply()
        };
        assert!(!is_our_reply(&hdr));
    }

    #[test]
    fn skips_a_kernel_broadcast() {
        // What actually shares the socket with us: an unsolicited announcement, carrying its own
        // message type and seq 0.
        let hdr = RtMsgHdr {
            msg_type: u8::try_from(libc::RTM_NEWADDR).unwrap(),
            seq: 0,
            ..our_reply()
        };
        assert!(!is_our_reply(&hdr));
    }

    #[test]
    fn skips_another_message_type() {
        let hdr = RtMsgHdr {
            msg_type: u8::try_from(libc::RTM_DELADDR).unwrap(),
            ..our_reply()
        };
        assert!(!is_our_reply(&hdr));
    }

    #[test]
    fn skips_a_foreign_sequence() {
        let hdr = RtMsgHdr {
            seq: REQUEST_SEQ + 1,
            ..our_reply()
        };
        assert!(!is_our_reply(&hdr));
    }

    #[test]
    fn skips_another_protocol_version() {
        let hdr = RtMsgHdr {
            version: u8::try_from(libc::RTM_VERSION).unwrap() - 1,
            ..our_reply()
        };
        assert!(!is_our_reply(&hdr));
    }
}
