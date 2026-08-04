//! BSD address resolution: a single `getifaddrs` pass yields the v4 address, the MAC, and
//! the v6 candidates, with `SIOCGIFAFLAG_IN6` per v6 candidate to drop tentative /
//! duplicated / deprecated addresses.

use std::ffi::CStr;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr;

use libc::c_int;

use super::{InterfaceAddresses, V6Pick, v6_rank};
use crate::net::mac::MacAddr;

/// Resolve `if_name`'s current source addresses in one `getifaddrs` pass.
///
/// # Errors
/// Returns an error if `getifaddrs` fails or the v6 flag socket can't open; an unknown
/// interface (or one with no addresses yet) yields an all-absent [`InterfaceAddresses`],
/// as does a host with no IPv6 stack.
pub(super) fn resolve(if_name: &str) -> io::Result<InterfaceAddresses> {
    // One socket for the per-v6 `SIOCGIFAFLAG_IN6` ioctl.
    let v6_sock = inet6_socket()?;

    let mut head: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: `getifaddrs` writes a freshly-allocated linked list into `head` (or returns
    // nonzero); we own it and release it with `freeifaddrs` below.
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut addrs = InterfaceAddresses::default();
    let mut v6_pick = V6Pick::default();
    let mut node = head;
    while !node.is_null() {
        // SAFETY: `node` points at a live list entry owned by `head`, valid until
        // `freeifaddrs`.
        let ifa = unsafe { &*node };
        node = ifa.ifa_next;
        if ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: `ifa_name` is a NUL-terminated name; `ifa_addr` is a non-null `sockaddr`
        // whose `sa_family` tags the concrete type the helpers reinterpret it as.
        let (name, family) = unsafe {
            (
                CStr::from_ptr(ifa.ifa_name),
                c_int::from((*ifa.ifa_addr).sa_family),
            )
        };
        if name.to_bytes() != if_name.as_bytes() {
            continue;
        }
        match family {
            libc::AF_INET => {
                let v4 = read_v4(ifa.ifa_addr);
                // First address wins, matching the rtnetlink backend. Taking the last would let a
                // secondary alias and the kernel's enumeration order flip the chosen v4 on unrelated
                // alias churn, producing a spurious v4 delta that needlessly evicts DIAL proxies.
                if addrs.v4.is_none() {
                    log::trace!("{if_name}: v4 {v4}");
                    addrs.v4 = Some(v4);
                } else {
                    log::trace!("{if_name}: v4 {v4} (ignored; already have one)");
                }
            }
            libc::AF_LINK => {
                let mac = read_mac(ifa.ifa_addr);
                match mac {
                    Some(mac) => log::trace!("{if_name}: mac {mac}"),
                    None => log::trace!("{if_name}: link layer carries no mac"),
                }
                addrs.mac = mac;
            }
            libc::AF_INET6 => {
                // SAFETY: family is `AF_INET6`, so `ifa_addr` points at a `sockaddr_in6`.
                let sin6 =
                    unsafe { ptr::read_unaligned(ifa.ifa_addr.cast::<libc::sockaddr_in6>()) };
                let addr = canonical_v6(sin6.sin6_addr.s6_addr);
                let flags = v6_sock
                    .as_ref()
                    .and_then(|sock| v6_flags(sock, if_name, sin6));
                let usable = flags.is_some_and(|f| f & IN6_IFF_UNUSABLE == 0);
                let rank = v6_rank(addr);
                match flags {
                    Some(f) => log::trace!(
                        "{if_name}: v6 {addr} flags {f:#06x} rank {rank:?} -> {}",
                        if usable { "usable" } else { "filtered" }
                    ),
                    None => log::trace!("{if_name}: v6 {addr} flag query failed -> filtered"),
                }
                if usable {
                    v6_pick.consider(&mut addrs, addr);
                }
            }
            _ => {}
        }
    }

    // SAFETY: `head` came from the matching `getifaddrs` and has not been freed yet.
    unsafe { libc::freeifaddrs(head) };
    Ok(addrs)
}

/// The IPv4 address of an `AF_INET` `sockaddr`.
fn read_v4(addr: *const libc::sockaddr) -> Ipv4Addr {
    // SAFETY: the caller matched `AF_INET`, so `addr` points at a `sockaddr_in`;
    // `read_unaligned` copies it without assuming alignment.
    let sin = unsafe { ptr::read_unaligned(addr.cast::<libc::sockaddr_in>()) };
    // `s_addr` is in network byte order, i.e. its in-memory bytes *are* the octets.
    Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes())
}

/// The MAC of an `AF_LINK` `sockaddr_dl`, or `None` if the link has none (e.g. loopback).
/// The address sits in the variable-length tail, after the name.
fn read_mac(addr: *const libc::sockaddr) -> Option<MacAddr> {
    use std::mem::offset_of;

    let base = addr.cast::<u8>();
    // Read only the fixed `sockaddr_dl` header fields, not the whole `libc` struct: its
    // `sdl_data` is larger than the kernel's variable tail (46 bytes on FreeBSD), so
    // copying it whole would over-read a short sockaddr. `sdl_len` is the sockaddr's own
    // byte count that getifaddrs sizes the allocation to, so it bounds every read.
    // SAFETY: an `AF_LINK` sockaddr_dl always carries its 8-byte header, so these three
    // bytes (offsets 0/5/6) are within the allocation.
    let (sdl_len, nlen, alen) = unsafe {
        (
            usize::from(base.add(offset_of!(libc::sockaddr_dl, sdl_len)).read()),
            usize::from(base.add(offset_of!(libc::sockaddr_dl, sdl_nlen)).read()),
            base.add(offset_of!(libc::sockaddr_dl, sdl_alen)).read(),
        )
    };
    // The address sits after the `nlen`-byte name. Bail on no link address (e.g. loopback)
    // or a length that would run past the sockaddr. This is the bound check.
    let offset = offset_of!(libc::sockaddr_dl, sdl_data) + nlen;
    if alen != 6 || offset + 6 > sdl_len {
        return None;
    }
    let mut mac = [0u8; 6];
    // SAFETY: `offset + 6 <= sdl_len <= the allocation`, so the 6 bytes are within it.
    unsafe { ptr::copy_nonoverlapping(base.add(offset), mac.as_mut_ptr(), 6) };
    Some(MacAddr::from(mac))
}

/// Canonicalize a link-local address from `getifaddrs`: the BSDs embed the scope id (the
/// interface index) in bytes 2-3 of a `fe80::/10` `sockaddr_in6` (the KAME convention), so
/// clear them to recover the on-the-wire `fe80::/64`. A no-op for any other address.
fn canonical_v6(mut octets: [u8; 16]) -> Ipv6Addr {
    if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
        octets[2] = 0;
        octets[3] = 0;
    }
    Ipv6Addr::from(octets)
}

/// An `AF_INET6` datagram socket for the flag ioctl, or `None` if the host has no IPv6.
///
/// # Errors
/// Any other `socket` failure. Under fd or memory pressure the host still has IPv6, and
/// reading that as "no v6" would filter every candidate and commit the false loss; the error
/// fails the whole resolve instead, which the caller retries.
fn inet6_socket() -> io::Result<Option<OwnedFd>> {
    // SAFETY: `socket` returns a fresh fd or -1.
    let raw = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if raw >= 0 {
        // SAFETY: `raw` is a fresh owned socket fd.
        return Ok(Some(unsafe { OwnedFd::from_raw_fd(raw) }));
    }
    let err = io::Error::last_os_error();
    if no_ipv6_stack(&err) {
        return Ok(None);
    }
    Err(err)
}

/// Whether a `socket(AF_INET6, ...)` failure means the host has no IPv6 stack, the one case
/// where an absent socket is the truth rather than a transient failure.
fn no_ipv6_stack(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT)
    )
}

/// `IN6_IFF_*` bits that disqualify a v6 address as a source: DAD in progress, DAD failed
/// (duplicate), or preferred-lifetime expired.
const IN6_IFF_UNUSABLE: c_int =
    libc::IN6_IFF_TENTATIVE | libc::IN6_IFF_DUPLICATED | libc::IN6_IFF_DEPRECATED;

/// The `IN6_IFF_*` flags of `addr` on `if_name`, queried via `SIOCGIFAFLAG_IN6`, or `None`
/// if the ioctl fails (the address is then treated as unusable).
fn v6_flags(sock: &OwnedFd, if_name: &str, addr: libc::sockaddr_in6) -> Option<c_int> {
    // SAFETY: an all-zero `in6_ifreq` is valid (a zeroed name and union).
    let mut req: libc::in6_ifreq = unsafe { std::mem::zeroed() };
    let n = if_name.len().min(libc::IFNAMSIZ - 1);
    // SAFETY: copy `n` name bytes into the zeroed `c_char` buffer (same layout as `u8`);
    // the trailing zero keeps it NUL-terminated.
    unsafe {
        ptr::copy_nonoverlapping(if_name.as_ptr(), req.ifr_name.as_mut_ptr().cast::<u8>(), n);
    }
    req.ifr_ifru.ifru_addr = addr;
    // SAFETY: the ioctl reads `req` (name + queried address) and writes the address flags
    // back into the union; `sock` is a valid `AF_INET6` socket.
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFAFLAG_IN6, &raw mut req) } < 0 {
        return None;
    }
    // SAFETY: a successful ioctl wrote `ifru_flags6` into the union.
    Some(unsafe { req.ifr_ifru.ifru_flags6 })
}

#[cfg(test)]
mod tests {
    use std::mem::offset_of;

    use super::*;

    #[test]
    fn only_a_missing_ipv6_stack_reads_as_no_v6() {
        let of = io::Error::from_raw_os_error;
        assert!(no_ipv6_stack(&of(libc::EAFNOSUPPORT)));
        assert!(no_ipv6_stack(&of(libc::EPROTONOSUPPORT)));
        // Pressure errnos fail the resolve instead of committing a false v6 loss.
        assert!(!no_ipv6_stack(&of(libc::EMFILE)));
        assert!(!no_ipv6_stack(&of(libc::ENOBUFS)));
    }

    #[test]
    fn canonical_v6_strips_the_embedded_scope_from_link_local() {
        // The BSDs embed the scope id (ifindex) in bytes 2-3 of a fe80::/10 address (the KAME
        // convention); the canonical form zeroes them to recover the on-the-wire fe80::/64.
        let embedded = [
            0xfe, 0x80, 0x00, 0x07, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x11, 0x22, 0x33,
        ];
        assert_eq!(
            canonical_v6(embedded),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0x0211, 0x2233)
        );
        // A non-link-local address is untouched.
        let global = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(canonical_v6(global), Ipv6Addr::from(global));
    }

    /// A raw `AF_LINK` `sockaddr_dl`: an `nlen`-byte name then `mac`, with `sdl_alen`/`sdl_len` set as
    /// given so the bounds branches can be exercised. Laid out via `offset_of` so it matches the real
    /// struct.
    fn dl_bytes(name: &[u8], mac: &[u8], alen: u8, sdl_len: u8) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[offset_of!(libc::sockaddr_dl, sdl_family)] = u8::try_from(libc::AF_LINK).unwrap();
        buf[offset_of!(libc::sockaddr_dl, sdl_nlen)] = u8::try_from(name.len()).unwrap();
        buf[offset_of!(libc::sockaddr_dl, sdl_alen)] = alen;
        buf[offset_of!(libc::sockaddr_dl, sdl_len)] = sdl_len;
        let data = offset_of!(libc::sockaddr_dl, sdl_data);
        buf[data..data + name.len()].copy_from_slice(name);
        buf[data + name.len()..data + name.len() + mac.len()].copy_from_slice(mac);
        buf
    }

    #[test]
    fn read_mac_extracts_the_address_after_the_name() {
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let data = offset_of!(libc::sockaddr_dl, sdl_data);
        let len = u8::try_from(data + 3 + 6).unwrap(); // header + "en0" + 6-byte MAC
        let buf = dl_bytes(b"en0", &mac, 6, len);
        assert_eq!(
            read_mac(buf.as_ptr().cast::<libc::sockaddr>()),
            Some(MacAddr::from(mac))
        );
    }

    #[test]
    fn read_mac_is_none_without_a_link_address() {
        // Loopback carries a name but no address (alen 0).
        let data = offset_of!(libc::sockaddr_dl, sdl_data);
        let len = u8::try_from(data + 3).unwrap();
        let buf = dl_bytes(b"lo0", &[], 0, len);
        assert_eq!(read_mac(buf.as_ptr().cast::<libc::sockaddr>()), None);
    }

    #[test]
    fn read_mac_is_none_when_the_address_runs_past_the_sockaddr() {
        // sdl_alen claims 6, but sdl_len stops short of the MAC: rejected, not over-read.
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let data = offset_of!(libc::sockaddr_dl, sdl_data);
        let short = u8::try_from(data + 3 + 3).unwrap(); // 3 bytes short of the MAC
        let buf = dl_bytes(b"en0", &mac, 6, short);
        assert_eq!(read_mac(buf.as_ptr().cast::<libc::sockaddr>()), None);
    }
}
