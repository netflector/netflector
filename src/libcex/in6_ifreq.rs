//! BSD `SIOCGIFAFLAG_IN6` FFI (macOS + FreeBSD): the `in6_ifreq` request struct and the `IN6_IFF_*`
//! address-flag bits used to decide whether a v6 address is usable. libc exposes `in6_ifreq` on macOS
//! only, and the `IN6_IFF_*` bits on neither BSD, so both are hand-rolled.

use libc::c_int;

/// `IN6_IFF_*` bits that disqualify a v6 address as a source: DAD in progress, DAD failed
/// (duplicate), or preferred-lifetime expired. Same values on macOS and FreeBSD.
pub(crate) const IN6_IFF_UNUSABLE: c_int = 0x02 | 0x04 | 0x10; // TENTATIVE | DUPLICATED | DEPRECATED

/// `in6_ifreq` for `SIOCGIFAFLAG_IN6`: an interface name plus a union holding the queried
/// address (going in) and its flags (coming out). Hand-rolled — `libc` exposes it on
/// macOS only, not FreeBSD.
#[repr(C)]
pub(crate) struct In6Ifreq {
    pub(crate) name: [libc::c_char; libc::IFNAMSIZ],
    pub(crate) ifru: In6Ifru,
}

#[repr(C)]
pub(crate) union In6Ifru {
    pub(crate) addr: libc::sockaddr_in6,
    pub(crate) flags6: c_int,
    // The kernel's `in6_ifreq` union is sized by its largest member, `icmp6_ifstat` — 34
    // `u_quad_t` on both macOS and FreeBSD. This pad makes the whole struct match — load-
    // bearing: `_IOWR` bakes `sizeof(in6_ifreq)` into the request code and the kernel
    // dispatches on the whole code, so a too-small struct yields a request the kernel
    // rejects, and every v6 address would be silently dropped. See the size assertions.
    _icmp6_ifstat: [u64; 34],
}

// `libc` exposes `in6_ifreq` on macOS, so cross-check the hand-rolled size against it
// there; FreeBSD's (16 + 34×8) is 288.
#[cfg(target_os = "macos")]
const _: () = assert!(size_of::<In6Ifreq>() == size_of::<libc::in6_ifreq>());
#[cfg(target_os = "freebsd")]
const _: () = assert!(size_of::<In6Ifreq>() == 288);

/// `_IOWR('i', 73, in6_ifreq)` — the BSD `ioctl` request code, derived from the (now
/// kernel-accurate) struct size rather than hardcoded.
pub(crate) fn siocgifaflag_in6() -> libc::c_ulong {
    const IOC_INOUT: libc::c_ulong = 0xc000_0000;
    const IOCPARM_MASK: libc::c_ulong = 0x1fff;
    const GROUP: libc::c_ulong = 0x69; // 'i'
    const NUM: libc::c_ulong = 73;
    let size = size_of::<In6Ifreq>() as libc::c_ulong;
    IOC_INOUT | ((size & IOCPARM_MASK) << 16) | (GROUP << 8) | NUM
}

#[cfg(test)]
mod tests {
    use super::*;

    // The encoded request must equal the kernel's registered `SIOCGIFAFLAG_IN6`, or the
    // ioctl is rejected and every v6 address is silently dropped. A too-small `In6Ifreq`
    // (omitting the large union members) is exactly how that regresses.
    #[test]
    fn siocgifaflag_in6_is_the_kernel_request_code() {
        // Identical on macOS and FreeBSD: both size `in6_ifreq` at 288 bytes.
        assert_eq!(siocgifaflag_in6(), 0xc120_6949);
    }
}
