//! Multicast-group FFI absent from `libc`: the RFC 3678 by-index group join.

use libc::c_int;

/// RFC 3678 by-index join (no IPv4 by-address pick of the wrong NIC). libc has it only on Linux;
/// the BSDs share the value 80 (Darwin SDK and FreeBSD headers).
#[cfg(target_os = "linux")]
pub(crate) const MCAST_JOIN_GROUP: c_int = libc::MCAST_JOIN_GROUP;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) const MCAST_JOIN_GROUP: c_int = 80;

/// `struct group_req` (RFC 3678), absent from libc everywhere. macOS declares the multicast request
/// structs `#pragma pack(4)`: `gr_group` at offset 4, size 132 not 136, and the padded layout fails
/// the join with `EINVAL`. Linux and FreeBSD align `gr_group` naturally, which `repr(C)` matches.
#[cfg_attr(target_os = "macos", repr(C, packed(4)))]
#[cfg_attr(not(target_os = "macos"), repr(C))]
pub(crate) struct GroupReq {
    pub(crate) gr_interface: u32,
    pub(crate) gr_group: libc::sockaddr_storage,
}

// Pins the packed layout: a `repr(C)` "cleanup" would reintroduce the offset-8 gap that fails
// the join with `EINVAL`. Linux and FreeBSD track the kernel by natural alignment, including
// the 4-byte offset on 32-bit, so they need no pin.
#[cfg(target_os = "macos")]
const _: () = {
    assert!(size_of::<GroupReq>() == 132);
    assert!(std::mem::offset_of!(GroupReq, gr_group) == 4);
};
