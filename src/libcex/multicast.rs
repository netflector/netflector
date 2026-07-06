//! Multicast-group FFI absent from `libc`: the RFC 3678 by-index group join.

use libc::c_int;

/// `MCAST_JOIN_GROUP` (RFC 3678): by-index interface selection, no IPv4 by-address fallback to the
/// wrong NIC. libc defines it only on Linux; the BSDs share the value 80 (checked against the Darwin
/// SDK and FreeBSD headers).
#[cfg(target_os = "linux")]
pub(crate) const MCAST_JOIN_GROUP: c_int = libc::MCAST_JOIN_GROUP;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) const MCAST_JOIN_GROUP: c_int = 80;

/// `struct group_req` (RFC 3678), absent from libc everywhere. The layout differs by platform: Linux and
/// FreeBSD align `gr_group` naturally, so `#[repr(C)]` (which pads `gr_interface` out to the
/// `sockaddr_storage` alignment) matches. macOS declares the multicast request structs `#pragma pack(4)`,
/// putting `gr_group` at offset 4 with no padding (size 132, not 136); sending the padded layout there
/// fails the join with `EINVAL`. So pack the struct on macOS and leave it natural elsewhere.
#[cfg_attr(target_os = "macos", repr(C, packed(4)))]
#[cfg_attr(not(target_os = "macos"), repr(C))]
pub(crate) struct GroupReq {
    pub(crate) gr_interface: u32,
    pub(crate) gr_group: libc::sockaddr_storage,
}

/// Pin the macOS packed layout so a naive `#[repr(C)]` "cleanup" can't silently reintroduce the offset-8
/// gap that fails the join with `EINVAL`. (Linux/FreeBSD track the kernel by natural alignment, incl. the
/// 4-byte offset on 32-bit, so they need no pin.)
#[cfg(target_os = "macos")]
const _: () = {
    assert!(size_of::<GroupReq>() == 132);
    assert!(std::mem::offset_of!(GroupReq, gr_group) == 4);
};
