//! Multicast-group FFI absent from `libc`: the RFC 3678 by-index group join.

use libc::c_int;

/// `MCAST_JOIN_GROUP` (RFC 3678): by-index interface selection, no IPv4 by-address fallback to the
/// wrong NIC. libc defines it only on Linux; the BSDs share the value 80 (checked against the Darwin
/// SDK and FreeBSD headers).
#[cfg(target_os = "linux")]
pub(crate) const MCAST_JOIN_GROUP: c_int = libc::MCAST_JOIN_GROUP;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) const MCAST_JOIN_GROUP: c_int = 80;

/// `struct group_req` (RFC 3678). Absent from libc everywhere, so hand-rolled. `#[repr(C)]` plus
/// `sockaddr_storage`'s alignment reproduce the C layout: 4 bytes of padding after `gr_interface`.
#[repr(C)]
pub(crate) struct GroupReq {
    pub(crate) gr_interface: u32,
    pub(crate) gr_group: libc::sockaddr_storage,
}
