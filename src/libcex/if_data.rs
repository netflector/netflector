//! Apple's `<net/if_var.h>` `struct if_data`, which `getifaddrs` hangs off every `AF_LINK`
//! entry's `ifa_data`. libc binds it for FreeBSD but not apple (only the sysctl-side
//! `if_data64`, whose field order this matches).

use libc::c_uchar;

/// Field names follow the header for a future libc submission; the resolver reads only
/// `ifi_mtu`. `ifi_lastchange` is `timeval32` on 64-bit userland (the only apple target shipped).
#[repr(C)]
#[allow(clippy::struct_field_names)] // the header's own `ifi_` prefix, kept for the submission
pub(crate) struct IfData {
    pub(crate) ifi_type: c_uchar,
    pub(crate) ifi_typelen: c_uchar,
    pub(crate) ifi_physical: c_uchar,
    pub(crate) ifi_addrlen: c_uchar,
    pub(crate) ifi_hdrlen: c_uchar,
    pub(crate) ifi_recvquota: c_uchar,
    pub(crate) ifi_xmitquota: c_uchar,
    pub(crate) ifi_unused1: c_uchar,
    pub(crate) ifi_mtu: u32,
    pub(crate) ifi_metric: u32,
    pub(crate) ifi_baudrate: u32,
    pub(crate) ifi_ipackets: u32,
    pub(crate) ifi_ierrors: u32,
    pub(crate) ifi_opackets: u32,
    pub(crate) ifi_oerrors: u32,
    pub(crate) ifi_collisions: u32,
    pub(crate) ifi_ibytes: u32,
    pub(crate) ifi_obytes: u32,
    pub(crate) ifi_imcasts: u32,
    pub(crate) ifi_omcasts: u32,
    pub(crate) ifi_iqdrops: u32,
    pub(crate) ifi_noproto: u32,
    pub(crate) ifi_recvtiming: u32,
    pub(crate) ifi_xmittiming: u32,
    pub(crate) ifi_lastchange: libc::timeval32,
    pub(crate) ifi_unused2: u32,
    pub(crate) ifi_hwassist: u32,
    pub(crate) ifi_reserved1: u32,
    pub(crate) ifi_reserved2: u32,
}

const _: () = assert!(size_of::<IfData>() == 96);
// The one field the resolver reads, pinned by offset so a transcription slip can't shift it.
const _: () = assert!(std::mem::offset_of!(IfData, ifi_mtu) == 8);
