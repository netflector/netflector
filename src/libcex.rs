//! `libcex` ("libc extended"): C library / kernel FFI definitions missing from the `libc` crate for the
//! platforms we build, gathered in one place. Elsewhere the code references only `libc::`
//! (upstream-maintained) and `libcex::` (these hand-rolled fills).
//!
//! This module does NOT re-export `libc`. The prefix is a provenance signal for `unsafe` FFI: `libc::x`
//! is maintained and vetted upstream across platforms; `libcex::x` we transcribed from a C header and
//! must scrutinise for layout, value, and `cfg`. The split also keeps pressure to delete a fill once
//! libc ships it. Where libc provides a definition on *some* platform, the hand-rolled arm is anchored
//! to it with a `const _: () = assert!(…)` so it can't silently drift.

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod bpf_device;
mod multicast;
#[cfg(target_os = "linux")]
mod netlink;
#[cfg(target_os = "freebsd")]
mod route;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) use self::bpf_device::bpf_wordalign;
// `BPF_ALIGN` is used outside `bpf_device` only by the BPF capture's test helpers (production rounds
// via `bpf_wordalign`), so re-export it only for tests.
#[cfg(all(test, any(target_os = "macos", target_os = "freebsd")))]
pub(crate) use self::bpf_device::BPF_ALIGN;
pub(crate) use self::multicast::{GroupReq, MCAST_JOIN_GROUP};
#[cfg(target_os = "linux")]
pub(crate) use self::netlink::{
    IfAddrMsg, NETLINK_ROUTE, NLM_F_DUMP, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, NlMsgHdr, RtAttr,
    SockAddrNl, nl_align,
};
#[cfg(target_os = "freebsd")]
pub(crate) use self::route::RtMsgHdr;
