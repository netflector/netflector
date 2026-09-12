//! FFI definitions missing from the `libc` crate on the platforms we build. The prefix is a
//! provenance signal: `libc::x` is vetted upstream, `libcex::x` was transcribed from a C header
//! here and must be checked for layout, value and `cfg`. Never re-exports `libc`; delete a fill
//! once libc ships it. Where libc has the definition on some platform, the hand-rolled arm is
//! pinned to it with a `const _: () = assert!(…)`.

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod bpf_device;
mod multicast;
#[cfg(target_os = "linux")]
mod netlink;
#[cfg(target_os = "freebsd")]
mod route;

#[cfg(all(test, any(target_os = "macos", target_os = "freebsd")))]
pub(crate) use self::bpf_device::BPF_ALIGN;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) use self::bpf_device::bpf_wordalign;
pub(crate) use self::multicast::{GroupReq, MCAST_JOIN_GROUP};
#[cfg(target_os = "linux")]
pub(crate) use self::netlink::nl_align;
#[cfg(target_os = "freebsd")]
pub(crate) use self::route::RtMsgHdr;
