//! Classic-BPF instruction encoding, shared by the Linux socket filter (`SO_ATTACH_FILTER`) and the
//! BSD BPF device (`BIOCSETF`). libc has `sock_filter`/`bpf_insn` on Linux and FreeBSD but not apple,
//! so define it once here for all three.

/// One classic-BPF instruction (`{ u16 code; u8 jt; u8 jf; u32 k }`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BpfInsn {
    pub(crate) code: u16,
    pub(crate) jt: u8,
    pub(crate) jf: u8,
    pub(crate) k: u32,
}

// On Linux this same struct installs as a `sock_filter` via `SO_ATTACH_FILTER`;
// pin its layout to libc's.
#[cfg(target_os = "linux")]
const _: () = assert!(size_of::<BpfInsn>() == size_of::<libc::sock_filter>());
