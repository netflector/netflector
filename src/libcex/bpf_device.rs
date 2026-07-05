//! BSD BPF-device FFI (macOS + FreeBSD): the `DLT_*` link types, the `bpf_program` filter struct, and
//! `BPF_WORDALIGN` batch-record alignment. libc provides some of these on only one of the two BSDs.

use libc::c_uint;

use super::bpf::BpfInsn;

// DLT_EN10MB (Ethernet, 1) and DLT_NULL (0) are stable BPF link types,
// but libc exposes them only on apple — define them locally, anchored to libc's
// values where available.
pub(crate) const DLT_EN10MB: c_uint = 1;
pub(crate) const DLT_NULL: c_uint = 0;
#[cfg(target_os = "macos")]
const _: () = assert!(DLT_EN10MB == libc::DLT_EN10MB);
#[cfg(target_os = "macos")]
const _: () = assert!(DLT_NULL == libc::DLT_NULL);

/// `struct bpf_program` — the filter handed to `BIOCSETF`. libc provides this
/// (and `bpf_insn`) on FreeBSD but not apple, so define it for both; the asserts
/// anchor the layout to libc where it exists. The per-frame header is read as
/// `libc::bpf_hdr` (apple + FreeBSD both have it, with the right per-OS timestamp).
#[repr(C)]
pub(crate) struct BpfProgram {
    pub(crate) bf_len: c_uint,
    pub(crate) bf_insns: *mut BpfInsn,
}
#[cfg(target_os = "freebsd")]
const _: () = assert!(size_of::<BpfProgram>() == size_of::<libc::bpf_program>());
#[cfg(target_os = "freebsd")]
const _: () = assert!(size_of::<BpfInsn>() == size_of::<libc::bpf_insn>());

// `BPF_ALIGNMENT` as a usize. libc types it differently per platform (`c_int` on
// apple, `usize` on FreeBSD), so normalize it once here.
#[cfg(target_os = "macos")]
pub(crate) const BPF_ALIGN: usize = libc::BPF_ALIGNMENT as usize;
#[cfg(target_os = "freebsd")]
pub(crate) const BPF_ALIGN: usize = libc::BPF_ALIGNMENT;

pub(crate) const fn bpf_wordalign(x: usize) -> usize {
    (x + (BPF_ALIGN - 1)) & !(BPF_ALIGN - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordalign_rounds_up_to_alignment() {
        // BPF_ALIGN is per-OS (4 on macOS, sizeof(long)=8 on FreeBSD/64-bit), so assert the round-up
        // invariant against the real boundary rather than a hardcoded width.
        assert_eq!(bpf_wordalign(0), 0);
        assert_eq!(bpf_wordalign(1), BPF_ALIGN);
        assert_eq!(bpf_wordalign(BPF_ALIGN), BPF_ALIGN);
        assert_eq!(bpf_wordalign(BPF_ALIGN + 1), 2 * BPF_ALIGN);
    }
}
