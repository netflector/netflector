//! BSD BPF-device batch-record alignment (macOS + FreeBSD): `BPF_WORDALIGN`, which libc does not
//! provide. The per-frame header is read as `libc::bpf_hdr` (both BSDs have it, with the right
//! per-OS timestamp).

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
