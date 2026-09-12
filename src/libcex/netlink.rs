//! `NLMSG_ALIGN`, which libc does not provide (only the attribute-level `NLA_ALIGNTO`).

pub(crate) const fn nl_align(n: usize) -> usize {
    (n + 3) & !3
}
