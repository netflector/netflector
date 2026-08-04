//! Netlink message-length alignment, which libc does not provide: there is no upstream
//! `NLMSG_ALIGN`, only the attribute-level `NLA_ALIGNTO`.

/// `NLMSG_ALIGN`: netlink's 4-byte alignment for message and attribute lengths.
pub(crate) const fn nl_align(n: usize) -> usize {
    (n + 3) & !3
}
