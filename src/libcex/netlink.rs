//! rtnetlink (`NETLINK_ROUTE`) message-framing FFI, hand-rolled because `libc` exposes it for Android
//! only, not glibc/musl.

use libc::c_int;

pub(crate) const NETLINK_ROUTE: c_int = 0;
pub(crate) const NLM_F_REQUEST: u16 = 0x01;
pub(crate) const NLM_F_DUMP: u16 = 0x0300; // NLM_F_ROOT | NLM_F_MATCH
pub(crate) const NLMSG_DONE: u16 = 0x03;
pub(crate) const NLMSG_ERROR: u16 = 0x02;

/// `struct nlmsghdr`. Shared with the address monitor (`len`/`msg_type` drive its walk).
#[repr(C)]
pub(crate) struct NlMsgHdr {
    pub(crate) len: u32,
    pub(crate) msg_type: u16,
    pub(crate) flags: u16,
    pub(crate) seq: u32,
    pub(crate) pid: u32,
}

/// `struct ifaddrmsg`: the body of an `RTM_*ADDR` message. A zeroed value (family
/// `AF_UNSPEC`) is the dump request body. The address monitor reads `index` from it.
#[repr(C)]
#[derive(Default)]
pub(crate) struct IfAddrMsg {
    pub(crate) family: u8,
    pub(crate) prefixlen: u8,
    pub(crate) flags: u8,
    pub(crate) scope: u8,
    pub(crate) index: u32,
}

/// `struct rtattr`: a type-length-value attribute header within a message.
#[repr(C)]
pub(crate) struct RtAttr {
    pub(crate) len: u16,
    pub(crate) attr_type: u16,
}

/// `struct sockaddr_nl`.
#[repr(C)]
#[derive(Default)]
pub(crate) struct SockAddrNl {
    pub(crate) family: u16,
    pub(crate) pad: u16,
    pub(crate) pid: u32,
    pub(crate) groups: u32,
}

/// `NLMSG_ALIGN`: netlink's 4-byte alignment for message and attribute lengths.
pub(crate) const fn nl_align(n: usize) -> usize {
    (n + 3) & !3
}
