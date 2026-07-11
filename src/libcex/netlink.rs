//! rtnetlink (`NETLINK_ROUTE`) message-framing FFI, hand-rolled because `libc` does not expose it for
//! glibc/musl.

use libc::c_int;

pub(crate) const NETLINK_ROUTE: c_int = 0;
pub(crate) const NLM_F_REQUEST: u16 = 0x01;
pub(crate) const NLM_F_DUMP: u16 = 0x0300; // NLM_F_ROOT | NLM_F_MATCH
pub(crate) const NLMSG_DONE: u16 = 0x03;
pub(crate) const NLMSG_ERROR: u16 = 0x02;

/// `struct nlmsghdr`. Shared with the interface monitor (`len`/`msg_type` drive its walk).
#[repr(C)]
pub(crate) struct NlMsgHdr {
    pub(crate) len: u32,
    pub(crate) msg_type: u16,
    pub(crate) flags: u16,
    pub(crate) seq: u32,
    pub(crate) pid: u32,
}

// libc exposes no netlink structs to anchor against on glibc/musl, so pin the on-wire sizes directly.
const _: () = assert!(size_of::<NlMsgHdr>() == 16);

/// `struct ifaddrmsg`: the body of an `RTM_*ADDR` message. A zeroed value (family
/// `AF_UNSPEC`) is the dump request body. The interface monitor reads `index` from it.
#[repr(C)]
#[derive(Default)]
pub(crate) struct IfAddrMsg {
    pub(crate) family: u8,
    pub(crate) prefixlen: u8,
    pub(crate) flags: u8,
    pub(crate) scope: u8,
    pub(crate) index: u32,
}

const _: () = assert!(size_of::<IfAddrMsg>() == 8);

/// `struct rtattr`: a type-length-value attribute header within a message.
#[repr(C)]
pub(crate) struct RtAttr {
    pub(crate) len: u16,
    pub(crate) attr_type: u16,
}

const _: () = assert!(size_of::<RtAttr>() == 4);

/// `struct sockaddr_nl`.
#[repr(C)]
#[derive(Default)]
pub(crate) struct SockAddrNl {
    pub(crate) family: u16,
    pub(crate) pad: u16,
    pub(crate) pid: u32,
    pub(crate) groups: u32,
}

const _: () = assert!(size_of::<SockAddrNl>() == 12);

/// `NLMSG_ALIGN`: netlink's 4-byte alignment for message and attribute lengths.
pub(crate) const fn nl_align(n: usize) -> usize {
    (n + 3) & !3
}
