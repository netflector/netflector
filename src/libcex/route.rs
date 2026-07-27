//! `PF_ROUTE` message framing, hand-rolled because `libc` exposes `rt_msghdr` for apple only.
//!
//! Transcribed from FreeBSD 14.4 `<net/route.h>`.

use libc::{c_int, c_ulong, pid_t};

#[repr(C)]
#[derive(Default)]
pub(crate) struct RtMsgHdr {
    /// `rtm_msglen`: the whole message, header and trailing sockaddrs.
    pub(crate) msglen: u16,
    pub(crate) version: u8,
    /// `rtm_type`: which `RTM_*` message this is.
    pub(crate) msg_type: u8,
    /// `rtm_index`: the interface associated with the route.
    pub(crate) index: u16,
    pub(crate) spare1: u16,
    pub(crate) flags: c_int,
    /// `rtm_addrs`: which `RTA_*` sockaddrs follow the header.
    pub(crate) addrs: c_int,
    pub(crate) pid: pid_t,
    pub(crate) seq: c_int,
    pub(crate) errno: c_int,
    /// `rtm_fmask`: which metrics an `RTM_CHANGE` sets.
    pub(crate) fmask: c_int,
    /// `rtm_inits`: which metrics the message initializes.
    pub(crate) inits: c_ulong,
    pub(crate) rmx: RtMetrics,
}

const _: () = assert!(size_of::<RtMsgHdr>() == 152);

#[repr(C)]
#[derive(Default)]
pub(crate) struct RtMetrics {
    /// Metrics the kernel must leave alone.
    pub(crate) locks: c_ulong,
    pub(crate) mtu: c_ulong,
    pub(crate) hopcount: c_ulong,
    /// Lifetime for the route, e.g. a redirect.
    pub(crate) expire: c_ulong,
    /// Inbound delay-bandwidth product.
    pub(crate) recvpipe: c_ulong,
    /// Outbound delay-bandwidth product.
    pub(crate) sendpipe: c_ulong,
    /// Outbound gateway buffer limit.
    pub(crate) ssthresh: c_ulong,
    pub(crate) rtt: c_ulong,
    pub(crate) rttvar: c_ulong,
    pub(crate) pksent: c_ulong,
    pub(crate) weight: c_ulong,
    pub(crate) nhidx: c_ulong,
    /// `rmx_filler`: reserved.
    pub(crate) filler: [c_ulong; 2],
}

const _: () = assert!(size_of::<RtMetrics>() == 112);
