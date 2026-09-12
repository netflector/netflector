//! `PF_ROUTE` message framing, hand-rolled because `libc` exposes `rt_msghdr` for apple only.
//!
//! Transcribed from FreeBSD 14.4 `<net/route.h>`.

use libc::{c_int, c_ulong, pid_t};

#[repr(C)]
#[derive(Default)]
pub(crate) struct RtMsgHdr {
    /// `rtm_msglen`: header plus the trailing sockaddrs.
    pub(crate) msglen: u16,
    pub(crate) version: u8,
    pub(crate) msg_type: u8,
    /// `rtm_index`: the route's interface.
    pub(crate) index: u16,
    pub(crate) spare1: u16,
    pub(crate) flags: c_int,
    /// `rtm_addrs`: which `RTA_*` sockaddrs follow the header.
    pub(crate) addrs: c_int,
    pub(crate) pid: pid_t,
    pub(crate) seq: c_int,
    pub(crate) errno: c_int,
    pub(crate) fmask: c_int,
    pub(crate) inits: c_ulong,
    pub(crate) rmx: RtMetrics,
}

const _: () = assert!(size_of::<RtMsgHdr>() == 152);

#[repr(C)]
#[derive(Default)]
pub(crate) struct RtMetrics {
    pub(crate) locks: c_ulong,
    pub(crate) mtu: c_ulong,
    pub(crate) hopcount: c_ulong,
    pub(crate) expire: c_ulong,
    pub(crate) recvpipe: c_ulong,
    pub(crate) sendpipe: c_ulong,
    pub(crate) ssthresh: c_ulong,
    pub(crate) rtt: c_ulong,
    pub(crate) rttvar: c_ulong,
    pub(crate) pksent: c_ulong,
    pub(crate) weight: c_ulong,
    pub(crate) nhidx: c_ulong,
    pub(crate) filler: [c_ulong; 2],
}

const _: () = assert!(size_of::<RtMetrics>() == 112);
