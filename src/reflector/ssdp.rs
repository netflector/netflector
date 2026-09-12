//! The SSDP reflector: `NOTIFY` advertisements reflect target → source as a plain multicast
//! re-emit, `M-SEARCH`es source → target with each searcher's unicast `200 OK` routed back through
//! a per-searcher session. With `dial`, [`DialRewrite`] rewrites a target→source datagram's DIAL
//! `LOCATION` to a source-side proxy on both legs.

use std::time::Duration;

use crate::config::Reflector;
use crate::dispatch::{CaptureKey, MessageType, PacketDispatcher};
use crate::interface::InterfaceAddresses;
use crate::net::MAX_UDP_PAYLOAD_LEN;
use crate::net::ssdp::{
    MSEARCH_MX_DEFAULT, SSDP_GROUP_V4, SSDP_GROUP_V6_LINK_LOCAL, SSDP_GROUP_V6_SITE_LOCAL,
    SSDP_PORT, SSDP_TTL, SsdpKind, advertises_only_unreachable, classify, parse_msearch_mx,
};
use crate::net::stream_buffer::StreamBuffer;
use crate::reactor::Reactor;

use super::dial::{ProxyPlacement, rewrite_location};
use super::{
    BuildError, InterfaceMap, ReplyRewrite, SearchProtocol, Verdict, build_pair,
    directional_verdict,
};

/// The SSDP [`ReplyRewrite`] with `dial`: rewrites a device's `LOCATION` to a source-side proxy.
/// The device's address and interface resolve through `target` per rewrite, so nothing is cached
/// across an address change.
struct DialRewrite {
    target: CaptureKey,
    /// Sized to the payload that still frames within [`MAX_FRAME_LEN`](crate::net::MAX_FRAME_LEN),
    /// so a rewrite that fits is always sendable.
    scratch: StreamBuffer,
}

impl DialRewrite {
    fn new(target: CaptureKey) -> Self {
        Self {
            target,
            scratch: StreamBuffer::with_capacity(MAX_UDP_PAYLOAD_LEN),
        }
    }
}

impl ReplyRewrite for DialRewrite {
    fn rewrite<'a>(
        &'a mut self,
        payload: &[u8],
        egress: CaptureKey,
        dispatcher: &mut PacketDispatcher,
        reactor: &mut Reactor,
    ) -> Option<&'a [u8]> {
        let (Some(source), Some(target)) = (
            dispatcher
                .egress_addrs(egress)
                .and_then(InterfaceAddresses::v4),
            dispatcher
                .egress_addrs(self.target)
                .and_then(InterfaceAddresses::v4),
        ) else {
            log::debug!("SSDP: source or target has no IPv4; DIAL rewrite skipped");
            return None;
        };
        let (ctx, target_iface) = dispatcher.dial_context(self.target);
        let placement = ProxyPlacement {
            source_capture: egress,
            source,
            target_capture: self.target,
            target,
            target_iface,
        };
        self.scratch.clear();
        if rewrite_location(ctx, reactor, payload, placement, &mut self.scratch) {
            Some(self.scratch.pending())
        } else {
            None
        }
    }
}

impl From<SsdpKind> for MessageType {
    fn from(kind: SsdpKind) -> Self {
        match kind {
            SsdpKind::Advertisement => Self::SsdpAdvertisement,
            SsdpKind::Search => Self::SsdpSearch,
        }
    }
}

fn advertisement_verdict(payload: &[u8]) -> Verdict {
    directional_verdict(classify(payload), SsdpKind::Advertisement)
}

fn search_verdict(payload: &[u8]) -> Verdict {
    directional_verdict(classify(payload), SsdpKind::Search)
}

/// Slack past the MX window for a device's late 200 OK.
const SESSION_GRACE: Duration = Duration::from_secs(2);

fn search_window(payload: &[u8]) -> Duration {
    let mx = parse_msearch_mx(payload).unwrap_or_else(|| {
        log::debug!(
            "SSDP: M-SEARCH has no usable MX; using the default {MSEARCH_MX_DEFAULT}s window"
        );
        MSEARCH_MX_DEFAULT
    });
    Duration::from_secs(u64::from(mx)) + SESSION_GRACE
}

/// Unlike mDNS and WSD, SSDP has two IPv6 scopes.
const SSDP: SearchProtocol = SearchProtocol {
    name: "SSDP",
    announcement_kind: "advertisement",
    port: SSDP_PORT,
    ttl: SSDP_TTL,
    group_v4: SSDP_GROUP_V4,
    groups_v6: &[SSDP_GROUP_V6_LINK_LOCAL, SSDP_GROUP_V6_SITE_LOCAL],
    response_type: MessageType::SsdpResponse,
    announcement_verdict: advertisement_verdict,
    search_verdict,
    window: search_window,
    suppress: advertises_only_unreachable,
};

/// # Errors
/// As [`build_pair`].
pub(crate) fn build(
    reflector: &Reflector,
    interfaces: &InterfaceMap,
    dispatcher: &mut PacketDispatcher,
) -> Result<(), BuildError> {
    let Some(ssdp) = &reflector.ssdp else {
        return Ok(());
    };
    let (rewrite, summary) = if ssdp.dial {
        (
            Some(dial_rewrite as fn(CaptureKey) -> Box<dyn ReplyRewrite>),
            "advertisements + searches + DIAL",
        )
    } else {
        (None, "advertisements + searches")
    };
    build_pair(reflector, interfaces, dispatcher, SSDP, rewrite, summary)
}

fn dial_rewrite(target: CaptureKey) -> Box<dyn ReplyRewrite> {
    Box::new(DialRewrite::new(target))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssdp_reflects_both_ipv6_scopes() {
        let groups = SSDP.groups(crate::config::AddressFamily::Ipv6);
        assert_eq!(
            groups,
            [
                std::net::SocketAddr::from((SSDP_GROUP_V6_LINK_LOCAL, SSDP_PORT)),
                std::net::SocketAddr::from((SSDP_GROUP_V6_SITE_LOCAL, SSDP_PORT)),
            ]
        );
    }

    #[test]
    fn verdicts_gate_by_direction() {
        let notify = b"NOTIFY * HTTP/1.1\r\n";
        let msearch = b"M-SEARCH * HTTP/1.1\r\n";
        assert_eq!(
            advertisement_verdict(notify),
            Verdict::Reflect(MessageType::SsdpAdvertisement)
        );
        assert_eq!(
            advertisement_verdict(msearch),
            Verdict::Skip(MessageType::SsdpSearch)
        );
        assert_eq!(advertisement_verdict(b"junk"), Verdict::Junk);
        assert_eq!(
            search_verdict(msearch),
            Verdict::Reflect(MessageType::SsdpSearch)
        );
        assert_eq!(
            search_verdict(notify),
            Verdict::Skip(MessageType::SsdpAdvertisement)
        );
        assert_eq!(search_verdict(b"junk"), Verdict::Junk);
    }
}
