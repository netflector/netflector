//! The SSDP reflector reflects Simple Service Discovery Protocol (`UPnP`) between the source and
//! target interfaces so service discovery crosses the link. Advertisements (`NOTIFY`) reflect
//! target → source as a plain multicast re-emit (a [`SimpleReflector`](super::SimpleReflector)). Searches (`M-SEARCH`)
//! reflect source → target and each searcher's unicast `200 OK` replies route back through a
//! per-searcher session (the shared [`SearchReflector`](super::search::SearchReflector)). Re-emits go to the same group at TTL 2,
//! sourced from the egress interface. With `dial`, a target→source datagram's DIAL `LOCATION` is
//! rewritten to a source-side proxy: [`DialRewrite`] is the SSDP [`ReplyRewrite`], used by both the
//! advertisement direction and each search session's response.

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

/// What a DIAL-enabled SSDP reflector needs to rewrite a device's `LOCATION` to a source-side proxy: the
/// target capture the device sits behind (its address and interface name resolve through it per
/// rewrite) and a reused scratch sink the rewritten datagram is built in. Owned per rewriting reflector
/// (the advertisement direction, and one per M-SEARCH session's response reflector), so it isn't `Copy`.
struct DialRewrite {
    target: CaptureKey,
    /// Reused sink for the rewritten datagram; see the [`ReplyRewrite`] impl. Bounded by the
    /// payload that still frames within [`MAX_FRAME_LEN`](crate::net::MAX_FRAME_LEN), so a rewrite
    /// that fits is always sendable.
    scratch: StreamBuffer,
}

impl DialRewrite {
    /// A rewriter for the device behind `target`.
    fn new(target: CaptureKey) -> Self {
        Self {
            target,
            scratch: StreamBuffer::with_capacity(MAX_UDP_PAYLOAD_LEN),
        }
    }
}

impl ReplyRewrite for DialRewrite {
    /// Rewrite a target→source SSDP datagram's DIAL `LOCATION` to a source-side description proxy, into
    /// the reused scratch. Returns the rewritten slice, or `None` to forward `payload` verbatim.
    /// `egress` is the source capture the datagram reflects onto.
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
            // A family the proxy can't bridge yet; any DIAL LOCATION goes through unrewritten.
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

/// SSDP's classifier kind maps to its two group message types. The unicast `200 OK` reply is a
/// separate leg ([`MessageType::SsdpResponse`]), carried by the response reflector, not the classifier.
impl From<SsdpKind> for MessageType {
    fn from(kind: SsdpKind) -> Self {
        match kind {
            SsdpKind::Advertisement => Self::SsdpAdvertisement,
            SsdpKind::Search => Self::SsdpSearch,
        }
    }
}

/// The directional gate for the advertisement leg: a `NOTIFY` is an advertisement to reflect, an
/// `M-SEARCH` belongs to the search direction, and anything else on the group is junk.
fn advertisement_verdict(payload: &[u8]) -> Verdict {
    directional_verdict(classify(payload), SsdpKind::Advertisement)
}

/// The directional gate for the search leg: an `M-SEARCH` is a search to reflect, a `NOTIFY` belongs to
/// the advertisement direction, and anything else on the group is junk.
fn search_verdict(payload: &[u8]) -> Verdict {
    directional_verdict(classify(payload), SsdpKind::Search)
}

/// A session outlives the searcher's MX window by this grace, since a device's 200-OK may lag the
/// search.
const SESSION_GRACE: Duration = Duration::from_secs(2);

/// An `M-SEARCH`'s session window: its MX response window (clamped by [`parse_msearch_mx`]) plus the
/// reply grace. A search with no usable MX falls back to the protocol default.
fn search_window(payload: &[u8]) -> Duration {
    let mx = parse_msearch_mx(payload).unwrap_or_else(|| {
        log::debug!(
            "SSDP: M-SEARCH has no usable MX; using the default {MSEARCH_MX_DEFAULT}s window"
        );
        MSEARCH_MX_DEFAULT
    });
    Duration::from_secs(u64::from(mx)) + SESSION_GRACE
}

/// SSDP as a search-style protocol: one IPv4 group and, unlike mDNS and WSD, BOTH IPv6 scopes.
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

/// Build the SSDP reflector for `reflector` and register both directions on `dispatcher`: the
/// advertisement and search legs of [`build_pair`], with `dial` adding the DIAL `LOCATION` rewrite
/// to both. A no-op when SSDP isn't enabled.
///
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

/// The DIAL rewrite for the device behind `target`.
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
