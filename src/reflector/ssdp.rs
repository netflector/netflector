//! The SSDP reflector reflects Simple Service Discovery Protocol (`UPnP`) between the source and
//! target interfaces so service discovery crosses the link. Advertisements (`NOTIFY`) reflect
//! target → source as a plain multicast re-emit (a [`SimpleReflector`]). Searches (`M-SEARCH`)
//! reflect source → target and each searcher's unicast `200 OK` replies route back through a
//! per-searcher session (the shared [`SearchReflector`]). Re-emits go to the same group at TTL 2,
//! sourced from the egress interface. With `dial`, a target→source datagram's DIAL `LOCATION` is
//! rewritten to a source-side proxy: [`DialRewrite`] is the SSDP [`ReplyRewrite`], used by both the
//! advertisement direction and each search session's response.

use std::net::SocketAddr;
use std::time::Duration;

use crate::config::{AddressFamily, Reflector};
use crate::dispatch::{CaptureKey, Filter, IpSet, MessageType, PacketDispatcher};
use crate::interface::InterfaceAddresses;
use crate::net::MAX_UDP_PAYLOAD_LEN;
use crate::net::ssdp::{
    MSEARCH_MX_DEFAULT, SSDP_GROUP_V4, SSDP_GROUP_V6_LINK_LOCAL, SSDP_GROUP_V6_SITE_LOCAL,
    SSDP_PORT, SSDP_TTL, SsdpKind, advertises_only_unreachable, classify, parse_msearch_mx,
};
use crate::net::uninit_buf::UninitBuf;
use crate::reactor::Reactor;

use super::dial::{ProxyPlacement, rewrite_location};
use super::{
    BuildError, Emit, InterfaceMap, NoRewrite, ReplyRewrite, SearchReflector, SimpleReflector,
    Verdict, require_bidirectional_families, require_group_join, require_macs_matchable,
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
    scratch: UninitBuf,
}

impl DialRewrite {
    /// A rewriter for the device behind `target`.
    fn new(target: CaptureKey) -> Self {
        Self {
            target,
            scratch: UninitBuf::with_capacity(MAX_UDP_PAYLOAD_LEN),
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
            Some(self.scratch.filled())
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
    match classify(payload) {
        Some(kind @ SsdpKind::Advertisement) => Verdict::Reflect(kind.into()),
        Some(kind @ SsdpKind::Search) => Verdict::Skip(kind.into()),
        None => Verdict::Junk,
    }
}

/// The directional gate for the search leg: an `M-SEARCH` is a search to reflect, a `NOTIFY` belongs to
/// the advertisement direction, and anything else on the group is junk.
fn search_verdict(payload: &[u8]) -> Verdict {
    match classify(payload) {
        Some(kind @ SsdpKind::Search) => Verdict::Reflect(kind.into()),
        Some(kind @ SsdpKind::Advertisement) => Verdict::Skip(kind.into()),
        None => Verdict::Junk,
    }
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

/// Build the SSDP reflector for `reflector` and register both directions on `dispatcher`. A no-op
/// when SSDP isn't enabled. It joins every in-use family's group on BOTH interfaces, then registers
/// two handlers spanning them: advertisements target → source (a [`SimpleReflector`]), and searches
/// source → target with their unicast 200-OK replies (the shared [`SearchReflector`]). One
/// [`SearchReflector`] for every group means its sessions share one table and one cap. A
/// required family must be sendable on BOTH interfaces, since the reflector re-emits on both.
///
/// # Errors
/// [`BuildError::UnknownInterface`] for an unopened source/target, or
/// [`BuildError::RequiredFamilyUnavailable`] if either interface can't send a required family.
pub(crate) fn build(
    reflector: &Reflector,
    interfaces: &InterfaceMap,
    dispatcher: &mut PacketDispatcher,
) -> Result<(), BuildError> {
    let Some(ssdp) = &reflector.ssdp else {
        return Ok(());
    };
    let source = interfaces.require(reflector.source_if.as_str())?;
    let target = interfaces.require(reflector.target_if.as_str())?;

    // Re-emits on both interfaces (advertisements on source, searches and their responses on target),
    // so a required family must be sendable on BOTH.
    require_bidirectional_families(
        dispatcher,
        reflector.address_family,
        source,
        reflector.source_if.as_str(),
        target,
        reflector.target_if.as_str(),
    )?;
    require_macs_matchable(
        dispatcher,
        reflector.macs.as_ref(),
        target,
        reflector.target_if.as_str(),
    )?;

    // Advertisements are captured on target, searches on source; join every group on both. A family
    // with no address yet is recorded and re-attempted on the next address change.
    let groups = used_groups(reflector.address_family);
    for group in &groups {
        require_group_join(
            dispatcher,
            target,
            group.ip(),
            "SSDP",
            reflector.target_if.as_str(),
        )?;
        require_group_join(
            dispatcher,
            source,
            group.ip(),
            "SSDP",
            reflector.source_if.as_str(),
        )?;
    }
    // One handler per direction spans every group; its filter matches the group set at the SSDP port.
    let group_ips: IpSet = groups.iter().map(SocketAddr::ip).collect();
    // target -> source: advertisements (a stateless re-emit), optionally filtered to the configured
    // device's MAC. With `dial`, the reflected `LOCATION` is rewritten to a source-side proxy.
    // A NOTIFY whose LOCATION names a link-local or never-a-peer address advertises an endpoint
    // the source side can never use.
    let advertisement = SimpleReflector::new(
        source,
        "SSDP",
        "advertisement",
        advertisement_verdict,
        Emit::fixed(SSDP_PORT, SSDP_TTL),
    )
    .with_suppress(advertises_only_unreachable);
    let advertisement = if ssdp.dial {
        advertisement.with_rewrite(Box::new(DialRewrite::new(target)))
    } else {
        advertisement
    };
    dispatcher.register(
        target,
        Filter {
            dst_ip: Some(group_ips.clone()),
            dst_port: Some(SSDP_PORT.into()),
            src_mac: reflector.macs.clone(),
            ..Filter::default()
        },
        Box::new(advertisement),
    );
    // source -> target: searches (unfiltered, any source client may search); each searcher's unicast
    // 200-OK replies route back through a per-searcher session. The filter deliberately pins only
    // the group and port: a search relayed by another netflector arrives from its reserved
    // ephemeral source port, so a src_port or src_mac pin would silently break chained
    // (router-to-router) deployments. With `dial`, each session's reply
    // rewrites the device's DIAL `LOCATION` (a fresh DialRewrite per session); else it passes through.
    let make_reply: Box<dyn Fn() -> Box<dyn ReplyRewrite>> = if ssdp.dial {
        Box::new(move || Box::new(DialRewrite::new(target)) as Box<dyn ReplyRewrite>)
    } else {
        Box::new(|| Box::new(NoRewrite) as Box<dyn ReplyRewrite>)
    };
    dispatcher.register(
        source,
        Filter {
            dst_ip: Some(group_ips),
            dst_port: Some(SSDP_PORT.into()),
            ..Filter::default()
        },
        Box::new(SearchReflector::new(
            source,
            target,
            reflector.macs.clone(),
            "SSDP",
            MessageType::SsdpResponse,
            SSDP_TTL,
            search_verdict,
            search_window,
            make_reply,
            // Each session's 200 OK reply is gated the same way as the NOTIFY leg.
            advertises_only_unreachable,
        )),
    );
    log::info!(
        "SSDP reflector \"{}\": {} <-> {} (advertisements + searches{})",
        reflector.name.as_str(),
        reflector.source_if.as_str(),
        reflector.target_if.as_str(),
        if ssdp.dial { " + DIAL" } else { "" }
    );
    Ok(())
}

/// The SSDP groups `family` re-emits to: one IPv4 group, and (unlike mDNS) BOTH IPv6 scopes,
/// link-local `ff02::c` and site-local `ff05::c`.
fn used_groups(family: AddressFamily) -> Vec<SocketAddr> {
    let mut groups = Vec::with_capacity(3);
    if family.uses_ipv4() {
        groups.push(SocketAddr::from((SSDP_GROUP_V4, SSDP_PORT)));
    }
    if family.uses_ipv6() {
        groups.push(SocketAddr::from((SSDP_GROUP_V6_LINK_LOCAL, SSDP_PORT)));
        groups.push(SocketAddr::from((SSDP_GROUP_V6_SITE_LOCAL, SSDP_PORT)));
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn used_groups_follows_the_address_family() {
        let v4 = SocketAddr::from((SSDP_GROUP_V4, SSDP_PORT));
        let link_local = SocketAddr::from((SSDP_GROUP_V6_LINK_LOCAL, SSDP_PORT));
        let site_local = SocketAddr::from((SSDP_GROUP_V6_SITE_LOCAL, SSDP_PORT));
        // Default and Dual reflect both families; IPv6 uses both scopes (link-local + site-local).
        assert_eq!(
            used_groups(AddressFamily::Default),
            vec![v4, link_local, site_local]
        );
        assert_eq!(
            used_groups(AddressFamily::Dual),
            vec![v4, link_local, site_local]
        );
        assert_eq!(used_groups(AddressFamily::Ipv4), vec![v4]);
        assert_eq!(
            used_groups(AddressFamily::Ipv6),
            vec![link_local, site_local]
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
