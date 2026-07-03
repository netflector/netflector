//! The SSDP reflector: reflects Simple Service Discovery Protocol (`UPnP`) between the source and
//! target interfaces so service discovery crosses the link. Advertisements (`NOTIFY`) reflect
//! target → source as a plain multicast re-emit (the [`advertisement`] module); searches (`M-SEARCH`)
//! reflect source → target and each searcher's unicast `200 OK` replies route back through a
//! per-searcher session (the shared [`SearchReflector`]). Re-emits go to the same group at TTL 2,
//! sourced from the egress interface. With `dial`, a target→source datagram's DIAL `LOCATION` is
//! rewritten to a source-side proxy: [`DialRewrite`] is the SSDP [`ReplyRewrite`], used by both the
//! advertisement direction and each search session's response.

mod advertisement;

use std::net::SocketAddr;
use std::time::Duration;

use crate::config::{AddressFamily, Reflector};
use crate::dispatch::{CaptureKey, Filter, IpSet, PacketDispatcher};
use crate::interface::InterfaceAddresses;
use crate::net::ssdp::{
    MSEARCH_MX_DEFAULT, SSDP_GROUP_V4, SSDP_GROUP_V6_LINK_LOCAL, SSDP_GROUP_V6_SITE_LOCAL,
    SSDP_PORT, SSDP_TTL, SsdpKind, classify, parse_msearch_mx,
};
use crate::net::uninit_buf::UninitBuf;
use crate::reactor::Reactor;

use self::advertisement::SsdpAdvertisementReflector;
use super::dial::{ProxyPlacement, REWRITE_BUF_LEN, rewrite_location};
use super::{
    BuildError, InterfaceMap, NoRewrite, ReplyRewrite, SearchReflector, Verdict,
    require_bidirectional_families,
};

/// What a DIAL-enabled SSDP reflector needs to rewrite a device's `LOCATION` to a source-side proxy: the
/// target capture the device sits behind (for its address), that interface's egress-pin ifindex, and a
/// reused scratch sink the rewritten datagram is built in. Owned per rewriting reflector — the
/// advertisement direction, and one per M-SEARCH session's response reflector — so it isn't `Copy`.
struct DialRewrite {
    target: CaptureKey,
    target_ifindex: u32,
    /// Reused sink for the rewritten datagram; see the [`ReplyRewrite`] impl.
    scratch: UninitBuf,
}

impl DialRewrite {
    /// A rewriter for the device behind `target` (`target_ifindex` scopes the IPv6 reserved-port bind),
    /// with a fresh scratch sink.
    fn new(target: CaptureKey, target_ifindex: u32) -> Self {
        Self {
            target,
            target_ifindex,
            scratch: UninitBuf::with_capacity(REWRITE_BUF_LEN),
        }
    }
}

impl ReplyRewrite for DialRewrite {
    /// Rewrite a target→source SSDP datagram's DIAL `LOCATION` to a source-side description proxy, into
    /// the reused scratch. Returns the rewritten slice on success, else `payload` (forward verbatim).
    /// `egress` is the source capture the datagram reflects onto. Used by both the advertisement
    /// direction and each search session's response.
    fn rewrite<'a>(
        &'a mut self,
        payload: &'a [u8],
        egress: CaptureKey,
        dispatcher: &mut PacketDispatcher,
        reactor: &mut Reactor,
    ) -> &'a [u8] {
        let (Some(source), Some(target)) = (
            dispatcher
                .egress_addrs(egress)
                .and_then(InterfaceAddresses::v4),
            dispatcher
                .egress_addrs(self.target)
                .and_then(InterfaceAddresses::v4),
        ) else {
            return payload; // a family the proxy can't bridge yet — forward unchanged
        };
        let placement = ProxyPlacement {
            source_capture: egress,
            source,
            target_capture: self.target,
            target,
            target_ifindex: self.target_ifindex,
        };
        self.scratch.clear();
        if rewrite_location(
            dispatcher.dial_context(),
            reactor,
            payload,
            placement,
            &mut self.scratch,
        ) {
            self.scratch.filled()
        } else {
            payload
        }
    }
}

/// The directional gate for the search leg: an `M-SEARCH` is a search to reflect, a `NOTIFY` belongs to
/// the advertisement direction, and anything else on the group is junk.
fn search_verdict(payload: &[u8]) -> Verdict {
    match classify(payload) {
        Some(SsdpKind::Search) => Verdict::Reflect,
        Some(SsdpKind::Advertisement) => Verdict::Skip,
        None => Verdict::Junk,
    }
}

/// A session outlives the searcher's MX window by this grace, since a device's 200-OK may lag the
/// search (mirrors the C++).
const SESSION_GRACE: Duration = Duration::from_secs(2);

/// An `M-SEARCH`'s session window: its MX response window (clamped by [`parse_msearch_mx`]) plus the
/// reply grace. A search with no usable MX falls back to the protocol default.
fn search_window(payload: &[u8]) -> Duration {
    let mx = parse_msearch_mx(payload).unwrap_or_else(|| {
        log::info!(
            "SSDP: M-SEARCH has no usable MX; using the default {MSEARCH_MX_DEFAULT}s window"
        );
        MSEARCH_MX_DEFAULT
    });
    Duration::from_secs(u64::from(mx)) + SESSION_GRACE
}

/// Build the SSDP reflector for `reflector` and register both directions on `dispatcher` — a no-op
/// when SSDP isn't enabled. For each address family in use it joins every group on BOTH interfaces and
/// registers two handlers per group: advertisements target → source ([`SsdpAdvertisementReflector`]),
/// and searches source → target with their unicast 200-OK replies (the shared [`SearchReflector`]). A
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

    // The reserved-port bind for an IPv6 link-local target source needs the target's scope id; use
    // the ifindex the capture already cached (the single source of truth the joiners bake too).
    let target_ifindex = dispatcher.capture_ifindex(target).unwrap_or(0);

    // Advertisements are captured on target, searches on source — join every group on both. A family
    // with no address yet is recorded and re-attempted on the next address change.
    let groups = used_groups(reflector.address_family);
    for group in &groups {
        if let Err(e) = dispatcher.join_group(target, group.ip()) {
            log::debug!("SSDP: join {} on target deferred: {e}", group.ip());
        }
        if let Err(e) = dispatcher.join_group(source, group.ip()) {
            log::debug!("SSDP: join {} on source deferred: {e}", group.ip());
        }
    }
    // One handler per direction spans every group; its filter matches the group set at the SSDP port.
    let group_ips: IpSet = groups.iter().map(SocketAddr::ip).collect();
    // target -> source: advertisements, optionally filtered to the configured device's MAC.
    dispatcher.register(
        target,
        Filter {
            dst_ip: Some(group_ips.clone()),
            dst_port: Some(SSDP_PORT.into()),
            src_mac: reflector.macs.clone(),
            ..Filter::default()
        },
        Box::new(SsdpAdvertisementReflector::new(
            source,
            ssdp.dial.then(|| DialRewrite::new(target, target_ifindex)),
        )),
    );
    // source -> target: searches (unfiltered — any source client may search); each searcher's unicast
    // 200-OK replies route back through a per-searcher session. With `dial`, each session's reply
    // rewrites the device's DIAL `LOCATION` (a fresh DialRewrite per session); else it passes through.
    let make_reply: Box<dyn Fn() -> Box<dyn ReplyRewrite>> = if ssdp.dial {
        Box::new(move || {
            Box::new(DialRewrite::new(target, target_ifindex)) as Box<dyn ReplyRewrite>
        })
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
            target_ifindex,
            reflector.macs.clone(),
            "SSDP",
            SSDP_TTL,
            search_verdict,
            search_window,
            make_reply,
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

/// The SSDP groups `family` re-emits to: one IPv4 group, and — unlike mDNS — BOTH IPv6 scopes
/// (link-local `ff02::c` and site-local `ff05::c`).
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
}
