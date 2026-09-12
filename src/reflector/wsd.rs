//! The WSD (WS-Discovery) reflector: reflects WS-Discovery between the source and target interfaces so
//! ONVIF-camera / Windows-device discovery crosses the link. Structurally SSDP-without-DIAL: `Hello` /
//! `Bye` announcements reflect device → client as a stateless multicast re-emit (a [`SimpleReflector`](super::SimpleReflector),
//! like mDNS), and `Probe` / `Resolve` searches reflect client → device with their unicast
//! `ProbeMatches` / `ResolveMatches` replies routed back through a per-searcher session (the shared
//! [`SearchReflector`](super::search::SearchReflector)). Re-emits go to the same group at TTL 1, sourced from the egress interface.

use std::time::Duration;

use crate::config::Reflector;
use crate::dispatch::{MessageType, PacketDispatcher};
use crate::net::wsd::{
    WSD_GROUP_V4, WSD_GROUP_V6, WSD_PORT, WSD_TTL, WsdKind, advertises_only_unreachable, classify,
};

use super::{BuildError, InterfaceMap, SearchProtocol, Verdict, build_pair, directional_verdict};

/// WSD's classifier kind maps to its group message types. The `ProbeMatches`/`ResolveMatches` unicast
/// replies are a separate leg ([`MessageType::WsdResponse`]), carried by the response reflector.
impl From<WsdKind> for MessageType {
    fn from(kind: WsdKind) -> Self {
        match kind {
            WsdKind::Announcement => Self::WsdAnnouncement,
            WsdKind::Search => Self::WsdSearch,
        }
    }
}

/// The directional gate for the announcement direction: reflect `Hello` / `Bye`, skip a search (it
/// flows the other way), and treat anything else on the group as junk.
fn announcement_verdict(payload: &[u8]) -> Verdict {
    directional_verdict(classify(payload), WsdKind::Announcement)
}

/// The directional gate for the search direction: the mirror of [`announcement_verdict`].
fn search_verdict(payload: &[u8]) -> Verdict {
    directional_verdict(classify(payload), WsdKind::Search)
}

/// A `Probe` / `Resolve` carries no MX field, so the reply window is fixed: long enough for a
/// device's unicast match (WS-Discovery caps the reply delay at ~500 ms) plus network slack.
const SESSION_WINDOW: Duration = Duration::from_secs(5);

fn window(_: &[u8]) -> Duration {
    SESSION_WINDOW
}

/// WSD as a search-style protocol: the IPv4 group and, unlike SSDP, only the link-local IPv6 scope.
const WSD: SearchProtocol = SearchProtocol {
    name: "WSD",
    announcement_kind: "announcement",
    port: WSD_PORT,
    ttl: WSD_TTL,
    group_v4: WSD_GROUP_V4,
    groups_v6: &[WSD_GROUP_V6],
    response_type: MessageType::WsdResponse,
    announcement_verdict,
    search_verdict,
    window,
    suppress: advertises_only_unreachable,
};

/// Build the WSD reflector for `reflector` and register both directions on `dispatcher`: the
/// announcement and search legs of [`build_pair`]. A no-op when WSD isn't enabled.
///
/// # Errors
/// As [`build_pair`].
pub(crate) fn build(
    reflector: &Reflector,
    interfaces: &InterfaceMap,
    dispatcher: &mut PacketDispatcher,
) -> Result<(), BuildError> {
    if !reflector.wsd {
        return Ok(());
    }
    build_pair(
        reflector,
        interfaces,
        dispatcher,
        WSD,
        None,
        "announcements + searches",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdicts_gate_by_direction() {
        let hello = b"<a:Action>http://x/Hello</a:Action>";
        let probe = b"<a:Action>http://x/Probe</a:Action>";
        assert_eq!(
            announcement_verdict(hello),
            Verdict::Reflect(MessageType::WsdAnnouncement)
        );
        assert_eq!(
            announcement_verdict(probe),
            Verdict::Skip(MessageType::WsdSearch)
        );
        assert_eq!(announcement_verdict(b"junk"), Verdict::Junk);
        assert_eq!(
            search_verdict(probe),
            Verdict::Reflect(MessageType::WsdSearch)
        );
        assert_eq!(
            search_verdict(hello),
            Verdict::Skip(MessageType::WsdAnnouncement)
        );
        assert_eq!(search_verdict(b"junk"), Verdict::Junk);
    }
}
