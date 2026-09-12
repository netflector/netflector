//! The WSD (WS-Discovery) reflector, for ONVIF-camera / Windows-device discovery. Structurally
//! SSDP without DIAL: `Hello` / `Bye` announcements reflect device → client, `Probe` / `Resolve`
//! searches client → device with their unicast `ProbeMatches` / `ResolveMatches` routed back per
//! searcher.

use std::time::Duration;

use crate::config::Reflector;
use crate::dispatch::{MessageType, PacketDispatcher};
use crate::net::wsd::{
    WSD_GROUP_V4, WSD_GROUP_V6, WSD_PORT, WSD_TTL, WsdKind, advertises_only_unreachable, classify,
};

use super::{BuildError, InterfaceMap, SearchProtocol, Verdict, build_pair, directional_verdict};

impl From<WsdKind> for MessageType {
    fn from(kind: WsdKind) -> Self {
        match kind {
            WsdKind::Announcement => Self::WsdAnnouncement,
            WsdKind::Search => Self::WsdSearch,
        }
    }
}

fn announcement_verdict(payload: &[u8]) -> Verdict {
    directional_verdict(classify(payload), WsdKind::Announcement)
}

fn search_verdict(payload: &[u8]) -> Verdict {
    directional_verdict(classify(payload), WsdKind::Search)
}

/// A `Probe` / `Resolve` carries no MX, so the window is fixed: WS-Discovery caps the match delay
/// at ~500 ms, the rest is slack.
const SESSION_WINDOW: Duration = Duration::from_secs(5);

fn window(_: &[u8]) -> Duration {
    SESSION_WINDOW
}

/// Unlike SSDP, only the link-local IPv6 scope.
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
