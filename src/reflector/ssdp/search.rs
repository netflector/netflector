//! The SSDP search leg: the protocol glue that drives the shared [`SearchReflector`] for `M-SEARCH`.
//!
//! The session machinery is shared (`reflector::search`); this module supplies SSDP's specifics — the
//! directional classifier, the MX-derived session window, and (with `dial`) the per-session DIAL
//! `LOCATION` rewrite via the parent's [`DialRewrite`].

use std::time::Duration;

use crate::dispatch::CaptureKey;
use crate::net::mac::MacSet;
use crate::net::ssdp::{MSEARCH_MX_DEFAULT, SSDP_TTL, SsdpKind, classify, parse_msearch_mx};
use crate::reflector::{NoRewrite, ReplyRewrite, SearchReflector, Verdict};

use super::DialRewrite;

/// The directional gate: an `M-SEARCH` is a search to reflect, a `NOTIFY` belongs to the advertisement
/// direction, and anything else on the group is junk.
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
fn window(payload: &[u8]) -> Duration {
    let mx = parse_msearch_mx(payload).unwrap_or_else(|| {
        log::info!(
            "SSDP: M-SEARCH has no usable MX; using the default {MSEARCH_MX_DEFAULT}s window"
        );
        MSEARCH_MX_DEFAULT
    });
    Duration::from_secs(u64::from(mx)) + SESSION_GRACE
}

/// The shared [`SearchReflector`] configured for SSDP: source → target `M-SEARCH` reflection with
/// per-searcher 200-OK sessions. With `dial`, each session's reply rewrites the device's DIAL
/// `LOCATION` (a fresh [`DialRewrite`] per session); otherwise replies pass through unchanged.
pub(super) fn reflector(
    source: CaptureKey,
    target: CaptureKey,
    target_ifindex: u32,
    device_macs: Option<MacSet>,
    dial: bool,
) -> SearchReflector {
    let make_reply: Box<dyn Fn() -> Box<dyn ReplyRewrite>> = if dial {
        Box::new(move || {
            Box::new(DialRewrite::new(target, target_ifindex)) as Box<dyn ReplyRewrite>
        })
    } else {
        Box::new(|| Box::new(NoRewrite) as Box<dyn ReplyRewrite>)
    };
    SearchReflector::new(
        source,
        target,
        target_ifindex,
        device_macs,
        "SSDP",
        SSDP_TTL,
        search_verdict,
        window,
        make_reply,
    )
}
