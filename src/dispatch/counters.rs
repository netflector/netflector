//! Observability counters: what the reflector did with each packet, tallied per message type and
//! interface.
//!
//! A single packet can match several handlers: mirrored `a→b`/`b→a` reflectors put one reflecting and
//! one skipping handler on the same interface, and a source fanned out to several targets (`a→b`,
//! `a→c`) puts several reflecting handlers there. Each handler returns an [`Outcome`]; the dispatcher
//! folds them with [`Outcome::combine`] into the single highest-precedence disposition and records that
//! once, so one packet is counted once per ingress. The fold also surfaces "can't happen under a valid
//! config" [`Anomalies`] for the dispatcher to log.
//!
//! The interface dimension is the ingress [`CaptureKey`](super::CaptureKey), which the dispatcher
//! supplies; a [`CaptureCounters`] row per interface holds the tallies.

use std::fmt;

/// Declare [`MessageType`] from a single `Variant => (protocol, direction)` list, deriving its report
/// labels, the `ALL` roster, and [`MESSAGE_TYPE_COUNT`] from it. Count and counter-row order both come
/// from the list, so reordering variants is harmless and adding or removing one can't leave the count
/// (the counter-array width) stale.
macro_rules! message_types {
    ($($variant:ident => ($protocol:literal, $direction:literal)),+ $(,)?) => {
        /// A protocol and direction: the flat set of reflector legs the counters key on, one variant
        /// per direction of each protocol. Handlers report the packet's *intrinsic* type, not the leg
        /// they serve, so every handler that sees one packet agrees on it. A disagreement is a bug; see
        /// [`Anomalies::type_mismatch`].
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(crate) enum MessageType {
            $($variant),+
        }

        impl MessageType {
            /// Every variant, in declaration (counter-row) order; the source of truth for the count.
            const ALL: &'static [MessageType] = &[$(Self::$variant),+];

            /// The protocol and direction words for the report, e.g. `("mDNS", "query")`. A type with
            /// no direction pair (Wake-on-LAN) leaves the second word empty.
            fn labels(self) -> (&'static str, &'static str) {
                match self {
                    $(Self::$variant => ($protocol, $direction)),+
                }
            }
        }

        /// The number of [`MessageType`] variants: the width of a per-interface counter row. Derived
        /// from the variant list, so it can never drift from the enum.
        pub(crate) const MESSAGE_TYPE_COUNT: usize = MessageType::ALL.len();
    };
}

message_types! {
    MdnsQuery => ("mDNS", "query"),
    MdnsResponse => ("mDNS", "response"),
    SsdpAdvertisement => ("SSDP", "advertisement"),
    SsdpSearch => ("SSDP", "search"),
    SsdpResponse => ("SSDP", "response"),
    WsdAnnouncement => ("WSD", "announcement"),
    WsdSearch => ("WSD", "search"),
    WsdResponse => ("WSD", "response"),
    WakeOnLan => ("WoL", ""),
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.labels() {
            (protocol, "") => f.write_str(protocol),
            (protocol, direction) => write!(f, "{protocol} {direction}"),
        }
    }
}

/// Fold precedence for [`Outcome`], ordered worst-to-best so the higher variant wins when several
/// handlers see one packet (the derived `Ord` follows declaration order). `Reflected` dominates (the
/// packet crossed); a failed reflect (`Dropped`/`Stalled`) outranks a `Skipped` (a correct
/// non-forward); `Filtered` (junk) is last. Fieldless, so precedence belongs to the disposition alone
/// and `MessageType` needn't be `Ord`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Disposition {
    Filtered,
    Skipped,
    Stalled,
    Dropped,
    Reflected,
}

/// Invariants an [`Outcome::combine`] fold can violate. Never expected under a valid config, so the
/// dispatcher logs them rather than silently miscounting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Anomalies {
    /// Two handlers classified one packet to different message types: a classifier or config bug.
    pub(crate) type_mismatch: bool,
}

/// What a handler did with a packet: its `on_packet` return, folded by the dispatcher. The carried
/// [`MessageType`] is the packet's intrinsic type, present on every disposition but junk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Re-emitted on the egress interface.
    Reflected(MessageType),
    /// Recognized, but the wrong direction for this leg: the loop-breaker, not ours to forward.
    Skipped(MessageType),
    /// The right direction, but the re-emit failed (a send error or a resource cap).
    Dropped(MessageType),
    /// The right direction, but the egress has no source address of the family yet (transient).
    Stalled(MessageType),
    /// Not a message we handle: unrecognized junk on the group, or an unhandled address family.
    Filtered,
}

impl Outcome {
    /// This outcome's fold-precedence key (see [`Disposition`]).
    fn disposition(self) -> Disposition {
        match self {
            Self::Reflected(_) => Disposition::Reflected,
            Self::Dropped(_) => Disposition::Dropped,
            Self::Stalled(_) => Disposition::Stalled,
            Self::Skipped(_) => Disposition::Skipped,
            Self::Filtered => Disposition::Filtered,
        }
    }

    /// The packet's message type, or `None` for `Filtered`: junk has no direction to attribute.
    fn message_type(self) -> Option<MessageType> {
        match self {
            Self::Reflected(t) | Self::Skipped(t) | Self::Dropped(t) | Self::Stalled(t) => Some(t),
            Self::Filtered => None,
        }
    }

    /// Fold another handler's outcome for the *same* packet into this running one: keep the
    /// higher-precedence disposition, and report any invariant [`Anomalies`]. Order-independent (a max
    /// over [`disposition`](Self::disposition)), so handler visitation order doesn't change the result.
    pub(crate) fn combine(self, other: Outcome) -> (Outcome, Anomalies) {
        let anomalies = Anomalies {
            type_mismatch: matches!(
                (self.message_type(), other.message_type()),
                (Some(a), Some(b)) if a != b
            ),
        };
        let merged = if other.disposition() > self.disposition() {
            other
        } else {
            self
        };
        (merged, anomalies)
    }
}

/// The four typed tallies for one message type on one interface.
#[derive(Clone, Copy, Default)]
struct TypeCounters {
    reflected: u64,
    skipped: u64,
    dropped: u64,
    stalled: u64,
}

impl TypeCounters {
    /// The non-zero tallies as `reflected=.. skipped=..`, or `None` when every tally is zero (so the
    /// report omits a message type nothing has happened to).
    fn format_nonzero(&self) -> Option<String> {
        let parts: Vec<String> = [
            ("reflected", self.reflected),
            ("skipped", self.skipped),
            ("dropped", self.dropped),
            ("stalled", self.stalled),
        ]
        .into_iter()
        .filter(|&(_, count)| count > 0)
        .map(|(label, count)| format!("{label}={count}"))
        .collect();
        (!parts.is_empty()).then(|| parts.join(" "))
    }
}

/// Every tally for one interface (capture): one [`TypeCounters`] per [`MessageType`], a type-less
/// `filtered` count for junk, and a `recoveries` count of completed interface rebuilds (a recreated
/// or returned interface whose captures re-bound).
#[derive(Clone, Default)]
pub(crate) struct CaptureCounters {
    types: [TypeCounters; MESSAGE_TYPE_COUNT],
    filtered: u64,
    recoveries: u64,
}

impl CaptureCounters {
    /// Tally one packet's folded [`Outcome`].
    pub(crate) fn record(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Reflected(t) => self.types[t as usize].reflected += 1,
            Outcome::Skipped(t) => self.types[t as usize].skipped += 1,
            Outcome::Dropped(t) => self.types[t as usize].dropped += 1,
            Outcome::Stalled(t) => self.types[t as usize].stalled += 1,
            Outcome::Filtered => self.filtered += 1,
        }
    }

    /// Tally one completed recovery of the interface behind this row: its kernel identity was
    /// recreated (or it returned from absent) and its captures re-bound. A lifecycle event, not a
    /// per-packet outcome, so it leads the report line.
    pub(crate) fn record_recovery(&mut self) {
        self.recoveries += 1;
    }

    /// This row's non-zero tallies as one line, e.g. `recoveries=1; mDNS query reflected=42
    /// skipped=10; SSDP search reflected=5 dropped=1; filtered=2`. `None` when nothing has been
    /// counted, so an idle interface produces no report line.
    fn format_nonzero(&self) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        if self.recoveries > 0 {
            parts.push(format!("recoveries={}", self.recoveries));
        }
        parts.extend(
            MessageType::ALL
                .iter()
                .zip(&self.types)
                .filter_map(|(ty, counts)| {
                    counts
                        .format_nonzero()
                        .map(|fields| format!("{ty} {fields}"))
                }),
        );
        if self.filtered > 0 {
            parts.push(format!("filtered={}", self.filtered));
        }
        (!parts.is_empty()).then(|| parts.join("; "))
    }
}

/// Log one `info` line per interface with any non-zero tallies (idle interfaces stay silent). The
/// dispatcher calls this from its periodic report; the `(interface, row)` pairs come from the
/// interface table, which owns the capture→interface-name mapping.
pub(crate) fn log_counters<'a>(rows: impl Iterator<Item = (&'a str, &'a CaptureCounters)>) {
    for (interface, counters) in rows {
        if let Some(summary) = counters.format_nonzero() {
            log::info!("counters {interface}: {summary}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl CaptureCounters {
        /// The four typed tallies (`reflected, skipped, dropped, stalled`) for `ty`. The test reader
        /// for recorded outcomes, here and in the dispatcher's route-fold test.
        pub(crate) fn typed(&self, ty: MessageType) -> (u64, u64, u64, u64) {
            let c = self.types[ty as usize];
            (c.reflected, c.skipped, c.dropped, c.stalled)
        }
        fn filtered(&self) -> u64 {
            self.filtered
        }
        /// This row's recovery tally. Read from the dispatcher's reconcile test through the
        /// interface table, hence `pub(crate)`.
        pub(crate) fn recoveries(&self) -> u64 {
            self.recoveries
        }
    }

    #[test]
    fn message_type_display_omits_the_empty_direction() {
        assert_eq!(MessageType::MdnsQuery.to_string(), "mDNS query");
        assert_eq!(
            MessageType::SsdpAdvertisement.to_string(),
            "SSDP advertisement"
        );
        assert_eq!(MessageType::WakeOnLan.to_string(), "WoL");
    }

    #[test]
    fn message_types_are_labelled_and_contiguously_indexed() {
        // `record` indexes the counter array by `ty as usize`, so each variant's discriminant must
        // equal its position in `ALL`, and every label must be non-empty.
        for (index, &ty) in MessageType::ALL.iter().enumerate() {
            assert!(!ty.to_string().is_empty(), "{ty:?} has an empty label");
            assert_eq!(
                ty as usize, index,
                "discriminants must be contiguous from 0"
            );
        }
    }

    #[test]
    fn disposition_orders_worst_to_best() {
        use Disposition::*;
        assert!(
            Reflected > Dropped && Dropped > Stalled && Stalled > Skipped && Skipped > Filtered
        );
    }

    #[test]
    fn record_bumps_the_matching_bucket() {
        let mut c = CaptureCounters::default();
        c.record(Outcome::Reflected(MessageType::MdnsQuery));
        c.record(Outcome::Reflected(MessageType::MdnsQuery));
        c.record(Outcome::Skipped(MessageType::MdnsQuery));
        c.record(Outcome::Dropped(MessageType::SsdpSearch));
        c.record(Outcome::Stalled(MessageType::SsdpSearch));
        c.record(Outcome::Filtered);
        assert_eq!(c.typed(MessageType::MdnsQuery), (2, 1, 0, 0));
        assert_eq!(c.typed(MessageType::SsdpSearch), (0, 0, 1, 1));
        assert_eq!(c.typed(MessageType::WakeOnLan), (0, 0, 0, 0));
        assert_eq!(c.filtered(), 1);
    }

    #[test]
    fn record_recovery_counts_and_leads_the_summary() {
        let mut c = CaptureCounters::default();
        assert_eq!(c.recoveries(), 0);
        c.record_recovery();
        c.record_recovery();
        assert_eq!(c.recoveries(), 2);
        // A recovered but otherwise-idle interface still reports, recoveries leading.
        assert_eq!(c.format_nonzero().as_deref(), Some("recoveries=2"));
        c.record(Outcome::Reflected(MessageType::MdnsQuery));
        assert_eq!(
            c.format_nonzero().as_deref(),
            Some("recoveries=2; mDNS query reflected=1"),
        );
    }

    #[test]
    fn format_nonzero_summarizes_only_touched_tallies() {
        let mut c = CaptureCounters::default();
        assert_eq!(c.format_nonzero(), None, "an untouched row logs no line");
        c.record(Outcome::Reflected(MessageType::MdnsQuery));
        c.record(Outcome::Reflected(MessageType::MdnsQuery));
        c.record(Outcome::Skipped(MessageType::MdnsQuery));
        c.record(Outcome::Dropped(MessageType::SsdpSearch));
        c.record(Outcome::Filtered);
        // Only touched types and sub-tallies appear, in declaration order, then the filtered total.
        assert_eq!(
            c.format_nonzero().as_deref(),
            Some("mDNS query reflected=2 skipped=1; SSDP search dropped=1; filtered=1"),
        );
    }

    #[test]
    fn combine_takes_the_higher_precedence_disposition() {
        use MessageType::MdnsQuery as Q;
        // Reflected dominates a skip; a failed reflect (dropped/stalled) still outranks a skip; junk
        // is last.
        assert_eq!(
            Outcome::Reflected(Q).combine(Outcome::Skipped(Q)).0,
            Outcome::Reflected(Q)
        );
        assert_eq!(
            Outcome::Dropped(Q).combine(Outcome::Skipped(Q)).0,
            Outcome::Dropped(Q)
        );
        assert_eq!(
            Outcome::Stalled(Q).combine(Outcome::Skipped(Q)).0,
            Outcome::Stalled(Q)
        );
        assert_eq!(
            Outcome::Skipped(Q).combine(Outcome::Filtered).0,
            Outcome::Skipped(Q)
        );
    }

    #[test]
    fn combine_is_order_independent() {
        use MessageType::MdnsResponse as R;
        let a = Outcome::Skipped(R);
        let b = Outcome::Reflected(R);
        assert_eq!(a.combine(b).0, b.combine(a).0);
    }

    #[test]
    fn fan_out_folds_multiple_reflects_without_anomaly() {
        use MessageType::MdnsQuery as Q;
        // A source fanned out to several targets (a->b, a->c) reflects one query from each leg on the
        // shared ingress. That is a legal config, not a duplicate-reflector bug: the fold keeps one
        // Reflected and flags nothing.
        let (merged, anomalies) = Outcome::Reflected(Q).combine(Outcome::Reflected(Q));
        assert_eq!(merged, Outcome::Reflected(Q));
        assert_eq!(anomalies, Anomalies::default());
    }

    #[test]
    fn combine_flags_a_type_mismatch() {
        use MessageType::{MdnsQuery as Q, MdnsResponse as R};
        // Handlers seeing one packet must agree on its type; a mismatch is a classifier/config bug.
        assert!(
            Outcome::Reflected(Q)
                .combine(Outcome::Skipped(R))
                .1
                .type_mismatch
        );
        assert!(
            !Outcome::Reflected(Q)
                .combine(Outcome::Skipped(Q))
                .1
                .type_mismatch
        );
        // Junk carries no type, so it never triggers a mismatch.
        assert!(
            !Outcome::Filtered
                .combine(Outcome::Skipped(Q))
                .1
                .type_mismatch
        );
    }
}
