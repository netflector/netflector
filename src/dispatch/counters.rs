//! Observability counters: what netflector did with each packet, per message type and interface.
//!
//! A packet can match several handlers (mirrored `a→b`/`b→a` legs, a source fanned out to several
//! targets). Each returns an [`Outcome`]; the dispatcher folds them with [`Outcome::combine`] and
//! records one per ingress.

use std::fmt;

/// Declares [`MessageType`], its labels, `ALL` and [`MESSAGE_TYPE_COUNT`] from one list, so the
/// counter-row width can't drift from the enum.
macro_rules! message_types {
    ($($variant:ident => ($protocol:literal, $direction:literal)),+ $(,)?) => {
        /// A protocol and direction. Handlers report the packet's intrinsic type, not the leg they
        /// serve, so every handler seeing one packet agrees on it.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(crate) enum MessageType {
            $($variant),+
        }

        impl MessageType {
            const ALL: &'static [MessageType] = &[$(Self::$variant),+];

            fn labels(self) -> (&'static str, &'static str) {
                match self {
                    $(Self::$variant => ($protocol, $direction)),+
                }
            }

            /// The UDP relay's type yields to a protocol handler's verdict on the same packet.
            fn is_specific(self) -> bool {
                self != Self::UdpDatagram
            }
        }

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
    UdpDatagram => ("UDP relay", ""),
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.labels() {
            (protocol, "") => f.write_str(protocol),
            (protocol, direction) => write!(f, "{protocol} {direction}"),
        }
    }
}

/// Fold precedence for [`Outcome`], worst to best (the derived `Ord` follows declaration order):
/// a failed reflect outranks a correct non-forward.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Disposition {
    Filtered,
    Skipped,
    Stalled,
    Dropped,
    Reflected,
}

/// Invariants an [`Outcome::combine`] fold can violate; never expected under a valid config.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Anomalies {
    /// Two handlers classified one packet to different protocols; the relay's type doesn't count.
    pub(crate) type_mismatch: bool,
}

/// What a handler did with a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Reflected(MessageType),
    /// The wrong direction for this leg: not ours to forward.
    Skipped(MessageType),
    /// The right direction, but not re-emitted: a send error, a cap, a suppression.
    Dropped(MessageType),
    /// The right direction, but the egress has no source address of the family yet.
    Stalled(MessageType),
    /// Not a message we handle.
    Filtered,
}

impl Outcome {
    fn disposition(self) -> Disposition {
        match self {
            Self::Reflected(_) => Disposition::Reflected,
            Self::Dropped(_) => Disposition::Dropped,
            Self::Stalled(_) => Disposition::Stalled,
            Self::Skipped(_) => Disposition::Skipped,
            Self::Filtered => Disposition::Filtered,
        }
    }

    fn message_type(self) -> Option<MessageType> {
        match self {
            Self::Reflected(t) | Self::Skipped(t) | Self::Dropped(t) | Self::Stalled(t) => Some(t),
            Self::Filtered => None,
        }
    }

    fn with_type(self, message_type: MessageType) -> Outcome {
        match self {
            Self::Reflected(_) => Self::Reflected(message_type),
            Self::Skipped(_) => Self::Skipped(message_type),
            Self::Dropped(_) => Self::Dropped(message_type),
            Self::Stalled(_) => Self::Stalled(message_type),
            Self::Filtered => Self::Filtered,
        }
    }

    /// Fold another handler's outcome for the same packet: the higher disposition wins, under
    /// the protocol's type when one side is the relay. Order-independent.
    pub(crate) fn combine(self, other: Outcome) -> (Outcome, Anomalies) {
        let types = (self.message_type(), other.message_type());
        let anomalies = Anomalies {
            type_mismatch: matches!(
                types,
                (Some(a), Some(b)) if a != b && a.is_specific() && b.is_specific()
            ),
        };
        let merged = if other.disposition() > self.disposition() {
            other
        } else {
            self
        };
        let merged = match types {
            (Some(a), Some(b)) if a.is_specific() != b.is_specific() => {
                merged.with_type(if a.is_specific() { a } else { b })
            }
            _ => merged,
        };
        (merged, anomalies)
    }
}

#[derive(Clone, Copy, Default)]
struct TypeCounters {
    reflected: u64,
    skipped: u64,
    dropped: u64,
    stalled: u64,
}

impl TypeCounters {
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

#[derive(Clone, Default)]
pub(crate) struct CaptureCounters {
    types: [TypeCounters; MESSAGE_TYPE_COUNT],
    filtered: u64,
    /// Our own re-emits the link handed back, dropped before routing.
    echoed: u64,
    /// Completed interface rebuilds.
    recoveries: u64,
    /// Received frames too large to forward, dropped before parsing.
    oversized: u64,
}

impl CaptureCounters {
    pub(crate) fn record(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Reflected(t) => self.types[t as usize].reflected += 1,
            Outcome::Skipped(t) => self.types[t as usize].skipped += 1,
            Outcome::Dropped(t) => self.types[t as usize].dropped += 1,
            Outcome::Stalled(t) => self.types[t as usize].stalled += 1,
            Outcome::Filtered => self.filtered += 1,
        }
    }

    pub(crate) fn record_recovery(&mut self) {
        self.recoveries += 1;
    }

    pub(crate) fn record_oversized(&mut self, n: u64) {
        self.oversized += n;
    }

    pub(crate) fn record_echo(&mut self) {
        self.echoed += 1;
    }

    /// e.g. `recoveries=1; mDNS query reflected=42 skipped=10; filtered=2`; `None` when idle.
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
        if self.echoed > 0 {
            parts.push(format!("echoed={}", self.echoed));
        }
        if self.oversized > 0 {
            parts.push(format!("oversized={}", self.oversized));
        }
        (!parts.is_empty()).then(|| parts.join("; "))
    }
}

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
        /// The four typed counts (`reflected, skipped, dropped, stalled`) for `ty`. The test reader
        /// for recorded outcomes, here and in the dispatcher's route-fold test.
        pub(crate) fn typed(&self, ty: MessageType) -> (u64, u64, u64, u64) {
            let c = self.types[ty as usize];
            (c.reflected, c.skipped, c.dropped, c.stalled)
        }

        fn filtered(&self) -> u64 {
            self.filtered
        }

        /// The echo count, for the dispatcher's echo-drop test.
        pub(crate) fn echoed(&self) -> u64 {
            self.echoed
        }

        /// This row's recovery count. Read from the dispatcher's reconcile test through the
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
    fn record_oversized_counts_and_reports() {
        let mut c = CaptureCounters::default();
        c.record_oversized(3);
        c.record_oversized(2);
        // Reported on its own even with no routed packet, trailing the summary.
        assert_eq!(c.format_nonzero().as_deref(), Some("oversized=5"));
        c.record(Outcome::Filtered);
        assert_eq!(
            c.format_nonzero().as_deref(),
            Some("filtered=1; oversized=5")
        );
    }

    #[test]
    fn record_echo_counts_and_reports() {
        let mut c = CaptureCounters::default();
        c.record_echo();
        c.record_echo();
        assert_eq!(c.echoed(), 2);
        // Interface-wide counts trail the typed ones: filtered, echoed, oversized.
        c.record(Outcome::Filtered);
        c.record_oversized(1);
        assert_eq!(
            c.format_nonzero().as_deref(),
            Some("filtered=1; echoed=2; oversized=1")
        );
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
    fn format_nonzero_summarizes_only_touched_counters() {
        let mut c = CaptureCounters::default();
        assert_eq!(c.format_nonzero(), None, "an untouched row logs no line");
        c.record(Outcome::Reflected(MessageType::MdnsQuery));
        c.record(Outcome::Reflected(MessageType::MdnsQuery));
        c.record(Outcome::Skipped(MessageType::MdnsQuery));
        c.record(Outcome::Dropped(MessageType::SsdpSearch));
        c.record(Outcome::Filtered);
        // Only touched types and sub-counts appear, in declaration order, then the filtered total.
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
    fn combine_counts_a_packet_the_relay_shares_under_the_protocol() {
        use MessageType::{MdnsQuery as Q, MdnsResponse as R, UdpDatagram as U};
        // A relay and a protocol handler on one ingress see the same packet: the protocol's type
        // wins in either order and at either disposition, and it is no mismatch.
        for (mine, theirs) in [
            (Outcome::Reflected(Q), Outcome::Reflected(U)),
            (Outcome::Reflected(U), Outcome::Reflected(Q)),
        ] {
            let (merged, anomalies) = mine.combine(theirs);
            assert_eq!(merged, Outcome::Reflected(Q));
            assert!(!anomalies.type_mismatch);
        }
        // The relay forwards a response the protocol's leg skips: reflected, as a response.
        let (merged, anomalies) = Outcome::Skipped(R).combine(Outcome::Reflected(U));
        assert_eq!(merged, Outcome::Reflected(R));
        assert!(!anomalies.type_mismatch);
        // Two relays agree with each other.
        let (merged, anomalies) = Outcome::Reflected(U).combine(Outcome::Reflected(U));
        assert_eq!(merged, Outcome::Reflected(U));
        assert!(!anomalies.type_mismatch);
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
