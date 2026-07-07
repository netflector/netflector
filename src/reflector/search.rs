//! The shared search direction for the unicast-reply discovery protocols (SSDP and WSD).
//!
//! A search (SSDP `M-SEARCH`, WSD `Probe` / `Resolve`) is reflected source → target, and each
//! searcher's *unicast* reply (SSDP `200 OK`, WSD `ProbeMatches` / `ResolveMatches`) is routed back
//! through a per-searcher session: a reserved ephemeral port on the target with a dedicated response
//! capture, so a reply reaches only the searcher that asked. [`SearchReflector`] owns the sessions and
//! reflects searches; a per-session [`ResponseReflector`] routes each reply back.
//!
//! Protocol specifics enter as parameters: the [`Verdict`] classifier (is this payload a search?), the
//! session-window policy, the re-emit TTL, and a [`ReplyRewrite`] factory. SSDP injects its DIAL
//! `LOCATION` rewrite; WSD uses the [`NoRewrite`](super::NoRewrite) no-op.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::dispatch::{
    CaptureKey, Filter, MessageType, Outcome, PacketDispatcher, PacketHandler, RegistrationKey,
};
use crate::interface::{InterfaceAddresses, Ipv6Scope};
use crate::net::mac::{MacAddr, MacSet};
use crate::net::packet::Packet;
use crate::net::port_reservation::PortReservation;
use crate::reactor::Reactor;

use super::{ReplyRewrite, Verdict, egress_sources};

/// In-flight session cap, so a burst of searchers can't exhaust ephemeral ports or registrations. At
/// the cap a new search is dropped (no live session is evicted early).
const MAX_SESSIONS: usize = 64;

/// One in-flight search, keyed by `(searcher, dest)`. The searcher (`ip:port`) plus the group it
/// searched: each group's replies arrive at a different scope-matched target address (link-local for
/// `ff02::c`, routable for `ff05::c`), so one searcher's searches to two scopes need separate sessions.
/// `expiry` is when the session lapses; `reservation` holds the ephemeral target reply port for the
/// session's life (dropping it frees the port); `response_key` is the per-session response capture. A
/// `RegistrationKey` is not a RAII guard, so eviction and rollback `unregister` it by hand.
struct Session {
    searcher: SocketAddr,
    /// The multicast group searched; part of the dedup key, since its scope picks the reserved reply
    /// address — a different group is a new session, not a retransmit.
    dest: SocketAddr,
    expiry: Instant,
    reservation: PortReservation,
    response_key: RegistrationKey,
}

/// One search session's reply path: a standalone leaf that re-emits each unicast reply (captured at
/// the session's reserved port on the target) onto `egress` (the source), back to the single
/// `searcher` that searched. It carries everything a reply needs, so no session lookup is required: the
/// reply goes to the searcher's captured frame MAC (no ARP/ND) and is sourced from the responding
/// device's own reply port. [`SearchReflector`] creates one per session and drops it on expiry.
struct ResponseReflector {
    searcher: SocketAddr,
    searcher_mac: MacAddr,
    egress: CaptureKey,
    /// Protocol label for logs, e.g. `"SSDP"`.
    name: &'static str,
    /// This reply leg's message type, for the counters (e.g. [`MessageType::SsdpResponse`]).
    message_type: MessageType,
    ttl: u8,
    reply: Box<dyn ReplyRewrite>,
}

impl PacketHandler for ResponseReflector {
    fn on_packet(
        &mut self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        reactor: &mut Reactor,
    ) -> Outcome {
        // The dispatcher's filter already pinned this capture to the reserved port, so every packet
        // here is a unicast reply for this searcher; nothing to classify. A family the source can't
        // currently send is a transient drop (address loss), returned as Stalled rather than a failure.
        if !egress_sources(dispatcher, self.egress, self.searcher) {
            log::debug!(
                "{}: egress has no source for searcher {} yet; dropping response from {}",
                self.name,
                self.searcher,
                packet.source
            );
            return Outcome::Stalled(self.message_type);
        }
        let payload = self
            .reply
            .rewrite(packet.payload, self.egress, dispatcher, reactor);
        match dispatcher.send_udp(
            self.egress,
            self.searcher,
            self.searcher_mac,
            packet.source.port(),
            self.ttl,
            payload,
        ) {
            Ok(()) => {
                log::debug!(
                    "reflected {} response from {} to searcher {}",
                    self.name,
                    packet.source,
                    self.searcher
                );
                Outcome::Reflected(self.message_type)
            }
            Err(e) => {
                log::warn!(
                    "{}: cannot reflect response to searcher {}: {e}",
                    self.name,
                    self.searcher
                );
                Outcome::Dropped(self.message_type)
            }
        }
    }
}

/// Reflects searches source → target and routes each unicast reply back to its searcher. Registered
/// per group on the source and owns the sessions for searches to that group. On a search it dedups
/// against live sessions (a retransmit refreshes the window and re-reflects from the same reserved
/// port), else opens a session (reserve an ephemeral port on the target, register a
/// [`ResponseReflector`] for its replies) and reflects the search from that port. The deadline timer
/// sweeps expired sessions.
///
/// Protocol-specific behaviour is injected: `classify` gates the ingress ([`Verdict::Reflect`] = a
/// search to handle, [`Verdict::Skip`] = the other direction, [`Verdict::Junk`] = log and drop);
/// `window` is the per-search session lifetime; `make_reply` mints the per-session reply transform.
pub(crate) struct SearchReflector {
    /// The source capture: this reflector's ingress, and the egress its responses leave reply on.
    source: CaptureKey,
    /// The target capture: where the search is re-emitted and the replies are captured.
    target: CaptureKey,
    /// The target interface's index, for the IPv6 link-local reserved-port bind.
    target_ifindex: u32,
    /// The configured device allow-set, scoping the response capture as the announcement direction is.
    device_macs: Option<MacSet>,
    /// Protocol label for logs, e.g. `"SSDP"`.
    name: &'static str,
    /// The reply leg's message type, handed to each session's [`ResponseReflector`] for the counters.
    response_type: MessageType,
    /// The TTL each reflected search and reply is re-emitted at.
    ttl: u8,
    /// The ingress gate: is this payload a search for this direction?
    classify: fn(&[u8]) -> Verdict,
    /// A search's session lifetime (e.g. SSDP's MX window + grace; a fixed value for WSD).
    window: fn(&[u8]) -> Duration,
    /// Mints a fresh reply transform per session (its own scratch, for a rewriting protocol).
    make_reply: Box<dyn Fn() -> Box<dyn ReplyRewrite>>,
    sessions: Vec<Session>,
}

impl SearchReflector {
    #[allow(clippy::too_many_arguments)] // each is a distinct protocol parameter; grouping them buys nothing
    pub(crate) fn new(
        source: CaptureKey,
        target: CaptureKey,
        target_ifindex: u32,
        device_macs: Option<MacSet>,
        name: &'static str,
        response_type: MessageType,
        ttl: u8,
        classify: fn(&[u8]) -> Verdict,
        window: fn(&[u8]) -> Duration,
        make_reply: Box<dyn Fn() -> Box<dyn ReplyRewrite>>,
    ) -> Self {
        Self {
            source,
            target,
            target_ifindex,
            device_macs,
            name,
            response_type,
            ttl,
            classify,
            window,
            make_reply,
            sessions: Vec::new(),
        }
    }

    /// Open a session for a new searcher: reserve an ephemeral port on the target's own address of the
    /// search's family and register the reply capture there, before the caller reflects, so a fast
    /// responder can't beat the capture. `message_type` is the search's own type, carried on the
    /// failure outcomes. `Err` (logged) is either [`Outcome::Stalled`] (the target has no source
    /// address of the search's family yet; transient / best-effort v6) or [`Outcome::Dropped`] (a real
    /// inability to open the session: session cap, no source MAC to reply to, reservation failure).
    fn make_session(
        &self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        expiry: Instant,
        message_type: MessageType,
    ) -> Result<Session, Outcome> {
        if self.sessions.len() >= MAX_SESSIONS {
            log::warn!(
                "{}: dropping search from {}: {MAX_SESSIONS} sessions in flight (cap)",
                self.name,
                packet.source
            );
            return Err(Outcome::Dropped(message_type));
        }
        let Some(searcher_mac) = packet.src_mac else {
            log::warn!(
                "{}: cannot reflect search from {}: frame has no source MAC to reply to",
                self.name,
                packet.source
            );
            return Err(Outcome::Dropped(message_type));
        };
        // The replies come to the address the reflected search is sourced from, at the reserved port,
        // so this must be the same scope-matched pick `build_udp` makes for `packet.dest`, or the
        // device replies to a source the response capture below isn't watching.
        let our_addr = match packet.dest.ip() {
            IpAddr::V4(_) => dispatcher
                .egress_addrs(self.target)
                .and_then(InterfaceAddresses::v4)
                .map(IpAddr::V4),
            IpAddr::V6(dst6) => dispatcher
                .egress_addrs(self.target)
                .and_then(|a| a.v6(Ipv6Scope::of(dst6)))
                .map(IpAddr::V6),
        };
        let Some(our_addr) = our_addr else {
            log::warn!(
                "{}: cannot reflect search from {}: target has no source address for {} yet",
                self.name,
                packet.source,
                packet.dest.ip()
            );
            return Err(Outcome::Stalled(message_type));
        };
        let reservation = match PortReservation::create(our_addr, self.target_ifindex) {
            Ok(reservation) => reservation,
            Err(e) => {
                log::warn!(
                    "{}: port reservation for searcher {} failed: {e}",
                    self.name,
                    packet.source
                );
                return Err(Outcome::Dropped(message_type));
            }
        };
        // Register before the reflect so a fast responder's reply is captured, not ICMP-rejected.
        let response_key = dispatcher.register(
            self.target,
            Filter {
                dst_ip: Some(our_addr.into()),
                dst_port: Some(reservation.port().into()),
                src_mac: self.device_macs.clone(),
                ..Filter::default()
            },
            Box::new(ResponseReflector {
                searcher: packet.source,
                searcher_mac,
                egress: self.source,
                name: self.name,
                message_type: self.response_type,
                ttl: self.ttl,
                reply: (self.make_reply)(),
            }),
        );
        Ok(Session {
            searcher: packet.source,
            dest: packet.dest,
            expiry,
            reservation,
            response_key,
        })
    }
}

/// The live session a search belongs to: same searcher *and* same group. The group is part of the key
/// because its scope picks the reserved reply address, so a search to a different group is a new session,
/// not a retransmit. A free fn over `&mut [Session]`, not a `&mut self` method: a `&mut self` return
/// would lock all of `self`, but the caller reads other fields (`target`, `ttl`) while holding the
/// session.
fn session_for(
    sessions: &mut [Session],
    source: SocketAddr,
    dest: SocketAddr,
) -> Option<&mut Session> {
    sessions
        .iter_mut()
        .find(|s| s.searcher == source && s.dest == dest)
}

impl PacketHandler for SearchReflector {
    fn on_packet(
        &mut self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) -> Outcome {
        let message_type = match (self.classify)(packet.payload) {
            Verdict::Reflect(message_type) => message_type,
            // A message for the other direction (an announcement) flows through that reflector.
            Verdict::Skip(message_type) => return Outcome::Skipped(message_type),
            Verdict::Junk => {
                log::debug!(
                    "{}: dropping unrecognized payload ({} B) on the search path from {}",
                    self.name,
                    packet.payload.len(),
                    packet.source
                );
                return Outcome::Filtered;
            }
        };
        let expiry = Instant::now() + (self.window)(packet.payload);

        // A retransmit from a known searcher to the same group reuses its session: refresh the window and
        // re-reflect from the same reserved port. A new searcher, or the same searcher to a different
        // group (a different reply scope), opens a fresh session.
        if let Some(session) = session_for(&mut self.sessions, packet.source, packet.dest) {
            let port = session.reservation.port();
            return match dispatcher.send_udp_group(
                self.target,
                packet.dest,
                port,
                self.ttl,
                packet.payload,
            ) {
                Ok(()) => {
                    session.expiry = expiry;
                    log::debug!(
                        "re-reflected {} search from {} to {} on reserved port {port}",
                        self.name,
                        packet.source,
                        packet.dest
                    );
                    Outcome::Reflected(message_type)
                }
                Err(e) => {
                    log::warn!(
                        "{}: cannot reflect search from {} to {}: {e}",
                        self.name,
                        packet.source,
                        packet.dest
                    );
                    Outcome::Dropped(message_type)
                }
            };
        }

        let session = match self.make_session(packet, dispatcher, expiry, message_type) {
            Ok(session) => session,
            Err(outcome) => return outcome, // make_session logged the cause
        };
        let port = session.reservation.port();
        match dispatcher.send_udp_group(self.target, packet.dest, port, self.ttl, packet.payload) {
            Ok(()) => {
                self.sessions.push(session);
                log::debug!(
                    "reflected {} search from {} to {} on reserved port {port}; opened a session, {} active",
                    self.name,
                    packet.source,
                    packet.dest,
                    self.sessions.len()
                );
                Outcome::Reflected(message_type)
            }
            Err(e) => {
                // Roll back the response capture just registered; the reservation drops with `session`.
                log::warn!(
                    "{}: cannot reflect search from {} to {}: {e}",
                    self.name,
                    packet.source,
                    packet.dest
                );
                dispatcher.unregister(session.response_key);
                Outcome::Dropped(message_type)
            }
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.sessions.iter().map(|s| s.expiry).min()
    }

    fn on_deadline(
        &mut self,
        now: Instant,
        dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) {
        self.sessions.retain(|session| {
            if session.expiry <= now {
                dispatcher.unregister(session.response_key);
                log::debug!(
                    "evicted {} session for searcher {} on reserved port {}",
                    self.name,
                    session.searcher,
                    session.reservation.port()
                );
                false
            } else {
                true
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::capture::Capture;
    use crate::reflector::NoRewrite;

    const TEST_TTL: u8 = 2;

    /// A trivial ingress gate: every payload is a search. The session bookkeeping under test is
    /// independent of how a protocol classifies.
    fn always_reflect(_: &[u8]) -> Verdict {
        Verdict::Reflect(MessageType::SsdpSearch)
    }

    /// A fixed session window, standing in for a protocol's window policy.
    fn fixed_window(_: &[u8]) -> Duration {
        Duration::from_secs(2)
    }

    fn test_reflector() -> SearchReflector {
        SearchReflector::new(
            CaptureKey::from_u64(1),
            CaptureKey::from_u64(0),
            0,
            None,
            "TEST",
            MessageType::SsdpResponse,
            TEST_TTL,
            always_reflect,
            fixed_window,
            Box::new(|| Box::new(NoRewrite) as Box<dyn ReplyRewrite>),
        )
    }

    /// Push a session for `searcher` onto `reflector`: a real loopback port reservation plus a
    /// registered response capture, so eviction has a registration to tear down. (`PortReservation`
    /// binds a socket directly, so no capture / `CAP_NET_RAW` is needed.)
    fn push_session(
        reflector: &mut SearchReflector,
        dispatcher: &mut PacketDispatcher,
        searcher: &str,
        dest: &str,
        expiry: Instant,
    ) {
        let searcher: SocketAddr = searcher.parse().unwrap();
        let dest: SocketAddr = dest.parse().unwrap();
        let (target, source) = (reflector.target, reflector.source);
        let reservation = PortReservation::create(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
            .expect("reserve a loopback port");
        let response_key = dispatcher.register(
            target,
            Filter::default(),
            Box::new(ResponseReflector {
                searcher,
                searcher_mac: MacAddr::from([0; 6]),
                egress: source,
                name: "TEST",
                message_type: MessageType::SsdpResponse,
                ttl: TEST_TTL,
                reply: Box::new(NoRewrite),
            }),
        );
        reflector.sessions.push(Session {
            searcher,
            dest,
            expiry,
            reservation,
            response_key,
        });
    }

    #[test]
    fn next_deadline_is_the_soonest_session_expiry() {
        let mut dispatcher = PacketDispatcher::new();
        let mut reflector = test_reflector();
        assert_eq!(
            reflector.next_deadline(),
            None,
            "no sessions means no timer"
        );
        let base = Instant::now();
        push_session(
            &mut reflector,
            &mut dispatcher,
            "10.0.0.1:5",
            "239.255.255.250:1900",
            base + Duration::from_secs(5),
        );
        push_session(
            &mut reflector,
            &mut dispatcher,
            "10.0.0.2:5",
            "239.255.255.250:1900",
            base + Duration::from_secs(2),
        );
        assert_eq!(
            reflector.next_deadline(),
            Some(base + Duration::from_secs(2))
        );
    }

    #[test]
    fn on_deadline_evicts_expired_sessions_and_unregisters_their_captures() {
        let mut dispatcher = PacketDispatcher::new();
        let mut reactor = Reactor::new().unwrap();
        let mut reflector = test_reflector();
        let base = Instant::now();
        push_session(
            &mut reflector,
            &mut dispatcher,
            "10.0.0.1:5",
            "239.255.255.250:1900",
            base,
        ); // already due
        push_session(
            &mut reflector,
            &mut dispatcher,
            "10.0.0.2:5",
            "239.255.255.250:1900",
            base + Duration::from_secs(10),
        ); // live
        assert_eq!(dispatcher.registration_count(), 2);

        reflector.on_deadline(base + Duration::from_secs(1), &mut dispatcher, &mut reactor);

        assert_eq!(
            reflector.sessions.len(),
            1,
            "the expired session is dropped"
        );
        assert_eq!(
            reflector.sessions[0].searcher,
            "10.0.0.2:5".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            dispatcher.registration_count(),
            1,
            "its response capture is unregistered with it"
        );
        assert_eq!(
            reflector.next_deadline(),
            Some(base + Duration::from_secs(10))
        );
    }

    #[test]
    fn a_retransmit_reuses_its_session_and_refreshes_the_window() {
        let mut dispatcher = PacketDispatcher::new();
        let mut reactor = Reactor::new().unwrap();
        // A synthetic target: send_udp_group on an unknown egress drops the datagram and returns Ok,
        // so the re-reflect "succeeds" with no real capture; this exercises only the bookkeeping.
        let mut reflector = test_reflector();
        let base = Instant::now();
        push_session(
            &mut reflector,
            &mut dispatcher,
            "10.0.0.7:50000",
            "239.255.255.250:1900",
            base,
        );
        assert_eq!(dispatcher.registration_count(), 1);

        let packet = Packet {
            source: "10.0.0.7:50000".parse().unwrap(),
            dest: "239.255.255.250:1900".parse().unwrap(),
            ttl: TEST_TTL,
            dst_mac: None,
            src_mac: Some(MacAddr::from([0x02, 0, 0, 0, 0, 1])),
            payload: b"a search",
        };
        reflector.on_packet(&packet, &mut dispatcher, &mut reactor);

        assert_eq!(
            reflector.sessions.len(),
            1,
            "a retransmit reuses its session, not a new one"
        );
        assert_eq!(
            dispatcher.registration_count(),
            1,
            "no second response capture is registered"
        );
        assert!(
            reflector.sessions[0].expiry > base,
            "the session's window is refreshed"
        );
    }

    #[test]
    fn a_session_is_keyed_by_searcher_and_group() {
        // The dedup key is (searcher, group). One live session for a searcher's link-local search: a
        // retransmit (same searcher, same group) finds it, but the same searcher's site-local search does
        // not — its replies come to a different scope-matched address, so it needs its own session. The
        // bug keyed on the searcher alone, so the site-local search wrongly reused the link-local session.
        let mut dispatcher = PacketDispatcher::new();
        let mut reflector = test_reflector();
        push_session(
            &mut reflector,
            &mut dispatcher,
            "[fe80::1]:50000",
            "[ff02::c]:1900",
            Instant::now(),
        );
        let searcher: SocketAddr = "[fe80::1]:50000".parse().unwrap();
        let link_local: SocketAddr = "[ff02::c]:1900".parse().unwrap();
        let site_local: SocketAddr = "[ff05::c]:1900".parse().unwrap();
        assert!(session_for(&mut reflector.sessions, searcher, link_local).is_some());
        assert!(session_for(&mut reflector.sessions, searcher, site_local).is_none());
    }

    #[test]
    fn make_session_drops_a_search_with_no_source_mac() {
        // No source MAC means no L2 address to reply to, so make_session drops the search rather than
        // open a session it could never answer.
        let mut dispatcher = PacketDispatcher::new();
        let reflector = test_reflector();
        let packet = Packet {
            source: "10.0.0.1:5".parse().unwrap(),
            dest: "239.255.255.250:1900".parse().unwrap(),
            ttl: TEST_TTL,
            dst_mac: None,
            src_mac: None,
            payload: b"search",
        };
        let outcome = reflector.make_session(
            &packet,
            &mut dispatcher,
            Instant::now(),
            MessageType::SsdpSearch,
        );
        assert!(matches!(
            outcome,
            Err(Outcome::Dropped(MessageType::SsdpSearch))
        ));
    }

    #[test]
    fn make_session_drops_at_the_session_cap() {
        // At MAX_SESSIONS in flight a new searcher is dropped; no live session is evicted early.
        let mut dispatcher = PacketDispatcher::new();
        let mut reflector = test_reflector();
        for _ in 0..MAX_SESSIONS {
            push_session(
                &mut reflector,
                &mut dispatcher,
                "10.0.0.1:5",
                "239.255.255.250:1900",
                Instant::now(),
            );
        }
        assert_eq!(reflector.sessions.len(), MAX_SESSIONS);
        let packet = Packet {
            source: "10.0.0.9:5".parse().unwrap(),
            dest: "239.255.255.250:1900".parse().unwrap(),
            ttl: TEST_TTL,
            dst_mac: None,
            src_mac: Some(MacAddr::from([0x02, 0, 0, 0, 0, 1])),
            payload: b"search",
        };
        let outcome = reflector.make_session(
            &packet,
            &mut dispatcher,
            Instant::now(),
            MessageType::SsdpSearch,
        );
        assert!(matches!(
            outcome,
            Err(Outcome::Dropped(MessageType::SsdpSearch))
        ));
    }

    /// Open a loopback capture, or `None` (skip) without `CAP_NET_RAW`. A real capture gives the target
    /// a resolvable address, so `make_session` can succeed.
    fn open_loopback_or_skip() -> Option<Capture> {
        match Capture::open(crate::interface::LOOPBACK_IFACE) {
            Ok(cap) => Some(cap),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skip: no CAP_NET_RAW to open a loopback capture ({e})");
                None
            }
            Err(e) => panic!("unexpected loopback capture open failure: {e}"),
        }
    }

    #[test]
    fn a_failed_reflect_rolls_back_the_session_registration() {
        // make_session registers the response capture before reflecting; if the reflect then fails, that
        // registration must be rolled back, not leaked. A real loopback target lets make_session succeed;
        // an oversized payload then makes build_udp reject the reflect deterministically.
        let Some(target_cap) = open_loopback_or_skip() else {
            return;
        };
        let mut dispatcher = PacketDispatcher::new();
        let target = dispatcher
            .add_capture(target_cap)
            .expect("add the loopback capture");
        let mut reactor = Reactor::new().expect("reactor");
        let mut reflector = SearchReflector::new(
            CaptureKey::from_u64(999), // synthetic source: no reply comes back in this test
            target,
            0,
            None,
            "TEST",
            MessageType::SsdpResponse,
            TEST_TTL,
            always_reflect,
            fixed_window,
            Box::new(|| Box::new(NoRewrite) as Box<dyn ReplyRewrite>),
        );
        let before = dispatcher.registration_count();
        let packet = Packet {
            source: "10.0.0.1:5".parse().unwrap(),
            dest: "239.255.255.250:1900".parse().unwrap(),
            ttl: TEST_TTL,
            dst_mac: None,
            src_mac: Some(MacAddr::from([0x02, 0, 0, 0, 0, 1])),
            payload: &[0u8; 4096], // too large to build, so the reflect fails and rolls back
        };
        let outcome = reflector.on_packet(&packet, &mut dispatcher, &mut reactor);
        assert!(matches!(outcome, Outcome::Dropped(_)));
        assert_eq!(
            reflector.sessions.len(),
            0,
            "no session survives a failed reflect"
        );
        assert_eq!(
            dispatcher.registration_count(),
            before,
            "make_session's response capture was rolled back"
        );
    }
}
