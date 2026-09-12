//! The shared search direction for the unicast-reply discovery protocols (SSDP and WSD).
//!
//! A search (SSDP `M-SEARCH`, WSD `Probe` / `Resolve`) is reflected source → target, and each
//! searcher's *unicast* reply (SSDP `200 OK`, WSD `ProbeMatches` / `ResolveMatches`) is routed back
//! through a per-searcher session: a reserved ephemeral port on the target with a dedicated response
//! registration, so a reply reaches only the searcher that asked. [`SearchReflector`] owns the sessions and
//! reflects searches; a per-session [`SimpleReflector`] under a fixed unicast [`Delivery`] routes each
//! reply back.
//!
//! Protocol specifics enter as a [`SearchProtocol`] plus a [`ReplyRewrite`] factory: SSDP injects its
//! DIAL `LOCATION` rewrite; WSD uses the [`NoRewrite`] no-op.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use crate::config::{AddressFamily, Reflector};
use crate::dispatch::{
    CaptureKey, DatagramSource, Filter, IpSet, MessageType, Outcome, PacketDispatcher,
    PacketHandler, RegistrationKey,
};
use crate::interface::{InterfaceAddresses, Ipv6Scope};
use crate::linear_map::LinearMap;
use crate::logging::log_rate;
use crate::net::mac::{MacAddr, MacSet};
use crate::net::packet::Packet;
use crate::net::port_reservation::PortReservation;
use crate::reactor::Reactor;

use super::{
    BuildError, Delivery, Emit, InterfaceMap, NoRewrite, ReplyRewrite, SimpleReflector, Verdict,
    WARN_WINDOW, group_addrs, open_pair,
};

/// In-flight session cap, so a burst of searchers can't exhaust ephemeral ports or registrations. At
/// the cap a new search is dropped (no live session is evicted early).
const MAX_SESSIONS: usize = 64;

/// What tells one search-style protocol from another: its wire constants, the two directional
/// gates, the session-window policy and the unreachable-advertisement check. SSDP and WSD each
/// describe themselves as one of these; [`build_pair`] and [`SearchReflector`] do the rest.
#[derive(Clone, Copy)]
pub(crate) struct SearchProtocol {
    /// The protocol label for logs, e.g. `"SSDP"`.
    pub(crate) name: &'static str,
    /// What the announcement leg's messages are called in logs, e.g. `"advertisement"`.
    pub(crate) announcement_kind: &'static str,
    pub(crate) port: u16,
    /// The TTL every re-emit carries.
    pub(crate) ttl: u8,
    pub(crate) group_v4: Ipv4Addr,
    pub(crate) groups_v6: &'static [Ipv6Addr],
    /// The reply leg's message type, for the counters.
    pub(crate) response_type: MessageType,
    /// The announcement leg's gate: reflect an announcement, skip a search.
    pub(crate) announcement_verdict: fn(&[u8]) -> Verdict,
    /// The search leg's gate: reflect a search, skip an announcement.
    pub(crate) search_verdict: fn(&[u8]) -> Verdict,
    /// A search's session lifetime (SSDP's MX window plus grace; a fixed value for WSD).
    pub(crate) window: fn(&[u8]) -> Duration,
    /// The protocol's `advertises_only_unreachable` check: an untouched announcement or reply it
    /// flags is dropped rather than reflected.
    pub(crate) suppress: fn(&[u8]) -> bool,
}

impl SearchProtocol {
    /// The group socket addresses `family` reflects to.
    pub(crate) fn groups(&self, family: AddressFamily) -> Vec<SocketAddr> {
        group_addrs(family, self.port, self.group_v4, self.groups_v6)
    }
}

/// What identifies an in-flight search session: the searcher (`ip:port`) plus the group it
/// searched. The group is part of the key because its scope picks the reserved reply address
/// (link-local for `ff02::c`, routable for `ff05::c`), so one searcher's searches to two scopes
/// are separate sessions, not retransmits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct SessionKey {
    searcher: SocketAddr,
    /// The multicast group searched.
    dest: SocketAddr,
}

/// One in-flight search. `expiry` is when the session lapses; `reservation` holds the ephemeral
/// target reply port for the session's life (dropping it frees the port); `response_key` is the
/// per-session response registration. A `RegistrationKey` is not a RAII guard, so eviction and
/// rollback `unregister` it by hand.
struct Session {
    expiry: Instant,
    reservation: PortReservation,
    response_key: RegistrationKey,
}

/// Reflects searches source → target and routes each unicast reply back to its searcher. Registered
/// per group on the source and owns the sessions for searches to that group. On a search it dedups
/// against live sessions (a retransmit refreshes the window and re-reflects from the same reserved
/// port), else opens a session (reserve an ephemeral port on the target, register a
/// reply reflector for its replies) and reflects the search from that port. The deadline timer
/// sweeps expired sessions.
///
/// The protocol's `search_verdict` gates the ingress ([`Verdict::Reflect`] = a search to handle,
/// [`Verdict::Skip`] = the other direction, [`Verdict::Junk`] = log and drop); its `window` is the
/// per-search session lifetime; `make_reply` mints the per-session reply transform.
pub(crate) struct SearchReflector {
    /// The source capture: this reflector's ingress, and the egress its responses leave on.
    source: CaptureKey,
    /// The target capture: where the search is re-emitted and the replies are captured.
    target: CaptureKey,
    /// Where the re-emitted searches go on `target`.
    delivery: Delivery,
    /// The configured device allow-set, scoping the response registration as the announcement direction is.
    device_macs: Option<MacSet>,
    protocol: SearchProtocol,
    /// Mints a fresh reply transform per session (its own scratch, for a rewriting protocol).
    make_reply: Box<dyn Fn() -> Box<dyn ReplyRewrite>>,
    sessions: LinearMap<SessionKey, Session>,
}

impl SearchReflector {
    pub(crate) fn new(
        source: CaptureKey,
        target: CaptureKey,
        delivery: Delivery,
        device_macs: Option<MacSet>,
        protocol: SearchProtocol,
        make_reply: Box<dyn Fn() -> Box<dyn ReplyRewrite>>,
    ) -> Self {
        Self {
            source,
            target,
            delivery,
            device_macs,
            protocol,
            make_reply,
            sessions: LinearMap::new(),
        }
    }

    /// Open a session for a new searcher: reserve an ephemeral port on the target's own address of
    /// the scope the search reaches (the group's, or the peers' behind a tunnel) and register the
    /// reply capture there, before the caller reflects, so a fast responder can't beat the
    /// capture. `message_type` is the search's own type, carried on the
    /// failure outcomes. `Err` (logged) is either [`Outcome::Stalled`] (the target has no source
    /// address of the search's family yet; transient / best-effort v6) or [`Outcome::Dropped`] (a real
    /// inability to open the session: session cap, reservation failure).
    fn make_session(
        &self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        expiry: Instant,
        message_type: MessageType,
    ) -> Result<Session, Outcome> {
        if self.sessions.len() >= MAX_SESSIONS {
            log_rate!(
                log::Level::Warn,
                WARN_WINDOW,
                "{}: dropping search from {}: {MAX_SESSIONS} sessions in flight (cap)",
                self.protocol.name,
                packet.source
            );
            return Err(Outcome::Dropped(message_type));
        }
        // A frame off a link without MACs has none; the reply's L2 destination goes unused there.
        let searcher_mac = packet.src_mac.unwrap_or(MacAddr::broadcast());
        let destination = self.delivery.destination(packet.dest.ip());
        let Some(our_addr) = reply_source(dispatcher, self.target, destination) else {
            log::debug!(
                "{}: cannot reflect search from {}: target has no source address for \
                 {destination} yet",
                self.protocol.name,
                packet.source
            );
            return Err(Outcome::Stalled(message_type));
        };
        // The scope id for an IPv6 link-local bind: read per session, not cached at build, so it
        // tracks the interface table.
        let target_ifindex = dispatcher.capture_ifindex(self.target).unwrap_or(0);
        let reservation = match PortReservation::create(our_addr, target_ifindex) {
            Ok(reservation) => reservation,
            Err(e) => {
                log_rate!(
                    log::Level::Warn,
                    WARN_WINDOW,
                    "{}: port reservation for searcher {} failed: {e}",
                    self.protocol.name,
                    packet.source
                );
                return Err(Outcome::Dropped(message_type));
            }
        };
        log::trace!(
            "{}: reserved {} (ifindex {target_ifindex}) for searcher {}",
            self.protocol.name,
            SocketAddr::new(our_addr, reservation.port()),
            packet.source
        );
        // Register before the reflect so a fast responder's reply is captured, not ICMP-rejected.
        // The filter pins the reserved port, so every packet the reply leg sees is a reply: it
        // admits them all, sourced from the responding device's own port.
        let response_type = self.protocol.response_type;
        let response_key = dispatcher.register(
            self.target,
            Filter {
                dst_ip: Some(our_addr.into()),
                dst_port: Some(reservation.port().into()),
                src_mac: self.device_macs.clone(),
                ..Filter::default()
            },
            Box::new(
                SimpleReflector::new(
                    self.source,
                    Delivery::Unicast {
                        to: packet.source,
                        mac: searcher_mac,
                    },
                    self.protocol.name,
                    "response",
                    move |_: &[u8]| Verdict::Reflect(response_type),
                    Emit::reply(self.protocol.ttl),
                )
                .with_rewrite((self.make_reply)())
                .with_suppress(self.protocol.suppress),
            ),
        );
        Ok(Session {
            expiry,
            reservation,
            response_key,
        })
    }
}

/// The target-side source address replies to `dest` come back to: the same scope-matched pick
/// `build_udp` makes for the reflected search, so the reserved port and its response registration
/// watch the address the device actually answers.
fn reply_source(dispatcher: &PacketDispatcher, target: CaptureKey, dest: IpAddr) -> Option<IpAddr> {
    match dest {
        IpAddr::V4(_) => dispatcher
            .egress_addrs(target)
            .and_then(InterfaceAddresses::v4)
            .map(IpAddr::V4),
        IpAddr::V6(dst6) => dispatcher
            .egress_addrs(target)
            .and_then(|a| a.v6(Ipv6Scope::of(dst6)))
            .map(IpAddr::V6),
    }
}

impl PacketHandler for SearchReflector {
    fn on_packet(
        &mut self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) -> Outcome {
        let message_type = match (self.protocol.search_verdict)(packet.payload) {
            Verdict::Reflect(message_type) => message_type,
            // A message for the other direction (an announcement) flows through that reflector.
            Verdict::Skip(message_type) => return Outcome::Skipped(message_type),
            Verdict::Excluded => return Outcome::Filtered,
            Verdict::Junk => {
                log::debug!(
                    "{}: dropping unrecognized payload ({} B) on the search path from {}",
                    self.protocol.name,
                    packet.payload.len(),
                    packet.source
                );
                return Outcome::Filtered;
            }
        };
        let expiry = Instant::now() + (self.protocol.window)(packet.payload);

        // A retransmit from a known searcher to the same group reuses its session: extend the window
        // and re-reflect from the same reserved port. A new searcher, or the same searcher to a
        // different group (a different reply scope), opens a fresh session. No staleness check here:
        // an interface recreation or address change orphans a session's reservation, but the dispatcher
        // drops such sessions eagerly via [`on_iface_change`](SearchReflector::on_iface_change), so a
        // reused session is always bound to the interface's current identity.
        let key = SessionKey {
            searcher: packet.source,
            dest: packet.dest,
        };
        if let Some(session) = self.sessions.get_mut(&key) {
            let source = session.reservation.source();
            return match self.delivery.send(
                dispatcher,
                self.target,
                packet.dest,
                DatagramSource::Exact(source),
                self.protocol.ttl,
                packet.payload,
            ) {
                Ok(()) => {
                    // Extend, never shorten: devices answering an earlier search may use its whole
                    // MX window, so a retransmit with a smaller MX must not cut their replies off.
                    session.expiry = session.expiry.max(expiry);
                    log::debug!(
                        "re-reflected {} search from {} to {} from {source}",
                        self.protocol.name,
                        packet.source,
                        packet.dest
                    );
                    Outcome::Reflected(message_type)
                }
                Err(e) => {
                    log_rate!(
                        log::Level::Warn,
                        WARN_WINDOW,
                        "{}: cannot reflect search from {} to {}: {e}",
                        self.protocol.name,
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
        let source = session.reservation.source();
        match self.delivery.send(
            dispatcher,
            self.target,
            packet.dest,
            DatagramSource::Exact(source),
            self.protocol.ttl,
            packet.payload,
        ) {
            Ok(()) => {
                self.sessions.insert(key, session);
                log::debug!(
                    "reflected {} search from {} to {} from {source}; opened a session, {} active",
                    self.protocol.name,
                    packet.source,
                    packet.dest,
                    self.sessions.len()
                );
                Outcome::Reflected(message_type)
            }
            Err(e) => {
                // Roll back the response registration just made; the reservation drops with `session`.
                log_rate!(
                    log::Level::Warn,
                    WARN_WINDOW,
                    "{}: cannot reflect search from {} to {}: {e}",
                    self.protocol.name,
                    packet.source,
                    packet.dest
                );
                dispatcher.unregister(session.response_key);
                Outcome::Dropped(message_type)
            }
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.sessions.iter().map(|(_, s)| s.expiry).min()
    }

    fn on_deadline(
        &mut self,
        now: Instant,
        dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) {
        self.sessions.retain(|key, session| {
            if session.expiry <= now {
                dispatcher.unregister(session.response_key);
                log::debug!(
                    "evicted {} session for searcher {} on reserved port {}",
                    self.protocol.name,
                    key.searcher,
                    session.reservation.port()
                );
                false
            } else {
                true
            }
        });
    }

    /// The target interface was rebound (recreated) or its reply address moved, so every session's
    /// reserved port and response registration -- both bound to the target -- are stale; drop them all
    /// (their ports free with the reservations) and let the next search re-open fresh. A SOURCE change
    /// is deliberately ignored: the reply leg holds only the source's `CaptureKey` (stable across a
    /// rebind) and re-resolves the source address at send time, so a session outlives it untouched.
    fn on_iface_change(
        &mut self,
        captures: &[CaptureKey],
        dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) {
        if self.sessions.is_empty() || !captures.contains(&self.target) {
            return;
        }
        for (_, session) in self.sessions.iter() {
            dispatcher.unregister(session.response_key);
        }
        self.sessions.clear();
        log::debug!(
            "{}: cleared all sessions after the target interface changed",
            self.protocol.name
        );
    }
}

/// Build a search-style protocol's two legs for `reflector`: announcements target → source (a
/// [`SimpleReflector`]) and searches source → target with their unicast replies (a
/// [`SearchReflector`]). `rewrite`, when given, mints the payload transform of the announcement leg
/// and of each session's replies; `summary` describes the legs in the startup log line.
///
/// # Errors
/// As [`open_pair`].
pub(crate) fn build_pair(
    reflector: &Reflector,
    interfaces: &InterfaceMap,
    dispatcher: &mut PacketDispatcher,
    protocol: SearchProtocol,
    rewrite: Option<fn(CaptureKey) -> Box<dyn ReplyRewrite>>,
    summary: &str,
) -> Result<(), BuildError> {
    let groups = protocol.groups(reflector.address_family);
    let (source, target) = open_pair(reflector, interfaces, dispatcher, protocol.name, &groups)?;
    let group_ips: IpSet = groups.iter().map(SocketAddr::ip).collect();
    // target -> source: announcements, a stateless re-emit, optionally filtered to the configured
    // device's MAC. One naming only addresses the source side can never reach is suppressed.
    let mut announcement = SimpleReflector::new(
        source,
        Delivery::new(reflector.source_peers.as_ref()),
        protocol.name,
        protocol.announcement_kind,
        protocol.announcement_verdict,
        Emit::fixed(protocol.port, protocol.ttl),
    )
    .with_suppress(protocol.suppress);
    if let Some(rewrite) = rewrite {
        announcement = announcement.with_rewrite(rewrite(target));
    }
    dispatcher.register(
        target,
        Filter {
            dst_ip: Some(group_ips.clone()),
            dst_port: Some(protocol.port.into()),
            src_mac: reflector.macs.clone(),
            ..Filter::default()
        },
        Box::new(announcement),
    );
    // source -> target: searches; each searcher's unicast replies route back through a per-searcher
    // session. The filter deliberately pins only the group and port: a search relayed by another
    // netflector arrives from its reserved ephemeral source port, so a src_port or src_mac pin would
    // silently break chained (router-to-router) deployments.
    let make_reply: Box<dyn Fn() -> Box<dyn ReplyRewrite>> = match rewrite {
        Some(rewrite) => Box::new(move || rewrite(target)),
        None => Box::new(|| Box::new(NoRewrite) as Box<dyn ReplyRewrite>),
    };
    dispatcher.register(
        source,
        Filter {
            dst_ip: Some(group_ips),
            dst_port: Some(protocol.port.into()),
            ..Filter::default()
        },
        Box::new(SearchReflector::new(
            source,
            target,
            Delivery::new(reflector.target_peers.as_ref()),
            reflector.macs.clone(),
            protocol,
            make_reply,
        )),
    );
    log::info!(
        "{} reflector \"{}\": {} <-> {} ({summary})",
        protocol.name,
        reflector.name.as_str(),
        reflector.source_if.as_str(),
        reflector.target_if.as_str()
    );
    Ok(())
}

#[cfg(test)]
mod tests;
