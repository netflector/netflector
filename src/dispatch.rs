//! Packet dispatch: the routing layer between captures and reflectors.
//!
//! [`PacketDispatcher`] is the single owner of every interface [`Capture`] (each linked
//! to its interface and addressed by a `Copy` [`CaptureKey`]) and of the routing
//! registrations. When an interface's fd is readable, [`drain_and_route`] takes that
//! capture *out* of the table, drains it, parses each frame into a [`Packet`], and
//! offers it to every registration whose [`Filter`] matches. A matching reflector
//! re-emits on the opposite interface via [`send_udp`], keyed.
//!
//! Taking the ingress capture out is load-bearing: the parsed `Packet` then borrows a
//! local, not `self`, so `&mut PacketDispatcher` is free to hand to a reflector, which
//! can send on the *other* captures still in the table and register further work. The
//! reflector never owns an fd; the fd lives in exactly one `Capture`, reached by key.
//! `egress == ingress` can't arise: reflectors bridge A→B, never A→A. If it did, the
//! key resolves to the taken-out `None` slot and the send is a logged drop, not UB.
//!
//! [`drain_and_route`]: PacketDispatcher::drain_and_route
//! [`send_udp`]: PacketDispatcher::send_udp

mod counters;
mod datagram;
mod dial_context;
mod egress;
mod interface_table;
mod lifecycle;
mod multicast;

#[cfg(test)]
mod pair_tests;

pub(crate) use self::counters::{MessageType, Outcome};
pub(crate) use self::datagram::DatagramSource;
pub(crate) use self::dial_context::{DialContext, DialProxyKey};
pub(crate) use self::multicast::{join_capped, join_deferrable};

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use crate::capture::{Capture, Read};
use crate::config::AddressFamily;
use crate::interface::InterfaceAddresses;
use crate::net::LinkType;
use crate::net::mac::{MacAddr, MacSet};
use crate::net::packet::Packet;
use crate::reactor::{Arena, ControlEvent, Handler, Key, Reactor, ReadyEvent};

use self::counters::log_counters;
use self::egress::{Datagram, Egress};
use self::interface_table::InterfaceTable;
use self::lifecycle::InterfaceLifecycle;

/// The most frames drained per readable event before yielding, so a flooded interface
/// can't starve the others. `AF_PACKET` stops here and the level-triggered wait
/// re-reports the rest; BPF finishes its current userland batch past this, since the
/// wait won't re-fire for those already-read records.
const MAX_FRAMES_PER_EVENT: u32 = 64;

/// The reactor `user_data` for the interface monitor's fd. A [`CaptureKey`] packs a `u32`
/// (via [`to_u64`](CaptureKey::to_u64)), so `u64::MAX` never collides with a real capture.
const MONITOR_TAG: u64 = u64::MAX;

/// A `Copy` handle to a capture the dispatcher owns: an index into the interface table's
/// captures. A newtype, not a bare alias, so it can't be passed where an [`InterfaceKey`](interface_table::InterfaceKey)
/// or a reactor key is expected, where it would silently miss instead of failing to
/// compile. Captures are insert-only, so the index is a stable identity (no generation).
/// Reflectors hold these for the interface(s) they egress on and send by key, never
/// touching an fd directly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct CaptureKey(u32);

impl CaptureKey {
    /// Pack into the reactor's opaque `user_data` slot, recoverable via
    /// [`from_u64`](Self::from_u64). With no generation to carry, this is a trivial widen,
    /// kept as a named seam so the reactor wiring stays unchanged.
    #[must_use]
    fn to_u64(self) -> u64 {
        u64::from(self.0)
    }

    /// Reconstruct a key packed by [`to_u64`](Self::to_u64); also how a test mints a synthetic key
    /// for a capture it never opens (the value is only resolved against the table on a real drain).
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn from_u64(packed: u64) -> Self {
        CaptureKey(packed as u32)
    }
}

/// A `Copy` handle to a routing registration: the generational arena [`Key`] of its slot, newtyped
/// so it can't be confused with a reactor key or a [`CaptureKey`]. Returned by
/// [`register`](PacketDispatcher::register); the SSDP search reflector will hold it to
/// [`unregister`](PacketDispatcher::unregister) a per-searcher response registration when its
/// session ends.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct RegistrationKey(Key);

/// A non-empty set of one filter field's accepted values, so a single registration can span several:
/// mDNS's two multicast groups (`dst_ip`), or `WoL`'s ports (`dst_port`). A one-element set pins a
/// single value.
#[derive(Clone)]
pub(crate) struct FilterSet<T>(Box<[T]>);

impl<T> Deref for FilterSet<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> From<T> for FilterSet<T> {
    fn from(value: T) -> Self {
        FilterSet(Box::new([value]))
    }
}

impl<T, const N: usize> From<[T; N]> for FilterSet<T> {
    fn from(values: [T; N]) -> Self {
        FilterSet(Box::from(values))
    }
}

impl<T> FromIterator<T> for FilterSet<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        FilterSet(iter.into_iter().collect())
    }
}

/// The `dst_ip` filter set: the multicast groups one handler serves.
pub(crate) type IpSet = FilterSet<IpAddr>;
/// The `dst_port` filter set: the ports one handler serves.
pub(crate) type PortSet = FilterSet<u16>;

/// An optional-field packet filter: an unset field
/// matches anything. A `src_mac`/`dst_mac` filter never matches a packet from a link without
/// L2 addresses (`DLT_NULL`, raw IP). `dst_ip`/`dst_port` match membership in their [`FilterSet`].
#[derive(Clone, Default)]
pub(crate) struct Filter {
    pub(crate) src_ip: Option<IpAddr>,
    pub(crate) dst_ip: Option<IpSet>,
    pub(crate) src_port: Option<u16>,
    pub(crate) dst_port: Option<PortSet>,
    /// Allow-set on the source MAC: the packet's source must be a member.
    pub(crate) src_mac: Option<MacSet>,
    pub(crate) dst_mac: Option<MacAddr>,
    /// Require an IPv4 broadcast destination, see [`Packet::is_broadcast`].
    pub(crate) broadcast: bool,
    /// Widen `dst_ip` to the ingress interface's own addresses of these families: an answer sent
    /// to this host.
    pub(crate) dst_own: Option<AddressFamily>,
}

impl Filter {
    /// Whether `p` satisfies every set field (an unset field matches anything), given the
    /// ingress's addresses: its directed broadcast for the `broadcast` field on a link without
    /// MACs, its own addresses for `dst_own`.
    fn matches(&self, p: &Packet, ingress: Option<&InterfaceAddresses>) -> bool {
        (!self.broadcast
            || p.is_broadcast(ingress.and_then(InterfaceAddresses::v4_directed_broadcast)))
            && self.src_ip.is_none_or(|ip| p.source.ip() == ip)
            && self.dst_ip.as_ref().is_none_or(|set| {
                set.contains(&p.dest.ip())
                    || self.dst_own.is_some_and(|family| {
                        family.uses(p.dest.ip())
                            && ingress.is_some_and(|addrs| addrs.has(p.dest.ip()))
                    })
            })
            && self.src_port.is_none_or(|port| p.source.port() == port)
            && self
                .dst_port
                .as_ref()
                .is_none_or(|set| set.contains(&p.dest.port()))
            && self
                .src_mac
                .as_ref()
                .is_none_or(|set| p.src_mac.is_some_and(|mac| set.contains(&mac)))
            && self.dst_mac.is_none_or(|mac| p.dst_mac == Some(mac))
    }
}

/// A reflector: re-emits matching packets on its egress capture(s) via
/// `dispatcher.send(key, ..)`, and may register further work through `&mut Dispatcher`
/// / `&mut Reactor`. Called only after a registration's filter matches.
pub(crate) trait PacketHandler {
    fn on_packet(
        &mut self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        reactor: &mut Reactor,
    ) -> Outcome;

    /// The earliest instant this handler wants [`on_deadline`](Self::on_deadline) called, or `None`
    /// (the default) if it keeps no timer. The dispatcher reports the soonest of these to the reactor,
    /// which waits within it, so a handler tracking timed state (e.g. expiring sessions) is swept on
    /// time without polling.
    fn next_deadline(&self) -> Option<Instant> {
        None
    }

    /// `now` has reached this handler's [`next_deadline`](Self::next_deadline). As in `on_packet`, it
    /// gets `&mut PacketDispatcher` (to send / register / unregister) and `&mut Reactor`.
    fn on_deadline(
        &mut self,
        _now: Instant,
        _dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) {
    }

    /// One of `captures` was rebound to a recreated interface or had an address moved, so any state
    /// this handler pinned to it (a reserved port, a response registration) may be stale. The search
    /// reflectors drop their sessions on that interface; most handlers re-resolve per packet and keep
    /// nothing, so the default is a no-op. Broadcast to every handler after the dispatcher has already
    /// repaired the table, so `dispatcher` reads current state.
    fn on_iface_change(
        &mut self,
        _captures: &[CaptureKey],
        _dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) {
    }
}

/// One routing registration: the ingress it applies to, its filter, and the reflector
/// it gates. The handler is taken out of its slot for its call (so the dispatcher is
/// free to pass `&mut self`), mirroring the reactor's take-out one level down.
struct Registration {
    ingress: CaptureKey,
    filter: Filter,
    handler: Option<Box<dyn PacketHandler>>,
}

/// The periodic counter-summary schedule: log every capture's counts every `interval`. Held as an
/// `Option` on the dispatcher; `None` disables reporting, and the counters accrue regardless.
struct CounterReport {
    interval: Duration,
    next: Instant,
}

/// Owns the interface table and the routing registrations. The sole owner of capture fds:
/// egress goes through [`send_udp`](Self::send_udp), keyed.
pub(crate) struct PacketDispatcher {
    table: InterfaceTable,
    registrations: Arena<Registration>,
    /// Reused scratch for [`route`](Self::route)'s per-packet snapshot of the live registration
    /// keys, taken once at the start of a route so a mid-route registration isn't fed the
    /// in-flight frame, and kept allocated across calls so the data path doesn't allocate per packet.
    route_keys: Vec<RegistrationKey>,
    /// The address-change monitor and the recreation reconcile.
    lifecycle: InterfaceLifecycle,
    /// The DIAL proxy registry, shared across the SSDP advertisement/response reflectors. Empty unless a
    /// DIAL reflector is configured; the dispatcher evicts its past-grace proxies on the deadline sweep.
    dial: DialContext,
    /// The frame-build scratch and the duplicate-send scope of the packet being routed.
    egress: Egress,
    /// The periodic counter-summary schedule, or `None` when the summary is disabled.
    report: Option<CounterReport>,
}

impl PacketDispatcher {
    /// A dispatcher with no captures yet.
    pub(crate) fn new() -> Self {
        Self::with_table(InterfaceTable::new())
    }

    /// A dispatcher that joins no multicast group: `--no-join`.
    pub(crate) fn without_group_joins() -> Self {
        Self::with_table(InterfaceTable::without_group_joins())
    }

    fn with_table(table: InterfaceTable) -> Self {
        Self {
            table,
            registrations: Arena::new(),
            route_keys: Vec::new(),
            lifecycle: InterfaceLifecycle::new(),
            dial: DialContext::new(),
            egress: Egress::new(),
            report: None,
        }
    }

    /// Enable the periodic counter summary: log each capture's counts every `interval`, first firing
    /// `interval` after `now`. Called from [`run`](crate::run) when the config sets a positive
    /// interval; the counters accrue regardless, so this controls only whether they are reported.
    pub(crate) fn enable_counter_report(&mut self, interval: Duration, now: Instant) {
        self.report = Some(CounterReport {
            interval,
            next: now + interval,
        });
    }

    /// Hand a capture to the dispatcher; the returned key is how reflectors send on it. The
    /// capture's interface is found-or-created from its [`if_name`](Capture::if_name), so
    /// captures on the same interface share one [`Interface`](crate::interface::Interface) record.
    ///
    /// # Errors
    /// Propagates a resolution syscall failure when first opening the capture's interface.
    pub(crate) fn add_capture(&mut self, capture: Capture) -> io::Result<CaptureKey> {
        let interface = self.table.find_or_add_interface(capture.if_name())?;
        let key = self.table.add_capture(capture, interface);
        self.lifecycle
            .saw_interface(self.table.interface_index(interface).unwrap_or(0));
        if let Some(name) = self.table.interface_name(interface) {
            log::debug!("watching {name} as capture {key:?}");
        }
        Ok(key)
    }

    /// Each capture's `(fd, user_data)` for [`Reactor::register_with_fds`]: the reactor
    /// watches them all under the dispatcher's one handler key, tagging each with its
    /// [`CaptureKey`] so `on_readable` recovers the capture without a lookup. The address
    /// monitor's fd, when it opened, rides along under [`MONITOR_TAG`].
    pub(crate) fn capture_watches(&self) -> Vec<(RawFd, u64)> {
        let mut watches = self.table.capture_watches();
        if let Some(fd) = self.lifecycle.monitor_fd() {
            watches.push((fd, MONITOR_TAG));
        }
        watches
    }

    /// Register `handler`, gated by `filter`, for packets captured on `ingress`. The returned
    /// [`Key`] removes it again via [`unregister`](Self::unregister), for the per-searcher response
    /// registrations the SSDP search reflector creates dynamically; a static reflector ignores it.
    pub(crate) fn register(
        &mut self,
        ingress: CaptureKey,
        filter: Filter,
        handler: Box<dyn PacketHandler>,
    ) -> RegistrationKey {
        RegistrationKey(self.registrations.insert(Registration {
            ingress,
            filter,
            handler: Some(handler),
        }))
    }

    /// Remove the registration `key` addresses, freeing its slot; a stale key is a safe no-op.
    /// Tears down a per-searcher response registration when its session expires.
    pub(crate) fn unregister(&mut self, key: RegistrationKey) {
        self.registrations.remove(key.0);
    }

    /// Join `group`'s multicast membership on the interface behind `capture`, so the raw capture
    /// is admitted the group's frames. Records the group for re-attempt when the interface's
    /// addresses next change. A reflector calls this at build, once per group per interface.
    ///
    /// # Errors
    /// Propagates the join's OS error. A family with no address yet is *not* an error: it's
    /// recorded and retried on the next address-up event; only a hard failure surfaces here.
    pub(crate) fn join_group(&mut self, capture: CaptureKey, group: IpAddr) -> io::Result<()> {
        let Some(interface) = self.table.interface_of(capture) else {
            log::warn!("join_group: capture {capture:?} unknown; group {group} not joined");
            return Ok(());
        };
        self.table.join_on(interface, group)
    }

    /// The MTU of the interface behind `capture`, as of its last resolution.
    pub(crate) fn interface_mtu(&self, capture: CaptureKey) -> Option<u32> {
        self.table.mtu_of(capture)
    }

    /// The current source addresses of the interface behind `egress`, for a reflector
    /// building a frame. `InterfaceAddresses` is `Copy`, so a caller reads out the fields it
    /// needs.
    pub(crate) fn egress_addrs(&self, egress: CaptureKey) -> Option<&InterfaceAddresses> {
        self.table.egress_addrs(egress)
    }

    /// The DIAL proxy registry, shared by the SSDP advertisement/response reflectors so a device gets
    /// one proxy across both paths (see [`rewrite_location`](crate::reflector::dial::rewrite_location)),
    /// paired with the name of the interface behind `target` (the proxy's egress pin). One call
    /// returns both because they come from disjoint fields of one `&mut self`: a caller could not
    /// hold the borrowed name across a second `&mut` accessor.
    pub(crate) fn dial_context(&mut self, target: CaptureKey) -> (&mut DialContext, Option<&str>) {
        let target_iface = self
            .table
            .interface_of(target)
            .and_then(|interface| self.table.interface_name(interface));
        (&mut self.dial, target_iface)
    }

    /// The kernel ifindex of the interface behind `capture`: the table's cached identity,
    /// re-pointed by the reconcile when the interface is recreated (0 while it is parked
    /// absent). The SSDP/WSD search reflectors read it per session for their IPv6 link-local
    /// reserved-port binds. `None` if the key is unknown.
    pub(crate) fn capture_ifindex(&self, capture: CaptureKey) -> Option<u32> {
        self.table.ifindex_of(capture)
    }

    /// The link-layer framing of the capture behind `egress`, so [`send_udp_group`](Self::send_udp_group)
    /// picks the matching frame builder. `None` if the key is unknown or its capture is
    /// currently taken out (mid-drain).
    pub(crate) fn link_type(&self, egress: CaptureKey) -> Option<LinkType> {
        self.table.capture(egress).map(Capture::link_type)
    }

    /// Build a UDP datagram from `source` with `dst_mac` as the L2 destination, and inject it on
    /// `egress`. The caller supplies the L2 MAC, so this serves unicast, multicast, and broadcast
    /// alike; the link framing (Ethernet vs `DLT_NULL`) follows the egress's link type, and `ttl`
    /// and `payload` are carried verbatim. Builds into the dispatcher's reused scratch buffer, so
    /// the data path never allocates. An unknown or draining egress is a logged drop.
    ///
    /// # Errors
    /// Propagates a send failure, and reports a frame that can't be built from the egress's
    /// current state: no source address/MAC for the datagram, a captured source of the other
    /// family, or a payload that overflows the scratch buffer or the datagram length fields.
    pub(crate) fn send_udp(
        &mut self,
        egress: CaptureKey,
        dst: SocketAddr,
        dst_mac: MacAddr,
        source: DatagramSource,
        ttl: u8,
        payload: &[u8],
    ) -> io::Result<()> {
        let datagram = Datagram {
            dst,
            source,
            ttl,
            payload,
        };
        self.egress
            .send_udp(&mut self.table, egress, dst_mac, datagram)
    }

    /// Inject a broadcast/multicast UDP datagram on `egress`, deriving the L2 destination MAC from
    /// `dst`'s address class (all-ones for the IPv4 limited broadcast, the RFC-derived group MAC
    /// for multicast). A unicast `dst` has no derivable group MAC, so it is a
    /// [`DatagramError::UnicastDestination`](datagram::DatagramError::UnicastDestination); use
    /// [`send_udp`](Self::send_udp) with an explicit MAC for unicast.
    ///
    /// # Errors
    /// As [`send_udp`](Self::send_udp), plus [`DatagramError::UnicastDestination`](datagram::DatagramError::UnicastDestination) for a unicast `dst`.
    pub(crate) fn send_udp_group(
        &mut self,
        egress: CaptureKey,
        dst: SocketAddr,
        source: DatagramSource,
        ttl: u8,
        payload: &[u8],
    ) -> io::Result<()> {
        let datagram = Datagram {
            dst,
            source,
            ttl,
            payload,
        };
        self.egress
            .send_udp_group(&mut self.table, egress, datagram)
    }

    /// Deliver a group or broadcast datagram to `peers` instead: one unicast copy per peer of
    /// `dst`'s family, at `dst`'s port. Each copy is checked against the packet's earlier sends on
    /// its own, so two entries whose lists share a peer deliver to it once.
    ///
    /// # Errors
    /// As [`send_udp`](Self::send_udp) when no copy went out at all. A peer the link cannot reach
    /// (a `WireGuard` peer without an endpoint) costs only its own copy, logged.
    pub(crate) fn send_udp_to_peers(
        &mut self,
        egress: CaptureKey,
        peers: &[IpAddr],
        dst: SocketAddr,
        source: DatagramSource,
        ttl: u8,
        payload: &[u8],
    ) -> io::Result<()> {
        let datagram = Datagram {
            dst,
            source,
            ttl,
            payload,
        };
        self.egress
            .send_udp_to_peers(&mut self.table, egress, peers, datagram)
    }

    /// Drain the capture `ingress` addresses and route each parsed packet. Makes up to
    /// [`MAX_FRAMES_PER_EVENT`] reads, dropped oversized frames included, then yields for
    /// fairness (the BPF batch exception is via `has_buffered`); a read error abandons the
    /// batch and logs.
    fn drain_and_route(&mut self, ingress: CaptureKey, reactor: &mut Reactor) {
        // Take the ingress capture OUT: the parsed Packet then borrows the owned local, not
        // `self`, so `&mut self` is free for routing, and a reflector can send on the OTHER
        // captures still in the table.
        let Some(mut capture) = self.table.take(ingress) else {
            if self.table.contains(ingress) {
                // In range but already taken out: a reflector re-entered the drain on its
                // own ingress, which it shouldn't; the take-out makes it a safe no-op.
                log::warn!("drain_and_route: ingress {ingress:?} already draining; skipped");
            } else {
                // Out of range: a `user_data` that names no capture reached us (a bug).
                log::warn!("drain_and_route: ingress {ingress:?} out of range; skipped");
            }
            return;
        };
        let link = capture.link_type(); // hoisted: next_frame's borrow would pin `capture`
        let fd = capture.as_raw_fd();
        let mut drained = 0u32;
        let mut oversized = 0u64;
        loop {
            if drained >= MAX_FRAMES_PER_EVENT && !capture.has_buffered() {
                break;
            }
            let frame = match capture.next_frame() {
                Ok(Some(Read::Frame(frame))) => frame,
                Ok(Some(Read::Oversized)) => {
                    drained += 1;
                    oversized += 1;
                    continue;
                }
                Ok(None) => break,
                Err(e) => {
                    // The expected first sign of an interface destruction: pull the reconcile
                    // forward. It must not run from here, mid-drain, with this capture taken
                    // out of its slot. Other read errors say nothing about the interface and
                    // are left to the tick.
                    if Capture::lost_interface(&e) {
                        log::info!("fd {fd}: capture lost its interface ({e}); reconciling");
                        self.lifecycle.reconcile_now();
                    } else {
                        log::error!("fd {fd}: capture read failed, abandoning batch: {e}");
                    }
                    break;
                }
            };
            match Packet::parse(link, frame) {
                // `packet` borrows the local `capture`, not `self`, so routing through
                // `&mut self` is legal.
                Ok(packet) => {
                    log::trace!(
                        "fd {fd}: routing {} -> {} ({} B)",
                        packet.source,
                        packet.dest,
                        packet.payload.len()
                    );
                    self.route(ingress, &packet, reactor);
                }
                Err(e) => log::trace!("fd {fd}: skip unparsable frame: {e}"),
            }
            drained += 1;
        }
        if drained > 0 {
            log::trace!("fd {fd}: drained {drained} frame(s)");
        }
        if oversized > 0 {
            self.table.record_oversized(ingress, oversized);
        }
        if !self.table.restore(ingress, capture) {
            log::warn!("drain_and_route: ingress {ingress:?} vanished mid-drain; capture dropped");
        }
    }

    /// Offer `packet` (captured on `ingress`) to every matching registration, in order.
    fn route(&mut self, ingress: CaptureKey, packet: &Packet, reactor: &mut Reactor) {
        // A handler is `None` only while it is out for a call, so one missing here proves a
        // handler re-entered routing (it would clear the shared `route_keys` scratch out from
        // under the outer loop). The same-ingress case bounces off the capture take-out guard;
        // this catches the cross-ingress case the guard cannot see.
        debug_assert!(
            self.registrations
                .iter()
                .all(|(_, reg)| reg.handler.is_some()),
            "route re-entered from inside a handler call"
        );
        // Our own re-emit handed back by the link (a hairpin bridge port, an access point that
        // re-broadcasts a station's multicast) arrives as an ordinary received frame, past the
        // capture's outgoing drop, and a same-direction handler on this ingress (the mirrored leg
        // of a bidirectional pair) would relay it again. Only its source MAC gives it away.
        if is_own_echo(
            packet.src_mac,
            self.table
                .egress_addrs(ingress)
                .and_then(InterfaceAddresses::mac),
        ) {
            self.table.record_echo(ingress);
            log::trace!(
                "dropping our own echoed frame {} -> {} on {ingress:?}",
                packet.source,
                packet.dest
            );
            return;
        }
        // Snapshot the live registration keys into the reused buffer. Taking them once means a
        // reflector registering mid-route isn't fed the in-flight frame (its key isn't in the
        // snapshot whether it appended or reused a freed slot), and a generational key keeps the
        // put-back safe even if a registration is removed during its own call (the key goes stale
        // and the restore is a no-op). `route` never nests: a handler sends but never re-drains,
        // so one shared buffer suffices.
        self.route_keys.clear();
        self.route_keys.extend(
            self.registrations
                .iter()
                .map(|(key, _)| RegistrationKey(key)),
        );
        let ingress_addrs = self.table.egress_addrs(ingress).copied();
        self.egress.begin_packet();
        let mut final_outcome: Option<Outcome> = None;
        for i in 0..self.route_keys.len() {
            let key = self.route_keys[i];
            let applies = self.registrations.get(key.0).is_some_and(|reg| {
                reg.ingress == ingress && reg.filter.matches(packet, ingress_addrs.as_ref())
            });
            if !applies {
                continue;
            }
            // Take the matched reflector out so `&mut self` is free for the call, then restore it
            // by key. `take` never misses: a `handler` is `None` only transiently while out
            // mid-call, and `route` doesn't re-enter the same registration in one pass. A `get_mut`
            // miss on the put-back means the call removed this registration: drop it, don't revive.
            let mut handler = self
                .registrations
                .get_mut(key.0)
                .expect("a key that just matched is still live")
                .handler
                .take()
                .expect("a matching registration has its handler present");
            let outcome = handler.on_packet(packet, self, reactor);
            if let Some(reg) = self.registrations.get_mut(key.0) {
                reg.handler = Some(handler);
            }
            // Fold this handler's outcome into the packet's running result (highest disposition wins),
            // logging the "can't happen under a valid config" anomalies the fold surfaces.
            final_outcome = Some(match final_outcome {
                None => outcome,
                Some(prev) => {
                    let (merged, anomalies) = prev.combine(outcome);
                    if anomalies.type_mismatch {
                        log::error!(
                            "handlers disagree on a packet's message type on {ingress:?} \
                             ({prev:?} vs {outcome:?})"
                        );
                    }
                    merged
                }
            });
        }
        self.egress.end_packet();
        // One packet, one count: record the folded outcome on the ingress capture's row. The row
        // always exists: `route` is reached only via the drain, whose take-out guard admits only a
        // real, in-range ingress key.
        if let Some(outcome) = final_outcome {
            self.table.record(ingress, outcome);
        } else {
            // The one drop no counter covers: past the kernel filter but matching no
            // registration (e.g. a reply outliving its search session's registration).
            log::trace!(
                "no registration matched {} -> {} on {ingress:?}",
                packet.source,
                packet.dest
            );
        }
    }

    /// Drain the interface monitor, then act on what moved: evict the DIAL proxies whose interface
    /// lost the v4 address they bound, drop the search sessions whose reserved port was bound to a
    /// re-addressed interface, and reconcile when an event may announce a recreation.
    fn refresh_changed_interfaces(&mut self, reactor: &mut Reactor) {
        let changes = self.lifecycle.drain(&mut self.table);
        self.dial.evict_on_interface_change(
            reactor,
            &changes.v4_moved,
            "after its interface's address changed",
        );
        self.notify_iface_change(&changes.touched, reactor);
        if changes.reconcile {
            self.reconcile_interfaces(reactor);
        }
    }

    /// Broadcast [`PacketHandler::on_iface_change`] to every registered handler for the interfaces
    /// backing `captures`, taking each handler out for its call so `&mut self` is free. Off the data
    /// path (only the interface-change / reconcile path, which allocates anyway), so it snapshots the
    /// live keys into a fresh `Vec` rather than a reused scratch. A handler that unregisters a sibling
    /// mid-broadcast (a search reflector dropping its sessions' response registrations) is fine: the vacated
    /// slot is skipped.
    fn notify_iface_change(&mut self, captures: &[CaptureKey], reactor: &mut Reactor) {
        if captures.is_empty() {
            return;
        }
        let keys: Vec<RegistrationKey> = self
            .registrations
            .iter()
            .map(|(key, _)| RegistrationKey(key))
            .collect();
        for key in keys {
            let Some(mut handler) = self
                .registrations
                .get_mut(key.0)
                .and_then(|reg| reg.handler.take())
            else {
                // Expected, not an error: an earlier reflector in this broadcast cleared its sessions
                // and unregistered their response registrations, which are in this snapshot, so they resolve
                // to None here. Mirrors on_deadline's mid-sweep skip.
                log::trace!(
                    "iface-change broadcast: handler for {key:?} gone mid-broadcast, skipped"
                );
                continue;
            };
            handler.on_iface_change(captures, self, reactor);
            if let Some(reg) = self.registrations.get_mut(key.0) {
                reg.handler = Some(handler);
            }
        }
    }

    /// Run the recreation reconcile, then evict the DIAL proxies and drop the search sessions on
    /// every rebuilt interface's captures: their mint-time snapshots and reserved ports belonged
    /// to the interface that was removed or recreated, whatever the new one resolves to.
    fn reconcile_interfaces(&mut self, reactor: &mut Reactor) {
        for rebuilt in self.lifecycle.reconcile(&mut self.table) {
            let reason = if rebuilt.removed {
                "after its interface was removed"
            } else {
                "after its interface was recreated"
            };
            self.dial
                .evict_on_interface_change(reactor, &rebuilt.captures, reason);
            self.notify_iface_change(&rebuilt.captures, reactor);
        }
    }
}

impl Handler for PacketDispatcher {
    /// [`MONITOR_TAG`] routes to an address-monitor drain; otherwise `event.user_data` is the
    /// ready capture's [`CaptureKey`] (tagged at registration), so drain that capture
    /// directly, no fd lookup. A bad capture value resolves to a stale key and is a logged
    /// drop in [`drain_and_route`](Self::drain_and_route).
    fn on_readable(&mut self, event: ReadyEvent, reactor: &mut Reactor) {
        if event.user_data == MONITOR_TAG {
            self.refresh_changed_interfaces(reactor);
        } else {
            self.drain_and_route(CaptureKey::from_u64(event.user_data), reactor);
        }
    }

    /// The soonest deadline any registered handler keeps; the reactor waits within it.
    fn next_deadline(&self) -> Option<Instant> {
        // O(registrations) every run-loop iteration. n is bounded by MAX_SESSIONS per search
        // reflector (SSDP and WSD each, per reflector pair) plus a few base handlers, so a
        // fan-out config carries hundreds. The scan still beats a min-heap, whose O(1) peek isn't
        // worth the entry invalidation a cancelled or moved deadline would force. Revisit if
        // timers grow.
        self.registrations
            .iter()
            .filter_map(|(_, reg)| reg.handler.as_ref().and_then(|h| h.next_deadline()))
            .chain(self.dial.next_grace()) // and the soonest DIAL proxy grace, for its eviction sweep
            .chain(self.report.as_ref().map(|r| r.next)) // and the next counter summary, if enabled
            .chain(Some(self.lifecycle.next_reconcile())) // and the interface reconcile tick
            .min()
    }

    /// Fire [`PacketHandler::on_deadline`] on every registration whose deadline has reached `now`,
    /// taking each handler out for its call (as `route` does) so `&mut self` is free. Reached at most
    /// about once a second and only while a handler keeps a timer, so the snapshot allocation is off
    /// the data path. A registration removed during its own call isn't restored.
    fn on_deadline(&mut self, now: Instant, reactor: &mut Reactor) {
        let due: Vec<RegistrationKey> = self
            .registrations
            .iter()
            .filter(|(_, reg)| {
                reg.handler
                    .as_ref()
                    .and_then(|h| h.next_deadline())
                    .is_some_and(|d| d <= now)
            })
            .map(|(key, _)| RegistrationKey(key))
            .collect();
        for key in due {
            // Gone if an earlier handler in this sweep unregistered it (a sibling, or itself).
            let Some(mut handler) = self
                .registrations
                .get_mut(key.0)
                .and_then(|reg| reg.handler.take())
            else {
                log::trace!("deadline sweep: handler for {key:?} gone mid-sweep, skipped");
                continue;
            };
            handler.on_deadline(now, self, reactor);
            if let Some(reg) = self.registrations.get_mut(key.0) {
                reg.handler = Some(handler);
            }
        }
        self.dial.sweep(now, reactor); // evict DIAL proxies whose advertisement grace has lapsed

        // The periodic counter summary, when enabled and due.
        if let Some(report) = &mut self.report
            && now >= report.next
        {
            log_counters(self.table.counter_rows());
            report.next = now + report.interval;
        }

        // The interface reconcile tick (it re-arms itself): the detection floor for
        // recreations whose events were lost, and the retry driver while one is mid-recovery.
        if now >= self.lifecycle.next_reconcile() {
            self.reconcile_interfaces(reactor);
        }
    }

    /// A SIGUSR1 diagnostics dump: log the per-interface counter summary on demand. Independent of the
    /// periodic report's interval (the counters accrue regardless), so it works even when unconfigured.
    fn on_control(&mut self, event: ControlEvent, _reactor: &mut Reactor) {
        match event {
            ControlEvent::Dump => log_counters(self.table.counter_rows()),
        }
    }
}

/// Whether a captured frame is one of our own re-emits handed back by the link: its source MAC is
/// the ingress interface's own. The all-zero address is exempt: Linux reports it as a loopback's
/// hardware address and every loopback frame carries it, so it identifies nothing.
fn is_own_echo(src_mac: Option<MacAddr>, own_mac: Option<MacAddr>) -> bool {
    match (src_mac, own_mac) {
        (Some(src), Some(own)) => src == own && !own.is_unspecified(),
        _ => false,
    }
}

#[cfg(test)]
mod tests;
