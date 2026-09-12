//! Packet dispatch: the routing layer between captures and reflectors.
//!
//! [`PacketDispatcher`] owns every [`Capture`], addressed by a `Copy` [`CaptureKey`], and the
//! routing registrations. A readable fd drains its capture, parses each frame into a [`Packet`]
//! and offers it to every registration whose [`Filter`] matches; a reflector re-emits on its
//! egress by key and never holds an fd.

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
use crate::reactor::{Arena, ControlEvent, Handler, HandlerSlot, Key, Reactor, ReadyEvent};

use self::counters::log_counters;
use self::egress::{Datagram, Egress};
use self::interface_table::InterfaceTable;
use self::lifecycle::InterfaceLifecycle;

/// Frames drained per readable event before yielding, so a flooded interface can't starve the
/// others. BPF finishes its current userland batch past this: the wait won't re-fire for
/// records already read.
const MAX_FRAMES_PER_EVENT: u32 = 64;

/// The reactor `user_data` for the interface monitor's fd. A [`CaptureKey`] packs a `u32`, so
/// this never collides with a capture.
const MONITOR_TAG: u64 = u64::MAX;

/// A `Copy` handle to a capture the dispatcher owns: an index into the interface table.
/// Captures are insert-only, so the index is a stable identity with no generation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct CaptureKey(u32);

impl CaptureKey {
    #[must_use]
    fn to_u64(self) -> u64 {
        u64::from(self.0)
    }

    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn from_u64(packed: u64) -> Self {
        CaptureKey(packed as u32)
    }
}

/// A `Copy` handle to a routing registration: the generational arena [`Key`] of its slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct RegistrationKey(Key);

/// The values one filter field accepts: mDNS's two groups for `dst_ip`, `WoL`'s ports for
/// `dst_port`.
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

pub(crate) type IpSet = FilterSet<IpAddr>;
pub(crate) type PortSet = FilterSet<u16>;

/// A packet filter; an unset field matches anything. A MAC field never matches a packet from a
/// link without L2 addresses (`DLT_NULL`, raw IP).
#[derive(Clone, Default)]
pub(crate) struct Filter {
    pub(crate) src_ip: Option<IpAddr>,
    pub(crate) dst_ip: Option<IpSet>,
    pub(crate) src_port: Option<u16>,
    pub(crate) dst_port: Option<PortSet>,
    pub(crate) src_mac: Option<MacSet>,
    pub(crate) dst_mac: Option<MacAddr>,
    /// Require an IPv4 broadcast destination ([`Packet::is_broadcast`]).
    pub(crate) broadcast: bool,
    /// Also accept a `dst_ip` equal to an ingress address of this family: an answer to this host.
    pub(crate) dst_own: Option<AddressFamily>,
}

impl Filter {
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

/// A reflector, called for each packet its registration's filter admits.
pub(crate) trait PacketHandler {
    fn on_packet(
        &mut self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        reactor: &mut Reactor,
    ) -> Outcome;

    /// When [`on_deadline`](Self::on_deadline) is next wanted; `None` keeps no timer.
    fn next_deadline(&self) -> Option<Instant> {
        None
    }

    fn on_deadline(
        &mut self,
        _now: Instant,
        _dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) {
    }

    /// One of `captures` was rebound to a recreated interface or had an address move; state
    /// pinned to it (a reserved port, a response registration) is stale. The table is already
    /// repaired when this runs, so `dispatcher` reads current state.
    fn on_iface_change(
        &mut self,
        _captures: &[CaptureKey],
        _dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) {
    }
}

/// The handler is `None` only while taken out for its call.
struct Registration {
    ingress: CaptureKey,
    filter: Filter,
    handler: Option<Box<dyn PacketHandler>>,
}

impl HandlerSlot for Registration {
    type Handler = dyn PacketHandler;

    fn slot(&self) -> &Option<Box<dyn PacketHandler>> {
        &self.handler
    }

    fn slot_mut(&mut self) -> &mut Option<Box<dyn PacketHandler>> {
        &mut self.handler
    }
}

struct CounterReport {
    interval: Duration,
    next: Instant,
}

pub(crate) struct PacketDispatcher {
    table: InterfaceTable,
    registrations: Arena<Registration>,
    /// Scratch for [`route`](Self::route), kept allocated so the data path doesn't allocate.
    route_keys: Vec<RegistrationKey>,
    lifecycle: InterfaceLifecycle,
    dial: DialContext,
    egress: Egress,
    report: Option<CounterReport>,
}

impl PacketDispatcher {
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

    /// Log each capture's counts every `interval`, first `interval` after `now`. The counters
    /// accrue whether or not this is called.
    pub(crate) fn enable_counter_report(&mut self, interval: Duration, now: Instant) {
        self.report = Some(CounterReport {
            interval,
            next: now + interval,
        });
    }

    /// Captures on the same interface share one [`Interface`](crate::interface::Interface) record.
    ///
    /// # Errors
    /// A resolution syscall failure when first opening the capture's interface.
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

    /// Each capture's `(fd, user_data)` for [`Reactor::register_with_fds`], plus the address
    /// monitor's fd under [`MONITOR_TAG`].
    pub(crate) fn capture_watches(&self) -> Vec<(RawFd, u64)> {
        let mut watches = self.table.capture_watches();
        if let Some(fd) = self.lifecycle.monitor_fd() {
            watches.push((fd, MONITOR_TAG));
        }
        watches
    }

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

    /// A stale key is a no-op.
    pub(crate) fn unregister(&mut self, key: RegistrationKey) {
        self.registrations.remove(key.0);
    }

    /// Join `group` on the interface behind `capture`; the group is re-joined on the interface's
    /// later address changes.
    ///
    /// # Errors
    /// The join's OS error; [`join_deferrable`] tells a missing-address deferral from a hard
    /// failure.
    pub(crate) fn join_group(&mut self, capture: CaptureKey, group: IpAddr) -> io::Result<()> {
        let Some(interface) = self.table.interface_of(capture) else {
            log::warn!("join_group: capture {capture:?} unknown; group {group} not joined");
            return Ok(());
        };
        self.table.join_on(interface, group)
    }

    pub(crate) fn interface_mtu(&self, capture: CaptureKey) -> Option<u32> {
        self.table.mtu_of(capture)
    }

    pub(crate) fn egress_addrs(&self, egress: CaptureKey) -> Option<&InterfaceAddresses> {
        self.table.egress_addrs(egress)
    }

    /// The DIAL registry with the name of the interface behind `target`. One call returns both:
    /// a caller could not hold the borrowed name across a second `&mut self` accessor.
    pub(crate) fn dial_context(&mut self, target: CaptureKey) -> (&mut DialContext, Option<&str>) {
        let target_iface = self
            .table
            .interface_of(target)
            .and_then(|interface| self.table.interface_name(interface));
        (&mut self.dial, target_iface)
    }

    /// The kernel ifindex behind `capture`, 0 while its interface is parked absent.
    pub(crate) fn capture_ifindex(&self, capture: CaptureKey) -> Option<u32> {
        self.table.ifindex_of(capture)
    }

    /// `None` for an unknown key or a capture taken out for its drain.
    pub(crate) fn link_type(&self, egress: CaptureKey) -> Option<LinkType> {
        self.table.capture(egress).map(Capture::link_type)
    }

    /// Build a UDP datagram and inject it on `egress`. The caller supplies the L2 destination,
    /// so this serves unicast and group sends alike. An unknown or draining egress is a logged
    /// drop.
    ///
    /// # Errors
    /// A send failure, or a frame that can't be built from the egress's current state: no
    /// source address or MAC, a source of the other family, an oversized payload.
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

    /// Inject a broadcast/multicast datagram on `egress`, deriving the L2 destination from `dst`.
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

    /// Deliver `dst`'s datagram as one unicast copy per peer of its family, at `dst`'s port. Two
    /// entries whose lists share a peer deliver to it once.
    ///
    /// # Errors
    /// As [`send_udp`](Self::send_udp), only when no copy went out; an unreachable peer costs
    /// its own copy and logs.
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

    fn drain_and_route(&mut self, ingress: CaptureKey, reactor: &mut Reactor) {
        // Taken out so the parsed Packet borrows a local and `&mut self` stays free for the
        // reflectors, which send on the other captures still in the table.
        let Some(mut capture) = self.table.take(ingress) else {
            if self.table.contains(ingress) {
                log::warn!("drain_and_route: ingress {ingress:?} already draining; skipped");
            } else {
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
                    // The reconcile can't run from here, mid-drain with this capture taken
                    // out; pull it forward instead.
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

    fn route(&mut self, ingress: CaptureKey, packet: &Packet, reactor: &mut Reactor) {
        // A handler still out for its call means a handler re-entered routing, which would
        // clear the shared `route_keys` under the outer loop.
        debug_assert!(
            self.registrations
                .iter()
                .all(|(_, reg)| reg.handler.is_some()),
            "route re-entered from inside a handler call"
        );
        // A hairpin bridge port or an AP re-broadcasting a station's multicast hands our own
        // re-emit back as an ordinary received frame, past the capture's outgoing drop.
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
        // Snapshot the keys: a registration made mid-route isn't fed the in-flight frame, and a
        // generational key makes the restore of one removed during its own call a no-op.
        // One shared buffer rather than a per-packet Vec: `route` never nests, a handler sends
        // but never re-drains.
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
            let mut handler = self
                .registrations
                .take_handler(key.0)
                .expect("a registration that just matched is live with its handler present");
            let outcome = handler.on_packet(packet, self, reactor);
            self.registrations.restore_handler(key.0, handler);
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
        if let Some(outcome) = final_outcome {
            self.table.record(ingress, outcome);
        } else {
            log::trace!(
                "no registration matched {} -> {} on {ingress:?}",
                packet.source,
                packet.dest
            );
        }
    }

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
            let Some(mut handler) = self.registrations.take_handler(key.0) else {
                log::trace!(
                    "iface-change broadcast: handler for {key:?} gone mid-broadcast, skipped"
                );
                continue;
            };
            handler.on_iface_change(captures, self, reactor);
            self.registrations.restore_handler(key.0, handler);
        }
    }

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
    fn on_readable(&mut self, event: ReadyEvent, reactor: &mut Reactor) {
        if event.user_data == MONITOR_TAG {
            self.refresh_changed_interfaces(reactor);
        } else {
            self.drain_and_route(CaptureKey::from_u64(event.user_data), reactor);
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        // O(n) per loop iteration; n is bounded by MAX_SESSIONS per search reflector plus a few
        // base handlers. The scan beats a min-heap, whose O(1) peek isn't worth the entry
        // invalidation a cancelled or moved deadline would force. Revisit if timers grow.
        self.registrations
            .handlers()
            .filter_map(|(_, handler)| handler.next_deadline())
            .chain(self.dial.next_grace())
            .chain(self.report.as_ref().map(|r| r.next))
            .chain(Some(self.lifecycle.next_reconcile()))
            .min()
    }

    /// Off the data path (about once a second at most), so the snapshot may allocate.
    fn on_deadline(&mut self, now: Instant, reactor: &mut Reactor) {
        let due: Vec<RegistrationKey> = self
            .registrations
            .handlers()
            .filter(|(_, handler)| handler.next_deadline().is_some_and(|d| d <= now))
            .map(|(key, _)| RegistrationKey(key))
            .collect();
        for key in due {
            let Some(mut handler) = self.registrations.take_handler(key.0) else {
                log::trace!("deadline sweep: handler for {key:?} gone mid-sweep, skipped");
                continue;
            };
            handler.on_deadline(now, self, reactor);
            self.registrations.restore_handler(key.0, handler);
        }
        self.dial.sweep(now, reactor);

        if let Some(report) = &mut self.report
            && now >= report.next
        {
            log_counters(self.table.counter_rows());
            report.next = now + report.interval;
        }

        if now >= self.lifecycle.next_reconcile() {
            self.reconcile_interfaces(reactor);
        }
    }

    /// `Dump` is SIGUSR1: log the counters on demand, whether or not the periodic report is on.
    fn on_control(&mut self, event: ControlEvent, _reactor: &mut Reactor) {
        match event {
            ControlEvent::Dump => log_counters(self.table.counter_rows()),
        }
    }
}

/// The all-zero address is exempt: Linux reports it as a loopback's hardware address, so it
/// identifies nothing.
fn is_own_echo(src_mac: Option<MacAddr>, own_mac: Option<MacAddr>) -> bool {
    match (src_mac, own_mac) {
        (Some(src), Some(own)) => src == own && !own.is_unspecified(),
        _ => false,
    }
}

#[cfg(test)]
mod tests;
