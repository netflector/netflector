//! Interface lifecycle: keeping the table current as addresses change and as the kernel destroys
//! and recreates interfaces. The monitor drain refreshes what a notification names and decides
//! when the reconcile is due; the reconcile re-points a stale entry at its name's current interface
//! (or parks it absent) and re-binds its captures in place. Both report what moved as capture keys,
//! for the dispatcher to evict DIAL proxies and notify handlers by.

use std::os::fd::RawFd;
use std::time::{Duration, Instant};

use crate::interface::{InterfaceEvent, InterfaceMonitor};
use crate::linear_map::LinearMap;

use super::CaptureKey;
use super::interface_table::InterfaceTable;

/// The reconcile's periodic floor: the guarantee that an interface recreation whose every
/// event was lost (macOS's silent route-socket overflow) is still detected. Cheap while
/// healthy -- one name lookup per watched interface plus one kernel probe per capture.
pub(super) const RECONCILE_TICK: Duration = Duration::from_secs(30);

/// The reconcile cadence while an interface is parked absent or a rebuild step failed: the
/// retry driver that picks up the interface's return and re-attempts failed re-binds.
pub(super) const RECONCILE_RETRY: Duration = Duration::from_secs(1);

/// What a monitor drain found, as the captures on the interfaces concerned.
#[derive(Default)]
pub(super) struct Changes {
    /// The interface lost or moved its IPv4 address, or could not be re-resolved: the DIAL
    /// proxies, which bind IPv4, must re-mint.
    pub(super) v4_moved: Vec<CaptureKey>,
    /// The interface moved an address of either family: a search session's reserved reply
    /// address may be stale.
    pub(super) touched: Vec<CaptureKey>,
    /// An event that can announce a destroyed or recreated interface arrived.
    pub(super) reconcile: bool,
}

/// One interface the reconcile rebuilt (or parked absent), with its captures. Whatever the
/// replacement resolved to, state pinned to the old interface is stale.
pub(super) struct Rebuilt {
    pub(super) captures: Vec<CaptureKey>,
    pub(super) removed: bool,
}

/// The address-change monitor and the reconcile schedule.
pub(super) struct InterfaceLifecycle {
    /// Opened best-effort in [`new`](Self::new). `None` is a degraded mode: addresses stay at
    /// their startup-resolved values.
    monitor: Option<InterfaceMonitor>,
    /// The largest kernel ifindex seen: the watched interfaces' own, raised by every drained
    /// notification. On monotonic platforms ([`InterfaceMonitor::INDEXES_MONOTONIC`]) an
    /// unknown-index Link event at or below this ceiling is churn on an existing unwatched
    /// interface, not a creation, so it doesn't trigger the reconcile.
    max_seen_ifindex: u32,
    /// When the next reconcile pass is due: the [`RECONCILE_TICK`] floor when healthy,
    /// [`RECONCILE_RETRY`] while an interface is parked absent or a rebuild step failed, `now`
    /// when a capture read error pulls it forward.
    next_reconcile: Instant,
}

impl InterfaceLifecycle {
    /// Opens the monitor up front, before the first capture resolves, so a change during startup
    /// is already queued rather than missed.
    pub(super) fn new() -> Self {
        Self {
            monitor: open_monitor(),
            max_seen_ifindex: 0,
            next_reconcile: Instant::now() + RECONCILE_TICK,
        }
    }

    /// The monitor's fd to watch, if it opened.
    pub(super) fn monitor_fd(&self) -> Option<RawFd> {
        self.monitor.as_ref().map(InterfaceMonitor::as_raw_fd)
    }

    /// Seed the seen-index ceiling with a watched interface's own identity.
    pub(super) fn saw_interface(&mut self, ifindex: u32) {
        self.max_seen_ifindex = self.max_seen_ifindex.max(ifindex);
    }

    pub(super) fn next_reconcile(&self) -> Instant {
        self.next_reconcile
    }

    /// Pull the next reconcile forward to now: a capture read the error that says its interface
    /// is gone.
    pub(super) fn reconcile_now(&mut self) {
        self.next_reconcile = Instant::now();
    }

    /// Drain the monitor and re-resolve each interface a notification names, coalescing duplicates
    /// so one interface re-resolves at most once per wakeup. An [`InterfaceEvent::Overflow`]
    /// re-resolves every interface. Best-effort: a read or resolution failure logs and is
    /// dropped, and the daemon keeps its last-known addresses.
    ///
    /// Doubles as the recreation detector: the returned [`Changes::reconcile`] asks for one after
    /// an event that can announce a destroyed or recreated interface. A `Link` event on a watched
    /// interface, or one carrying an index above everything seen (a creation, on platforms whose
    /// indexes are monotonic), or any unknown-index event where no lifecycle messages exist
    /// (macOS), or an overflow (the announcement may be among the drops) -- and, for a recreation
    /// that reused the watched index, a per-capture kernel probe on every matched refresh.
    pub(super) fn drain(&mut self, table: &mut InterfaceTable) -> Changes {
        let Some(monitor) = self.monitor.as_mut() else {
            return Changes::default();
        };
        // Coalesce to one ifindex -> saw-a-Link-event entry per interface.
        let mut changed: LinearMap<u32, bool> = LinearMap::new();
        let mut overflow = false;
        if let Err(e) = monitor.drain(|event| match event {
            InterfaceEvent::Overflow => overflow = true,
            InterfaceEvent::Address(ifindex) | InterfaceEvent::Link(ifindex) => {
                let is_link = matches!(event, InterfaceEvent::Link(_));
                match changed.get_mut(&ifindex) {
                    Some(link) => *link |= is_link,
                    None => {
                        changed.insert(ifindex, is_link);
                    }
                }
            }
        }) {
            // The drain already consumed and collected these notifications before failing, so refresh
            // what we have rather than discard it; the socket's unread remainder stays readable and the
            // level-triggered wait re-drains it.
            log::warn!(
                "interface monitor read failed mid-drain; refreshing what was collected: {e}"
            );
        }
        if changed.is_empty() && !overflow {
            // nothing collected (a spurious wakeup, or a drain error before the first read)
            return Changes::default();
        }
        // The creation gate compares against the ceiling from BEFORE this batch: the creation's
        // own Link event would otherwise raise the ceiling past itself and slip through.
        let prior_ceiling = self.max_seen_ifindex;
        for (ifindex, _) in changed.iter() {
            self.max_seen_ifindex = self.max_seen_ifindex.max(*ifindex);
        }
        let mut want_reconcile = overflow;
        // The DIAL proxies bind IPv4 only, so collect the interfaces whose v4 address actually moved. A
        // routine v6 or MAC change must not churn a proxy whose v4 (and cached LOCATION) is unchanged.
        let mut v4_moved: Vec<u32> = Vec::new();
        // Interfaces whose addresses actually moved this cycle, for the session notification below:
        // search reflectors drop sessions whose reserved port was bound to a re-addressed interface.
        // Only a real address delta (either family) qualifies, not a benign Link / no-op-Address event,
        // so a healthy session survives a carrier flap or an unrelated interface's churn. (DIAL is
        // v4-only via v4_moved; sessions can be either family. Recreations are handled by the reconcile,
        // keyed by capture, so they need no entry here.)
        let mut touched: Vec<u32> = Vec::new();
        if overflow {
            // Notifications were dropped, so re-resolve every interface.
            log::debug!("interface monitor overflow; re-resolving all interfaces");
            for (ifindex, result) in table.refresh_all() {
                match result {
                    Ok(change) => {
                        if change.v4 {
                            v4_moved.push(ifindex);
                        }
                        if change.v4 || change.v6 {
                            touched.push(ifindex);
                        }
                    }
                    Err(e) => {
                        // The overflow already means notifications were dropped, so this is the one
                        // chance to catch a move whose event was lost, and we can't confirm the address
                        // survived. Treat it as moved so any DIAL proxy re-mints and any session drops
                        // rather than keeping a listener bound to a possibly-vanished address.
                        log::warn!(
                            "re-resolving ifindex {ifindex} failed: {e}; evicting its proxies"
                        );
                        v4_moved.push(ifindex);
                        touched.push(ifindex);
                    }
                }
            }
        } else {
            for (ifindex, is_link) in changed.iter() {
                match table.refresh_by_ifindex(*ifindex) {
                    Ok(Some(change)) => {
                        log::debug!("re-resolved interface (ifindex {ifindex}) after a change");
                        if change.v4 {
                            v4_moved.push(*ifindex);
                        }
                        // Only a real address delta invalidates a session's reserved reply address; a
                        // bare Link event (carrier / MTU / flag) with no delta must not clear sessions.
                        if change.v4 || change.v6 {
                            touched.push(*ifindex);
                        }
                        // A lifecycle event on a watched interface, or a capture whose kernel
                        // binding died behind this (possibly reused) index: reconcile.
                        if *is_link || !table.probe_by_ifindex(*ifindex) {
                            want_reconcile = true;
                        }
                    }
                    Ok(None) => {
                        // An interface we don't watch -- unless it is one of ours, recreated
                        // under a new index. A Link event above every index seen so far is a
                        // creation where indexes are monotonic; where they aren't (FreeBSD),
                        // any Link announcement reconciles; where lifecycle events don't
                        // exist at all (macOS), any unknown-index event has to.
                        let creation = if InterfaceMonitor::INDEXES_MONOTONIC {
                            *is_link && *ifindex > prior_ceiling
                        } else {
                            *is_link
                        };
                        if creation || !InterfaceMonitor::LIFECYCLE_EVENTS {
                            want_reconcile = true;
                        }
                    }
                    Err(e) => {
                        // Same conservative stance as the overflow branch: a failed re-resolve can't
                        // confirm the bound v4 survived (a notification arrived, so something changed),
                        // so evict any proxy on it rather than risk a stale, silently-dead listener.
                        // Reconcile, since it can't confirm the interface survived either.
                        log::warn!(
                            "re-resolving ifindex {ifindex} failed: {e}; evicting its proxies"
                        );
                        v4_moved.push(*ifindex);
                        touched.push(*ifindex);
                        want_reconcile = true;
                    }
                }
            }
        }
        Changes {
            v4_moved: captures_for(table, &v4_moved),
            touched: captures_for(table, &touched),
            reconcile: want_reconcile,
        }
    }

    /// Detect and repair interfaces whose kernel identity moved out from under the table: the
    /// recreation recovery. Each stale entry is re-pointed at its name's current interface (or
    /// parked absent) and its captures re-bound in place behind their stable keys; the caller
    /// evicts the interface's DIAL proxies and notifies the handlers, whose state died with the
    /// old interface whatever the new one's values. Re-arms the next pass:
    /// the [`RECONCILE_TICK`] floor when healthy, [`RECONCILE_RETRY`] while an interface is
    /// absent or a rebuild step failed (the probe keeps re-flagging a half-rebuilt entry).
    pub(super) fn reconcile(&mut self, table: &mut InterfaceTable) -> Vec<Rebuilt> {
        let mut pending = false;
        let mut rebuilt = Vec::new();
        for stale in table.stale_interfaces() {
            let name = table
                .interface_name(stale.key)
                .expect("stale keys come from this table's own scan")
                .to_owned();
            let captures = table.captures_of(stale.key);
            let mut failed = false;
            match (stale.cached, stale.cur) {
                (was, 0) => {
                    log::info!(
                        "interface {name} is gone (was ifindex {was}); parking until it returns"
                    );
                }
                (0, now) => {
                    log::info!("interface {name}: returned as ifindex {now}; re-binding");
                }
                (was, now) => {
                    log::info!("interface {name}: recreated (ifindex {was} -> {now}); re-binding");
                }
            }
            match table.rebind_interface(stale.key, stale.cur) {
                // Both kinds are retried on every later address event, but only a deferral has a
                // trigger that will resolve it, so only that one may promise a retry.
                Ok(counts) => {
                    if counts.failed > 0 {
                        log::warn!(
                            "{} group membership(s) on {name} did not re-join; that traffic is \
                             not reflected until they do",
                            counts.failed
                        );
                    }
                    if counts.deferred > 0 {
                        log::warn!(
                            "{} group membership(s) on {name} not re-joined yet; retrying \
                             on its next address event",
                            counts.deferred
                        );
                    }
                }
                Err(e) => {
                    log::warn!("re-resolving {name} failed: {e}; will retry");
                    failed = true;
                }
            }
            if stale.cur != 0 {
                for capture in &captures {
                    match table.rebind_capture(*capture) {
                        Ok(true) => {}
                        Ok(false) => {
                            log::warn!("capture {capture:?} missing during {name}'s rebuild");
                        }
                        Err(e) => {
                            log::warn!("re-binding a capture on {name} failed: {e}; will retry");
                            failed = true;
                        }
                    }
                }
            }
            if stale.cur != 0 && !failed {
                for capture in &captures {
                    table.record_recovery(*capture);
                }
                log::info!("interface {name}: recovery complete");
            }
            pending |= failed;
            rebuilt.push(Rebuilt {
                captures,
                removed: stale.cur == 0,
            });
        }
        // The fast cadence also covers parked interfaces (quiescent, so not in the stale list):
        // their return must be picked up promptly even if every event for it is lost.
        let retry = pending || table.any_absent();
        self.next_reconcile = Instant::now()
            + if retry {
                RECONCILE_RETRY
            } else {
                RECONCILE_TICK
            };
        rebuilt
    }
}

/// The captures on the interfaces currently at `ifindexes`, mapping the refresh path's kernel
/// indexes to the stable [`CaptureKey`]s the eviction and session notification are keyed by.
fn captures_for(table: &InterfaceTable, ifindexes: &[u32]) -> Vec<CaptureKey> {
    ifindexes
        .iter()
        .flat_map(|ifindex| table.captures_at_ifindex(*ifindex))
        .collect()
}

fn open_monitor() -> Option<InterfaceMonitor> {
    match InterfaceMonitor::open() {
        Ok(monitor) => {
            log::debug!("interface monitor installed");
            Some(monitor)
        }
        Err(e) => {
            log::warn!("interface monitor unavailable; addresses won't refresh on change: {e}");
            None
        }
    }
}
