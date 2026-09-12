//! Interface lifecycle: keeping the table current as addresses change and as the kernel destroys
//! and recreates interfaces. The monitor drain refreshes what a notification names; the reconcile
//! re-points a stale entry at its name's current interface (or parks it absent) and re-binds its
//! captures in place.

use std::os::fd::RawFd;
use std::time::{Duration, Instant};

use crate::interface::{InterfaceEvent, InterfaceMonitor};
use crate::linear_map::LinearMap;

use super::CaptureKey;
use super::interface_table::InterfaceTable;

/// The reconcile's periodic floor: an interface recreation whose every event was lost (macOS's
/// silent route-socket overflow) is still detected.
pub(super) const RECONCILE_TICK: Duration = Duration::from_secs(30);

/// The reconcile cadence while an interface is parked absent or a rebuild step failed.
pub(super) const RECONCILE_RETRY: Duration = Duration::from_secs(1);

/// What a monitor drain found, as the captures on the interfaces concerned.
#[derive(Default)]
pub(super) struct Changes {
    /// The interface moved (or failed to re-resolve) its IPv4 address; DIAL proxies bind v4.
    pub(super) v4_moved: Vec<CaptureKey>,
    /// The interface moved an address of either family.
    pub(super) touched: Vec<CaptureKey>,
    /// An event that can announce a destroyed or recreated interface arrived.
    pub(super) reconcile: bool,
}

/// One interface the reconcile rebuilt (or parked absent), with its captures.
pub(super) struct Rebuilt {
    pub(super) captures: Vec<CaptureKey>,
    pub(super) removed: bool,
}

pub(super) struct InterfaceLifecycle {
    /// `None` is a degraded mode: addresses stay at their startup values.
    monitor: Option<InterfaceMonitor>,
    /// The largest kernel ifindex seen. Where indexes are monotonic, an unknown-index Link event
    /// at or below this is churn on an unwatched interface, not a creation.
    max_seen_ifindex: u32,
    next_reconcile: Instant,
}

impl InterfaceLifecycle {
    /// Opens the monitor before the first capture resolves, so a change during startup is
    /// queued rather than missed.
    pub(super) fn new() -> Self {
        Self {
            monitor: open_monitor(),
            max_seen_ifindex: 0,
            next_reconcile: Instant::now() + RECONCILE_TICK,
        }
    }

    pub(super) fn monitor_fd(&self) -> Option<RawFd> {
        self.monitor.as_ref().map(InterfaceMonitor::as_raw_fd)
    }

    pub(super) fn saw_interface(&mut self, ifindex: u32) {
        self.max_seen_ifindex = self.max_seen_ifindex.max(ifindex);
    }

    pub(super) fn next_reconcile(&self) -> Instant {
        self.next_reconcile
    }

    pub(super) fn reconcile_now(&mut self) {
        self.next_reconcile = Instant::now();
    }

    /// Drain the monitor and re-resolve each interface a notification names, once per interface
    /// per wakeup; an [`InterfaceEvent::Overflow`] re-resolves every interface. Best-effort: a
    /// failure logs and the last-known addresses stand. [`Changes::reconcile`] is set by anything
    /// that can announce a destroyed or recreated interface: a Link event on a watched interface,
    /// an unknown index that reads as a creation, an overflow, or a capture whose kernel binding
    /// died behind a matched index.
    pub(super) fn drain(&mut self, table: &mut InterfaceTable) -> Changes {
        let Some(monitor) = self.monitor.as_mut() else {
            return Changes::default();
        };
        // ifindex -> saw a Link event
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
            // The unread remainder stays readable; the level-triggered wait re-drains it.
            log::warn!(
                "interface monitor read failed mid-drain; refreshing what was collected: {e}"
            );
        }
        if changed.is_empty() && !overflow {
            return Changes::default();
        }
        // Compared before this batch raises the ceiling, or a creation's own Link event would
        // slip past.
        let prior_ceiling = self.max_seen_ifindex;
        for (ifindex, _) in changed.iter() {
            self.max_seen_ifindex = self.max_seen_ifindex.max(*ifindex);
        }
        let mut want_reconcile = overflow;
        let mut v4_moved: Vec<u32> = Vec::new();
        let mut touched: Vec<u32> = Vec::new();
        if overflow {
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
                        // Can't confirm the address survived: treat it as moved rather than keep
                        // a listener on a possibly-vanished address.
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
                        // A bare Link event (carrier, MTU, flags) must not clear sessions.
                        if change.v4 || change.v6 {
                            touched.push(*ifindex);
                        }
                        if *is_link || !table.probe_by_ifindex(*ifindex) {
                            want_reconcile = true;
                        }
                    }
                    Ok(None) => {
                        // Unwatched, unless it is ours recreated under a new index. With monotonic
                        // indexes a Link event above the ceiling is a creation; FreeBSD reuses
                        // indexes, so any Link event reconciles; macOS has no lifecycle events,
                        // so any unknown-index event does.
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
                        // As in the overflow branch: an unconfirmed address counts as moved, and
                        // the interface may not have survived either.
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

    /// Repair every stale interface: re-point it at its name's current interface (or park it
    /// absent) and re-bind its captures behind their stable keys. Re-arms the next pass at
    /// [`RECONCILE_TICK`], or [`RECONCILE_RETRY`] while an interface is absent or a step failed.
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
                // Both are retried on every address event, but only a deferral has a trigger to
                // promise.
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
        // Parked interfaces are not in the stale list; the fast cadence picks up their return.
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
