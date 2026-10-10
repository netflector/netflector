//! Interface lifecycle: keeping the table current as addresses change and as the kernel destroys
//! and recreates interfaces. The monitor drain refreshes what a notification names, and a periodic
//! re-read catches what none announces; the reconcile parks an interface whose name resolves to
//! nothing and binds one whose name resolves elsewhere. Each of them ends by attempting the groups
//! the interface has not joined.

use std::num::NonZeroU32;
use std::os::fd::RawFd;
use std::time::{Duration, Instant};

use crate::interface::{InterfaceEvent, InterfaceMonitor};
use crate::linear_map::LinearMap;

use super::CaptureKey;
use super::interface_table::{InterfaceKey, InterfaceTable, Presence, Step};

/// The reconcile's periodic floor: an interface recreation whose every event was lost (macOS's
/// silent route-socket overflow) is still detected.
pub(super) const RECONCILE_TICK: Duration = Duration::from_secs(30);

/// The reconcile cadence while an interface is parked absent or a step could not settle.
pub(super) const RECONCILE_RETRY: Duration = Duration::from_secs(1);

/// Some address changes come with no notification: a BSD address finishing duplicate address
/// detection or reaching the end of its lifetime, a MAC change on a BSD virtual interface, a
/// macOS route socket overflowing without saying so.
pub(super) const RECHECK_INTERVAL: Duration = Duration::from_secs(30);

/// What a monitor drain or a re-read found, as the captures on the interfaces concerned.
#[derive(Default)]
pub(super) struct Changes {
    /// The interface moved (or failed to re-resolve) its IPv4 address; DIAL proxies bind v4.
    pub(super) v4_moved: Vec<CaptureKey>,
    /// The interface moved an address of either family.
    pub(super) touched: Vec<CaptureKey>,
    /// An event that can announce a destroyed or recreated interface arrived.
    pub(super) reconcile: bool,
}

/// One interface whose captures the reconcile re-bound or released, with its captures.
pub(super) struct Rebuilt {
    pub(super) captures: Vec<CaptureKey>,
    pub(super) removed: bool,
}

pub(super) struct InterfaceLifecycle {
    /// `None` is a degraded mode: addresses stay at their startup values.
    monitor: Option<InterfaceMonitor>,
    /// The largest kernel ifindex seen. Where indexes are monotonic, an unknown-index Link event
    /// at or below this is churn on an unwatched interface, not a creation.
    max_seen_ifindex: Option<NonZeroU32>,
    next_reconcile: Instant,
    next_recheck: Instant,
}

impl InterfaceLifecycle {
    /// Opens the monitor before the first capture resolves, so a change during startup is
    /// queued rather than missed.
    pub(super) fn new() -> Self {
        Self {
            monitor: open_monitor(),
            max_seen_ifindex: None,
            next_reconcile: Instant::now() + RECONCILE_TICK,
            next_recheck: Instant::now() + RECHECK_INTERVAL,
        }
    }

    pub(super) fn monitor_fd(&self) -> Option<RawFd> {
        self.monitor.as_ref().map(InterfaceMonitor::as_raw_fd)
    }

    pub(super) fn saw_interface(&mut self, ifindex: NonZeroU32) {
        self.max_seen_ifindex = self.max_seen_ifindex.max(Some(ifindex));
    }

    pub(super) fn next_reconcile(&self) -> Instant {
        self.next_reconcile
    }

    pub(super) fn reconcile_now(&mut self) {
        self.next_reconcile = Instant::now();
    }

    pub(super) fn next_recheck(&self) -> Instant {
        self.next_recheck
    }

    /// A failed read keeps the last-known addresses: nothing says they moved, and the next pass
    /// retries.
    pub(super) fn recheck(&mut self, table: &mut InterfaceTable, now: Instant) -> Changes {
        self.next_recheck = now + RECHECK_INTERVAL;
        let mut v4_moved = Vec::new();
        let mut touched = Vec::new();
        for (key, result) in table.refresh_all() {
            match result {
                Ok(change) => {
                    if change.v4 {
                        v4_moved.push(key);
                    }
                    if change.v4 || change.v6 {
                        touched.push(key);
                    }
                }
                Err(e) => log::debug!(
                    "re-reading {} failed: {e}; keeping its last-known addresses",
                    name_of(table, key)
                ),
            }
        }
        Changes {
            v4_moved: captures_for(table, &v4_moved),
            touched: captures_for(table, &touched),
            reconcile: table.converge_all(now).is_err(),
        }
    }

    /// Drain the monitor and re-resolve each interface a notification names, once per interface
    /// per wakeup; an [`InterfaceEvent::Overflow`] re-resolves every interface. Best-effort: a
    /// failure logs and the last-known addresses stand. [`Changes::reconcile`] is set by anything
    /// that can announce a destroyed or recreated interface: a Link event on a watched interface,
    /// an unknown index that reads as a creation, an overflow, a capture whose kernel binding
    /// died behind a matched index, or a join finding its index dead.
    pub(super) fn drain(&mut self, table: &mut InterfaceTable, now: Instant) -> Changes {
        let Some(monitor) = self.monitor.as_mut() else {
            return Changes::default();
        };
        // ifindex -> saw a Link event
        let mut changed: LinearMap<NonZeroU32, bool> = LinearMap::new();
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
            self.max_seen_ifindex = self.max_seen_ifindex.max(Some(*ifindex));
        }
        let mut want_reconcile = overflow;
        let mut v4_moved = Vec::new();
        let mut touched = Vec::new();
        if overflow {
            log::debug!("interface monitor overflow; re-resolving all interfaces");
            table.wake_all_unbound(now);
            for (key, result) in table.refresh_all() {
                match result {
                    Ok(change) => {
                        if change.v4 {
                            v4_moved.push(key);
                        }
                        if change.v4 || change.v6 {
                            touched.push(key);
                        }
                    }
                    Err(e) => {
                        // Can't confirm the address survived: treat it as moved rather than keep
                        // a listener on a possibly-vanished address.
                        log::warn!(
                            "re-resolving {} failed: {e}; evicting its proxies",
                            name_of(table, key)
                        );
                        v4_moved.push(key);
                        touched.push(key);
                    }
                }
            }
        } else {
            for (ifindex, is_link) in changed.iter() {
                let Some(key) = table.key_by_ifindex(*ifindex) else {
                    want_reconcile |=
                        unwatched_event_reconciles(table, *ifindex, *is_link, prior_ceiling, now);
                    continue;
                };
                match table.refresh(key) {
                    Ok(change) => {
                        log::debug!("re-resolved interface (ifindex {ifindex}) after a change");
                        if change.v4 {
                            v4_moved.push(key);
                        }
                        // A bare Link event (carrier, MTU, flags) must not clear sessions.
                        if change.v4 || change.v6 {
                            touched.push(key);
                        }
                        // A detached capture says the index is another interface's now: the
                        // reconcile joins after it re-binds.
                        let attached = table.probe(key);
                        let gone = attached && table.converge(key, now).is_err();
                        if *is_link || !attached || gone {
                            want_reconcile = true;
                        }
                    }
                    Err(e) => {
                        // As in the overflow branch: an unconfirmed address counts as moved, and
                        // the interface may not have survived either.
                        log::warn!(
                            "re-resolving ifindex {ifindex} failed: {e}; evicting its proxies"
                        );
                        v4_moved.push(key);
                        touched.push(key);
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

    /// Step every interface (see [`InterfaceTable::step`]). Re-arms the next pass at
    /// [`RECONCILE_TICK`], at [`RECONCILE_RETRY`] while an interface is parked or a step could not
    /// settle, and no later than the earliest retry of a failed bind.
    pub(super) fn reconcile(&mut self, table: &mut InterfaceTable, now: Instant) -> Vec<Rebuilt> {
        let mut retry_soon = false;
        let mut rebuilt = Vec::new();
        for interface in table.interfaces() {
            let step = table.step(interface, now);
            report(name_of(table, interface), &step);
            // A kept interface can still have groups to join, ones whose event an overflow lost;
            // with every group joined this costs no syscall.
            let gone = matches!(step, Step::Kept) && table.converge(interface, now).is_err();
            retry_soon |=
                gone || matches!(step, Step::LookupFailed(_) | Step::Bound { gone: true, .. });
            if let Some(moved) = moved(&step) {
                rebuilt.push(Rebuilt {
                    captures: table.captures_of(interface),
                    removed: moved == Moved::Removed,
                });
            }
        }
        self.next_reconcile = next_pass(
            now,
            retry_soon || table.any_parked(),
            table.next_bind_retry(),
        );
        rebuilt
    }
}

/// Whether an event on `ifindex`, an index no bound interface has, can concern one of ours: an
/// interface that failed to bind there, or one recreated under a new index. With monotonic
/// indexes a Link event above the ceiling is a creation; FreeBSD reuses indexes, so any Link event
/// reconciles; macOS has no lifecycle events, so any event does.
fn unwatched_event_reconciles(
    table: &mut InterfaceTable,
    ifindex: NonZeroU32,
    is_link: bool,
    prior_ceiling: Option<NonZeroU32>,
    now: Instant,
) -> bool {
    if table.wake_unbound(ifindex, now) {
        return true;
    }
    let creation = if InterfaceMonitor::INDEXES_MONOTONIC {
        is_link && Some(ifindex) > prior_ceiling
    } else {
        is_link
    };
    creation || !InterfaceMonitor::LIFECYCLE_EVENTS
}

fn report(name: &str, step: &Step) {
    match step {
        Step::Kept => {}
        Step::LookupFailed(e) => log::debug!("looking up {name} failed: {e}; retrying"),
        Step::Parked { was: Some(was) } => {
            log::info!("interface {name} is gone (was ifindex {was}); parking until it returns");
        }
        Step::Parked { was: None } => {
            log::info!("interface {name} is gone; parking until it returns");
        }
        Step::Bound { was, ifindex, .. } => match was {
            Presence::Present(bound) => {
                log::info!("interface {name}: recreated (ifindex {bound} -> {ifindex}); re-bound");
            }
            Presence::Parked => {
                log::info!("interface {name}: returned as ifindex {ifindex}; re-bound");
            }
            Presence::Unbound(unbound) if unbound.ifindex == *ifindex => {
                log::info!("interface {name}: bound to ifindex {ifindex} on a retry");
            }
            Presence::Unbound(unbound) => log::info!(
                "interface {name}: recreated (ifindex {} -> {ifindex}); re-bound",
                unbound.ifindex
            ),
        },
        Step::BindFailed {
            ifindex,
            error,
            retry_in,
            first,
            ..
        } => {
            if *first {
                log::warn!(
                    "interface {name}: binding to ifindex {ifindex} failed; retrying in {}s: \
                     {error}",
                    retry_in.as_secs()
                );
            } else {
                log::debug!("interface {name}: binding to ifindex {ifindex} still fails: {error}");
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Moved {
    /// The captures read the interface the name resolves to now.
    Rebound,
    /// The captures read nothing.
    Removed,
}

/// How a step changed what the interface's captures read, if it did.
fn moved(step: &Step) -> Option<Moved> {
    match step {
        Step::Parked { was: Some(_) }
        | Step::BindFailed {
            was: Presence::Present(_),
            ..
        } => Some(Moved::Removed),
        Step::Bound { .. } => Some(Moved::Rebound),
        // Its captures were not reading anything before either.
        Step::Kept
        | Step::LookupFailed(_)
        | Step::Parked { was: None }
        | Step::BindFailed { .. } => None,
    }
}

/// Soon while something is unsettled, else at the slow tick, and no later than a failed bind's
/// retry. A retry already due was stepped in this pass; arming at it would spin.
fn next_pass(now: Instant, soon: bool, bind_retry: Option<Instant>) -> Instant {
    let next = now
        + if soon {
            RECONCILE_RETRY
        } else {
            RECONCILE_TICK
        };
    bind_retry
        .filter(|due| *due > now)
        .map_or(next, |due| due.min(next))
}

fn captures_for(table: &InterfaceTable, interfaces: &[InterfaceKey]) -> Vec<CaptureKey> {
    interfaces
        .iter()
        .flat_map(|interface| table.captures_of(*interface))
        .collect()
}

fn name_of(table: &InterfaceTable, interface: InterfaceKey) -> &str {
    table.interface_name(interface).map_or("?", |name| name)
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

#[cfg(test)]
mod tests {
    use std::io;

    use super::super::interface_table::Unbound;
    use super::*;
    use crate::interface::{InterfaceName, if_index};

    fn loopback_index() -> NonZeroU32 {
        if_index(&InterfaceName::loopback()).expect("loopback has an ifindex")
    }

    #[test]
    fn a_retry_already_due_does_not_arm_the_next_pass() {
        let past = Instant::now();
        let now = past + Duration::from_secs(1);
        assert_eq!(next_pass(now, true, Some(past)), now + RECONCILE_RETRY);
        assert_eq!(next_pass(now, false, Some(past)), now + RECONCILE_TICK);
        let soon = now + Duration::from_millis(500);
        assert_eq!(next_pass(now, true, Some(soon)), soon);
        let later = now + Duration::from_secs(5);
        assert_eq!(next_pass(now, true, Some(later)), now + RECONCILE_RETRY);
        assert_eq!(next_pass(now, false, Some(later)), later);
    }

    #[test]
    fn only_a_change_of_what_the_captures_read_moves_them() {
        let index = loopback_index();
        let failed = |was| Step::BindFailed {
            was,
            ifindex: index,
            error: io::Error::from(io::ErrorKind::Unsupported),
            retry_in: RECONCILE_RETRY,
            first: true,
        };
        assert_eq!(
            moved(&Step::Parked { was: Some(index) }),
            Some(Moved::Removed)
        );
        assert_eq!(
            moved(&failed(Presence::Present(index))),
            Some(Moved::Removed)
        );
        assert_eq!(
            moved(&Step::Bound {
                was: Presence::Parked,
                ifindex: index,
                gone: false
            }),
            Some(Moved::Rebound)
        );
        assert_eq!(moved(&failed(Presence::Parked)), None);
        assert_eq!(moved(&Step::Parked { was: None }), None);
        assert_eq!(moved(&Step::Kept), None);
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn an_event_on_an_unbound_index_wakes_its_retry() -> io::Result<()> {
        let mut table = InterfaceTable::new();
        let key = table.find_or_add_interface(&InterfaceName::loopback())?;
        let now = Instant::now();
        table.set_test_presence(
            key,
            Presence::Unbound(Unbound::test_due(
                loopback_index(),
                now + Duration::from_secs(30),
            )),
        );
        assert!(unwatched_event_reconciles(
            &mut table,
            loopback_index(),
            false,
            Some(loopback_index()),
            now
        ));
        assert_eq!(table.next_bind_retry(), Some(now));
        Ok(())
    }
}
