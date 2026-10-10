//! The dispatcher's interface table: every interface with its presence and group memberships,
//! and every capture linked to its interface, all addressed by `Copy` index keys.

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use crate::capture::Capture;
use crate::interface::{
    AddressChange, Interface, InterfaceAddresses, InterfaceName, if_index_checked,
};

use super::counters::{CaptureCounters, Outcome};
use super::multicast::{Gone, JoinError, Memberships, Target, Wanted};
use super::{CaptureKey, retry_delay};

/// A `Copy` index into the table's interface entries; insert-only, so stable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct InterfaceKey(u32);

/// What an interface's captures are bound to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Presence {
    /// Bound to the interface at this index: its frames route, its addresses source sends, its
    /// groups are joined.
    Present(NonZeroU32),
    /// The name resolves to nothing. A capture bound to a renamed interface still reads; its
    /// frames are dropped.
    Parked,
    /// The name resolves, but binding to it failed. Treated as parked until a retry binds it.
    Unbound(Unbound),
}

impl fmt::Display for Presence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Present(ifindex) => write!(f, "bound to ifindex {ifindex}"),
            Self::Parked => f.write_str("parked, its name resolves to nothing"),
            Self::Unbound(unbound) => write!(
                f,
                "not bound, binding to ifindex {} failed",
                unbound.ifindex
            ),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct Unbound {
    pub(super) ifindex: NonZeroU32,
    attempts: u32,
    next_try: Instant,
}

/// What a [`step`](InterfaceTable::step) did to an interface.
#[derive(Debug)]
pub(super) enum Step {
    /// Nothing changed, or a failed bind is not due its retry yet.
    Kept,
    /// The name lookup could not run, so nothing is known.
    LookupFailed(io::Error),
    /// The name resolves to nothing. `was`: the index it was bound to, if it was bound.
    Parked { was: Option<NonZeroU32> },
    /// Bound to `ifindex`. `gone`: joining its groups already found the index dead.
    Bound {
        was: Presence,
        ifindex: NonZeroU32,
        gone: bool,
    },
    /// Binding to `ifindex` failed; retried in `retry_in`. `first`: not a retry at this index.
    BindFailed {
        was: Presence,
        ifindex: NonZeroU32,
        error: io::Error,
        retry_in: Duration,
        first: bool,
    },
}

/// `capture` is `None` while taken out for its drain; the rest stays resident, so addresses
/// resolve and outcomes record mid-drain.
struct CaptureEntry {
    capture: Option<Capture>,
    interface: InterfaceKey,
    counters: CaptureCounters,
    /// The packet last sent here (numbered from 1) and the digest of each datagram sent for it.
    sent_packet: u64,
    sent: Vec<u64>,
}

struct InterfaceEntry {
    interface: Interface,
    presence: Presence,
    /// `None`: `--no-join`.
    memberships: Option<Memberships>,
}

impl InterfaceEntry {
    fn ifindex(&self) -> Option<NonZeroU32> {
        match self.presence {
            Presence::Present(ifindex) => Some(ifindex),
            Presence::Parked | Presence::Unbound(_) => None,
        }
    }

    /// See [`Memberships::converge`]. Only a present interface joins.
    fn converge(&mut self, now: Instant) -> Result<(), Gone> {
        let (Presence::Present(ifindex), Some(memberships)) =
            (self.presence, self.memberships.as_mut())
        else {
            return Ok(());
        };
        let target = Target {
            name: &self.interface.name,
            ifindex,
        };
        memberships.converge(target, now)
    }

    /// Unbind: the memberships go with their sockets, and the addresses are forgotten.
    fn release(&mut self, presence: Presence) {
        self.presence = presence;
        if let Some(memberships) = &mut self.memberships {
            memberships.rebase();
        }
        self.interface.forget();
    }
}

pub(super) struct InterfaceTable {
    entries: Vec<InterfaceEntry>,
    captures: Vec<CaptureEntry>,
    join_groups: bool,
}

impl InterfaceTable {
    pub(super) fn new() -> Self {
        Self {
            entries: Vec::new(),
            captures: Vec::new(),
            join_groups: true,
        }
    }

    /// A table whose interfaces join no multicast group: `--no-join`.
    pub(super) fn without_group_joins() -> Self {
        Self {
            join_groups: false,
            ..Self::new()
        }
    }

    /// Want `group` on `interface` and join it. One not bound joins it once bound.
    ///
    /// # Errors
    /// See [`Memberships::join`].
    pub(super) fn join_on(
        &mut self,
        interface: InterfaceKey,
        group: IpAddr,
        wanted: Wanted,
        now: Instant,
    ) -> Result<(), JoinError> {
        // Startup-only with a fresh key, so the index is in range.
        let entry = &mut self.entries[interface.0 as usize];
        let Some(memberships) = &mut entry.memberships else {
            return Ok(());
        };
        match entry.presence {
            Presence::Present(ifindex) => {
                let target = Target {
                    name: &entry.interface.name,
                    ifindex,
                };
                memberships.join(group, wanted, target, now)
            }
            Presence::Parked | Presence::Unbound(_) => {
                memberships.add(group, wanted);
                Ok(())
            }
        }
    }

    /// Attempt the groups not joined on `interface`.
    ///
    /// # Errors
    /// See [`Memberships::converge`].
    pub(super) fn converge(&mut self, interface: InterfaceKey, now: Instant) -> Result<(), Gone> {
        self.entries
            .get_mut(interface.0 as usize)
            .map_or(Ok(()), |entry| entry.converge(now))
    }

    /// [`converge`](Self::converge) for every interface.
    ///
    /// # Errors
    /// [`Gone`] if any interface reported it; the others converge all the same.
    pub(super) fn converge_all(&mut self, now: Instant) -> Result<(), Gone> {
        let mut result = Ok(());
        for entry in &mut self.entries {
            if entry.converge(now).is_err() {
                result = Err(Gone);
            }
        }
        result
    }

    /// When the earliest failed join is due its retry.
    pub(super) fn next_join_retry(&self) -> Option<Instant> {
        self.entries
            .iter()
            .filter_map(|entry| entry.memberships.as_ref()?.next_retry())
            .min()
    }

    /// Startup-only.
    ///
    /// # Errors
    /// [`io::ErrorKind::NotFound`] for a name no interface bears, or a resolution syscall
    /// failure.
    pub(super) fn find_or_add_interface(
        &mut self,
        name: &InterfaceName,
    ) -> io::Result<InterfaceKey> {
        if let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.interface.name == *name)
        {
            return Ok(InterfaceKey(
                u32::try_from(index).expect("interface count fits a u32"),
            ));
        }
        let ifindex = if_index_checked(name)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("interface {name} not found"),
            )
        })?;
        let key =
            InterfaceKey(u32::try_from(self.entries.len()).expect("interface count fits a u32"));
        self.entries.push(InterfaceEntry {
            interface: Interface::open(name, ifindex)?,
            presence: Presence::Present(ifindex),
            memberships: self.join_groups.then(Memberships::new),
        });
        Ok(key)
    }

    pub(super) fn was_sent(&self, egress: CaptureKey, packet: u64, digest: u64) -> bool {
        self.captures
            .get(egress.0 as usize)
            .is_some_and(|entry| entry.sent_packet == packet && entry.sent.contains(&digest))
    }

    pub(super) fn record_sent(&mut self, egress: CaptureKey, packet: u64, digest: u64) {
        if let Some(entry) = self.captures.get_mut(egress.0 as usize) {
            if entry.sent_packet != packet {
                entry.sent_packet = packet;
                entry.sent.clear();
            }
            entry.sent.push(digest);
        }
    }

    /// Startup-only. The capture opens from the interface record, resolved once per name.
    ///
    /// # Errors
    /// A name no interface bears, a resolution syscall failure, or the capture failing to open.
    pub(super) fn open_capture(&mut self, name: &InterfaceName) -> io::Result<CaptureKey> {
        let interface = self.find_or_add_interface(name)?;
        let entry = &self.entries[interface.0 as usize];
        let ifindex = entry.ifindex().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("interface {name} not found"),
            )
        })?;
        let capture = Capture::open(&entry.interface, ifindex)?;
        let key = CaptureKey(u32::try_from(self.captures.len()).expect("capture count fits a u32"));
        self.captures.push(CaptureEntry {
            capture: Some(capture),
            interface,
            counters: CaptureCounters::default(),
            sent_packet: 0,
            sent: Vec::new(),
        });
        Ok(key)
    }

    pub(super) fn interface_of(&self, capture: CaptureKey) -> Option<InterfaceKey> {
        self.captures
            .get(capture.0 as usize)
            .map(|entry| entry.interface)
    }

    fn addrs(&self, interface: InterfaceKey) -> Option<&InterfaceAddresses> {
        self.entries
            .get(interface.0 as usize)
            .map(|entry| &entry.interface.addrs)
    }

    /// `None` for an unknown capture, or while its interface is not bound.
    pub(super) fn ifindex_of(&self, capture: CaptureKey) -> Option<NonZeroU32> {
        self.interface_index(self.interface_of(capture)?)
    }

    pub(super) fn interface_name(&self, interface: InterfaceKey) -> Option<&InterfaceName> {
        self.entries
            .get(interface.0 as usize)
            .map(|entry| &entry.interface.name)
    }

    /// For logs; `?` for an unknown key.
    pub(super) fn capture_name(&self, capture: CaptureKey) -> &str {
        self.interface_of(capture)
            .and_then(|interface| self.interface_name(interface))
            .map_or("?", |name| name)
    }

    /// `None` for an unknown key, or while the interface is not bound.
    pub(super) fn interface_index(&self, interface: InterfaceKey) -> Option<NonZeroU32> {
        self.entries
            .get(interface.0 as usize)
            .and_then(InterfaceEntry::ifindex)
    }

    pub(super) fn egress_addrs(&self, capture: CaptureKey) -> Option<&InterfaceAddresses> {
        self.addrs(self.interface_of(capture)?)
    }

    pub(super) fn mtu_of(&self, capture: CaptureKey) -> Option<u32> {
        self.entries
            .get(self.interface_of(capture)?.0 as usize)?
            .interface
            .mtu
    }

    pub(super) fn capture(&self, capture: CaptureKey) -> Option<&Capture> {
        self.captures.get(capture.0 as usize)?.capture.as_ref()
    }

    /// In range, whether or not taken out.
    pub(super) fn contains(&self, capture: CaptureKey) -> bool {
        (capture.0 as usize) < self.captures.len()
    }

    /// `None`: out of range, or already taken out.
    pub(super) fn take(&mut self, capture: CaptureKey) -> Option<Capture> {
        self.captures.get_mut(capture.0 as usize)?.capture.take()
    }

    #[must_use]
    pub(super) fn restore(&mut self, capture: CaptureKey, value: Capture) -> bool {
        if let Some(entry) = self.captures.get_mut(capture.0 as usize) {
            entry.capture = Some(value);
            true
        } else {
            false
        }
    }

    /// The row exists: the record_* methods only see keys the drain or the reconcile resolved.
    pub(super) fn record(&mut self, capture: CaptureKey, outcome: Outcome) {
        self.captures[capture.0 as usize].counters.record(outcome);
    }

    pub(super) fn record_oversized(&mut self, capture: CaptureKey, n: u64) {
        self.captures[capture.0 as usize]
            .counters
            .record_oversized(n);
    }

    pub(super) fn record_echo(&mut self, capture: CaptureKey) {
        self.captures[capture.0 as usize].counters.record_echo();
    }

    pub(super) fn record_unreassembled(&mut self, capture: CaptureKey) {
        self.captures[capture.0 as usize]
            .counters
            .record_unreassembled();
    }

    pub(super) fn counter_rows(&self) -> impl Iterator<Item = (&str, &CaptureCounters)> {
        self.captures.iter().filter_map(move |entry| {
            Some((
                self.interface_name(entry.interface)?.as_str(),
                &entry.counters,
            ))
        })
    }

    /// Each interface's name, presence and memberships, for the state dump.
    pub(super) fn interface_rows(
        &self,
    ) -> impl Iterator<Item = (&InterfaceName, Presence, Option<&Memberships>)> {
        self.entries.iter().map(|entry| {
            (
                &entry.interface.name,
                entry.presence,
                entry.memberships.as_ref(),
            )
        })
    }

    pub(super) fn interfaces(&self) -> impl Iterator<Item = InterfaceKey> + use<> {
        (0..self.entries.len())
            .map(|index| InterfaceKey(u32::try_from(index).expect("interface count fits a u32")))
    }

    /// The bound interface at kernel index `ifindex`; `None` for one we don't watch.
    pub(super) fn key_by_ifindex(&self, ifindex: NonZeroU32) -> Option<InterfaceKey> {
        self.entries
            .iter()
            .position(|entry| entry.ifindex() == Some(ifindex))
            .map(|index| InterfaceKey(u32::try_from(index).expect("interface count fits a u32")))
    }

    /// Make an interface that failed to bind to `ifindex` due for its retry now: an event on that
    /// index may be the change that lets it bind. Returns whether an interface was waiting on it.
    pub(super) fn wake_unbound(&mut self, ifindex: NonZeroU32, now: Instant) -> bool {
        let mut woke = false;
        for entry in &mut self.entries {
            if let Presence::Unbound(unbound) = &mut entry.presence
                && unbound.ifindex == ifindex
            {
                unbound.next_try = now;
                woke = true;
            }
        }
        woke
    }

    /// Make every interface that failed to bind due for its retry now: an overflow may have lost
    /// the event that lets one bind.
    pub(super) fn wake_all_unbound(&mut self, now: Instant) {
        for entry in &mut self.entries {
            if let Presence::Unbound(unbound) = &mut entry.presence {
                unbound.next_try = now;
            }
        }
    }

    /// Re-resolve the bound `interface` in place.
    ///
    /// # Errors
    /// A resolution syscall failure.
    pub(super) fn refresh(&mut self, interface: InterfaceKey) -> io::Result<AddressChange> {
        // Keys come from this table, so the index is in range.
        let entry = &mut self.entries[interface.0 as usize];
        match entry.presence {
            Presence::Present(ifindex) => entry.interface.refresh(ifindex),
            Presence::Parked | Presence::Unbound(_) => Ok(AddressChange::default()),
        }
    }

    /// Re-resolve every bound interface in place (an overflow, the periodic re-read); a
    /// per-interface failure is returned, not fatal.
    pub(super) fn refresh_all(&mut self) -> Vec<(InterfaceKey, io::Result<AddressChange>)> {
        self.entries
            .iter_mut()
            .enumerate()
            .filter_map(|(index, entry)| {
                let Presence::Present(ifindex) = entry.presence else {
                    return None;
                };
                let key = InterfaceKey(u32::try_from(index).expect("interface count fits a u32"));
                Some((key, entry.interface.refresh(ifindex)))
            })
            .collect()
    }

    /// Whether every capture on `interface` is still attached to its index (vacuously true while
    /// not bound): catches an index reused by a recreation as its first events arrive.
    pub(super) fn probe(&self, interface: InterfaceKey) -> bool {
        let Some(ifindex) = self.interface_index(interface) else {
            return true;
        };
        self.captures.iter().all(|entry| {
            entry.interface != interface
                || entry
                    .capture
                    .as_ref()
                    .is_none_or(|capture| capture.attached(ifindex))
        })
    }

    /// Whether any interface is parked absent: its return may come with no event at all.
    pub(super) fn any_parked(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.presence == Presence::Parked)
    }

    /// When the earliest interface that failed to bind is due its retry.
    pub(super) fn next_bind_retry(&self) -> Option<Instant> {
        self.entries
            .iter()
            .filter_map(|entry| match entry.presence {
                Presence::Unbound(unbound) => Some(unbound.next_try),
                Presence::Present(_) | Presence::Parked => None,
            })
            .min()
    }

    /// Bring `interface` in line with what its name resolves to now: park it when the name
    /// resolves to nothing, bind it when it resolves to an interface other than the bound one
    /// (or the same index with its captures detached, a recreation that reused it), and retry a
    /// failed bind once due.
    pub(super) fn step(&mut self, interface: InterfaceKey, now: Instant) -> Step {
        // Keys come from this table, so the index is in range.
        let entry = &mut self.entries[interface.0 as usize];
        let cur = match if_index_checked(&entry.interface.name) {
            Ok(cur) => cur,
            // Says nothing about the interface; reading it as absent would park a healthy one.
            Err(e) => return Step::LookupFailed(e),
        };
        match (entry.presence, cur) {
            (Presence::Parked, None) => Step::Kept,
            (Presence::Present(was), None) => {
                entry.release(Presence::Parked);
                Step::Parked { was: Some(was) }
            }
            (Presence::Unbound(_), None) => {
                entry.presence = Presence::Parked;
                Step::Parked { was: None }
            }
            (Presence::Present(bound), Some(cur)) if cur == bound && self.probe(interface) => {
                Step::Kept
            }
            (Presence::Unbound(unbound), Some(cur))
                if cur == unbound.ifindex && now < unbound.next_try =>
            {
                Step::Kept
            }
            (_, Some(cur)) => self.bind(interface, cur, now),
        }
    }

    /// All or nothing: the interface is read, every capture re-bound with the kind of link the
    /// read found, and only then are its addresses adopted and its groups joined, so the captures'
    /// probe vouches for the interface the groups join on.
    fn bind(&mut self, interface: InterfaceKey, ifindex: NonZeroU32, now: Instant) -> Step {
        let entry = &mut self.entries[interface.0 as usize];
        let was = entry.presence;
        if let Some(memberships) = &mut entry.memberships {
            memberships.rebase();
        }
        // Adopted last, the addresses of a bind that fails again log no gain on each retry.
        let bound = entry.interface.read(ifindex).and_then(|reading| {
            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            self.entries[interface.0 as usize]
                .interface
                .take_link(&reading);
            self.rebind_captures(interface, ifindex)?;
            self.entries[interface.0 as usize].interface.adopt(&reading);
            Ok(())
        });
        self.settle_bind(interface, ifindex, was, bound, now)
    }

    fn settle_bind(
        &mut self,
        interface: InterfaceKey,
        ifindex: NonZeroU32,
        was: Presence,
        bound: io::Result<()>,
        now: Instant,
    ) -> Step {
        let entry = &mut self.entries[interface.0 as usize];
        if let Err(error) = bound {
            let attempts = match was {
                Presence::Unbound(unbound) if unbound.ifindex == ifindex => {
                    unbound.attempts.saturating_add(1)
                }
                Presence::Present(_) | Presence::Parked | Presence::Unbound(_) => 0,
            };
            let retry_in = retry_delay(attempts);
            entry.release(Presence::Unbound(Unbound {
                ifindex,
                attempts,
                next_try: now + retry_in,
            }));
            return Step::BindFailed {
                was,
                ifindex,
                error,
                retry_in,
                first: attempts == 0,
            };
        }
        entry.presence = Presence::Present(ifindex);
        for capture in &mut self.captures {
            if capture.interface == interface {
                capture.counters.record_recovery();
            }
        }
        Step::Bound {
            was,
            ifindex,
            gone: self.converge(interface, now).is_err(),
        }
    }

    /// Re-bind every capture on `interface` in place: same fd, same slot, so held keys and the
    /// reactor's watch stay valid.
    fn rebind_captures(&mut self, interface: InterfaceKey, ifindex: NonZeroU32) -> io::Result<()> {
        let record = &self.entries[interface.0 as usize].interface;
        for entry in &mut self.captures {
            if entry.interface != interface {
                continue;
            }
            // Only a drain takes a capture out, and the drain never steps.
            if let Some(capture) = &mut entry.capture {
                capture.rebind(record, ifindex)?;
            }
        }
        Ok(())
    }

    pub(super) fn captures_of(&self, interface: InterfaceKey) -> Vec<CaptureKey> {
        self.captures
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.interface == interface)
            .map(|(index, _)| CaptureKey(u32::try_from(index).expect("capture count fits a u32")))
            .collect()
    }

    pub(super) fn capture_watches(&self) -> Vec<(RawFd, u64)> {
        self.captures
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                let key = CaptureKey(u32::try_from(index).expect("capture count fits a u32"));
                entry
                    .capture
                    .as_ref()
                    .map(|capture| (capture.as_raw_fd(), key.to_u64()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use super::*;
    use crate::dispatch::MessageType;
    use crate::dispatch::multicast::join_unsupported;
    use crate::dispatch::multicast::tests::BEST_EFFORT;
    use crate::interface::{LOOPBACK_IFACE, if_index};
    use crate::test_support::{Capability, skip};

    impl InterfaceTable {
        /// Overwrite an entry's presence, standing in for the kernel recreating the interface
        /// out from under the table. For the dispatcher's reconcile tests.
        pub(in crate::dispatch) fn set_test_presence(
            &mut self,
            interface: InterfaceKey,
            presence: Presence,
        ) {
            self.entries[interface.0 as usize].presence = presence;
        }

        pub(in crate::dispatch) fn presence_of(&self, interface: InterfaceKey) -> Presence {
            self.entries[interface.0 as usize].presence
        }

        pub(in crate::dispatch) fn test_memberships_mut(
            &mut self,
            interface: InterfaceKey,
        ) -> &mut Memberships {
            self.entries[interface.0 as usize]
                .memberships
                .as_mut()
                .expect("the table joins groups")
        }

        pub(in crate::dispatch) fn test_memberships(
            &self,
            interface: InterfaceKey,
        ) -> &Memberships {
            self.entries[interface.0 as usize]
                .memberships
                .as_ref()
                .expect("the table joins groups")
        }

        /// Rename an entry out from under its kernel interface, standing in for a vanished
        /// interface (the new name resolves to nothing). For the dispatcher's reconcile tests.
        pub(in crate::dispatch) fn set_test_name(
            &mut self,
            interface: InterfaceKey,
            name: &InterfaceName,
        ) {
            self.entries[interface.0 as usize].interface.name = name.clone();
        }

        /// Push a capture-less entry (no fd) so a routing test can mint a valid [`CaptureKey`] and
        /// exercise the record path without opening a capture; the dangling [`InterfaceKey`] is
        /// never resolved. Reachable from the dispatcher's own tests, hence `pub(in crate::dispatch)`.
        pub(in crate::dispatch) fn add_test_capture(&mut self) -> CaptureKey {
            let key =
                CaptureKey(u32::try_from(self.captures.len()).expect("capture count fits a u32"));
            self.captures.push(CaptureEntry {
                capture: None,
                interface: InterfaceKey(0),
                counters: CaptureCounters::default(),
                sent_packet: 0,
                sent: Vec::new(),
            });
            key
        }

        /// The `(reflected, skipped, dropped, stalled)` count recorded for `ty` on `capture`'s row.
        pub(in crate::dispatch) fn typed_counts(
            &self,
            capture: CaptureKey,
            ty: MessageType,
        ) -> (u64, u64, u64, u64) {
            self.captures[capture.0 as usize].counters.typed(ty)
        }

        /// The recovery count recorded on `capture`'s row, for the dispatcher's reconcile test.
        pub(in crate::dispatch) fn recoveries_of(&self, capture: CaptureKey) -> u64 {
            self.captures[capture.0 as usize].counters.recoveries()
        }

        /// The echo count recorded on `capture`'s row, for the dispatcher's echo-drop test.
        pub(in crate::dispatch) fn echoed_of(&self, capture: CaptureKey) -> u64 {
            self.captures[capture.0 as usize].counters.echoed()
        }

        /// Overwrite an interface's cached addresses, giving a routing test's ingress a known MAC
        /// without a real link. For the dispatcher's echo-drop test.
        pub(in crate::dispatch) fn set_test_addrs(
            &mut self,
            interface: InterfaceKey,
            addrs: InterfaceAddresses,
        ) {
            self.entries[interface.0 as usize].interface.addrs = addrs;
        }
    }

    impl Unbound {
        pub(in crate::dispatch) fn test_due(ifindex: NonZeroU32, next_try: Instant) -> Self {
            Self {
                ifindex,
                attempts: 0,
                next_try,
            }
        }
    }

    #[test]
    fn was_sent_remembers_every_datagram_of_the_packet_being_routed() {
        let mut table = InterfaceTable::new();
        let egress = table.add_test_capture();
        let other = table.add_test_capture();
        // Nothing recorded yet: a failed send leaves it that way, so a retry goes out.
        assert!(!table.was_sent(egress, 1, 0xf1));
        table.record_sent(egress, 1, 0xf1);
        table.record_sent(egress, 1, 0xf2);
        assert!(table.was_sent(egress, 1, 0xf1));
        assert!(table.was_sent(egress, 1, 0xf2));
        // Another egress, another digest, or the next packet: not a sent datagram.
        assert!(!table.was_sent(other, 1, 0xf1));
        assert!(!table.was_sent(egress, 1, 0xf3));
        assert!(!table.was_sent(egress, 2, 0xf1));
        // The next packet's first datagram clears the previous packet's.
        table.record_sent(egress, 2, 0xf3);
        assert!(table.was_sent(egress, 2, 0xf3));
        assert!(!table.was_sent(egress, 1, 0xf1));
        assert!(!table.was_sent(CaptureKey::from_u64(999), 2, 0xf3));
        table.record_sent(CaptureKey::from_u64(999), 2, 0xf3); // an unknown key is a no-op
    }

    fn loopback_index() -> NonZeroU32 {
        if_index(&InterfaceName::loopback()).expect("loopback has an ifindex")
    }

    fn rename(table: &mut InterfaceTable, interface: InterfaceKey, name: &str) {
        table.entries[interface.0 as usize].interface.name = name.parse().unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn an_absent_name_is_not_found_at_startup() {
        let mut table = InterfaceTable::new();
        let err = table
            .find_or_add_interface(&"nf-gone0".parse().unwrap())
            .expect_err("no interface bears the name");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn key_by_ifindex_finds_only_a_bound_interface() -> io::Result<()> {
        let mut table = InterfaceTable::new();
        let key = table.find_or_add_interface(&InterfaceName::loopback())?;
        assert_eq!(table.key_by_ifindex(loopback_index()), Some(key));
        assert_eq!(table.key_by_ifindex(NonZeroU32::MAX), None);
        let change = table.refresh(key)?;
        assert!(
            !change.v4,
            "re-resolving the unchanged loopback reports no v4 move, the bit the DIAL eviction gates on",
        );
        rename(&mut table, key, "nf-gone0");
        table.step(key, Instant::now());
        assert_eq!(table.key_by_ifindex(loopback_index()), None);
        Ok(())
    }

    // A parked interface is not re-read: on the BSDs a read by name would adopt the addresses of
    // an interface returning under it before its captures re-bind.
    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn refresh_all_reads_only_bound_interfaces() -> io::Result<()> {
        let mut table = InterfaceTable::new();
        let parked = table.find_or_add_interface(&InterfaceName::loopback())?;
        rename(&mut table, parked, "nf-gone0");
        table.step(parked, Instant::now());
        let bound = table.find_or_add_interface(&InterfaceName::loopback())?;
        let keys: Vec<InterfaceKey> = table
            .refresh_all()
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        assert_eq!(keys, [bound]);
        Ok(())
    }

    const MDNS_GROUPS: [IpAddr; 2] = [
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
        IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)),
    ];

    /// The loopback interface with both mDNS groups joined, or `None` after a skip note: QEMU
    /// user-mode emulation doesn't implement the join.
    fn loopback_joined() -> io::Result<Option<(InterfaceTable, InterfaceKey)>> {
        let mut table = InterfaceTable::new();
        let key = table.find_or_add_interface(&InterfaceName::loopback())?;
        for group in MDNS_GROUPS {
            match table.join_on(key, group, BEST_EFFORT, Instant::now()) {
                Ok(()) => {}
                Err(e) if join_unsupported(&e) => {
                    skip(Capability::Membership, format!("{e:?}"));
                    return Ok(None);
                }
                Err(e) => panic!("kernel must accept the {group} join on loopback: {e:?}"),
            }
        }
        Ok(Some((table, key)))
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn join_on_joins_the_group_on_the_interface() -> io::Result<()> {
        let Some((mut table, key)) = loopback_joined()? else {
            return Ok(());
        };
        assert!(table.test_memberships(key).test_all_joined());
        assert_eq!(table.converge_all(Instant::now()), Ok(()));
        assert_eq!(table.next_join_retry(), None);
        Ok(())
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn a_table_without_group_joins_wants_nothing() -> io::Result<()> {
        let mut table = InterfaceTable::without_group_joins();
        let key = table.find_or_add_interface(&InterfaceName::loopback())?;
        table
            .join_on(key, MDNS_GROUPS[0], BEST_EFFORT, Instant::now())
            .expect("nothing to fail");
        assert!(table.entries[key.0 as usize].memberships.is_none());
        assert_eq!(table.converge_all(Instant::now()), Ok(()));
        Ok(())
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn a_step_leaves_a_bound_interface_alone() -> io::Result<()> {
        let mut table = InterfaceTable::new();
        let key = table.find_or_add_interface(&InterfaceName::loopback())?;
        assert!(matches!(table.step(key, Instant::now()), Step::Kept));
        assert_eq!(table.presence_of(key), Presence::Present(loopback_index()));
        Ok(())
    }

    // Unprivileged: no captures, so the probe half of the check stays vacuous here (pair tests
    // cover it against real interfaces).
    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn a_step_binds_an_interface_whose_index_moved() -> io::Result<()> {
        let mut table = InterfaceTable::new();
        let key = table.find_or_add_interface(&InterfaceName::loopback())?;
        let moved = NonZeroU32::new(loopback_index().get() + 1000).unwrap();
        table.set_test_presence(key, Presence::Present(moved));
        let step = table.step(key, Instant::now());
        assert!(
            matches!(step, Step::Bound { was: Presence::Present(was), ifindex, gone: false }
                if was == moved && ifindex == loopback_index()),
            "{step:?}"
        );
        assert_eq!(table.presence_of(key), Presence::Present(loopback_index()));
        Ok(())
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn a_step_parks_a_vanished_interface_and_drops_what_it_held() -> io::Result<()> {
        let Some((mut table, key)) = loopback_joined()? else {
            return Ok(());
        };
        rename(&mut table, key, "nf-gone0");
        let now = Instant::now();
        let step = table.step(key, now);
        assert!(
            matches!(step, Step::Parked { was: Some(was) } if was == loopback_index()),
            "{step:?}"
        );
        assert_eq!(table.presence_of(key), Presence::Parked);
        assert!(table.any_parked());
        assert!(
            table.entries[key.0 as usize].interface.addrs.v4().is_none(),
            "a parked entry's addresses clear, closing the egress gate"
        );
        assert!(table.test_memberships(key).test_socketless());
        assert!(
            matches!(table.step(key, now), Step::Kept),
            "a parked interface whose name still resolves to nothing stays quiet"
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn a_parked_interface_joins_nothing() -> io::Result<()> {
        let Some((mut table, key)) = loopback_joined()? else {
            return Ok(());
        };
        rename(&mut table, key, "nf-gone0");
        let now = Instant::now();
        table.step(key, now);
        table.refresh_all();
        assert_eq!(table.converge_all(now), Ok(()));
        assert_eq!(table.converge(key, now), Ok(()));
        table
            .join_on(
                key,
                IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)),
                BEST_EFFORT,
                now,
            )
            .expect("wanted for the return");
        assert!(table.test_memberships(key).test_socketless());
        Ok(())
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn a_returned_interface_binds_and_joins_its_groups() -> io::Result<()> {
        let Some((mut table, key)) = loopback_joined()? else {
            return Ok(());
        };
        rename(&mut table, key, "nf-gone0");
        let now = Instant::now();
        table.step(key, now);
        rename(&mut table, key, LOOPBACK_IFACE);
        let step = table.step(key, now);
        assert!(
            matches!(
                step,
                Step::Bound {
                    was: Presence::Parked,
                    gone: false,
                    ..
                }
            ),
            "{step:?}"
        );
        assert_eq!(table.presence_of(key), Presence::Present(loopback_index()));
        assert!(table.test_memberships(key).test_all_joined());
        assert!(table.entries[key.0 as usize].interface.addrs.v4().is_some());
        Ok(())
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn a_failed_bind_is_retried_when_due_or_woken() -> io::Result<()> {
        let mut table = InterfaceTable::new();
        let key = table.find_or_add_interface(&InterfaceName::loopback())?;
        let now = Instant::now();
        let due = now + Duration::from_secs(4);
        table.set_test_presence(
            key,
            Presence::Unbound(Unbound {
                ifindex: loopback_index(),
                attempts: 2,
                next_try: due,
            }),
        );
        assert_eq!(table.next_bind_retry(), Some(due));
        assert_eq!(table.key_by_ifindex(loopback_index()), None);
        assert!(matches!(table.step(key, now), Step::Kept), "not due yet");

        assert!(table.wake_unbound(loopback_index(), now));
        assert!(matches!(
            table.step(key, now),
            Step::Bound {
                was: Presence::Unbound(_),
                ..
            }
        ));
        assert_eq!(table.presence_of(key), Presence::Present(loopback_index()));
        assert_eq!(table.next_bind_retry(), None);
        Ok(())
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn an_overflow_makes_every_failed_bind_due() -> io::Result<()> {
        let mut table = InterfaceTable::new();
        let key = table.find_or_add_interface(&InterfaceName::loopback())?;
        let now = Instant::now();
        let later = now + Duration::from_secs(30);
        table.set_test_presence(
            key,
            Presence::Unbound(Unbound::test_due(loopback_index(), later)),
        );
        table.wake_all_unbound(now);
        assert_eq!(table.next_bind_retry(), Some(now));
        Ok(())
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn a_failed_bind_releases_the_interface_and_backs_off() -> io::Result<()> {
        let Some((mut table, key)) = loopback_joined()? else {
            return Ok(());
        };
        let refused = || Err(io::Error::from(io::ErrorKind::Unsupported));
        let ifindex = loopback_index();
        let now = Instant::now();
        let first = table.settle_bind(key, ifindex, Presence::Present(ifindex), refused(), now);
        assert!(
            matches!(first, Step::BindFailed { first: true, retry_in, .. }
                if retry_in == Duration::from_secs(1)),
            "{first:?}"
        );
        let unbound = |attempts, seconds| {
            Presence::Unbound(Unbound {
                ifindex,
                attempts,
                next_try: now + Duration::from_secs(seconds),
            })
        };
        assert_eq!(table.presence_of(key), unbound(0, 1));
        assert!(table.entries[key.0 as usize].interface.addrs.v4().is_none());
        assert!(table.test_memberships(key).test_socketless());
        assert!(matches!(table.step(key, now), Step::Kept), "not due yet");

        let again = table.settle_bind(key, ifindex, unbound(0, 1), refused(), now);
        assert!(
            matches!(again, Step::BindFailed { first: false, retry_in, .. }
                if retry_in == Duration::from_secs(2)),
            "a retry is not reported as a new failure: {again:?}"
        );
        assert_eq!(table.presence_of(key), unbound(1, 2));
        Ok(())
    }

    // Only a retry at the same index waits for its time: a new index is a new interface.
    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn an_unbound_interface_at_a_new_index_binds_at_once() -> io::Result<()> {
        let mut table = InterfaceTable::new();
        let key = table.find_or_add_interface(&InterfaceName::loopback())?;
        let now = Instant::now();
        let failed_at = NonZeroU32::new(loopback_index().get() + 1000).unwrap();
        table.set_test_presence(
            key,
            Presence::Unbound(Unbound::test_due(failed_at, now + Duration::from_secs(30))),
        );
        let step = table.step(key, now);
        assert!(
            matches!(step, Step::Bound { was: Presence::Unbound(_), ifindex, .. }
                if ifindex == loopback_index()),
            "{step:?}"
        );
        Ok(())
    }

    // A recreated interface can be another kind of link: the captures re-bind with the kind the
    // bind read, or a loopback capture stops seeing what the host sends.
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn a_bind_re_binds_the_captures_with_the_link_it_read() -> io::Result<()> {
        use std::os::fd::AsRawFd;

        let _serial = crate::test_support::loopback_lock();
        let mut table = InterfaceTable::new();
        let capture = match table.open_capture(&InterfaceName::loopback()) {
            Ok(capture) => capture,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                skip(Capability::Capture, format_args!("cannot capture ({e})"));
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let key = table.captures[capture.0 as usize].interface;
        table.entries[key.0 as usize].interface.loopback = false;
        let moved = NonZeroU32::new(loopback_index().get() + 1000).unwrap();
        table.set_test_presence(key, Presence::Present(moved));

        let step = table.step(key, Instant::now());
        assert!(matches!(step, Step::Bound { .. }), "{step:?}");
        let fd = table.captures[capture.0 as usize]
            .capture
            .as_ref()
            .expect("the capture is held")
            .as_raw_fd();
        let mut see_sent: libc::c_uint = 0;
        // SAFETY: BIOCGSEESENT writes a `c_uint`.
        let rc = unsafe { libc::ioctl(fd, libc::BIOCGSEESENT, &raw mut see_sent) };
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());
        assert_eq!(see_sent, 1, "re-bound as a loopback");
        Ok(())
    }

    // Reading an interface's addresses again joins nothing by itself.
    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn a_refresh_leaves_the_memberships_alone() -> io::Result<()> {
        let Some((mut table, key)) = loopback_joined()? else {
            return Ok(());
        };
        table.entries[key.0 as usize]
            .memberships
            .as_mut()
            .unwrap()
            .rebase();
        table.refresh(key)?;
        table.refresh_all();
        assert!(table.test_memberships(key).test_socketless());
        Ok(())
    }

    #[test]
    fn captures_of_maps_the_reverse_link() {
        let mut table = InterfaceTable::new();
        let a = table.add_test_capture(); // both link InterfaceKey(0)
        let b = table.add_test_capture();
        assert_eq!(table.captures_of(InterfaceKey(0)), [a, b]);
        assert_eq!(table.captures_of(InterfaceKey(1)), []);
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn find_or_add_interface_dedups_by_name() -> io::Result<()> {
        let mut table = InterfaceTable::new();
        let first = table.find_or_add_interface(&InterfaceName::loopback())?;
        let second = table.find_or_add_interface(&InterfaceName::loopback())?;
        assert_eq!(first, second, "the same name resolves to one interface key");
        Ok(())
    }

    #[test]
    fn capture_accessors_reject_an_out_of_range_key() {
        let mut table = InterfaceTable::new();
        let forged = CaptureKey(0); // nothing added yet
        assert!(!table.contains(forged));
        assert!(table.interface_of(forged).is_none());
        assert!(table.ifindex_of(forged).is_none());
        assert!(table.capture(forged).is_none());
        assert!(table.egress_addrs(forged).is_none());
        assert!(table.take(forged).is_none());
    }
}
