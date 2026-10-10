//! The dispatcher's interface table: every interface with its group memberships, and every
//! capture linked to its interface, all addressed by `Copy` index keys.

use std::io;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, RawFd};
use std::time::Instant;

use crate::capture::Capture;
use crate::interface::{
    AddressChange, Interface, InterfaceAddresses, InterfaceName, if_index_checked,
};

use super::CaptureKey;
use super::counters::{CaptureCounters, Outcome};
use super::multicast::{Gone, JoinError, Memberships, Target, Wanted};

/// A `Copy` index into the table's interface entries; insert-only, so stable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct InterfaceKey(u32);

/// A stale entry from [`stale_interfaces`](InterfaceTable::stale_interfaces).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct StaleInterface {
    pub(super) key: InterfaceKey,
    /// The cached identity; 0 while parked absent.
    pub(super) cached: u32,
    /// What the name resolves to now; 0 for nothing.
    pub(super) cur: u32,
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
    /// `None`: `--no-join`.
    memberships: Option<Memberships>,
}

impl InterfaceEntry {
    /// `None` while parked absent, or with `--no-join`.
    fn join_target(&mut self) -> Option<(&mut Memberships, Target<'_>)> {
        let ifindex = NonZeroU32::new(self.interface.ifindex)?;
        let target = Target {
            name: &self.interface.name,
            ifindex,
        };
        Some((self.memberships.as_mut()?, target))
    }

    /// See [`Memberships::converge`].
    fn converge(&mut self, now: Instant) -> Result<(), Gone> {
        self.join_target().map_or(Ok(()), |(memberships, target)| {
            memberships.converge(target, now)
        })
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

    /// Startup-only.
    fn add_interface(&mut self, interface: Interface) -> InterfaceKey {
        let key =
            InterfaceKey(u32::try_from(self.entries.len()).expect("interface count fits a u32"));
        let memberships = self.join_groups.then(Memberships::new);
        self.entries.push(InterfaceEntry {
            interface,
            memberships,
        });
        key
    }

    /// Want `group` on `interface` and join it. A parked interface joins it when it returns.
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
        if let Some((memberships, target)) = entry.join_target() {
            memberships.join(group, wanted, target, now)
        } else {
            if let Some(memberships) = &mut entry.memberships {
                memberships.add(group, wanted);
            }
            Ok(())
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

    /// [`converge`](Self::converge) for the interface at kernel index `ifindex`, never 0.
    ///
    /// # Errors
    /// See [`Memberships::converge`].
    pub(super) fn converge_by_ifindex(&mut self, ifindex: u32, now: Instant) -> Result<(), Gone> {
        self.entries
            .iter_mut()
            .find(|entry| entry.interface.ifindex == ifindex)
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

    /// # Errors
    /// A resolution syscall failure when first opening the interface.
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
        Ok(self.add_interface(Interface::open(name)?))
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
    /// A resolution syscall failure, or the capture failing to open.
    pub(super) fn open_capture(&mut self, name: &InterfaceName) -> io::Result<CaptureKey> {
        let interface = self.find_or_add_interface(name)?;
        let capture = Capture::open(&self.entries[interface.0 as usize].interface)?;
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

    /// 0 while the interface is parked absent.
    pub(super) fn ifindex_of(&self, capture: CaptureKey) -> Option<u32> {
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

    pub(super) fn interface_index(&self, interface: InterfaceKey) -> Option<u32> {
        self.entries
            .get(interface.0 as usize)
            .map(|entry| entry.interface.ifindex)
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

    pub(super) fn record_recovery(&mut self, capture: CaptureKey) {
        self.captures[capture.0 as usize].counters.record_recovery();
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

    /// Re-resolve the interface at kernel index `ifindex` in place; `None` for one we don't
    /// watch. `ifindex` is never 0 here: both monitor backends drop index-0 notifications, and
    /// an overflow goes to [`refresh_all`](Self::refresh_all). A 0 would match the first parked
    /// entry.
    ///
    /// # Errors
    /// A resolution syscall failure.
    pub(super) fn refresh_by_ifindex(&mut self, ifindex: u32) -> io::Result<Option<AddressChange>> {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.interface.ifindex == ifindex)
        else {
            return Ok(None);
        };
        entry.interface.refresh().map(Some)
    }

    /// Every interface whose kernel identity no longer matches the cache: the identity moved
    /// (caught by the name lookup), or a capture's binding died behind an unchanged identity
    /// (an index reused by the recreation, caught by the
    /// [`attached`](crate::capture::Capture::attached) probe). A parked entry (cached 0, name
    /// still resolving to nothing) is quiescent, not stale.
    pub(super) fn stale_interfaces(&self) -> Vec<StaleInterface> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                let key = InterfaceKey(u32::try_from(index).expect("interface count fits a u32"));
                let cached = entry.interface.ifindex;
                // A failed lookup says nothing; reading it as 0 would park a healthy entry.
                // Skip until the next tick.
                let cur = if_index_checked(&entry.interface.name).ok()?.unwrap_or(0);
                let dead_capture = |c: &CaptureEntry| {
                    c.interface == key && c.capture.as_ref().is_some_and(|cap| !cap.attached(cur))
                };
                (cur != cached || (cur != 0 && self.captures.iter().any(dead_capture)))
                    .then_some(StaleInterface { key, cached, cur })
            })
            .collect()
    }

    /// Whether every capture on the interface at `ifindex` is still attached (vacuously true
    /// with no match): catches an index reused by a recreation as its first events arrive.
    pub(super) fn probe_by_ifindex(&self, ifindex: u32) -> bool {
        let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.interface.ifindex == ifindex)
        else {
            return true;
        };
        let key = InterfaceKey(u32::try_from(index).expect("interface count fits a u32"));
        self.captures.iter().all(|entry| {
            entry.interface != key
                || entry
                    .capture
                    .as_ref()
                    .is_none_or(|capture| capture.attached(ifindex))
        })
    }

    /// Whether any interface is parked absent (ifindex 0).
    pub(super) fn any_absent(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.interface.ifindex == 0)
    }

    /// Re-point interface `key` at kernel index `cur` (0 = parked absent), re-resolve its
    /// addresses and drop its memberships with their sockets. The refresh still runs while
    /// absent, so the addresses clear and the egress gate closes. The ifindex is written first:
    /// the Linux resolver keys its dumps by it. The captures re-bind
    /// ([`rebind_capture`](Self::rebind_capture)) and the groups join again
    /// ([`converge`](Self::converge)) separately, in that order: the captures' probe then
    /// vouches for the interface the groups joined on.
    ///
    /// # Errors
    /// A resolution syscall failure. The identity is rolled back so the entry stays visibly
    /// stale and the retry re-runs the rebuild; committed, it would scan as healthy while
    /// carrying the old interface's addresses.
    pub(super) fn rebind_interface(&mut self, key: InterfaceKey, cur: u32) -> io::Result<()> {
        // Keys come from this table's own scan, so the index is in range.
        let entry = &mut self.entries[key.0 as usize];
        let previous = entry.interface.ifindex;
        entry.interface.ifindex = cur;
        if let Some(memberships) = &mut entry.memberships {
            memberships.rebase();
        }
        let refreshed = entry.interface.refresh();
        if refreshed.is_err() {
            entry.interface.ifindex = previous;
        }
        refreshed.map(|_| ())
    }

    pub(super) fn captures_of(&self, interface: InterfaceKey) -> Vec<CaptureKey> {
        self.captures
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.interface == interface)
            .map(|(index, _)| CaptureKey(u32::try_from(index).expect("capture count fits a u32")))
            .collect()
    }

    pub(super) fn captures_at_ifindex(&self, ifindex: u32) -> Vec<CaptureKey> {
        match self
            .entries
            .iter()
            .position(|entry| entry.interface.ifindex == ifindex)
        {
            Some(index) => self.captures_of(InterfaceKey(
                u32::try_from(index).expect("interface count fits a u32"),
            )),
            None => Vec::new(),
        }
    }

    /// Re-bind the capture behind `key` in place: same fd, same slot, so held keys and the
    /// reactor's watch stay valid. `Ok(false)`: no capture in the slot. A failed re-bind retries
    /// when the `attached` probe re-flags the entry.
    ///
    /// # Errors
    /// The re-bind syscall failure.
    pub(super) fn rebind_capture(&mut self, key: CaptureKey) -> io::Result<bool> {
        match self.captures.get_mut(key.0 as usize) {
            Some(CaptureEntry {
                capture: Some(capture),
                interface,
                ..
            }) => capture
                .rebind(&self.entries[interface.0 as usize].interface)
                .map(|()| true),
            _ => Ok(false),
        }
    }

    /// Re-resolve every interface in place (an overflow, the periodic re-read); a per-interface
    /// failure is returned, not fatal.
    pub(super) fn refresh_all(&mut self) -> Vec<(u32, io::Result<AddressChange>)> {
        self.entries
            .iter_mut()
            .map(|entry| (entry.interface.ifindex, entry.interface.refresh()))
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

    use super::*;
    use crate::dispatch::MessageType;
    use crate::dispatch::multicast::join_unsupported;
    use crate::dispatch::multicast::tests::BEST_EFFORT;
    use crate::interface::if_index;
    use crate::test_support::{Capability, skip};

    impl InterfaceTable {
        /// Overwrite an entry's cached identity, standing in for the kernel recreating the
        /// interface out from under the table. For the dispatcher's reconcile tests.
        pub(in crate::dispatch) fn set_test_ifindex(
            &mut self,
            interface: InterfaceKey,
            ifindex: u32,
        ) {
            self.entries[interface.0 as usize].interface.ifindex = ifindex;
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

    // refresh_by_ifindex re-resolves only the interface(s) with the matching kernel index, reporting
    // the changed fields (`None` for an unwatched index). Resolution is unprivileged (no capture
    // needed), so this exercises the monitor's refresh path without CAP_NET_RAW.
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

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn refresh_by_ifindex_targets_the_matching_interface() -> io::Result<()> {
        let mut table = InterfaceTable::new();
        table.find_or_add_interface(&InterfaceName::loopback())?;
        let ifindex = if_index(&InterfaceName::loopback()).expect("loopback has an ifindex");
        let change = table
            .refresh_by_ifindex(ifindex)?
            .expect("the loopback interface matches its ifindex and re-resolves");
        assert!(
            !change.v4,
            "re-resolving the unchanged loopback reports no v4 move, the bit the DIAL eviction gates on",
        );
        assert!(
            table.refresh_by_ifindex(u32::MAX)?.is_none(),
            "an ifindex we don't watch should refresh nothing",
        );
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

    // stale_interfaces flags an entry whose cached index no longer matches its name's, and
    // rebind_interface repairs it. Unprivileged: pure resolution, no captures, so the probe
    // half of the predicate stays vacuous here (pair tests cover it against real interfaces).
    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn stale_interfaces_flags_and_rebind_repairs_a_moved_index() -> io::Result<()> {
        let mut table = InterfaceTable::new();
        let key = table.find_or_add_interface(&InterfaceName::loopback())?;
        assert!(
            table.stale_interfaces().is_empty(),
            "a fresh entry is healthy"
        );
        let real = if_index(&InterfaceName::loopback()).expect("loopback has an ifindex");
        // Simulate a recreation: the kernel identity moved while the cache kept the old index.
        table.entries[key.0 as usize].interface.ifindex = real + 1000;
        assert_eq!(
            table.stale_interfaces(),
            [StaleInterface {
                key,
                cached: real + 1000,
                cur: real
            }]
        );
        table.rebind_interface(key, real)?;
        assert!(
            table.stale_interfaces().is_empty(),
            "the rebuild repaired the identity"
        );
        assert_eq!(table.entries[key.0 as usize].interface.ifindex, real);
        Ok(())
    }

    // An entry whose name no longer resolves reports absent (0); rebinding to 0 parks it:
    // identity 0, addresses cleared (the egress gate closes), no join attempted (a join on
    // index 0 would let the kernel pick an arbitrary interface).
    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn rebind_to_absent_parks_the_entry() -> io::Result<()> {
        let mut table = InterfaceTable::new();
        let key = table.find_or_add_interface(&InterfaceName::loopback())?;
        table.entries[key.0 as usize].interface.name = "nf-gone0".parse().unwrap();
        let real = if_index(&InterfaceName::loopback()).expect("loopback has an ifindex");
        assert_eq!(
            table.stale_interfaces(),
            [StaleInterface {
                key,
                cached: real,
                cur: 0
            }]
        );
        table.rebind_interface(key, 0)?;
        assert!(
            table.entries[key.0 as usize].interface.addrs.v4().is_none(),
            "a parked entry's addresses clear, closing the egress gate"
        );
        assert!(
            table.stale_interfaces().is_empty(),
            "a parked entry matches its (absent) identity"
        );
        Ok(())
    }

    // A join on index 0 would let the kernel pick an arbitrary interface.
    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn a_parked_interface_joins_nothing() -> io::Result<()> {
        let Some((mut table, key)) = loopback_joined()? else {
            return Ok(());
        };
        table.entries[key.0 as usize].interface.name = "nf-gone0".parse().unwrap();
        table.rebind_interface(key, 0)?;
        assert!(table.test_memberships(key).test_socketless());

        let now = Instant::now();
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

    // The rebuild drops the memberships with their sockets, and the converge after the captures
    // re-bind joins every group again.
    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn a_rebuilt_interface_joins_its_groups_at_the_next_converge() -> io::Result<()> {
        let Some((mut table, key)) = loopback_joined()? else {
            return Ok(());
        };
        let ifindex = table.entries[key.0 as usize].interface.ifindex;
        table.rebind_interface(key, ifindex)?;
        assert!(table.test_memberships(key).test_socketless());
        assert!(!table.test_memberships(key).test_all_joined());

        assert_eq!(table.converge_by_ifindex(ifindex, Instant::now()), Ok(()));
        assert!(table.test_memberships(key).test_all_joined());
        Ok(())
    }

    // Reading an interface's addresses again joins nothing by itself.
    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn a_refresh_leaves_the_memberships_alone() -> io::Result<()> {
        let Some((mut table, key)) = loopback_joined()? else {
            return Ok(());
        };
        let ifindex = table.entries[key.0 as usize].interface.ifindex;
        table.rebind_interface(key, ifindex)?;
        table.refresh_by_ifindex(ifindex)?;
        table.refresh_all();
        assert!(table.test_memberships(key).test_socketless());
        Ok(())
    }

    #[test]
    fn captures_of_maps_the_reverse_link_and_empty_slots_rebind_as_noops() {
        let mut table = InterfaceTable::new();
        let a = table.add_test_capture(); // both link InterfaceKey(0)
        let b = table.add_test_capture();
        assert_eq!(table.captures_of(InterfaceKey(0)), [a, b]);
        assert_eq!(table.captures_of(InterfaceKey(1)), []);
        // Capture-less slots (drained, or test entries with no fd) and out-of-range keys
        // report Ok(false) -- a signal for the caller to log, not an error and not a success.
        assert!(matches!(table.rebind_capture(a), Ok(false)));
        assert!(matches!(table.rebind_capture(CaptureKey(99)), Ok(false)));
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
