//! Interface address resolution: the source MAC / IPv4 / IPv6 an interface currently has.
//! Read fresh, since a reflector re-emits from them; any may be absent (a loopback /
//! `DLT_NULL` link has no MAC, a link may be single-family). Backends: rtnetlink on Linux,
//! `getifaddrs` plus `SIOCGIFAFLAG_IN6` on the BSDs.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::net::mac::MacAddr;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod getifaddrs;
mod interface_monitor;
#[cfg(target_os = "linux")]
mod rtnetlink;

pub(crate) use self::interface_monitor::{InterfaceEvent, InterfaceMonitor};

/// An interface's current source addresses; any may be absent. The v6 fields stay private so a
/// sender reaches a v6 source only through [`v6`](Self::v6), naming the destination's scope.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct InterfaceAddresses {
    mac: Option<MacAddr>,
    v4: Option<Ipv4Addr>,
    v4_prefix: Option<u8>,
    v6: Option<Ipv6Addr>,
    v6_routable: Option<Ipv6Addr>,
}

impl InterfaceAddresses {
    pub(crate) fn mac(&self) -> Option<MacAddr> {
        self.mac
    }

    pub(crate) fn v4(&self) -> Option<Ipv4Addr> {
        self.v4
    }

    /// The directed broadcast of the v4 subnet; a /31 or /32 has none.
    pub(crate) fn v4_directed_broadcast(&self) -> Option<Ipv4Addr> {
        let (addr, prefix) = (self.v4?, self.v4_prefix?);
        if prefix > 30 {
            return None;
        }
        Some(Ipv4Addr::from(u32::from(addr) | (u32::MAX >> prefix)))
    }

    /// The v6 source for a destination of `dest_scope`, falling back to the other scope's address
    /// when the matching one is absent: a scope mismatch beats dropping the send.
    pub(crate) fn v6(&self, dest_scope: Ipv6Scope) -> Option<Ipv6Addr> {
        match dest_scope {
            Ipv6Scope::LinkLocal => self.v6,
            Ipv6Scope::Routable => self.v6_routable.or(self.v6),
        }
    }

    pub(crate) fn has(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.v4 == Some(v4),
            IpAddr::V6(v6) => self.v6 == Some(v6) || self.v6_routable == Some(v6),
        }
    }

    pub(crate) fn has_v4(&self) -> bool {
        self.v4.is_some()
    }

    /// `v6` is set whenever any usable v6 exists, so this covers both scopes.
    pub(crate) fn has_v6(&self) -> bool {
        self.v6.is_some()
    }
}

impl fmt::Display for InterfaceAddresses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mac ")?;
        match self.mac {
            Some(mac) => write!(f, "{mac}")?,
            None => f.write_str("none")?,
        }
        f.write_str(", v4 ")?;
        match (self.v4, self.v4_prefix) {
            (Some(v4), Some(prefix)) => write!(f, "{v4}/{prefix}")?,
            (Some(v4), None) => write!(f, "{v4}")?,
            (None, _) => f.write_str("none")?,
        }
        f.write_str(", v6 ")?;
        match self.v6 {
            Some(v6) => write!(f, "{v6}")?,
            None => f.write_str("none")?,
        }
        f.write_str(", v6-routable ")?;
        match self.v6_routable {
            Some(v6) => write!(f, "{v6}"),
            None => f.write_str("none"),
        }
    }
}

/// Which source fields a [`refresh`](Interface::refresh) changed, so a caller reacts only to the
/// family it depends on (the DIAL proxies re-mint only when `v4` moves).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct AddressChange {
    pub(crate) mac: bool,
    pub(crate) v4: bool,
    pub(crate) v6: bool,
}

/// An IPv6 destination's scope, coarsened to what source selection needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ipv6Scope {
    LinkLocal,
    /// Anything beyond the link: site-local, ULA or global.
    Routable,
}

impl Ipv6Scope {
    pub(crate) fn of(addr: Ipv6Addr) -> Self {
        if is_multicast_link_local(addr) || addr.is_unicast_link_local() {
            Self::LinkLocal
        } else {
            Self::Routable
        }
    }
}

/// One configured interface. `ifindex` caches what `name` resolves to, the process's only
/// persistent copy of an interface index: when the OS destroys and recreates the interface (a
/// `PPPoE` reconnect, a bridge/VLAN rebuild), the dispatcher's reconcile re-points it (0 while
/// the name resolves to nothing) and re-binds the captures.
pub(crate) struct Interface {
    pub(crate) name: String,
    pub(crate) ifindex: u32,
    pub(crate) addrs: InterfaceAddresses,
    /// Outside [`InterfaceAddresses`] on purpose: that struct's equality drives the refresh
    /// diffing, and a bare MTU change must not read as an address change (which clears sessions).
    pub(crate) mtu: Option<u32>,
}

impl Interface {
    /// `ifindex` is 0 while the name resolves to nothing; no real event carries 0.
    ///
    /// # Errors
    /// Propagates a resolution syscall failure.
    pub(crate) fn open(name: &str) -> io::Result<Self> {
        let mut iface = Self {
            name: name.to_owned(),
            ifindex: if_index(name).unwrap_or(0),
            addrs: InterfaceAddresses::default(),
            mtu: None,
        };
        match iface.ifindex {
            0 => log::debug!("{name}: no kernel ifindex (interface absent)"),
            i => log::debug!("{name}: ifindex {i}"),
        }
        iface.refresh()?;
        Ok(iface)
    }

    /// Re-resolve the addresses in place and report which source fields changed.
    ///
    /// # Errors
    /// Propagates a resolution syscall failure.
    pub(crate) fn refresh(&mut self) -> io::Result<AddressChange> {
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        let (addrs, mtu) = self::getifaddrs::resolve(&self.name)?;
        #[cfg(target_os = "linux")]
        let (addrs, mtu) = self::rtnetlink::resolve(&self.name, self.ifindex)?;
        self.mtu = mtu;
        match mtu {
            Some(mtu) => log::debug!("{}: resolved {addrs}, mtu {mtu}", self.name),
            None => log::debug!("{}: resolved {addrs}, mtu unreadable", self.name),
        }
        // Separate `let`s so both v6 transitions log; `||` would short-circuit the second.
        let v6 = log_field_change(&self.name, "IPv6", self.addrs.v6, addrs.v6);
        let v6_routable = log_field_change(
            &self.name,
            "IPv6 routable",
            self.addrs.v6_routable,
            addrs.v6_routable,
        );
        let change = AddressChange {
            mac: log_field_change(&self.name, "MAC", self.addrs.mac, addrs.mac),
            v4: log_field_change(&self.name, "IPv4", self.addrs.v4, addrs.v4),
            v6: v6 || v6_routable,
        };
        self.addrs = addrs;
        Ok(change)
    }
}

/// `None` if `name` names no interface or the lookup itself failed. A caller that acts
/// destructively on absence wants [`if_index_checked`] instead.
pub(crate) fn if_index(name: &str) -> Option<u32> {
    if_index_checked(name).ok().flatten()
}

/// Tells "no such interface" apart from a lookup that could not run: glibc and musl open a
/// socket inside `if_nametoindex`, so under fd pressure it reports 0 for a live interface.
///
/// # Errors
/// Only the resource errnos. Anything else still reads as absent, so an unlisted errno can't
/// mask a removed interface.
pub(crate) fn if_index_checked(name: &str) -> io::Result<Option<u32>> {
    let Ok(cname) = std::ffi::CString::new(name) else {
        return Ok(None); // an interior NUL names no interface
    };
    // SAFETY: `cname` is a valid NUL-terminated C string for the call's duration.
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if index != 0 {
        return Ok(Some(index));
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::ENOBUFS) => Err(err),
        _ => Ok(None),
    }
}

#[cfg(target_os = "freebsd")]
pub(crate) fn if_name(index: u32) -> Option<String> {
    let mut buf = [0u8; libc::IF_NAMESIZE];
    // SAFETY: `buf` is IF_NAMESIZE bytes, the size `if_indextoname` documents it writes into; it
    // returns NULL on failure without writing.
    let name = unsafe { libc::if_indextoname(index, buf.as_mut_ptr().cast()) };
    if name.is_null() {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end]).ok().map(str::to_owned)
}

/// Logged at `info`: the address-change e2e greps these lines. Returns whether the field changed.
fn log_field_change<A: PartialEq + fmt::Display>(
    iface: &str,
    family: &str,
    old: Option<A>,
    new: Option<A>,
) -> bool {
    match (old, new) {
        (None, Some(now)) => log::info!("interface {iface}: gained {family} {now}"),
        (Some(was), None) => log::info!("interface {iface}: lost {family} (was {was})"),
        (Some(was), Some(now)) if was != now => {
            log::info!("interface {iface}: {family} changed {was} -> {now}");
        }
        _ => return false,
    }
    true
}

/// Worst to best; the derived `Ord` follows declaration order. Link-local is preferred because
/// netflector reflects link-local service traffic.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Debug)]
enum V6Rank {
    #[default]
    NotASource,
    Global,
    UniqueLocal,
    LinkLocal,
}

fn v6_rank(addr: Ipv6Addr) -> V6Rank {
    if addr.is_multicast() || addr.is_unspecified() || addr.is_loopback() {
        V6Rank::NotASource
    } else if addr.is_unicast_link_local() {
        V6Rank::LinkLocal // fe80::/10
    } else if addr.is_unique_local() {
        V6Rank::UniqueLocal // fc00::/7
    } else {
        V6Rank::Global
    }
}

/// `Ipv6Addr::multicast_scope` is unstable (feature `ip`). The `is_multicast` check is not
/// redundant: the scope nibble alone also matches unicasts like `fd02::` or `2012::`.
fn is_multicast_link_local(addr: Ipv6Addr) -> bool {
    addr.is_multicast() && (addr.octets()[1] & 0x0f) == 0x02
}

/// Picks the best-overall v6 source (link-local preferred) and the best non-link-local one while
/// a backend scans an interface's usable addresses.
#[derive(Default)]
pub(super) struct V6Pick {
    best_rank: V6Rank,
    best_routable_rank: V6Rank,
}

impl V6Pick {
    pub(super) fn consider(&mut self, addrs: &mut InterfaceAddresses, addr: Ipv6Addr) {
        let rank = v6_rank(addr);
        if rank == V6Rank::NotASource {
            return;
        }
        if addrs.v6.is_none() || rank > self.best_rank {
            addrs.v6 = Some(addr);
            self.best_rank = rank;
        }
        if rank < V6Rank::LinkLocal
            && (addrs.v6_routable.is_none() || rank > self.best_routable_rank)
        {
            addrs.v6_routable = Some(addr);
            self.best_routable_rank = rank;
        }
    }
}

// `any(macos, freebsd)` rather than `not(linux)`: an unhandled target must fail to compile.
#[cfg(all(test, target_os = "linux"))]
pub(crate) const LOOPBACK_IFACE: &str = "lo";
#[cfg(all(test, any(target_os = "macos", target_os = "freebsd")))]
pub(crate) const LOOPBACK_IFACE: &str = "lo0";

#[cfg(test)]
mod tests {
    use super::*;

    impl InterfaceAddresses {
        /// Construct a record directly, for tests in other modules (the fields are private, so they
        /// can't use a struct literal). Production builds these through the platform resolvers.
        pub(crate) fn new(
            mac: Option<MacAddr>,
            v4: Option<Ipv4Addr>,
            v6: Option<Ipv6Addr>,
            v6_routable: Option<Ipv6Addr>,
        ) -> Self {
            Self {
                mac,
                v4,
                v4_prefix: None,
                v6,
                v6_routable,
            }
        }

        /// The record with its v4 prefix length set.
        pub(crate) fn with_v4_prefix(mut self, prefix: u8) -> Self {
            self.v4_prefix = Some(prefix);
            self
        }
    }

    #[test]
    fn v4_broadcast_needs_a_prefix_short_enough_for_one() {
        let base = InterfaceAddresses::new(None, Some(Ipv4Addr::new(192, 0, 2, 2)), None, None);
        assert_eq!(
            base.v4_directed_broadcast(),
            None,
            "no prefix, no broadcast"
        );
        assert_eq!(
            base.with_v4_prefix(24).v4_directed_broadcast(),
            Some(Ipv4Addr::new(192, 0, 2, 255))
        );
        assert_eq!(
            base.with_v4_prefix(30).v4_directed_broadcast(),
            Some(Ipv4Addr::new(192, 0, 2, 3))
        );
        assert_eq!(
            base.with_v4_prefix(0).v4_directed_broadcast(),
            Some(Ipv4Addr::BROADCAST)
        );
        // Point-to-point prefixes have no directed broadcast.
        assert_eq!(base.with_v4_prefix(31).v4_directed_broadcast(), None);
        assert_eq!(base.with_v4_prefix(32).v4_directed_broadcast(), None);
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn resolves_loopback_v4() {
        // Every host's loopback has 127.0.0.1; resolution needs no privileges, so this
        // exercises the full backend (the v4 path, and on Linux the rtnetlink round-trip).
        let addrs = Interface::open(LOOPBACK_IFACE).unwrap().addrs;
        assert_eq!(addrs.v4, Some(Ipv4Addr::LOCALHOST));
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn refresh_reports_which_source_fields_changed() {
        let mut iface = Interface::open(LOOPBACK_IFACE).unwrap();
        // Re-resolving an interface whose addresses are already current reports nothing moved.
        assert_eq!(iface.refresh().unwrap(), AddressChange::default());
        // With a stale v4 cached, the next resolve (back to the real 127.0.0.1) reports a v4 move, and
        // only v4. This is the flag the DIAL eviction gates on.
        iface.addrs.v4 = Some(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(
            iface.refresh().unwrap(),
            AddressChange {
                v4: true,
                ..AddressChange::default()
            },
        );
        // A stale v6 is reported independently of v4, so a routine v6 rotation can't masquerade as the
        // v4 change that would evict a DIAL proxy.
        iface.addrs.v6 = Some("2001:db8::1".parse().unwrap());
        let change = iface.refresh().unwrap();
        assert!(change.v6, "the differing v6 is reported");
        assert!(!change.v4, "but it does not look like a v4 change");
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn unknown_interface_has_no_addresses() {
        let addrs = Interface::open("nonexistent-xyz-999").unwrap().addrs;
        assert_eq!(addrs, InterfaceAddresses::default());
    }

    #[test]
    fn v6_rank_orders_link_local_above_ula_above_global() {
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        let ula: Ipv6Addr = "fc00::1".parse().unwrap();
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(v6_rank(ll) > v6_rank(ula));
        assert!(v6_rank(ula) > v6_rank(global));
        assert!(v6_rank(global) > v6_rank(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn ipv6_scope_of_reads_multicast_and_unicast() {
        // Link-local-scoped multicast (ff02::) and link-local unicast (fe80::) are LinkLocal; the
        // site-local SSDP group (ff05::) and a global address are wider (Routable).
        assert_eq!(
            Ipv6Scope::of("ff02::c".parse().unwrap()),
            Ipv6Scope::LinkLocal
        );
        assert_eq!(
            Ipv6Scope::of("fe80::1".parse().unwrap()),
            Ipv6Scope::LinkLocal
        );
        assert_eq!(
            Ipv6Scope::of("ff05::c".parse().unwrap()),
            Ipv6Scope::Routable
        );
        assert_eq!(
            Ipv6Scope::of("2001:db8::1".parse().unwrap()),
            Ipv6Scope::Routable
        );
        // A ULA whose second byte's low nibble is 2 (fd02::) must not be mistaken for a link-local
        // multicast group; the `is_multicast` half of is_multicast_link_local guards exactly this.
        assert_eq!(
            Ipv6Scope::of("fd02::1".parse().unwrap()),
            Ipv6Scope::Routable
        );
    }

    #[test]
    fn v6_picks_by_scope_and_falls_back() {
        let both = InterfaceAddresses {
            v6: Some("fe80::1".parse().unwrap()),
            v6_routable: Some("2001:db8::1".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(both.v6(Ipv6Scope::LinkLocal), both.v6);
        assert_eq!(both.v6(Ipv6Scope::Routable), both.v6_routable);
        // No routable address: a wider destination falls back to the link-local one (prior behavior).
        let link_only = InterfaceAddresses {
            v6: Some("fe80::1".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(link_only.v6(Ipv6Scope::Routable), link_only.v6);
        // No v6 at all: nothing to source.
        assert_eq!(InterfaceAddresses::default().v6(Ipv6Scope::Routable), None);
    }

    #[test]
    fn v6_pick_tracks_best_overall_and_best_routable() {
        let mut addrs = InterfaceAddresses::default();
        let mut pick = V6Pick::default();
        pick.consider(&mut addrs, "2001:db8::1".parse().unwrap()); // global
        pick.consider(&mut addrs, "fc00::1".parse().unwrap()); // ULA, outranks global
        pick.consider(&mut addrs, "fe80::1".parse().unwrap()); // link-local, best overall
        assert_eq!(
            addrs.v6,
            Some("fe80::1".parse::<Ipv6Addr>().unwrap()),
            "best overall is the link-local"
        );
        assert_eq!(
            addrs.v6_routable,
            Some("fc00::1".parse::<Ipv6Addr>().unwrap()),
            "best non-link-local is the ULA"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real if_nametoindex")]
    fn a_name_that_resolves_to_nothing_is_absent_not_an_error() {
        assert!(matches!(
            if_index_checked(LOOPBACK_IFACE),
            Ok(Some(index)) if index != 0
        ));
        // The two ways a name can fail to be one: no such interface, and an interior NUL that
        // can't reach the C call at all. Neither is a lookup failure.
        assert!(matches!(if_index_checked("nf-no-such-iface"), Ok(None)));
        assert!(matches!(if_index_checked("lo\0extra"), Ok(None)));
    }

    // Opt-in diagnostic: trace-log every address (and each v6's flag status) the resolver
    // finds on a real interface. Run with, e.g.:
    //   NETFLECTOR_TEST_IFACE=en0 cargo test -- --nocapture resolve_traces_test_interface
    #[test]
    fn resolve_traces_test_interface() {
        let Some(iface) = std::env::var_os("NETFLECTOR_TEST_IFACE") else {
            eprintln!("skip: set NETFLECTOR_TEST_IFACE to inspect an interface");
            return;
        };
        let iface = iface.to_string_lossy();
        crate::logging::init();
        crate::logging::set_level(crate::config::LogLevel::Trace);
        let addrs = Interface::open(&iface).expect("open failed").addrs;
        eprintln!("resolved {iface}: {addrs}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn resolves_loopback_mtu() {
        // The loopback MTU is a stable per-OS constant, so pin it exactly: this doubles as the
        // layout canary for the `if_data` read (a wrong field offset yields a counter or zero,
        // never this value). No privileges are needed on any OS.
        #[cfg(target_os = "linux")]
        const LOOPBACK_MTU: u32 = 65536;
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        const LOOPBACK_MTU: u32 = 16384;
        let mtu = Interface::open(LOOPBACK_IFACE)
            .unwrap()
            .mtu
            .expect("loopback has an MTU");
        assert_eq!(mtu, LOOPBACK_MTU);
    }
}
