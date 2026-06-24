//! Interface address resolution: the source MAC / IPv4 / IPv6 an interface currently has.
//! A reflector re-emits from these, so they must be read fresh (the address monitor keeps
//! them current). Any may be absent — a loopback / `DLT_NULL` link has no MAC, and a link
//! may be v4-only or v6-only.
//!
//! One backend per platform behind a uniform [`resolve`]: pure netlink on Linux (one
//! `RTM_GETADDR` dump for the addresses, one `RTM_GETLINK` for the MAC), `getifaddrs`
//! plus `SIOCGIFAFLAG_IN6` on the BSDs. Each yields the same [`InterfaceAddresses`].

use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::net::mac::MacAddr;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod getifaddrs;
#[cfg(target_os = "linux")]
mod netlink;

/// Resolve an interface's current source addresses via the platform backend. An unknown
/// interface yields an all-absent [`InterfaceAddresses`], not an error. The backend logs
/// each address it finds (and every v6's flag status) at `trace`.
///
/// # Errors
/// Returns an error if a resolution syscall fails.
pub(crate) fn resolve(if_name: &str) -> io::Result<InterfaceAddresses> {
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    let addrs = self::getifaddrs::resolve(if_name)?;
    #[cfg(target_os = "linux")]
    let addrs = self::netlink::resolve(if_name)?;
    log::debug!("{if_name}: resolved {addrs}");
    Ok(addrs)
}

/// An interface's current source addresses; any may be absent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct InterfaceAddresses {
    pub(crate) mac: Option<MacAddr>,
    pub(crate) v4: Option<Ipv4Addr>,
    pub(crate) v6: Option<Ipv6Addr>,
}

impl fmt::Display for InterfaceAddresses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mac ")?;
        match self.mac {
            Some(mac) => write!(f, "{mac}")?,
            None => f.write_str("none")?,
        }
        f.write_str(", v4 ")?;
        match self.v4 {
            Some(v4) => write!(f, "{v4}")?,
            None => f.write_str("none")?,
        }
        f.write_str(", v6 ")?;
        match self.v6 {
            Some(v6) => write!(f, "{v6}"),
            None => f.write_str("none"),
        }
    }
}

/// One configured interface: its name (kept for re-resolution) and current source
/// addresses. Built by [`open`](Self::open); the address monitor later refreshes `addrs`
/// in place.
pub(crate) struct Interface {
    pub(crate) name: String,
    pub(crate) addrs: InterfaceAddresses,
}

impl Interface {
    /// Build an interface record, resolving `name`'s current source addresses.
    ///
    /// # Errors
    /// Propagates a resolution syscall failure; an unknown interface yields all-absent
    /// addresses (not an error).
    pub(crate) fn open(name: &str) -> io::Result<Self> {
        Ok(Self {
            name: name.to_owned(),
            addrs: resolve(name)?,
        })
    }
}

/// Rank an IPv6 source candidate: link-local > ULA > global > other. The reflector relays
/// link-local service traffic, so a link-local source is preferred; a global address is
/// the fallback when no link-local is usable.
fn v6_rank(addr: Ipv6Addr) -> u8 {
    let o = addr.octets();
    if o[0] == 0xff || addr.is_unspecified() || addr.is_loopback() {
        0 // multicast / :: / ::1 — never a real source
    } else if o[0] == 0xfe && (o[1] & 0xc0) == 0x80 {
        3 // link-local fe80::/10
    } else if (o[0] & 0xfe) == 0xfc {
        2 // unique local fc00::/7
    } else {
        1 // global / other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    const LOOPBACK: &str = "lo";
    #[cfg(not(target_os = "linux"))]
    const LOOPBACK: &str = "lo0";

    #[test]
    fn resolves_loopback_v4() {
        // Every host's loopback has 127.0.0.1; resolution needs no privileges, so this
        // exercises the full backend (the v4 path, and on Linux the netlink round-trip).
        let addrs = resolve(LOOPBACK).unwrap();
        assert_eq!(addrs.v4, Some(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn unknown_interface_has_no_addresses() {
        let addrs = resolve("nonexistent-xyz-999").unwrap();
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

    // Opt-in diagnostic: trace-log every address (and each v6's flag status) the resolver
    // finds on a real interface. Run with, e.g.:
    //   REFLECTOR_TEST_IFACE=en0 cargo test -- --nocapture resolve_traces_test_interface
    #[test]
    fn resolve_traces_test_interface() {
        let Some(iface) = std::env::var_os("REFLECTOR_TEST_IFACE") else {
            eprintln!("skip: set REFLECTOR_TEST_IFACE to inspect an interface");
            return;
        };
        let iface = iface.to_string_lossy();
        crate::logging::init();
        crate::logging::set_level(crate::config::LogLevel::Trace);
        let addrs = resolve(&iface).expect("resolve failed");
        eprintln!("resolved {iface}: {addrs}");
    }
}
