//! Strongly-typed configuration values.
//!
//! Each type parses from a string via `FromStr` (used by the environment layer,
//! with variable-named errors) and deserializes via a matching `Deserialize` that
//! delegates to the same `FromStr` (used by the TOML layer, with located errors).
//! The newtypes make illegal values unrepresentable.

use std::fmt;
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::str::FromStr;

use serde::{Deserialize, Deserializer};
use thiserror::Error;

use crate::unique_list::{ListRule, UniqueList};

/// Minimum severity a record must have to be logged; `Off` disables logging
/// entirely. Ordered most-restrictive to most-verbose, mirroring `log`'s filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum LogLevel {
    Off,
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("expected one of: off, error, warn, info, debug, trace")]
pub(crate) struct ParseLogLevelError;

impl FromStr for LogLevel {
    type Err = ParseLogLevelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "error" => Ok(Self::Error),
            "warn" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            _ => Err(ParseLogLevelError),
        }
    }
}

impl<'de> Deserialize<'de> for LogLevel {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Which IP versions a reflector operates on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum AddressFamily {
    #[default]
    Default,
    Dual,
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    #[must_use]
    pub(crate) fn uses_ipv4(self) -> bool {
        matches!(self, Self::Default | Self::Dual | Self::Ipv4)
    }

    #[must_use]
    pub(crate) fn uses_ipv6(self) -> bool {
        matches!(self, Self::Default | Self::Dual | Self::Ipv6)
    }

    /// Whether the policy handles `ip`'s IP version.
    pub(crate) fn uses(self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => self.uses_ipv4(),
            IpAddr::V6(_) => self.uses_ipv6(),
        }
    }

    /// A v4 source must be present at startup, else the reflector fails to build. Same set as
    /// `uses_ipv4`, but distinct in meaning: `Default` requires v4 while treating v6 as
    /// best-effort.
    #[must_use]
    pub(crate) fn requires_ipv4(self) -> bool {
        matches!(self, Self::Default | Self::Dual | Self::Ipv4)
    }

    /// A v6 source must be present at startup, else the reflector fails to build: only `Dual`
    /// and `Ipv6`. Unlike `uses_ipv6`, `Default` reflects v6 when available but starts without it.
    #[must_use]
    pub(crate) fn requires_ipv6(self) -> bool {
        matches!(self, Self::Dual | Self::Ipv6)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("expected one of: default, dual, ipv4, ipv6")]
pub(crate) struct ParseAddressFamilyError;

impl FromStr for AddressFamily {
    type Err = ParseAddressFamilyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "default" => Ok(Self::Default),
            "dual" => Ok(Self::Dual),
            "ipv4" => Ok(Self::Ipv4),
            "ipv6" => Ok(Self::Ipv6),
            _ => Err(ParseAddressFamilyError),
        }
    }
}

impl<'de> Deserialize<'de> for AddressFamily {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// A network interface name: non-empty and whitespace-free. OS interface names never contain
/// whitespace; a padded one would miss the interface (a confusing capture error) and slip past the
/// `source_if`/`target_if` equality check, so reject it here rather than downstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InterfaceName(String);

impl InterfaceName {
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("interface name must not be empty or contain whitespace")]
pub(crate) struct ParseInterfaceNameError;

impl FromStr for InterfaceName {
    type Err = ParseInterfaceNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.chars().any(char::is_whitespace) {
            return Err(ParseInterfaceNameError);
        }
        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for InterfaceName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// A reflector's name: surrounding whitespace trimmed and ASCII-lowercased (names are the reflector's
/// case-insensitive identity), never empty. The canonical form makes `Eq` the identity check, so no
/// caller has to fold case itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReflectorName(String);

impl ReflectorName {
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ReflectorName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("reflector name must not be empty or whitespace-only")]
pub(crate) struct ParseReflectorNameError;

impl FromStr for ReflectorName {
    type Err = ParseReflectorNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(ParseReflectorNameError);
        }
        Ok(Self(trimmed.to_ascii_lowercase()))
    }
}

/// The rule for [`PortList`]: any UDP port; `NonZeroU16` keeps 0 out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ports;

impl ListRule for Ports {
    type Item = NonZeroU16;

    const NOUN: &'static str = "port";
}

/// A non-empty, duplicate-free list of UDP ports.
pub(crate) type PortList = UniqueList<Ports>;

/// The rule for [`GroupList`]: multicast addresses of either family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Groups;

impl ListRule for Groups {
    type Item = IpAddr;

    const NOUN: &'static str = "group";

    fn refuse(group: &IpAddr) -> Option<&'static str> {
        (!group.is_multicast()).then_some("is not a multicast address")
    }
}

/// A non-empty, duplicate-free list of multicast groups, of either family.
pub(crate) type GroupList = UniqueList<Groups>;

/// The rule for [`PeerList`]: unicast addresses of either family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Peers;

impl ListRule for Peers {
    type Item = IpAddr;

    const NOUN: &'static str = "peer";

    fn refuse(peer: &IpAddr) -> Option<&'static str> {
        let unicast = match peer {
            IpAddr::V4(v4) => !v4.is_multicast() && !v4.is_broadcast() && !v4.is_unspecified(),
            IpAddr::V6(v6) => !v6.is_multicast() && !v6.is_unspecified(),
        };
        (!unicast).then_some("is not a unicast address")
    }
}

/// A non-empty, duplicate-free list of unicast addresses, of either family: the hosts behind an
/// interface that has no broadcast domain.
pub(crate) type PeerList = UniqueList<Peers>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unique_list::ListError;

    #[test]
    fn peer_list_takes_unicast_addresses_only() {
        let peers: PeerList = "10.10.10.2, fd00::2".parse().unwrap();
        assert_eq!(peers.len(), 2);
        for bad in [
            "239.255.90.90",
            "255.255.255.255",
            "0.0.0.0",
            "ff02::1",
            "::",
        ] {
            assert!(matches!(
                bad.parse::<PeerList>(),
                Err(ListError::Refused { .. })
            ));
        }
        assert!(matches!(
            "10.10.10.2,10.10.10.2".parse::<PeerList>(),
            Err(ListError::Duplicate { .. })
        ));
        assert!(matches!(
            "".parse::<PeerList>(),
            Err(ListError::Invalid { .. })
        ));
        assert!(matches!(
            PeerList::try_from(Vec::new()),
            Err(ListError::Empty { .. })
        ));
    }

    #[test]
    fn address_family_uses_and_requires() {
        use AddressFamily as F;
        // Uses: which families the reflector handles. Default and Dual handle both.
        assert_eq!(
            (F::Default.uses_ipv4(), F::Default.uses_ipv6()),
            (true, true)
        );
        assert_eq!((F::Dual.uses_ipv4(), F::Dual.uses_ipv6()), (true, true));
        assert_eq!((F::Ipv4.uses_ipv4(), F::Ipv4.uses_ipv6()), (true, false));
        assert_eq!((F::Ipv6.uses_ipv4(), F::Ipv6.uses_ipv6()), (false, true));
        // Requires: which must be present at startup. Default requires v4 only (v6 best-effort).
        assert_eq!(
            (F::Default.requires_ipv4(), F::Default.requires_ipv6()),
            (true, false)
        );
        assert_eq!(
            (F::Dual.requires_ipv4(), F::Dual.requires_ipv6()),
            (true, true)
        );
        assert_eq!(
            (F::Ipv4.requires_ipv4(), F::Ipv4.requires_ipv6()),
            (true, false)
        );
        assert_eq!(
            (F::Ipv6.requires_ipv4(), F::Ipv6.requires_ipv6()),
            (false, true)
        );
    }

    #[test]
    fn log_level_parses_via_fromstr() {
        assert_eq!("off".parse::<LogLevel>().unwrap(), LogLevel::Off);
        assert_eq!("ERROR".parse::<LogLevel>().unwrap(), LogLevel::Error);
        assert_eq!("Warn".parse::<LogLevel>().unwrap(), LogLevel::Warn);
        assert_eq!("INFO".parse::<LogLevel>().unwrap(), LogLevel::Info);
        assert_eq!("debug".parse::<LogLevel>().unwrap(), LogLevel::Debug);
        assert_eq!("Trace".parse::<LogLevel>().unwrap(), LogLevel::Trace);
        assert_eq!("verbose".parse::<LogLevel>(), Err(ParseLogLevelError));
    }

    #[test]
    fn interface_name_parses_via_fromstr() {
        assert_eq!("en0".parse::<InterfaceName>().unwrap().as_str(), "en0");
        assert_eq!("".parse::<InterfaceName>(), Err(ParseInterfaceNameError));
        // Whitespace is rejected: a padded name misses the interface and dodges SameInterface.
        assert_eq!(
            " en0 ".parse::<InterfaceName>(),
            Err(ParseInterfaceNameError)
        );
        assert_eq!(
            "e n0".parse::<InterfaceName>(),
            Err(ParseInterfaceNameError)
        );
    }

    #[test]
    fn reflector_name_parses_via_fromstr() {
        assert_eq!("  tv  ".parse::<ReflectorName>().unwrap().as_str(), "tv");
        // Canonicalized to lowercase, so casing is not part of the identity.
        assert_eq!("TV".parse::<ReflectorName>().unwrap().as_str(), "tv");
        assert_eq!("".parse::<ReflectorName>(), Err(ParseReflectorNameError));
        assert_eq!("   ".parse::<ReflectorName>(), Err(ParseReflectorNameError));
    }

    #[test]
    fn port_list_parses_via_fromstr() {
        let ports = "7, 9, 4000".parse::<PortList>().unwrap();
        assert_eq!(
            ports.iter().map(|p| p.get()).collect::<Vec<_>>(),
            [7, 9, 4000]
        );
        assert!(matches!(
            "7,7".parse::<PortList>(),
            Err(ListError::Duplicate { item, .. }) if item.get() == 7
        ));
        assert!(matches!(
            "0".parse::<PortList>(),
            Err(ListError::Invalid { .. })
        ));
        assert!(matches!(
            "abc".parse::<PortList>(),
            Err(ListError::Invalid { .. })
        ));
    }

    #[test]
    fn group_list_parses_multicast_groups_only() {
        let groups = "239.255.90.90, ff12::8384".parse::<GroupList>().unwrap();
        assert_eq!(
            groups.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["239.255.90.90", "ff12::8384"]
        );
        let unicast: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(matches!(
            "192.0.2.1".parse::<GroupList>(),
            Err(ListError::Refused { item, .. }) if item == unicast
        ));
        let group: IpAddr = "239.255.90.90".parse().unwrap();
        assert!(matches!(
            "239.255.90.90,239.255.90.90".parse::<GroupList>(),
            Err(ListError::Duplicate { item, .. }) if item == group
        ));
        assert!(matches!(
            "roon".parse::<GroupList>(),
            Err(ListError::Invalid { .. })
        ));
        assert!(matches!(
            GroupList::try_from(Vec::<IpAddr>::new()),
            Err(ListError::Empty { .. })
        ));
    }

    #[test]
    fn address_family_parses_via_fromstr() {
        use AddressFamily as F;
        assert_eq!("default".parse::<F>().unwrap(), F::Default);
        assert_eq!("DUAL".parse::<F>().unwrap(), F::Dual);
        assert_eq!("ipv4".parse::<F>().unwrap(), F::Ipv4);
        assert_eq!("IPv6".parse::<F>().unwrap(), F::Ipv6);
        assert_eq!("both".parse::<F>(), Err(ParseAddressFamilyError));
    }

    #[test]
    fn port_list_rejects_an_empty_list() {
        // FromStr can't yield an empty list, so Empty is reachable only via the TryFrom path.
        assert!(matches!(
            PortList::try_from(Vec::<NonZeroU16>::new()),
            Err(ListError::Empty { .. })
        ));
    }
}
