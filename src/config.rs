//! Configuration loading and validation.
//!
//! TOML is deserialized into a raw form (`RawConfig`/`RawReflector`) and then
//! validated into the strongly-typed [`Config`]. Typed values make illegal states
//! unrepresentable ([`Wol::ports`] exists only when `WoL` is enabled;
//! [`InterfaceName`]/[`PortList`] can't be empty).
//!
//! Submodules: value types in `value`, errors in `error`, the serde layer in
//! `raw`, the environment parser in `env`. Each value type pairs `FromStr` with a
//! matching `Deserialize`, so one validation serves both the TOML path (serde,
//! located errors) and the environment path (`FromStr`, variable-named errors).
//! Cross-field and cross-reflector rules live in the `TryFrom` conversions here;
//! sources are combined in [`Config::from_sources`].
//!
//! Reflectors nest under `[reflectors.<name>]` rather than top-level tables to keep
//! the deserializer off `#[serde(flatten)]`, which would discard the line/column of
//! every value error.

mod env;
mod error;
mod raw;
mod value;

pub(crate) use self::error::{ConfigError, Protocol};
pub(crate) use self::value::{
    AddressFamily, GroupList, InterfaceName, LogLevel, PortList, ReflectorName,
};

use std::net::IpAddr;
use std::num::NonZeroU16;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use serde::Deserialize;

use self::raw::{RawConfig, RawReflector};
use crate::net::mac::MacSet;
use crate::net::mdns::{MDNS_GROUP_V4, MDNS_GROUP_V6, MDNS_PORT};
use crate::net::ssdp::{
    SSDP_GROUP_V4, SSDP_GROUP_V6_LINK_LOCAL, SSDP_GROUP_V6_SITE_LOCAL, SSDP_PORT,
};
use crate::net::wsd::{WSD_GROUP_V4, WSD_GROUP_V6, WSD_PORT};

/// Wake-on-LAN settings (present only when `WoL` is enabled for the reflector).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Wol {
    /// UDP destination ports whose magic packets are reflected.
    pub(crate) ports: PortList,
}

/// The ports a `wol = true` entry relays when `wol_ports` is absent.
const WOL_DEFAULT_PORTS: [NonZeroU16; 2] =
    [NonZeroU16::new(7).unwrap(), NonZeroU16::new(9).unwrap()];

impl Wol {
    fn default_ports() -> PortList {
        PortList::try_from(WOL_DEFAULT_PORTS.to_vec()).expect("two distinct ports")
    }
}

/// The destinations a protocol's filter admits on one port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// Any address the family uses: the Wake-on-LAN filter pins the port alone.
    Any(AddressFamily),
    Group(IpAddr),
    /// The limited broadcast and the segment's directed one.
    Broadcast,
}

impl Reach {
    /// Whether a datagram exists that both admit.
    fn overlaps(self, other: Reach) -> bool {
        match (self, other) {
            (Self::Any(a), Self::Any(b)) => families_overlap(a, b),
            (Self::Any(family), Self::Group(group)) | (Self::Group(group), Self::Any(family)) => {
                family_uses(family, group)
            }
            (Self::Any(family), Self::Broadcast) | (Self::Broadcast, Self::Any(family)) => {
                family.uses_ipv4()
            }
            (Self::Group(a), Self::Group(b)) => a == b,
            (Self::Broadcast, Self::Broadcast) => true,
            (Self::Group(_), Self::Broadcast) | (Self::Broadcast, Self::Group(_)) => false,
        }
    }
}

/// A class of datagrams an entry relays: those to `port` and `reach` arriving on `ingress`,
/// re-emitted on `egress`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Flow<'a> {
    protocol: Protocol,
    ingress: &'a InterfaceName,
    egress: &'a InterfaceName,
    port: u16,
    reach: Reach,
}

impl Flow<'_> {
    /// Whether a datagram exists in both flows.
    fn overlaps(&self, other: &Flow<'_>) -> bool {
        self.ingress == other.ingress
            && self.egress == other.egress
            && self.port == other.port
            && self.reach.overlaps(other.reach)
    }
}

/// The transparent UDP relay's settings (present only when `udp_ports` is set).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UdpRelay {
    /// Destination ports whose datagrams are relayed as sent.
    pub(crate) ports: PortList,
    /// Multicast groups to join and relay on those ports.
    pub(crate) groups: Option<GroupList>,
    /// Whether broadcasts on those ports are relayed too.
    pub(crate) broadcast: bool,
}

impl UdpRelay {
    fn destinations(&self) -> Vec<(u16, Reach)> {
        let groups = self.groups.as_deref().unwrap_or(&[]);
        self.ports
            .iter()
            .map(|port| port.get())
            .flat_map(|port| {
                let groups = groups.iter().map(move |group| (port, Reach::Group(*group)));
                groups.chain(self.broadcast.then_some((port, Reach::Broadcast)))
            })
            .collect()
    }
}

/// SSDP settings (present only when SSDP is enabled for the reflector).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ssdp {
    /// Whether the DIAL HTTP proxy is layered on top of SSDP.
    pub(crate) dial: bool,
}

/// One reflector: bridges `source_if` → `target_if` for the enabled protocols.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reflector {
    /// Display name for logs, from the `[reflectors.<name>]` key or
    /// `NETFLECTOR_<tag>_NAME`.
    pub(crate) name: ReflectorName,
    /// Interface to listen on.
    pub(crate) source_if: InterfaceName,
    /// Interface to emit on (always different from `source_if`).
    pub(crate) target_if: InterfaceName,
    /// Optional device allow-filter; `None` matches any device, `Some` a non-empty set.
    pub(crate) macs: Option<MacSet>,
    /// IP-version policy for this reflector.
    pub(crate) address_family: AddressFamily,
    /// Wake-on-LAN settings, or `None` when `WoL` is disabled.
    pub(crate) wol: Option<Wol>,
    pub(crate) mdns: bool,
    /// SSDP settings, or `None` when SSDP is disabled.
    pub(crate) ssdp: Option<Ssdp>,
    /// Whether WS-Discovery (WSD) is enabled.
    pub(crate) wsd: bool,
    /// Also relay every enabled protocol target → source: the entry is built a second time with
    /// its interfaces swapped.
    pub(crate) bidirectional: bool,
    /// The transparent UDP relay, or `None` when `udp_ports` is unset.
    pub(crate) udp: Option<UdpRelay>,
}

impl Reflector {
    /// This entry with its interfaces swapped: the second leg of a bidirectional entry, built
    /// exactly like the first.
    pub(crate) fn reversed(&self) -> Reflector {
        Reflector {
            source_if: self.target_if.clone(),
            target_if: self.source_if.clone(),
            ..self.clone()
        }
    }

    /// The `(source, target)` pairs this entry relays over: its own, plus the reverse when
    /// bidirectional.
    fn directions(&self) -> impl Iterator<Item = (&InterfaceName, &InterfaceName)> {
        std::iter::once((&self.source_if, &self.target_if)).chain(
            self.bidirectional
                .then_some((&self.target_if, &self.source_if)),
        )
    }

    /// Every flow the entry's protocols relay. mDNS, SSDP and WSD capture on both interfaces
    /// whatever the entry's direction, queries on the source and responses on the target, for
    /// the groups of the families the entry uses; Wake-on-LAN admits anything on its ports and
    /// the relay its groups and broadcast, each on the entry's directions.
    fn flows(&self) -> Vec<Flow<'_>> {
        let family = self.address_family;
        let mut flows = Vec::new();
        let mut discovery = |protocol, port, groups: &[IpAddr]| {
            for group in groups.iter().filter(|group| family_uses(family, **group)) {
                let legs = [
                    (&self.source_if, &self.target_if),
                    (&self.target_if, &self.source_if),
                ];
                flows.extend(legs.map(|(ingress, egress)| Flow {
                    protocol,
                    ingress,
                    egress,
                    port,
                    reach: Reach::Group(*group),
                }));
            }
        };
        if self.mdns {
            let v4 = IpAddr::V4(MDNS_GROUP_V4);
            let v6 = IpAddr::V6(MDNS_GROUP_V6);
            discovery(Protocol::Mdns, MDNS_PORT, &[v4, v6]);
        }
        if self.ssdp.is_some() {
            let v4 = IpAddr::V4(SSDP_GROUP_V4);
            let link_local = IpAddr::V6(SSDP_GROUP_V6_LINK_LOCAL);
            let site_local = IpAddr::V6(SSDP_GROUP_V6_SITE_LOCAL);
            discovery(Protocol::Ssdp, SSDP_PORT, &[v4, link_local, site_local]);
        }
        if self.wsd {
            let v4 = IpAddr::V4(WSD_GROUP_V4);
            let v6 = IpAddr::V6(WSD_GROUP_V6);
            discovery(Protocol::Wsd, WSD_PORT, &[v4, v6]);
        }
        for (ingress, egress) in self.directions() {
            if let Some(wol) = &self.wol {
                flows.extend(wol.ports.iter().map(|port| Flow {
                    protocol: Protocol::Wol,
                    ingress,
                    egress,
                    port: port.get(),
                    reach: Reach::Any(family),
                }));
            }
            if let Some(udp) = &self.udp {
                flows.extend(udp.destinations().into_iter().map(|(port, reach)| Flow {
                    protocol: Protocol::Udp,
                    ingress,
                    egress,
                    port,
                    reach,
                }));
            }
        }
        flows
    }

    /// The protocol on which `self` and `other` would reflect the same packet twice, if any: a
    /// protocol both enable, or a flow of one the UDP relay of the other overlaps. Two
    /// discovery protocols on one port don't duplicate: each classifier admits only its own
    /// messages. The relay admits every datagram it captures, so it duplicates any protocol
    /// capturing the same on the same leg, and the conflict is named after that protocol.
    fn conflicts_with(&self, other: &Reflector) -> Option<Protocol> {
        self.shared_protocol(other).or_else(|| {
            self.relay_overlap(other.flows())
                .or_else(|| other.relay_overlap(self.flows()))
                .map(|(protocol, _)| protocol)
        })
    }

    /// A protocol both enable on a shared direction with overlapping MAC selection and address
    /// family (for `WoL`, also a shared port).
    fn shared_protocol(&self, other: &Reflector) -> Option<Protocol> {
        if !self
            .directions()
            .any(|mine| other.directions().any(|theirs| theirs == mine))
        {
            return None;
        }
        if !macs_overlap(self.macs.as_ref(), other.macs.as_ref())
            || !families_overlap(self.address_family, other.address_family)
        {
            return None;
        }
        if let (Some(a), Some(b)) = (&self.wol, &other.wol)
            && a.ports.iter().any(|port| b.ports.contains(port))
        {
            return Some(Protocol::Wol);
        }
        if self.mdns && other.mdns {
            return Some(Protocol::Mdns);
        }
        if self.ssdp.is_some() && other.ssdp.is_some() {
            return Some(Protocol::Ssdp);
        }
        if self.wsd && other.wsd {
            return Some(Protocol::Wsd);
        }
        None
    }

    /// The first of `others` whose datagrams the entry's UDP relay would carry a second time,
    /// as its protocol and port.
    fn relay_overlap<'a>(
        &self,
        others: impl IntoIterator<Item = Flow<'a>>,
    ) -> Option<(Protocol, u16)> {
        let mine = self.flows();
        let relay = || mine.iter().filter(|flow| flow.protocol == Protocol::Udp);
        others
            .into_iter()
            .find(|other| relay().any(|mine| mine.overlaps(other)))
            .map(|other| (other.protocol, other.port))
    }
}

/// Whether `family` handles `ip`'s IP version.
fn family_uses(family: AddressFamily, ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => family.uses_ipv4(),
        IpAddr::V6(_) => family.uses_ipv6(),
    }
}

impl TryFrom<(String, RawReflector)> for Reflector {
    type Error = ConfigError;

    fn try_from((key, raw): (String, RawReflector)) -> Result<Self, ConfigError> {
        // Env `NAME` override is already validated; the identity key (file table
        // key / env tag) is validated here.
        let name = match raw.name {
            Some(name) => name,
            None => ReflectorName::from_str(&key)
                .map_err(|_| ConfigError::EmptyReflectorName { key: key.clone() })?,
        };
        let source_if = raw.source_if;
        let target_if = raw.target_if;
        if source_if == target_if {
            return Err(ConfigError::SameInterface {
                name,
                value: source_if,
            });
        }

        // The relay's own checks come first: an entry that sets only udp_groups is a relay
        // missing its ports, not an entry with no protocol.
        let udp = match (raw.udp_ports, raw.udp_groups, raw.udp_broadcast) {
            (None, None, false) => None,
            (None, _, _) => return Err(ConfigError::UdpRelayWithoutPorts { name }),
            (Some(_), None, false) => return Err(ConfigError::UdpRelayNoDestination { name }),
            (Some(ports), groups, broadcast) => {
                if broadcast && !raw.address_family.uses_ipv4() {
                    return Err(ConfigError::UdpBroadcastFamily { name });
                }
                let foreign = groups
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .find(|group| !family_uses(raw.address_family, **group));
                if let Some(group) = foreign {
                    return Err(ConfigError::UdpGroupFamily {
                        name,
                        group: *group,
                    });
                }
                Some(UdpRelay {
                    ports,
                    groups,
                    broadcast,
                })
            }
        };
        if !raw.wol && !raw.mdns && !raw.ssdp && !raw.wsd && udp.is_none() {
            return Err(ConfigError::NoProtocol { name });
        }
        if raw.wol_ports.is_some() && !raw.wol {
            return Err(ConfigError::WolPortsWithoutWol { name });
        }
        if raw.macs.is_some() && !raw.wol && !raw.mdns && !raw.ssdp && !raw.wsd {
            return Err(ConfigError::MacsUnused { name });
        }
        if raw.dial && !raw.ssdp {
            return Err(ConfigError::DialWithoutSsdp { name });
        }

        let wol = if raw.wol {
            let ports = raw.wol_ports.unwrap_or_else(Wol::default_ports);
            Some(Wol { ports })
        } else {
            None
        };

        let ssdp = if raw.ssdp {
            if raw.dial && !raw.address_family.uses_ipv4() {
                return Err(ConfigError::DialRequiresIpv4 { name });
            }
            Some(Ssdp { dial: raw.dial })
        } else {
            None
        };

        let reflector = Reflector {
            name,
            source_if,
            target_if,
            macs: raw.macs,
            address_family: raw.address_family,
            wol,
            mdns: raw.mdns,
            ssdp,
            wsd: raw.wsd,
            bidirectional: raw.bidirectional,
            udp,
        };
        let duplicated = {
            let flows = reflector.flows();
            let others = flows
                .iter()
                .copied()
                .filter(|flow| flow.protocol != Protocol::Udp);
            reflector.relay_overlap(others)
        };
        if let Some((protocol, port)) = duplicated {
            return Err(ConfigError::UdpRelayDuplicates {
                name: reflector.name,
                port,
                protocol,
            });
        }
        Ok(reflector)
    }
}

/// A fully-validated configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Config {
    /// Minimum severity to log.
    pub(crate) log_level: LogLevel,
    /// How often to log memory-footprint diagnostics, or `None` to disable them.
    pub(crate) debug_memory_interval: Option<Duration>,
    /// How often to log per-interface packet counters, or `None` to disable them.
    pub(crate) counter_interval: Option<Duration>,
    pub(crate) reflectors: Vec<Reflector>,
}

impl Config {
    /// Build a configuration from optional TOML text plus environment variables.
    ///
    /// Environment variables take precedence over the file for the global
    /// settings; reflectors from the two sources are combined, and a name defined
    /// by both is rejected. Kept free of I/O so it can be exercised directly.
    ///
    /// # Errors
    /// Returns [`ConfigError::Parse`] for malformed TOML, an `Env*` variant for a
    /// malformed or invalid environment variable, [`ConfigError::DuplicateReflector`]
    /// when a name is defined by both sources, or any cross-field [`ConfigError`].
    pub(crate) fn from_sources(
        toml_text: Option<&str>,
        env: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, ConfigError> {
        let mut raw: RawConfig = match toml_text {
            Some(text) => toml::from_str(text)?,
            None => RawConfig::default(),
        };
        raw.merge_env(env::parse_env(env)?)?;
        Config::try_from(raw)
    }
}

impl TryFrom<RawConfig> for Config {
    type Error = ConfigError;

    fn try_from(raw: RawConfig) -> Result<Self, ConfigError> {
        let mut reflectors = Vec::with_capacity(raw.reflectors.len());
        for (key, raw_reflector) in raw.reflectors {
            let reflector = Reflector::try_from((key, raw_reflector))?;
            log::debug!(
                "reflector {}: {} {} {} [{}] family={:?}",
                reflector.name,
                reflector.source_if,
                if reflector.bidirectional { "<->" } else { "->" },
                reflector.target_if,
                protocol_list(&reflector),
                reflector.address_family,
            );
            reflectors.push(reflector);
        }
        if reflectors.is_empty() {
            return Err(ConfigError::NoReflectors);
        }
        check_conflicts(&reflectors)?;

        Ok(Config {
            log_level: raw.log_level.unwrap_or_default(),
            debug_memory_interval: interval_from(
                raw.debug_memory_interval_secs,
                "debug_memory_interval_secs",
            )?,
            counter_interval: interval_from(raw.counters_interval_secs, "counters_interval_secs")?,
            reflectors,
        })
    }
}

/// One year. A diagnostic cadence beyond this is a config typo, and a value large enough to overflow the
/// reporter's `Instant + Duration` deadline would panic it at startup; reject it with a clear error.
const MAX_INTERVAL_SECS: u64 = 60 * 60 * 24 * 365;

/// A positive-seconds report interval as a `Duration`; `0` or absent disables the report. `field` is the
/// config key, named in the error for an over-large value.
///
/// # Errors
/// [`ConfigError::IntervalTooLarge`] when `secs` exceeds [`MAX_INTERVAL_SECS`].
fn interval_from(secs: Option<u64>, field: &'static str) -> Result<Option<Duration>, ConfigError> {
    match secs {
        Some(s) if s > MAX_INTERVAL_SECS => Err(ConfigError::IntervalTooLarge {
            field,
            secs: s,
            max: MAX_INTERVAL_SECS,
        }),
        Some(s) if s > 0 => Ok(Some(Duration::from_secs(s))),
        _ => Ok(None),
    }
}

/// Reads only the top-level `log_level`, ignoring everything else (no
/// `deny_unknown_fields`), so [`resolve_log_level`] can extract the level without
/// validating the reflector tables.
#[derive(Deserialize)]
struct LogLevelProbe {
    #[serde(default)]
    log_level: Option<LogLevel>,
}

/// Read a configuration file, mapping I/O failure to [`ConfigError::ReadFile`]. Takes a `Path` so a
/// non-UTF-8 path (valid on Unix) reads without loss; only the error message renders it lossily.
pub(crate) fn read_config_file(path: &Path) -> Result<String, ConfigError> {
    std::fs::read_to_string(path).map_err(|source| ConfigError::ReadFile {
        path: path.display().to_string(),
        source,
    })
}

/// Resolve just the log level from the environment and TOML text, before the full
/// configuration is parsed. Lets the logger be raised to the configured verbosity
/// so the rest of loading is logged at that level. Environment overrides the file,
/// which overrides the default.
///
/// Deliberately lightweight: it reads only `NETFLECTOR_LOG_LEVEL` and the file's
/// top-level `log_level`, never touching the reflector tables, so it can't fail
/// on a reflector error that should instead surface (logged) from the full parse.
///
/// # Errors
/// Returns [`ConfigError::Parse`] for malformed TOML, or [`ConfigError::EnvBadValue`]
/// if `NETFLECTOR_LOG_LEVEL` is not a valid level.
pub(crate) fn resolve_log_level(
    toml_text: Option<&str>,
    env: &[(String, String)],
) -> Result<LogLevel, ConfigError> {
    if let Some(level) = env::log_level_from_env(env)? {
        return Ok(level);
    }
    if let Some(text) = toml_text {
        let probe: LogLevelProbe = toml::from_str(text)?;
        if let Some(level) = probe.log_level {
            return Ok(level);
        }
    }
    Ok(LogLevel::default())
}

/// The enabled protocols of `reflector` as a comma-separated summary for logging,
/// with `WoL` ports, the SSDP DIAL flag, and the relay's ports and destinations.
fn protocol_list(reflector: &Reflector) -> String {
    let mut protocols: Vec<String> = Vec::new();
    if let Some(wol) = &reflector.wol {
        let ports: Vec<String> = wol.ports.iter().map(ToString::to_string).collect();
        protocols.push(format!("wol({})", ports.join(",")));
    }
    if reflector.mdns {
        protocols.push("mdns".to_owned());
    }
    if let Some(ssdp) = &reflector.ssdp {
        protocols.push(if ssdp.dial {
            "ssdp+dial".to_owned()
        } else {
            "ssdp".to_owned()
        });
    }
    if reflector.wsd {
        protocols.push("wsd".to_owned());
    }
    if let Some(udp) = &reflector.udp {
        let ports: Vec<String> = udp.ports.iter().map(ToString::to_string).collect();
        let groups = udp.groups.as_deref().unwrap_or(&[]);
        let mut destinations: Vec<String> = groups.iter().map(ToString::to_string).collect();
        if udp.broadcast {
            destinations.push("broadcast".to_owned());
        }
        protocols.push(format!(
            "udp({} on {})",
            ports.join(","),
            destinations.join(",")
        ));
    }
    protocols.join(", ")
}

/// Two MAC selections overlap when they share at least one address, or either is
/// absent (an absent filter matches any device).
fn macs_overlap(a: Option<&MacSet>, b: Option<&MacSet>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.iter().any(|mac| b.contains(mac)),
        _ => true,
    }
}

/// Two address families overlap when they both carry the same IP version.
fn families_overlap(a: AddressFamily, b: AddressFamily) -> bool {
    (a.uses_ipv4() && b.uses_ipv4()) || (a.uses_ipv6() && b.uses_ipv6())
}

/// Reject any pair of reflectors that share a name or would reflect the same packet twice. Names are the
/// canonical (lowercased) identity, so `==` catches keys that only differ in case or whitespace — which
/// `merge_env` folds env-vs-file but the file table cannot.
fn check_conflicts(reflectors: &[Reflector]) -> Result<(), ConfigError> {
    for (i, a) in reflectors.iter().enumerate() {
        for b in &reflectors[i + 1..] {
            if a.name == b.name {
                return Err(ConfigError::DuplicateReflectorName {
                    name: a.name.clone(),
                });
            }
            if let Some(protocol) = a.conflicts_with(b) {
                return Err(ConfigError::ConflictingReflectors {
                    protocol,
                    first: a.name.clone(),
                    second: b.name.clone(),
                    source_if: a.source_if.clone(),
                    target_if: a.target_if.clone(),
                });
            }
        }
    }
    log::debug!("no reflector conflicts");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_toml(text: &str) -> Result<Config, ConfigError> {
        Config::from_sources(Some(text), Vec::<(String, String)>::new())
    }

    fn err(text: &str) -> ConfigError {
        from_toml(text).unwrap_err()
    }

    #[test]
    fn minimal_reflector_uses_defaults() {
        let cfg = from_toml(
            r#"
            [reflectors.discovery]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            "#,
        )
        .unwrap();
        assert_eq!(cfg.log_level, LogLevel::Info);
        assert!(cfg.debug_memory_interval.is_none());
        assert_eq!(cfg.reflectors.len(), 1);
        let r = &cfg.reflectors[0];
        assert_eq!(r.name.as_str(), "discovery");
        assert_eq!(r.source_if.as_str(), "lan");
        assert_eq!(r.target_if.as_str(), "iot");
        assert!(r.mdns);
        assert!(r.macs.is_none());
        assert_eq!(r.address_family, AddressFamily::Default);
        assert!(r.wol.is_none());
        assert!(r.ssdp.is_none());
        assert!(!r.wsd);
    }

    #[test]
    fn wsd_reflector_parses() {
        let cfg = from_toml(
            r#"
            [reflectors.cameras]
            source_if = "lan"
            target_if = "cams"
            wsd = true
            "#,
        )
        .unwrap();
        let r = &cfg.reflectors[0];
        assert!(r.wsd);
        assert!(!r.mdns);
        assert!(r.wol.is_none());
        assert!(r.ssdp.is_none());
        assert!(!r.bidirectional);
    }

    #[test]
    fn wol_relays_ports_7_and_9_by_default() {
        let cfg = from_toml(
            r#"
            [reflectors.pc]
            source_if = "lan"
            target_if = "iot"
            wol = true
            "#,
        )
        .unwrap();
        let ports = &cfg.reflectors[0].wol.as_ref().unwrap().ports;
        assert_eq!(ports.iter().map(|p| p.get()).collect::<Vec<_>>(), [7, 9]);
    }

    #[test]
    fn udp_relay_parses() {
        let cfg = from_toml(
            r#"
            [reflectors.roon]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [9003]
            udp_groups = ["239.255.90.90"]
            udp_broadcast = true
            "#,
        )
        .unwrap();
        let udp = cfg.reflectors[0].udp.as_ref().unwrap();
        assert_eq!(
            udp.ports.iter().map(|p| p.get()).collect::<Vec<_>>(),
            [9003]
        );
        assert_eq!(
            udp.groups.as_ref().unwrap().to_vec(),
            ["239.255.90.90".parse::<IpAddr>().unwrap()]
        );
        assert!(udp.broadcast);
        assert!(cfg.reflectors[0].wol.is_none());
    }

    #[test]
    fn macs_need_a_protocol_that_applies_them() {
        let text = r#"
            [reflectors.roon]
            source_if = "lan"
            target_if = "iot"
            macs = ["00:00:00:00:00:01"]
            udp_ports = [9003]
            udp_broadcast = true
        "#;
        assert!(matches!(err(text), ConfigError::MacsUnused { .. }));
        let cfg = from_toml(
            r#"
            [reflectors.roon]
            source_if = "lan"
            target_if = "iot"
            macs = ["00:00:00:00:00:01"]
            wol = true
            udp_ports = [9003]
            udp_broadcast = true
            "#,
        )
        .unwrap();
        assert!(cfg.reflectors[0].macs.is_some());
    }

    #[test]
    fn udp_relay_needs_ports_and_a_destination() {
        // Groups or broadcast without ports: nothing says which datagrams to relay.
        let text = r#"
            [reflectors.roon]
            source_if = "lan"
            target_if = "iot"
            udp_groups = ["239.255.90.90"]
        "#;
        assert!(matches!(
            err(text),
            ConfigError::UdpRelayWithoutPorts { .. }
        ));
        // Ports without groups or broadcast: nothing to capture.
        let text = r#"
            [reflectors.roon]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [9003]
        "#;
        assert!(matches!(
            err(text),
            ConfigError::UdpRelayNoDestination { .. }
        ));
    }

    #[test]
    fn udp_group_must_be_of_a_used_family() {
        let text = r#"
            [reflectors.sync]
            source_if = "lan"
            target_if = "iot"
            address_family = "ipv4"
            udp_ports = [21027]
            udp_groups = ["ff12::8384"]
        "#;
        assert!(matches!(err(text), ConfigError::UdpGroupFamily { .. }));
    }

    #[test]
    fn udp_broadcast_needs_ipv4() {
        let text = r#"
            [reflectors.sync]
            source_if = "lan"
            target_if = "iot"
            address_family = "ipv6"
            udp_ports = [21027]
            udp_groups = ["ff12::8384"]
            udp_broadcast = true
        "#;
        assert!(matches!(err(text), ConfigError::UdpBroadcastFamily { .. }));
    }

    #[test]
    fn udp_relay_on_a_group_of_the_entrys_own_protocol_rejected() {
        let text = r#"
            [reflectors.lan]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            udp_ports = [5353]
            udp_groups = ["224.0.0.251"]
        "#;
        assert!(matches!(
            err(text),
            ConfigError::UdpRelayDuplicates {
                port: 5353,
                protocol: Protocol::Mdns,
                ..
            }
        ));
        // Wake-on-LAN captures every destination on its ports.
        let text = r#"
            [reflectors.lan]
            source_if = "lan"
            target_if = "iot"
            wol = true
            udp_ports = [9]
            udp_groups = ["239.255.90.90"]
        "#;
        assert!(matches!(
            err(text),
            ConfigError::UdpRelayDuplicates {
                port: 9,
                protocol: Protocol::Wol,
                ..
            }
        ));
    }

    #[test]
    fn udp_relay_off_the_entrys_own_groups_parses() {
        // mDNS never captures a broadcast, so the relay on its port duplicates nothing.
        let cfg = from_toml(
            r#"
            [reflectors.lan]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            udp_ports = [5353]
            udp_broadcast = true
            "#,
        )
        .unwrap();
        assert!(cfg.reflectors[0].udp.is_some());
    }

    #[test]
    fn bidirectional_reflector_parses_and_reverses() {
        let cfg = from_toml(
            r#"
            [reflectors.lan]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            bidirectional = true
            "#,
        )
        .unwrap();
        let r = &cfg.reflectors[0];
        assert!(r.bidirectional);
        let reversed = r.reversed();
        assert_eq!(reversed.source_if, r.target_if);
        assert_eq!(reversed.target_if, r.source_if);
        assert_eq!(reversed.name, r.name);
        assert!(reversed.mdns);
    }

    #[test]
    fn full_reflector_parses() {
        let cfg = from_toml(
            r#"
            log_level = "DEBUG"
            debug_memory_interval_secs = 30

            [reflectors.tv]
            source_if = "en0"
            target_if = "lo0"
            macs = ["B0:37:95:C5:60:BE"]
            wol = true
            mdns = true
            ssdp = true
            dial = true
            wol_ports = [7, 9, 4000]
            address_family = "dual"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.log_level, LogLevel::Debug);
        assert_eq!(cfg.debug_memory_interval, Some(Duration::from_secs(30)));
        assert_eq!(cfg.reflectors.len(), 1);
        let r = &cfg.reflectors[0];
        assert_eq!(r.name.as_str(), "tv");
        assert_eq!(r.source_if.as_str(), "en0");
        assert_eq!(r.target_if.as_str(), "lo0");
        let macs = r.macs.as_ref().unwrap();
        assert_eq!(macs.len(), 1);
        assert_eq!(macs[0].to_string(), "b0:37:95:c5:60:be");
        let wol = r.wol.as_ref().unwrap();
        assert!(r.mdns);
        let ssdp = r.ssdp.unwrap();
        assert!(ssdp.dial);
        assert_eq!(
            wol.ports.iter().map(|p| p.get()).collect::<Vec<_>>(),
            [7, 9, 4000]
        );
        assert_eq!(r.address_family, AddressFamily::Dual);
    }

    #[test]
    fn counter_interval_parses_and_zero_disables() {
        // A positive interval becomes a Duration; 0 disables it, as does omitting the key.
        let toml = |secs: &str| {
            format!(
                r#"
                {secs}
                [reflectors.d]
                source_if = "a"
                target_if = "b"
                mdns = true
                "#
            )
        };
        assert_eq!(
            from_toml(&toml("counters_interval_secs = 30"))
                .unwrap()
                .counter_interval,
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            from_toml(&toml("counters_interval_secs = 0"))
                .unwrap()
                .counter_interval,
            None
        );
        assert_eq!(from_toml(&toml("")).unwrap().counter_interval, None);
    }

    #[test]
    fn debug_memory_interval_parses_and_zero_disables() {
        // A positive interval becomes a Duration; 0 disables it, as does omitting the key.
        let toml = |secs: &str| {
            format!(
                r#"
                {secs}
                [reflectors.d]
                source_if = "a"
                target_if = "b"
                mdns = true
                "#
            )
        };
        assert_eq!(
            from_toml(&toml("debug_memory_interval_secs = 30"))
                .unwrap()
                .debug_memory_interval,
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            from_toml(&toml("debug_memory_interval_secs = 0"))
                .unwrap()
                .debug_memory_interval,
            None
        );
        assert_eq!(from_toml(&toml("")).unwrap().debug_memory_interval, None);
    }

    #[test]
    fn an_over_large_interval_is_rejected_by_field() {
        // Past the cap is a typo that would overflow the reporter's Instant+Duration deadline and panic
        // at startup; reject it, naming the key, rather than accept it. The cap itself is valid.
        let toml = |line: &str| {
            format!(
                r#"
                {line}
                [reflectors.d]
                source_if = "a"
                target_if = "b"
                mdns = true
                "#
            )
        };
        let too_big = MAX_INTERVAL_SECS + 1;
        assert!(matches!(
            from_toml(&toml(&format!("debug_memory_interval_secs = {too_big}"))),
            Err(ConfigError::IntervalTooLarge { field: "debug_memory_interval_secs", secs, .. })
                if secs == too_big
        ));
        assert!(matches!(
            from_toml(&toml(&format!("counters_interval_secs = {too_big}"))),
            Err(ConfigError::IntervalTooLarge {
                field: "counters_interval_secs",
                ..
            })
        ));
        // The cap itself is accepted, for both keys.
        let at_cap = from_toml(&toml(&format!(
            "debug_memory_interval_secs = {MAX_INTERVAL_SECS}\n\
             counters_interval_secs = {MAX_INTERVAL_SECS}"
        )))
        .unwrap();
        assert_eq!(
            at_cap.debug_memory_interval,
            Some(Duration::from_secs(MAX_INTERVAL_SECS))
        );
        assert_eq!(
            at_cap.counter_interval,
            Some(Duration::from_secs(MAX_INTERVAL_SECS))
        );
    }

    #[test]
    fn two_file_reflectors_cannot_share_a_folded_name() {
        // Table keys differing only in case or surrounding whitespace resolve to one display name;
        // reject rather than silently produce two reflectors sharing it (env-vs-file already folds).
        let cfg = |k1: &str, k2: &str| {
            format!(
                r#"
                [reflectors.{k1}]
                source_if = "a"
                target_if = "b"
                mdns = true
                [reflectors.{k2}]
                source_if = "c"
                target_if = "d"
                mdns = true
                "#
            )
        };
        assert!(matches!(
            from_toml(&cfg("TV", "tv")),
            Err(ConfigError::DuplicateReflectorName { name }) if name.as_str() == "tv"
        ));
        assert!(matches!(
            from_toml(&cfg("\"  tv  \"", "tv")),
            Err(ConfigError::DuplicateReflectorName { name }) if name.as_str() == "tv"
        ));
    }

    #[test]
    #[cfg_attr(miri, ignore = "opens a real file")]
    fn read_config_file_tolerates_a_non_utf8_path() {
        use std::os::unix::ffi::OsStrExt;
        // An invalid-UTF-8 path byte must not panic; a missing file yields ReadFile (rendered lossily).
        let path = std::path::Path::new(std::ffi::OsStr::from_bytes(b"/no/\xff/such.toml"));
        assert!(matches!(
            read_config_file(path),
            Err(ConfigError::ReadFile { .. })
        ));
    }

    #[test]
    fn old_debug_memory_bool_is_rejected() {
        // The 0.10.x `debug_memory = true` no longer parses (renamed to an interval, and the config
        // denies unknown fields). The deliberate breaking change fails loud at startup rather than
        // silently ignoring a stale setting.
        let text = r#"
            debug_memory = true
            [reflectors.d]
            source_if = "a"
            target_if = "b"
            mdns = true
            "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn wol_defaults_to_ports_7_and_9() {
        let cfg = from_toml(
            r#"
            [reflectors.w]
            source_if = "a"
            target_if = "b"
            wol = true
            "#,
        )
        .unwrap();
        let ports: Vec<u16> = cfg.reflectors[0]
            .wol
            .as_ref()
            .unwrap()
            .ports
            .iter()
            .map(|p| p.get())
            .collect();
        assert_eq!(ports, [7, 9]);
    }

    #[test]
    fn multiple_reflectors_parse() {
        let cfg = from_toml(
            r#"
            [reflectors.zebra]
            source_if = "a"
            target_if = "b"
            mdns = true

            [reflectors.alpha]
            source_if = "a"
            target_if = "c"
            mdns = true
            "#,
        )
        .unwrap();
        let mut names: Vec<&str> = cfg.reflectors.iter().map(|r| r.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["alpha", "zebra"]);
    }

    #[test]
    fn empty_config_is_rejected() {
        assert!(matches!(err(""), ConfigError::NoReflectors));
    }

    #[test]
    fn invalid_log_level() {
        let text = r#"
            log_level = "verbose"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            mdns = true
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn reflector_with_no_protocol() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
        "#;
        assert!(matches!(err(text), ConfigError::NoProtocol { name } if name.as_str() == "x"));
    }

    #[test]
    fn source_and_target_must_differ() {
        let text = r#"
            [reflectors.x]
            source_if = "same"
            target_if = "same"
            mdns = true
        "#;
        assert!(
            matches!(err(text), ConfigError::SameInterface { value, .. } if value.as_str() == "same")
        );
    }

    #[test]
    fn missing_source_if() {
        let text = r#"
            [reflectors.x]
            target_if = "b"
            mdns = true
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn empty_source_if() {
        let text = r#"
            [reflectors.x]
            source_if = ""
            target_if = "b"
            mdns = true
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn missing_target_if() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            mdns = true
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn empty_target_if() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = ""
            mdns = true
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn wol_ports_without_wol() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            mdns = true
            wol_ports = [7]
        "#;
        assert!(matches!(err(text), ConfigError::WolPortsWithoutWol { .. }));
    }

    #[test]
    fn dial_without_ssdp() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            mdns = true
            dial = true
        "#;
        assert!(matches!(err(text), ConfigError::DialWithoutSsdp { .. }));
    }

    #[test]
    fn dial_requires_ipv4() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            ssdp = true
            dial = true
            address_family = "ipv6"
        "#;
        assert!(matches!(err(text), ConfigError::DialRequiresIpv4 { .. }));
    }

    #[test]
    fn wol_port_zero_rejected() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            wol = true
            wol_ports = [0]
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn duplicate_wol_port_rejected() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            wol = true
            wol_ports = [7, 7]
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn empty_wol_ports_rejected() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            wol = true
            wol_ports = []
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn wol_port_out_of_range_rejected() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            wol = true
            wol_ports = [70000]
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn invalid_mac() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            mdns = true
            macs = ["zz:zz:zz:zz:zz:zz"]
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn invalid_address_family() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            mdns = true
            address_family = "ipv5"
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn unknown_reflector_key_rejected() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            mdns = true
            typo = true
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn unknown_top_level_key_rejected() {
        let text = r#"
            log_levle = "info"

            [reflectors.x]
            source_if = "a"
            target_if = "b"
            mdns = true
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn top_level_reflector_table_is_rejected() {
        // Reflectors must be nested under [reflectors.<name>], not top-level tables.
        let text = r#"
            [tv]
            source_if = "a"
            target_if = "b"
            mdns = true
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn empty_file_reflector_key_rejected() {
        let text = r#"
            [reflectors.""]
            source_if = "a"
            target_if = "b"
            mdns = true
        "#;
        assert!(matches!(err(text), ConfigError::EmptyReflectorName { .. }));
    }

    #[test]
    fn whitespace_file_reflector_key_rejected() {
        let text = r#"
            [reflectors."   "]
            source_if = "a"
            target_if = "b"
            mdns = true
        "#;
        assert!(matches!(err(text), ConfigError::EmptyReflectorName { .. }));
    }

    #[test]
    fn conflicting_mdns_reflectors_rejected() {
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            mdns = true
        "#;
        assert!(matches!(
            err(text),
            ConfigError::ConflictingReflectors {
                protocol: Protocol::Mdns,
                ..
            }
        ));
    }

    #[test]
    fn conflicting_wsd_reflectors_rejected() {
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "cams"
            wsd = true

            [reflectors.b]
            source_if = "lan"
            target_if = "cams"
            wsd = true
        "#;
        assert!(matches!(
            err(text),
            ConfigError::ConflictingReflectors {
                protocol: Protocol::Wsd,
                ..
            }
        ));
    }

    #[test]
    fn udp_relays_conflict_on_a_shared_port_and_destination() {
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [9003, 9004]
            udp_groups = ["239.255.90.90"]
            udp_broadcast = true

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [9004]
            udp_groups = ["239.255.90.90"]
        "#;
        assert!(matches!(
            err(text),
            ConfigError::ConflictingReflectors {
                protocol: Protocol::Udp,
                ..
            }
        ));
    }

    #[test]
    fn udp_relays_on_one_port_with_disjoint_destinations_coexist() {
        let cfg = from_toml(
            r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [9003]
            udp_broadcast = true

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [9003]
            udp_groups = ["239.255.90.90"]
            "#,
        )
        .unwrap();
        assert_eq!(cfg.reflectors.len(), 2);
    }

    #[test]
    fn udp_relay_on_a_protocols_group_conflicts_with_it() {
        // The relay on 5353 would carry mDNS a second time; the conflict names mDNS.
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [5353]
            udp_groups = ["224.0.0.251"]
        "#;
        assert!(matches!(
            err(text),
            ConfigError::ConflictingReflectors {
                protocol: Protocol::Mdns,
                ..
            }
        ));
    }

    #[test]
    fn udp_relay_on_a_protocols_group_conflicts_either_way_round() {
        // mDNS relays responses iot -> lan whatever the entry's direction.
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true

            [reflectors.b]
            source_if = "iot"
            target_if = "lan"
            udp_ports = [5353]
            udp_groups = ["224.0.0.251"]
        "#;
        assert!(matches!(
            err(text),
            ConfigError::ConflictingReflectors {
                protocol: Protocol::Mdns,
                ..
            }
        ));
    }

    #[test]
    fn macs_never_separate_a_discovery_protocol_from_a_udp_relay() {
        // Queries from any client are relayed regardless of `macs`.
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:01"]

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [5353]
            udp_groups = ["224.0.0.251"]
        "#;
        assert!(matches!(
            err(text),
            ConfigError::ConflictingReflectors {
                protocol: Protocol::Mdns,
                ..
            }
        ));
    }

    #[test]
    fn udp_relay_on_a_wol_port_in_the_other_direction_coexists() {
        // Wake-on-LAN relays source -> target only.
        let cfg = from_toml(
            r#"
            [reflectors.wake]
            source_if = "lan"
            target_if = "iot"
            wol = true

            [reflectors.relay]
            source_if = "iot"
            target_if = "lan"
            udp_ports = [9]
            udp_broadcast = true
            "#,
        )
        .unwrap();
        assert_eq!(cfg.reflectors.len(), 2);
    }

    #[test]
    fn udp_relay_off_a_protocols_groups_coexists_with_it() {
        let cfg = from_toml(
            r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [5353]
            udp_broadcast = true
            "#,
        )
        .unwrap();
        assert_eq!(cfg.reflectors.len(), 2);
    }

    #[test]
    fn udp_relay_on_a_wol_port_conflicts_in_a_family_wol_uses() {
        let text = r#"
            [reflectors.wake]
            source_if = "lan"
            target_if = "iot"
            wol = true

            [reflectors.relay]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [9]
            udp_broadcast = true
        "#;
        assert!(matches!(
            err(text),
            ConfigError::ConflictingReflectors {
                protocol: Protocol::Wol,
                ..
            }
        ));
        // An IPv4-only WoL entry never relays a v6 magic packet.
        let cfg = from_toml(
            r#"
            [reflectors.wake]
            source_if = "lan"
            target_if = "iot"
            address_family = "ipv4"
            wol = true

            [reflectors.relay]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [9]
            udp_groups = ["ff02::1"]
            "#,
        )
        .unwrap();
        assert_eq!(cfg.reflectors.len(), 2);
    }

    #[test]
    fn different_protocols_on_one_port_coexist() {
        // WoL admits only magic packets and SSDP only its own messages, so port 1900 shared
        // between them relays nothing twice.
        let cfg = from_toml(
            r#"
            [reflectors.wake]
            source_if = "lan"
            target_if = "iot"
            wol = true
            wol_ports = [1900]

            [reflectors.discovery]
            source_if = "lan"
            target_if = "iot"
            ssdp = true
            "#,
        )
        .unwrap();
        assert_eq!(cfg.reflectors.len(), 2);
    }

    #[test]
    fn udp_relays_on_disjoint_ports_coexist() {
        let cfg = from_toml(
            r#"
            [reflectors.roon]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [9003]
            udp_broadcast = true

            [reflectors.squeezebox]
            source_if = "lan"
            target_if = "iot"
            udp_ports = [3483]
            udp_broadcast = true
            "#,
        )
        .unwrap();
        assert_eq!(cfg.reflectors.len(), 2);
    }

    #[test]
    fn bidirectional_conflicts_with_the_reverse_entry() {
        // a relays both ways, so b's iot->lan leg duplicates a's second leg.
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            bidirectional = true

            [reflectors.b]
            source_if = "iot"
            target_if = "lan"
            mdns = true
        "#;
        assert!(matches!(
            err(text),
            ConfigError::ConflictingReflectors {
                protocol: Protocol::Mdns,
                ..
            }
        ));
    }

    #[test]
    fn bidirectional_entries_on_different_pairs_do_not_conflict() {
        let cfg = from_toml(
            r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            bidirectional = true

            [reflectors.b]
            source_if = "lan"
            target_if = "guest"
            mdns = true
            bidirectional = true
            "#,
        )
        .unwrap();
        assert_eq!(cfg.reflectors.len(), 2);
    }

    #[test]
    fn reverse_direction_does_not_conflict() {
        // lan->iot and iot->lan reflect opposite directions; not a duplicate.
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true

            [reflectors.b]
            source_if = "iot"
            target_if = "lan"
            mdns = true
        "#;
        assert!(from_toml(text).is_ok());
    }

    #[test]
    fn different_protocols_do_not_conflict() {
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            wol = true
        "#;
        assert!(from_toml(text).is_ok());
    }

    #[test]
    fn distinct_macs_do_not_conflict() {
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:01"]

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:02"]
        "#;
        assert!(from_toml(text).is_ok());
    }

    #[test]
    fn omitted_macs_conflicts_with_any() {
        // An absent MAC filter matches any device, so it overlaps a specific one.
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:01"]

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            mdns = true
        "#;
        assert!(matches!(
            err(text),
            ConfigError::ConflictingReflectors {
                protocol: Protocol::Mdns,
                ..
            }
        ));
    }

    #[test]
    fn macs_list_parses() {
        let cfg = from_toml(
            r#"
            [reflectors.tv]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:01", "00:00:00:00:00:02"]
            "#,
        )
        .unwrap();
        let macs = cfg.reflectors[0].macs.as_ref().unwrap();
        assert_eq!(macs.len(), 2);
        assert!(macs.contains(&"00:00:00:00:00:01".parse().unwrap()));
        assert!(macs.contains(&"00:00:00:00:00:02".parse().unwrap()));
    }

    #[test]
    fn legacy_mac_field_is_now_unknown() {
        // `mac` was replaced by `macs` in 0.9.0; deny_unknown_fields rejects the old key.
        let text = r#"
            [reflectors.tv]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            mac = "02:42:ac:11:00:09"
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn empty_macs_list_rejected() {
        let text = r#"
            [reflectors.tv]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = []
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn overlapping_macs_sets_conflict() {
        // The two allow-sets share 00:..:02, so both would reflect that device's mDNS.
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:01", "00:00:00:00:00:02"]

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:02", "00:00:00:00:00:03"]
        "#;
        assert!(matches!(
            err(text),
            ConfigError::ConflictingReflectors {
                protocol: Protocol::Mdns,
                ..
            }
        ));
    }

    #[test]
    fn disjoint_macs_sets_do_not_conflict() {
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:01", "00:00:00:00:00:02"]

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:03", "00:00:00:00:00:04"]
        "#;
        assert!(from_toml(text).is_ok());
    }

    #[test]
    fn disjoint_address_families_do_not_conflict() {
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            address_family = "ipv4"

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            address_family = "ipv6"
        "#;
        assert!(from_toml(text).is_ok());
    }

    #[test]
    fn overlapping_wol_ports_conflict() {
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            wol = true
            wol_ports = [7, 9]

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            wol = true
            wol_ports = [9, 4000]
        "#;
        assert!(matches!(
            err(text),
            ConfigError::ConflictingReflectors {
                protocol: Protocol::Wol,
                ..
            }
        ));
    }

    #[test]
    fn disjoint_wol_ports_do_not_conflict() {
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            wol = true
            wol_ports = [7, 9]

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            wol = true
            wol_ports = [4000]
        "#;
        assert!(from_toml(text).is_ok());
    }
}
