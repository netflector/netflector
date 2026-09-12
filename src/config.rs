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
//! Cross-field rules live in the `TryFrom` conversions here, the cross-reflector ones in
//! `conflict`; sources are combined in [`Config::from_sources`].
//!
//! Reflectors nest under `[reflectors.<name>]` rather than top-level tables to keep
//! the deserializer off `#[serde(flatten)]`, which would discard the line/column of
//! every value error.

mod conflict;
mod env;
mod error;
mod raw;
mod value;

pub(crate) use self::error::ConfigError;
pub(crate) use self::value::{
    AddressFamily, GroupList, InterfaceName, LogLevel, PeerList, PortList, ReflectorName,
};

use std::net::IpAddr;
use std::num::NonZeroU16;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use serde::Deserialize;

use self::conflict::check_conflicts;
use self::raw::{RawConfig, RawReflector};
use crate::net::mac::MacSet;

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
    /// The hosts behind `source_if` / `target_if` when that interface has no broadcast domain:
    /// a group or broadcast re-emitted there goes to each of them as unicast instead.
    pub(crate) source_peers: Option<PeerList>,
    pub(crate) target_peers: Option<PeerList>,
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
            source_peers: self.target_peers.clone(),
            target_peers: self.source_peers.clone(),
            ..self.clone()
        }
    }
}

/// The first listed peer of a family the entry's `address_family` does not use, if any.
fn peer_of_unused_family(raw: &RawReflector) -> Option<IpAddr> {
    [&raw.source_peers, &raw.target_peers]
        .into_iter()
        .flat_map(|peers| peers.as_deref().unwrap_or(&[]))
        .find(|peer| !raw.address_family.uses(**peer))
        .copied()
}

/// The peers parameter an mDNS entry's answers would go to, if any: `source_peers`, or
/// `target_peers` once the entry is bidirectional. A client takes a unicast answer only to a
/// question it asked with the unicast-response bit (RFC 6762 §5.4), so such peers get nothing.
fn mdns_answers_to_peers(raw: &RawReflector) -> Option<&'static str> {
    if !raw.mdns {
        return None;
    }
    if raw.source_peers.is_some() {
        Some("source_peers")
    } else if raw.bidirectional && raw.target_peers.is_some() {
        Some("target_peers")
    } else {
        None
    }
}

/// The peers checks: every peer of a family the entry uses, and none where an mDNS answer goes.
fn check_peers(raw: &RawReflector, name: &ReflectorName) -> Result<(), ConfigError> {
    if let Some(peer) = peer_of_unused_family(raw) {
        return Err(ConfigError::PeerFamily {
            name: name.clone(),
            peer,
        });
    }
    if let Some(param) = mdns_answers_to_peers(raw) {
        return Err(ConfigError::MdnsAnswersToPeers {
            name: name.clone(),
            param,
        });
    }
    Ok(())
}

impl TryFrom<(String, RawReflector)> for Reflector {
    type Error = ConfigError;

    fn try_from((key, mut raw): (String, RawReflector)) -> Result<Self, ConfigError> {
        // Env `NAME` override is already validated; the identity key (file table
        // key / env tag) is validated here.
        let name = match raw.name.take() {
            Some(name) => name,
            None => ReflectorName::from_str(&key)
                .map_err(|_| ConfigError::EmptyReflectorName { key: key.clone() })?,
        };
        check_peers(&raw, &name)?;

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
                    .find(|group| !raw.address_family.uses(**group));
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
            source_peers: raw.source_peers,
            target_peers: raw.target_peers,
            macs: raw.macs,
            address_family: raw.address_family,
            wol,
            mdns: raw.mdns,
            ssdp,
            wsd: raw.wsd,
            bidirectional: raw.bidirectional,
            udp,
        };
        if let Some((protocol, port)) = reflector.relay_duplicates() {
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

#[cfg(test)]
mod tests;
