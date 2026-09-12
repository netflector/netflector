//! Configuration loading and validation.
//!
//! TOML and the environment both deserialize into the raw form (`RawConfig`/`RawReflector`),
//! which is then validated into [`Config`].
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Wol {
    pub(crate) ports: PortList,
}

const WOL_DEFAULT_PORTS: [NonZeroU16; 2] =
    [NonZeroU16::new(7).unwrap(), NonZeroU16::new(9).unwrap()];

impl Wol {
    fn default_ports() -> PortList {
        PortList::try_from(WOL_DEFAULT_PORTS.to_vec()).expect("two distinct ports")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UdpRelay {
    pub(crate) ports: PortList,
    /// Multicast groups to join and relay on those ports.
    pub(crate) groups: Option<GroupList>,
    pub(crate) broadcast: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ssdp {
    pub(crate) dial: bool,
}

/// One reflector: bridges `source_if` → `target_if` for the enabled protocols.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reflector {
    pub(crate) name: ReflectorName,
    pub(crate) source_if: InterfaceName,
    /// Never equal to `source_if`.
    pub(crate) target_if: InterfaceName,
    /// The hosts behind `source_if` / `target_if` when that interface has no broadcast domain:
    /// a group or broadcast re-emitted there goes to each of them as unicast instead.
    pub(crate) source_peers: Option<PeerList>,
    pub(crate) target_peers: Option<PeerList>,
    /// Device allow-filter; `None` matches any device.
    pub(crate) macs: Option<MacSet>,
    pub(crate) address_family: AddressFamily,
    pub(crate) wol: Option<Wol>,
    pub(crate) mdns: bool,
    pub(crate) ssdp: Option<Ssdp>,
    pub(crate) wsd: bool,
    pub(crate) bidirectional: bool,
    pub(crate) udp: Option<UdpRelay>,
}

impl Reflector {
    /// The second leg of a bidirectional entry.
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Config {
    pub(crate) debug_memory_interval: Option<Duration>,
    pub(crate) counter_interval: Option<Duration>,
    pub(crate) reflectors: Vec<Reflector>,
}

impl Config {
    /// Environment globals override the file's; reflectors from both sources are combined.
    ///
    /// # Errors
    /// Any [`ConfigError`]: malformed TOML, a bad environment variable, or a failed validation rule.
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

/// One year. Beyond this is a typo, and a value large enough to overflow the reporter's
/// `Instant + Duration` deadline would panic at startup.
const MAX_INTERVAL_SECS: u64 = 60 * 60 * 24 * 365;

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

/// Only the top-level `log_level`, and no `deny_unknown_fields` on purpose: [`resolve_log_level`]
/// must not trip on the reflector tables.
#[derive(Deserialize)]
struct LogLevelProbe {
    #[serde(default)]
    log_level: Option<LogLevel>,
}

/// Takes a `Path` so a non-UTF-8 path (valid on Unix) still reads; only the error message renders
/// it lossily.
pub(crate) fn read_config_file(path: &Path) -> Result<String, ConfigError> {
    std::fs::read_to_string(path).map_err(|source| ConfigError::ReadFile {
        path: path.display().to_string(),
        source,
    })
}

/// The log level alone, resolved before the full parse so the logger can be raised to the
/// configured verbosity while the rest of loading runs. Environment overrides the file, which
/// overrides the default. Reads nothing but `NETFLECTOR_LOG_LEVEL` and the file's top-level
/// `log_level`, so a reflector error surfaces (logged) from the full parse rather than here.
///
/// # Errors
/// [`ConfigError::Parse`] for malformed TOML, [`ConfigError::EnvBadValue`] for a bad
/// `NETFLECTOR_LOG_LEVEL`.
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
