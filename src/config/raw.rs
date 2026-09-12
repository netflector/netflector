//! The raw, deserialized configuration, before validation.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::error::ConfigError;
use super::value::{
    AddressFamily, GroupList, InterfaceName, LogLevel, PeerList, PortList, ReflectorName,
};
use crate::net::mac::MacSet;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawConfig {
    /// Never read: the level is resolved by [`resolve_log_level`](super::resolve_log_level) before
    /// the full parse. The field only keeps the key in the schema.
    #[serde(rename = "log_level")]
    pub(super) _log_level: Option<LogLevel>,
    /// Seconds between memory-footprint diagnostic reports; `0` or absent disables them.
    pub(super) debug_memory_interval_secs: Option<u64>,
    /// Seconds between periodic counter summaries; `0` or absent disables them.
    pub(super) counters_interval_secs: Option<u64>,
    #[serde(default)]
    pub(super) reflectors: BTreeMap<String, RawReflector>,
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "independent toggles, not a state machine"
)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawReflector {
    /// Set only by the environment (`NETFLECTOR_<tag>_NAME`); a file reflector is named by its
    /// table key.
    #[serde(skip)]
    pub(super) name: Option<ReflectorName>,
    pub(super) source_if: InterfaceName,
    pub(super) target_if: InterfaceName,
    pub(super) source_peers: Option<PeerList>,
    pub(super) target_peers: Option<PeerList>,
    pub(super) macs: Option<MacSet>,
    #[serde(default)]
    pub(super) address_family: AddressFamily,
    #[serde(default)]
    pub(super) wol: bool,
    pub(super) wol_ports: Option<PortList>,
    #[serde(default)]
    pub(super) mdns: bool,
    #[serde(default)]
    pub(super) ssdp: bool,
    #[serde(default)]
    pub(super) dial: bool,
    #[serde(default)]
    pub(super) wsd: bool,
    #[serde(default)]
    pub(super) bidirectional: bool,
    pub(super) udp_ports: Option<PortList>,
    pub(super) udp_groups: Option<GroupList>,
    #[serde(default)]
    pub(super) udp_broadcast: bool,
}

impl RawConfig {
    pub(super) fn merge_env(&mut self, env: RawConfig) -> Result<(), ConfigError> {
        self.debug_memory_interval_secs = env
            .debug_memory_interval_secs
            .or(self.debug_memory_interval_secs);
        self.counters_interval_secs = env.counters_interval_secs.or(self.counters_interval_secs);
        for (name, reflector) in env.reflectors {
            // An env tag is already lowercase and unpadded; a TOML table key is verbatim, so
            // `[reflectors.TV]` and `NETFLECTOR_TV_*` must still collide.
            if self
                .reflectors
                .keys()
                .any(|k| k.trim().eq_ignore_ascii_case(&name))
            {
                return Err(ConfigError::DuplicateReflector { name });
            }
            self.reflectors.insert(name, reflector);
        }
        Ok(())
    }
}
