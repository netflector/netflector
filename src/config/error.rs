//! Configuration error types.

use std::fmt;
use std::net::IpAddr;
use std::num::NonZeroU16;

use thiserror::Error;

use super::conflict::Protocol;
use super::value::{
    InterfaceName, ParseAddressFamilyError, ParseInterfaceNameError, ParseLogLevelError,
    ParseReflectorNameError, ReflectorName,
};
use crate::net::mac::MacAddr;
use crate::unique_list::ListError;

/// Value-level TOML errors (wrong type, bad port, unparseable MAC) arrive as
/// [`ConfigError::Parse`]; the other variants are rules the deserializer cannot express.
#[derive(Debug, Error)]
pub(crate) enum ConfigError {
    #[error("invalid configuration: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("cannot read config file \"{path}\": {source}")]
    ReadFile {
        path: String,
        source: std::io::Error,
    },

    #[error("must define at least one reflector")]
    NoReflectors,

    #[error("reflector name \"{key}\" is empty or whitespace-only")]
    EmptyReflectorName { key: String },

    #[error("reflector \"{name}\" source_if and target_if must differ (both are \"{value}\")")]
    SameInterface {
        name: ReflectorName,
        value: InterfaceName,
    },

    #[error("reflector \"{name}\" enables no protocol (set wol, mdns, ssdp, wsd, or udp_ports)")]
    NoProtocol { name: ReflectorName },

    #[error("reflector \"{name}\" sets udp_groups or udp_broadcast but not udp_ports")]
    UdpRelayWithoutPorts { name: ReflectorName },

    #[error("reflector \"{name}\" sets udp_ports but neither udp_groups nor udp_broadcast")]
    UdpRelayNoDestination { name: ReflectorName },

    #[error(
        "reflector \"{name}\" lists UDP group {group}, whose family its address_family does not use"
    )]
    UdpGroupFamily { name: ReflectorName, group: IpAddr },

    #[error("reflector \"{name}\" lists peer {peer}, whose family its address_family does not use")]
    PeerFamily { name: ReflectorName, peer: IpAddr },

    #[error("reflector \"{name}\" sets udp_broadcast but its address_family has no IPv4")]
    UdpBroadcastFamily { name: ReflectorName },

    #[error(
        "reflector \"{name}\" would relay {protocol} on port {port} twice, through udp_ports as well"
    )]
    UdpRelayDuplicates {
        name: ReflectorName,
        port: u16,
        protocol: Protocol,
    },

    #[error("reflector \"{name}\" sets wol_ports but does not enable wol")]
    WolPortsWithoutWol { name: ReflectorName },

    #[error(
        "reflector \"{name}\" lists macs but enables only the UDP relay, which does not apply them"
    )]
    MacsUnused { name: ReflectorName },

    #[error("reflector \"{name}\" sets dial but does not enable ssdp")]
    DialWithoutSsdp { name: ReflectorName },

    #[error(
        "reflector \"{name}\" enables mdns with {param}, but a client takes a unicast mDNS answer \
         only to a question it asked with the unicast-response bit"
    )]
    MdnsAnswersToPeers {
        name: ReflectorName,
        param: &'static str,
    },

    #[error(
        "reflector \"{name}\" enables dial but the address family has no IPv4 (DIAL is IPv4-only)"
    )]
    DialRequiresIpv4 { name: ReflectorName },

    #[error("reflector \"{name}\" is defined in both the configuration file and the environment")]
    DuplicateReflector { name: String },

    #[error(
        "reflector name \"{name}\" is used by more than one reflector (names are compared case-insensitively and trimmed)"
    )]
    DuplicateReflectorName { name: ReflectorName },

    #[error(
        "reflectors \"{first}\" and \"{second}\" both reflect {protocol} on {source_if} -> {target_if} with overlapping MAC selection and address family"
    )]
    ConflictingReflectors {
        protocol: Protocol,
        first: ReflectorName,
        second: ReflectorName,
        source_if: InterfaceName,
        target_if: InterfaceName,
    },

    #[error("environment variable \"{var}\" is malformed (expected NETFLECTOR_<tag>_<param>)")]
    EnvMalformedVar { var: String },

    #[error(
        "environment variable \"{var}\" has invalid tag \"{tag}\" (tags must be non-empty and alphanumeric)"
    )]
    EnvInvalidTag { var: String, tag: String },

    #[error(
        "environment variable \"{var}\" uses a reserved tag (log, debug, and counters are globals)"
    )]
    EnvReservedTag { var: String },

    #[error("environment variable \"{var}\" sets unknown parameter \"{param}\"")]
    EnvUnknownParam { var: String, param: String },

    #[error(
        "environment variable \"{var}\" sets \"{param}\", which another variable already set \
         (names are case-insensitive)"
    )]
    EnvDuplicateParam { var: String, param: String },

    #[error("environment variable \"{var}\" has invalid value \"{value}\": {source}")]
    EnvBadValue {
        var: String,
        value: String,
        source: ParseValueError,
    },

    #[error("reflector \"{name}\" (from the environment) has no {field}")]
    EnvMissingField { name: String, field: RequiredField },

    #[error("{field} = {secs} is too large; the maximum is {max} seconds")]
    IntervalTooLarge {
        field: &'static str,
        secs: u64,
        max: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequiredField {
    SourceIf,
    TargetIf,
}

impl fmt::Display for RequiredField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SourceIf => "source_if",
            Self::TargetIf => "target_if",
        })
    }
}

/// The per-type parse errors, aggregated so [`ConfigError::EnvBadValue`] stays matchable in tests.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ParseValueError {
    #[error(transparent)]
    LogLevel(#[from] ParseLogLevelError),
    #[error(transparent)]
    AddressFamily(#[from] ParseAddressFamilyError),
    #[error(transparent)]
    Macs(#[from] ListError<MacAddr>),
    #[error(transparent)]
    Interface(#[from] ParseInterfaceNameError),
    #[error(transparent)]
    Ports(#[from] ListError<NonZeroU16>),
    #[error(transparent)]
    Addresses(#[from] ListError<IpAddr>),
    #[error(transparent)]
    ReflectorName(#[from] ParseReflectorNameError),
    #[error(transparent)]
    Bool(#[from] ParseBoolError),
    #[error(transparent)]
    Integer(#[from] std::num::ParseIntError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("expected true, false, 1, or 0")]
pub(crate) struct ParseBoolError;
