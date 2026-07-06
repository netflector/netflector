//! The reflectors: per-protocol packet handlers that re-emit matched traffic on the opposite
//! interface. Each implements the dispatcher's `PacketHandler` and is registered by `run()`
//! from config.

pub(crate) mod dial;
pub(crate) mod mdns;
pub(crate) mod ssdp;
pub(crate) mod wol;
pub(crate) mod wsd;

mod search;
mod simple;

pub(crate) use search::SearchReflector;
pub(crate) use simple::SimpleReflector;

use std::fmt;
use std::net::SocketAddr;

use thiserror::Error;

use crate::config::AddressFamily;
use crate::dispatch::{CaptureKey, MessageType, PacketDispatcher};
use crate::interface::InterfaceAddresses;
use crate::reactor::Reactor;

/// A reflector's verdict on a captured payload, from its protocol's classifier. `Reflect`/`Skip` carry
/// the message's own [`MessageType`] (the packet's *intrinsic* type) so the handler can tally it. See
/// [`From`] impls like `From<MdnsKind>` in each protocol reflector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// A message for this direction. Re-emit it.
    Reflect(MessageType),
    /// A message for the *other* direction; drop it silently. Dropping the opposite direction is
    /// the loop-breaker (atop the capture's own-egress drop): a reflected query re-emitted on the
    /// egress is still a query, which the egress side's response-only reflector skips.
    Skip(MessageType),
    /// Not a recognizable protocol message on this dedicated group. Drop it with a debug log.
    Junk,
}

/// Transforms a datagram's payload before it is re-emitted: the SSDP DIAL `LOCATION` rewrite, applied
/// on both the advertisement direction and each search session's reply. The returned slice is either
/// `payload` verbatim or a rewrite held in the implementor's own reused scratch. The `Fn` traits can't
/// express that lending signature, which is why this is a trait rather than a closure.
pub(crate) trait ReplyRewrite {
    fn rewrite<'a>(
        &'a mut self,
        payload: &'a [u8],
        egress: CaptureKey,
        dispatcher: &mut PacketDispatcher,
        reactor: &mut Reactor,
    ) -> &'a [u8];
}

/// The identity transform: forward the payload verbatim. A ZST for the reflectors (mDNS, WSD, and SSDP
/// without DIAL) that re-emit unchanged.
pub(crate) struct NoRewrite;

impl ReplyRewrite for NoRewrite {
    fn rewrite<'a>(
        &'a mut self,
        payload: &'a [u8],
        _egress: CaptureKey,
        _dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) -> &'a [u8] {
        payload
    }
}

/// A concrete IP version: the family a reflector requires of an interface. Distinct from the
/// config's `AddressFamily` policy (which may name both at once).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IpFamily {
    V4,
    V6,
}

impl fmt::Display for IpFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        })
    }
}

/// Maps each configured interface name to the capture `run()` opened for it, so a reflector's
/// `source_if` / `target_if` resolve to the ingress / egress [`CaptureKey`]s. `run()` opens one
/// capture per distinct interface and records it here; the per-protocol `build` functions look
/// names up. A plain `Vec`: only ever a handful of interfaces.
#[derive(Default)]
pub(crate) struct InterfaceMap(Vec<(String, CaptureKey)>);

impl InterfaceMap {
    /// Record the capture `run()` opened for `name`.
    pub(crate) fn insert(&mut self, name: String, key: CaptureKey) {
        self.0.push((name, key));
    }

    /// The capture key recorded for `name`, or `None` if none was.
    pub(crate) fn key_for(&self, name: &str) -> Option<CaptureKey> {
        self.0.iter().find(|(n, _)| n == name).map(|&(_, key)| key)
    }

    /// The capture key for `name`, or [`BuildError::UnknownInterface`]. Build functions call this
    /// to resolve a configured interface name to its capture.
    pub(crate) fn require(&self, name: &str) -> Result<CaptureKey, BuildError> {
        self.key_for(name)
            .ok_or_else(|| BuildError::UnknownInterface(name.to_owned()))
    }
}

/// Why a reflector could not be built from its config.
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum BuildError {
    /// Names a `source_if` / `target_if` that `run()` opened no capture for. A wiring bug.
    #[error("no capture for interface \"{0}\"")]
    UnknownInterface(String),
    /// An interface can't currently send a family the reflector requires, so it would reflect
    /// nothing for that family. A startup failure rather than a silent half-run. For a
    /// bidirectional reflector (mDNS/SSDP) the named interface may be the source or the target.
    #[error("interface \"{interface}\" cannot send {family}, required by the reflector")]
    RequiredFamilyUnavailable { interface: String, family: IpFamily },
}

/// Whether `egress` currently has a source address of `dst`'s family, which `send_udp_group` needs
/// to build the frame. The per-packet gate a reflector applies before re-emitting, so a family
/// whose address has gone away is dropped rather than mis-sent.
fn egress_sources(dispatcher: &PacketDispatcher, egress: CaptureKey, dst: SocketAddr) -> bool {
    dispatcher
        .egress_addrs(egress)
        .is_some_and(|addrs| match dst {
            SocketAddr::V4(_) => addrs.has_v4(),
            SocketAddr::V6(_) => addrs.has_v6(),
        })
}

/// The family `addrs` cannot source but `family` requires, if any: the startup check's verdict.
/// `None` means every required family is available (a v6-best-effort `Default` with no v6 passes).
fn missing_required_family(family: AddressFamily, addrs: &InterfaceAddresses) -> Option<IpFamily> {
    if family.requires_ipv4() && !addrs.has_v4() {
        Some(IpFamily::V4)
    } else if family.requires_ipv6() && !addrs.has_v6() {
        Some(IpFamily::V6)
    } else {
        None
    }
}

/// Enforce that a bidirectional reflector can source every required family on BOTH interfaces.
/// mDNS and SSDP re-emit on the source *and* the target, so a family required by `address_family`
/// must be sendable on each. Checks each required family on both interfaces (v4 before v6, the
/// single-interface policy order) and blames the side that actually lacks it: the source when it's
/// the one missing, otherwise the target.
///
/// # Errors
/// [`BuildError::RequiredFamilyUnavailable`] naming the interface and the family it can't send.
fn require_bidirectional_families(
    dispatcher: &PacketDispatcher,
    address_family: AddressFamily,
    source: CaptureKey,
    source_if: &str,
    target: CaptureKey,
    target_if: &str,
) -> Result<(), BuildError> {
    let src = dispatcher.egress_addrs(source).copied().unwrap_or_default();
    let tgt = dispatcher.egress_addrs(target).copied().unwrap_or_default();
    let unavailable = |family, missing_on_source| BuildError::RequiredFamilyUnavailable {
        interface: if missing_on_source {
            source_if
        } else {
            target_if
        }
        .to_owned(),
        family,
    };
    if address_family.requires_ipv4() && !(src.has_v4() && tgt.has_v4()) {
        return Err(unavailable(IpFamily::V4, !src.has_v4()));
    }
    if address_family.requires_ipv6() && !(src.has_v6() && tgt.has_v6()) {
        return Err(unavailable(IpFamily::V6, !src.has_v6()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn missing_required_family_enforces_the_requires_policy() {
        let none = InterfaceAddresses::default();
        let v4_only = InterfaceAddresses::new(None, Some(Ipv4Addr::LOCALHOST), None, None);
        // Default requires v4 only: a v4-less egress fails on v4, a v6-less one passes.
        assert_eq!(
            missing_required_family(AddressFamily::Default, &none),
            Some(IpFamily::V4)
        );
        assert_eq!(
            missing_required_family(AddressFamily::Default, &v4_only),
            None
        );
        // Dual requires both: a v4-only egress still misses v6.
        assert_eq!(
            missing_required_family(AddressFamily::Dual, &v4_only),
            Some(IpFamily::V6)
        );
        // Ipv6 requires v6.
        assert_eq!(
            missing_required_family(AddressFamily::Ipv6, &v4_only),
            Some(IpFamily::V6)
        );
    }
}
