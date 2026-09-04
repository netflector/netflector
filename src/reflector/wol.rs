//! Wake-on-LAN reflector: re-broadcasts magic packets seen on the source interface onto the
//! target interface, so a wake sent on one link reaches a sleeping device on another.
//!
//! A magic packet is 6 bytes of `0xFF` followed by the target device's MAC repeated 16 times
//! (102 bytes). A trailing `SecureOn` password, if present, is forwarded verbatim. The
//! [`WakeClassifier`] validates the payload and applies the optional device allow-set and the
//! family policy; the shared [`SimpleReflector`] re-emits on the target interface link-wide (a v4
//! limited broadcast or v6 all-nodes multicast), sourced from that interface's own address at the
//! captured source port and TTL ([`Emit::captured`]).

use std::net::SocketAddr;

use crate::config::{AddressFamily, Reflector};
use crate::dispatch::{Filter, MessageType, PacketDispatcher, PortSet};
use crate::net::mac::{MacAddr, MacSet};
use crate::net::packet::Packet;

use super::{
    BuildError, Classify, Emit, InterfaceMap, SimpleReflector, Verdict, missing_required_family,
};

const PREFIX_LEN: usize = 6;
const MAC_LEN: usize = 6;
const MAC_REPS: usize = 16;
/// Smallest valid magic packet: prefix plus the 16 MAC repetitions.
const MAGIC_LEN: usize = PREFIX_LEN + MAC_REPS * MAC_LEN;

/// The Wake-on-LAN gate: a magic packet whose target MAC the optional allow-set admits, in a
/// family the policy handles. The family is gated here because the filter pins only the port, so
/// both families arrive.
struct WakeClassifier {
    /// Optional device allow-set; `None` admits a wake for any device.
    target_macs: Option<MacSet>,
    family: AddressFamily,
}

impl Classify for WakeClassifier {
    fn classify(&self, packet: &Packet) -> Verdict {
        let Some(mac) = magic_packet_mac(packet.payload) else {
            return Verdict::Junk;
        };
        if !wake_allowed(mac, self.target_macs.as_ref()) {
            log::debug!(
                "WoL: ignoring wake for {mac} from {}: not in the configured device set",
                packet.source
            );
            return Verdict::Excluded;
        }
        let handled = match packet.dest {
            SocketAddr::V4(_) => self.family.uses_ipv4(),
            SocketAddr::V6(_) => self.family.uses_ipv6(),
        };
        if !handled {
            log::debug!(
                "WoL: {} is not a handled address family; ignoring",
                packet.source
            );
            return Verdict::Excluded;
        }
        Verdict::Reflect(MessageType::WakeOnLan)
    }
}

/// The target MAC of the Wake-on-LAN magic packet opening `payload`: the `6×0xFF` prefix followed
/// by one MAC repeated 16 times. `None` when the structure doesn't match. Only the leading
/// [`MAGIC_LEN`] bytes are inspected; trailing bytes (a `SecureOn` password) are ignored here and
/// forwarded as-is by the caller.
fn magic_packet_mac(payload: &[u8]) -> Option<MacAddr> {
    let magic = payload.get(..MAGIC_LEN)?;
    if magic[..PREFIX_LEN] != [0xff; PREFIX_LEN] {
        return None;
    }
    // The other 15 repetitions must all equal the first; the prefix length leaves no remainder.
    let ([mac, repeats @ ..], []) = magic[PREFIX_LEN..].as_chunks::<MAC_LEN>() else {
        return None;
    };
    if repeats.iter().any(|rep| rep != mac) {
        return None;
    }
    Some(MacAddr::from(*mac))
}

/// Whether the optional `targets` allow-set admits a wake for `mac`.
fn wake_allowed(mac: MacAddr, targets: Option<&MacSet>) -> bool {
    targets.is_none_or(|targets| targets.contains(&mac))
}

/// Build the Wake-on-LAN reflector for `reflector` and register it on `dispatcher`. No-op when
/// Wake-on-LAN isn't enabled. Registers a single handler covering all configured ports, re-emitting
/// on the target interface.
///
/// # Errors
/// [`BuildError::UnknownInterface`] if no capture was opened for the source/target, or
/// [`BuildError::RequiredFamilyUnavailable`] if the target can't currently send a required family.
pub(crate) fn build(
    reflector: &Reflector,
    interfaces: &InterfaceMap,
    dispatcher: &mut PacketDispatcher,
) -> Result<(), BuildError> {
    let Some(wol) = &reflector.wol else {
        return Ok(());
    };
    let ingress = interfaces.require(reflector.source_if.as_str())?;
    let egress = interfaces.require(reflector.target_if.as_str())?;

    let addrs = dispatcher.egress_addrs(egress).copied().unwrap_or_default();
    if let Some(family) = missing_required_family(reflector.address_family, &addrs) {
        return Err(BuildError::RequiredFamilyUnavailable {
            interface: reflector.target_if.as_str().to_owned(),
            family,
        });
    }

    // One handler spans every configured port via its filter. The re-emit uses the captured
    // destination port, so a single reflector serves them all.
    let ports: PortSet = wol.ports.iter().map(|port| port.get()).collect();
    dispatcher.register(
        ingress,
        Filter {
            dst_port: Some(ports),
            ..Filter::default()
        },
        Box::new(SimpleReflector::new(
            egress,
            "WoL",
            "wake",
            WakeClassifier {
                target_macs: reflector.macs.clone(),
                family: reflector.address_family,
            },
            Emit::captured(),
        )),
    );
    log::info!(
        "WoL reflector \"{}\": {} -> {} on {} port(s)",
        reflector.name.as_str(),
        reflector.source_if.as_str(),
        reflector.target_if.as_str(),
        wol.ports.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::mac::MacAddr;

    const DEVICE: [u8; 6] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];

    /// A well-formed magic packet for `mac`, plus optional `trailer` (`SecureOn`) bytes.
    fn magic_packet(mac: [u8; 6], trailer: &[u8]) -> Vec<u8> {
        let mut p = vec![0xff; PREFIX_LEN];
        for _ in 0..MAC_REPS {
            p.extend_from_slice(&mac);
        }
        p.extend_from_slice(trailer);
        p
    }

    fn packet_with(payload: &[u8]) -> Packet<'_> {
        Packet {
            source: "10.0.0.1:5".parse().unwrap(),
            dest: "10.0.0.2:9".parse().unwrap(),
            ttl: 64,
            dst_mac: None,
            src_mac: None,
            payload,
        }
    }

    #[test]
    fn accepts_any_device_when_unfiltered() {
        let mac = magic_packet_mac(&magic_packet(DEVICE, &[])).unwrap();
        assert!(wake_allowed(mac, None));
    }

    #[test]
    fn accepts_a_secureon_trailer() {
        // Bytes past the 102 are a SecureOn password: ignored here, forwarded by the caller.
        let packet = magic_packet(DEVICE, &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(magic_packet_mac(&packet), Some(MacAddr::from(DEVICE)));
    }

    #[test]
    fn filters_to_the_configured_device() {
        let mac = magic_packet_mac(&magic_packet(DEVICE, &[])).unwrap();
        let allowed = MacSet::from(MacAddr::from(DEVICE));
        assert!(wake_allowed(mac, Some(&allowed)));
        let others = MacSet::from(MacAddr::from([0xaa; 6]));
        assert!(!wake_allowed(mac, Some(&others)));
    }

    #[test]
    fn filters_to_any_of_several_configured_devices() {
        let mac = magic_packet_mac(&magic_packet(DEVICE, &[])).unwrap();
        let set = MacSet::try_from(vec![MacAddr::from([0xaa; 6]), MacAddr::from(DEVICE)]).unwrap();
        assert!(wake_allowed(mac, Some(&set)));
        let disjoint =
            MacSet::try_from(vec![MacAddr::from([0xaa; 6]), MacAddr::from([0xbb; 6])]).unwrap();
        assert!(!wake_allowed(mac, Some(&disjoint)));
    }

    #[test]
    fn rejects_a_short_payload() {
        let packet = magic_packet(DEVICE, &[]);
        assert!(magic_packet_mac(&packet[..MAGIC_LEN - 1]).is_none());
        assert!(magic_packet_mac(&[]).is_none());
    }

    #[test]
    fn rejects_a_broken_prefix() {
        let mut packet = magic_packet(DEVICE, &[]);
        packet[0] = 0xfe;
        assert!(magic_packet_mac(&packet).is_none());
    }

    #[test]
    fn rejects_inconsistent_repetitions() {
        let mut packet = magic_packet(DEVICE, &[]);
        // Corrupt the 7th repetition so it no longer matches the first.
        packet[PREFIX_LEN + 6 * MAC_LEN] ^= 0xff;
        assert!(magic_packet_mac(&packet).is_none());
    }

    #[test]
    fn classifier_reflects_admitted_wakes_and_excludes_the_rest() {
        let magic = magic_packet(DEVICE, &[]);
        let any = WakeClassifier {
            target_macs: None,
            family: AddressFamily::Dual,
        };
        assert_eq!(
            any.classify(&packet_with(&magic)),
            Verdict::Reflect(MessageType::WakeOnLan)
        );
        // A device outside the allow-set is excluded (recognized, configured out), not junk.
        let others = WakeClassifier {
            target_macs: Some(MacSet::from(MacAddr::from([0xaa; 6]))),
            family: AddressFamily::Dual,
        };
        assert_eq!(others.classify(&packet_with(&magic)), Verdict::Excluded);
        // So is a family the policy doesn't handle: the port-only filter lets both families in.
        let v4_only = WakeClassifier {
            target_macs: None,
            family: AddressFamily::Ipv4,
        };
        let mut v6 = packet_with(&magic);
        v6.dest = "[fe80::2]:9".parse().unwrap();
        assert_eq!(v4_only.classify(&v6), Verdict::Excluded);
        assert_eq!(any.classify(&packet_with(b"not magic")), Verdict::Junk);
    }
}
