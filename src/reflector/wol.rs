//! Wake-on-LAN reflector: re-broadcasts magic packets seen on the source interface onto the
//! target interface, so a wake sent on one link reaches a sleeping device on another.
//!
//! A magic packet is 6 bytes of `0xFF` followed by the target device's MAC repeated 16 times
//! (102 bytes). A trailing `SecureOn` password, if present, is forwarded verbatim. The reflector
//! validates the payload, then re-emits it on the target interface as a v4 limited broadcast or
//! v6 link-local all-nodes multicast, sourced from that interface's own address.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::config::{AddressFamily, Reflector};
use crate::dispatch::{
    CaptureKey, Filter, MessageType, Outcome, PacketDispatcher, PacketHandler, PortSet,
};
use crate::logging::log_rate;
use crate::net::mac::{MacAddr, MacSet};
use crate::net::packet::Packet;
use crate::reactor::Reactor;

use super::{BuildError, InterfaceMap, WARN_WINDOW, egress_sources, missing_required_family};

const PREFIX_LEN: usize = 6;
const MAC_LEN: usize = 6;
const MAC_REPS: usize = 16;
/// Smallest valid magic packet: prefix plus the 16 MAC repetitions.
const MAGIC_LEN: usize = PREFIX_LEN + MAC_REPS * MAC_LEN;

/// IPv6 link-local all-nodes group (`ff02::1`), the v6 equivalent of the IPv4 limited broadcast.
const V6_ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// Built Wake-on-LAN reflector: re-emits each validated magic packet on its `egress` interface.
/// One handler covers all configured ports.
struct WolReflector {
    egress: CaptureKey,
    /// Optional device allow-set; `None` reflects a wake for any device.
    target_macs: Option<MacSet>,
    /// IP-version policy: which families this reflector re-emits.
    family: AddressFamily,
}

impl PacketHandler for WolReflector {
    fn on_packet(
        &mut self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) -> Outcome {
        let Some(mac) = magic_packet_mac(packet.payload) else {
            log::debug!("WoL: ignoring non-magic packet from {}", packet.source);
            return Outcome::Filtered;
        };
        if !wake_allowed(mac, self.target_macs.as_ref()) {
            log::debug!(
                "WoL: ignoring wake for {mac} from {}: not in the configured device set",
                packet.source
            );
            return Outcome::Filtered;
        }
        let Some(dst) = wol_destination(self.family, packet) else {
            log::debug!(
                "WoL: {} is not a handled address family; ignoring",
                packet.source
            );
            return Outcome::Filtered;
        };
        // A family the egress can't currently source is a transient drop (address loss): Stalled,
        // not a genuine send failure.
        if !egress_sources(dispatcher, self.egress, dst) {
            log::debug!(
                "WoL: egress has no source for {dst} yet; dropping wake from {}",
                packet.source
            );
            return Outcome::Stalled(MessageType::WakeOnLan);
        }
        match dispatcher.send_udp_group(
            self.egress,
            dst,
            packet.source.port(),
            packet.ttl,
            packet.payload,
        ) {
            Ok(()) => {
                log::debug!("reflected WoL packet from {} to {dst}", packet.source);
                Outcome::Reflected(MessageType::WakeOnLan)
            }
            Err(e) => {
                log_rate!(
                    log::Level::Warn,
                    WARN_WINDOW,
                    "WoL: cannot reflect packet from {} to {dst}: {e}",
                    packet.source
                );
                Outcome::Dropped(MessageType::WakeOnLan)
            }
        }
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

/// Link-wide destination a captured magic `packet` re-emits to under `family`: the IPv4 limited
/// broadcast or the IPv6 link-local all-nodes group, at the captured destination port. `None` when
/// `family` doesn't handle the packet's IP version.
fn wol_destination(family: AddressFamily, packet: &Packet) -> Option<SocketAddr> {
    match packet.dest {
        SocketAddr::V4(dest) if family.uses_ipv4() => {
            Some(SocketAddr::from((Ipv4Addr::BROADCAST, dest.port())))
        }
        SocketAddr::V6(dest) if family.uses_ipv6() => {
            Some(SocketAddr::from((V6_ALL_NODES, dest.port())))
        }
        _ => None,
    }
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
        Box::new(WolReflector {
            egress,
            target_macs: reflector.macs.clone(),
            family: reflector.address_family,
        }),
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

    /// A packet whose `dest` (the captured Wake-on-LAN port) drives the re-emit destination.
    fn packet_to(dest: &str) -> Packet<'static> {
        Packet {
            source: "10.0.0.1:5".parse().unwrap(),
            dest: dest.parse().unwrap(),
            ttl: 64,
            dst_mac: None,
            src_mac: None,
            payload: b"",
        }
    }

    #[test]
    fn wol_destination_targets_the_link_for_used_families() {
        let v4 = packet_to("10.0.0.2:9");
        let v6 = packet_to("[fe80::2]:9");
        // Dual handles both: v4 -> limited broadcast, v6 -> ff02::1, at the captured dst port.
        assert_eq!(
            wol_destination(AddressFamily::Dual, &v4),
            Some("255.255.255.255:9".parse().unwrap())
        );
        assert_eq!(
            wol_destination(AddressFamily::Dual, &v6),
            Some("[ff02::1]:9".parse().unwrap())
        );
        // A single-family policy ignores the other family.
        assert_eq!(wol_destination(AddressFamily::Ipv4, &v6), None);
        assert_eq!(wol_destination(AddressFamily::Ipv6, &v4), None);
    }
}
