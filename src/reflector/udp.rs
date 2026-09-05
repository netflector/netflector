//! The transparent UDP relay: datagrams to the entry's ports, sent to a listed multicast group or,
//! when enabled, a broadcast, are re-emitted on the egress as sent, source ip:port and TTL included
//! ([`Emit::captured`]). It knows no protocol; the filter alone decides what crosses, so the
//! shared [`SimpleReflector`] runs with an admit-all classifier.

use crate::config::Reflector;
use crate::dispatch::{Filter, MessageType, PacketDispatcher, PortSet};

use super::{
    BuildError, Emit, InterfaceMap, SimpleReflector, Verdict, join_group_logged,
    missing_required_family,
};

/// Every captured datagram is a message for the leg.
fn relay(_payload: &[u8]) -> Verdict {
    Verdict::Reflect(MessageType::UdpDatagram)
}

/// Build the UDP relay for `reflector` and register it on `dispatcher`. No-op when `udp_ports`
/// isn't set. Joins the listed groups on the source interface and registers one handler for the
/// groups and one for the broadcasts, each spanning every port.
///
/// # Errors
/// [`BuildError::UnknownInterface`] if no capture was opened for the source/target, or
/// [`BuildError::RequiredFamilyUnavailable`] if the target can't currently send a required family.
pub(crate) fn build(
    reflector: &Reflector,
    interfaces: &InterfaceMap,
    dispatcher: &mut PacketDispatcher,
) -> Result<(), BuildError> {
    let Some(udp) = &reflector.udp else {
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

    let groups = udp.groups.as_deref().unwrap_or(&[]);
    for group in groups {
        join_group_logged(
            dispatcher,
            ingress,
            *group,
            "UDP relay",
            reflector.source_if.as_str(),
        );
    }

    // A filter matches every field it sets, so the groups and the broadcasts need one each.
    let ports: PortSet = udp.ports.iter().map(|port| port.get()).collect();
    let mut filters = Vec::with_capacity(2);
    if !groups.is_empty() {
        filters.push(Filter {
            dst_ip: Some(groups.iter().copied().collect()),
            dst_port: Some(ports.clone()),
            ..Filter::default()
        });
    }
    if udp.broadcast {
        filters.push(Filter {
            broadcast: true,
            dst_port: Some(ports),
            ..Filter::default()
        });
    }
    for filter in filters {
        dispatcher.register(
            ingress,
            filter,
            Box::new(SimpleReflector::new(
                egress,
                "UDP relay",
                "datagram",
                relay,
                Emit::captured(),
            )),
        );
    }
    log::info!(
        "UDP relay \"{}\": {} -> {} on {} port(s) to {} group(s){}",
        reflector.name.as_str(),
        reflector.source_if.as_str(),
        reflector.target_if.as_str(),
        udp.ports.len(),
        groups.len(),
        if udp.broadcast { " and broadcasts" } else { "" }
    );
    Ok(())
}
