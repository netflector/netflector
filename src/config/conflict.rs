//! The cross-reflector rule: no two entries may reflect the same packet twice. Each entry is
//! expanded into the classes of datagrams it relays ([`Flow`]s), and two entries conflict when a
//! datagram exists in a flow of each.

use std::fmt;
use std::net::IpAddr;

use super::value::{AddressFamily, InterfaceName};
use super::{ConfigError, Reflector, UdpRelay};
use crate::net::mac::MacSet;
use crate::net::mdns::{MDNS_GROUP_V4, MDNS_GROUP_V6, MDNS_PORT};
use crate::net::ssdp::{
    SSDP_GROUP_V4, SSDP_GROUP_V6_LINK_LOCAL, SSDP_GROUP_V6_SITE_LOCAL, SSDP_PORT,
};
use crate::net::wsd::{WSD_GROUP_V4, WSD_GROUP_V6, WSD_PORT};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocol {
    Wol,
    Mdns,
    Ssdp,
    Wsd,
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Wol => "WoL",
            Self::Mdns => "mDNS",
            Self::Ssdp => "SSDP",
            Self::Wsd => "WSD",
            Self::Udp => "UDP relay",
        })
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
    fn overlaps(self, other: Reach) -> bool {
        match (self, other) {
            (Self::Any(a), Self::Any(b)) => families_overlap(a, b),
            (Self::Any(family), Self::Group(group)) | (Self::Group(group), Self::Any(family)) => {
                family.uses(group)
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
    fn overlaps(&self, other: &Flow<'_>) -> bool {
        self.ingress == other.ingress
            && self.egress == other.egress
            && self.port == other.port
            && self.reach.overlaps(other.reach)
    }
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

impl Reflector {
    fn directions(&self) -> impl Iterator<Item = (&InterfaceName, &InterfaceName)> {
        std::iter::once((&self.source_if, &self.target_if)).chain(
            self.bidirectional
                .then_some((&self.target_if, &self.source_if)),
        )
    }

    /// mDNS, SSDP and WSD flow both ways whatever the entry's direction (queries arrive on the
    /// source, responses on the target); Wake-on-LAN and the relay follow the entry's directions.
    fn flows(&self) -> Vec<Flow<'_>> {
        let family = self.address_family;
        let mut flows = Vec::new();
        let mut discovery = |protocol, port, groups: &[IpAddr]| {
            for group in groups.iter().filter(|group| family.uses(**group)) {
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

    /// Two discovery protocols on one port don't duplicate: each classifier admits only its own
    /// messages. The relay admits everything it captures, so it duplicates any protocol on the
    /// same leg, and the conflict is named after that protocol.
    fn conflicts_with(&self, other: &Reflector) -> Option<Protocol> {
        self.shared_protocol(other).or_else(|| {
            self.relay_overlap(other.flows())
                .or_else(|| other.relay_overlap(self.flows()))
                .map(|(protocol, _)| protocol)
        })
    }

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

    pub(super) fn relay_duplicates(&self) -> Option<(Protocol, u16)> {
        let flows = self.flows();
        let others = flows
            .iter()
            .copied()
            .filter(|flow| flow.protocol != Protocol::Udp);
        self.relay_overlap(others)
    }
}

fn macs_overlap(a: Option<&MacSet>, b: Option<&MacSet>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.iter().any(|mac| b.contains(mac)),
        _ => true,
    }
}

fn families_overlap(a: AddressFamily, b: AddressFamily) -> bool {
    (a.uses_ipv4() && b.uses_ipv4()) || (a.uses_ipv6() && b.uses_ipv6())
}

/// Names compare in canonical form (trimmed, lowercased), so two file tables whose keys differ only
/// in case or padding collide here; as map keys they did not.
pub(super) fn check_conflicts(reflectors: &[Reflector]) -> Result<(), ConfigError> {
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
