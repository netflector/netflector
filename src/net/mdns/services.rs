//! The DNS-SD service-type allow-list an mDNS entry can carry (`mdns_services`).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer};
use thiserror::Error;

use super::message::{Budget, Entries, Entry, Labels, Malformed, Section, TYPE_PTR, Trimmer};
use super::{MdnsKind, classify};
use crate::unique_list::{ListRule, UniqueList};

/// The longest service label: a DNS label (63 octets, RFC 1035 §2.3.4) less its underscore.
/// RFC 6335 §5.1 caps a registered service name at 15, but unregistered ones run longer in the
/// wild (`_androidtvremote2`), so only the DNS limit is enforced.
const MAX_SERVICE_LEN: usize = 62;

/// The transport label of a service type (RFC 6763 §7): `_tcp` for a service over TCP, `_udp` for
/// one over any other transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    /// Case-insensitive, as DNS labels are.
    fn from_label(label: &[u8]) -> Option<Self> {
        if label.eq_ignore_ascii_case(b"_tcp") {
            Some(Self::Tcp)
        } else if label.eq_ignore_ascii_case(b"_udp") {
            Some(Self::Udp)
        } else {
            None
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Tcp => "_tcp",
            Self::Udp => "_udp",
        }
    }
}

/// The mDNS domain (RFC 6762 §3), accepted after a service type.
const LOCAL_SUFFIX: &[u8] = b".local";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("expected a DNS-SD service type such as \"_ipp._tcp\"")]
pub(crate) struct ParseServiceTypeError;

/// A DNS-SD service type, `_<service>._<proto>` (RFC 6763 §7). Stored ASCII-lowercased, the
/// service label without its underscore, so `Eq` is DNS's case-insensitive identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServiceType {
    service: [u8; MAX_SERVICE_LEN],
    len: u8,
    proto: Proto,
}

impl ServiceType {
    /// The type with service label `service` (no underscore) over `proto`, its octets taken as
    /// they are; `None` when the label is empty or longer than [`MAX_SERVICE_LEN`].
    fn from_wire(service: &[u8], proto: Proto) -> Option<Self> {
        if !(1..=MAX_SERVICE_LEN).contains(&service.len()) {
            return None;
        }
        let mut stored = [0u8; MAX_SERVICE_LEN];
        stored[..service.len()].copy_from_slice(service);
        stored.make_ascii_lowercase();
        Some(Self {
            service: stored,
            len: u8::try_from(service.len()).expect("at most MAX_SERVICE_LEN"),
            proto,
        })
    }

    fn service(&self) -> &[u8] {
        &self.service[..usize::from(self.len)]
    }
}

impl fmt::Display for ServiceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "_{}.{}",
            self.service().escape_ascii(),
            self.proto.label()
        )
    }
}

impl FromStr for ServiceType {
    type Err = ParseServiceTypeError;

    /// `_<service>._tcp` or `_<service>._udp`, optionally followed by the `local` domain and a
    /// root dot, which are dropped. The service label takes letters, digits, hyphens and
    /// underscores.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_suffix('.').unwrap_or(s);
        let s = match s.len().checked_sub(LOCAL_SUFFIX.len()) {
            // The suffix is ASCII, so the cut falls on a char boundary.
            Some(cut) if s.as_bytes()[cut..].eq_ignore_ascii_case(LOCAL_SUFFIX) => &s[..cut],
            _ => s,
        };
        let (service, proto) = s.split_once('.').ok_or(ParseServiceTypeError)?;
        let proto = Proto::from_label(proto.as_bytes()).ok_or(ParseServiceTypeError)?;
        service
            .strip_prefix('_')
            .map(str::as_bytes)
            .filter(|service| {
                service
                    .iter()
                    .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
            .and_then(|service| Self::from_wire(service, proto))
            .ok_or(ParseServiceTypeError)
    }
}

impl<'de> Deserialize<'de> for ServiceType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// The rule for [`ServiceList`]: any service type but DNS-SD's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Services;

impl ListRule for Services {
    type Item = ServiceType;

    const NOUN: &'static str = "service type";

    /// `_dns-sd` heads DNS-SD's meta-names (`_services._dns-sd._udp`, RFC 6763 §9), which
    /// [`service_of`] does not report as a service, so an entry for it could not match.
    fn refuse(item: &ServiceType) -> Option<&'static str> {
        (item.service() == b"dns-sd").then_some("names DNS-SD's own records, not a service")
    }
}

/// A non-empty, duplicate-free list of DNS-SD service types.
pub(crate) type ServiceList = UniqueList<Services>;

/// A log line names this many refused types at most; a message rarely names more.
const MAX_NAMED_REFUSALS: usize = 8;

/// The service types a message named and the list refused, for the log: the first
/// [`MAX_NAMED_REFUSALS`] distinct ones.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RefusedServices<'a>(&'a [ServiceType]);

impl fmt::Display for RefusedServices<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, service) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{service}")?;
        }
        Ok(())
    }
}

/// What an allow-list makes of one message.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Decision<'a> {
    /// Relay it verbatim: nothing in it is refused, or it is a query with a question worth asking.
    /// See [`ServiceFilter::decide`].
    Pass,
    /// The list refuses it: do not relay it. See [`ServiceFilter::decide`].
    Refuse(RefusedServices<'a>),
    /// A response the list trims: relay `payload`, the message less the `removed` records of the
    /// `refused` services.
    Trim {
        payload: &'a [u8],
        removed: usize,
        refused: RefusedServices<'a>,
    },
    /// Not walkable within bounds: truncated, a reserved label type, a looping or overlong name,
    /// more work than its length allows, or a trim that would outgrow it. Never relayed while a
    /// list is set.
    Malformed,
}

/// The decision before any rewrite; see [`ServiceFilter::decide`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Pass,
    Refuse,
    Trim,
}

/// An entry's allow-list over the messages of one leg: one [`decide`](Self::decide) per message,
/// trimming into a [`Trimmer`] it keeps between messages.
pub(crate) struct ServiceFilter {
    allowed: ServiceList,
    trimmer: Trimmer,
    refused: Vec<ServiceType>,
}

impl ServiceFilter {
    pub(crate) fn new(allowed: ServiceList) -> Self {
        Self {
            allowed,
            trimmer: Trimmer::default(),
            refused: Vec::new(),
        }
    }

    /// What the list makes of `payload`, a query or a response per its QR bit.
    ///
    /// A query is refused only when every question names a refused service: a mixed one goes out
    /// whole, and its answer is trimmed on the way back.
    ///
    /// A response with nothing refused passes. Otherwise its answers decide, and a trim always
    /// leaves one: it is trimmed when an answer naming an allowed service remains, or when it has
    /// answers and none names a service (a hostname answer carrying refused services as additional
    /// records). Anything else is refused, such as an announcement of refused services, whose
    /// address records would otherwise go out alone, wherever the sender put them.
    pub(crate) fn decide(&mut self, payload: &[u8]) -> Decision<'_> {
        self.refused.clear();
        let Ok(scope) = assess(payload, &self.allowed, &mut self.refused) else {
            return Decision::Malformed;
        };
        let allowed = &self.allowed;
        match scope {
            Scope::Pass => Decision::Pass,
            Scope::Refuse => Decision::Refuse(RefusedServices(&self.refused)),
            // `assess` walked every name the trim does, within the same budget, so a failure here
            // is a trim that would outgrow the message; it fails closed like any other.
            Scope::Trim => match self.trimmer.trim(payload, |entry, budget| {
                Ok(entry.section == Section::Question
                    || entry_service(entry, payload, budget)?
                        .is_none_or(|service| allows(allowed, service)))
            }) {
                Ok((payload, removed)) => Decision::Trim {
                    payload,
                    removed,
                    refused: RefusedServices(&self.refused),
                },
                Err(Malformed) => Decision::Malformed,
            },
        }
    }
}

/// The [`Scope`] `allowed` gives `payload`; see [`ServiceFilter::decide`]. Notes each refused
/// service type in `refused`, up to [`MAX_NAMED_REFUSALS`].
fn assess(
    payload: &[u8],
    allowed: &[ServiceType],
    refused: &mut Vec<ServiceType>,
) -> Result<Scope, Malformed> {
    let kind = classify(payload).ok_or(Malformed)?;
    let mut budget = Budget::for_message(payload);
    let (mut granted, mut any_refused, mut unscoped) = (false, false, false);
    // Whether an answer names a service, one names an allowed service, and one names none.
    let (mut answer_scoped, mut answer_granted, mut answer_unscoped) = (false, false, false);
    for entry in Entries::new(payload) {
        let entry = entry?;
        entry.check_names(payload, &mut budget)?;
        let asked = match kind {
            MdnsKind::Query => entry.section == Section::Question,
            MdnsKind::Response => entry.section != Section::Question,
        };
        if !asked {
            continue;
        }
        let answer = entry.section == Section::Answer;
        match entry_service(entry, payload, &mut budget)? {
            None => {
                unscoped = true;
                answer_unscoped |= answer;
            }
            Some(service) if allows(allowed, service) => {
                granted = true;
                answer_scoped |= answer;
                answer_granted |= answer;
            }
            Some((service, proto)) => {
                any_refused = true;
                answer_scoped |= answer;
                if let Some(service) = ServiceType::from_wire(service, proto)
                    && refused.len() < MAX_NAMED_REFUSALS
                    && !refused.contains(&service)
                {
                    refused.push(service);
                }
            }
        }
    }
    Ok(match kind {
        _ if !any_refused => Scope::Pass,
        // Any question worth asking keeps the query whole.
        MdnsKind::Query if granted || unscoped => Scope::Pass,
        MdnsKind::Response if answer_granted || (answer_unscoped && !answer_scoped) => Scope::Trim,
        MdnsKind::Query | MdnsKind::Response => Scope::Refuse,
    })
}

/// The service type a name falls under: its `_<service>._tcp` / `_<service>._udp` pair nearest the
/// domain, as the service label (underscore stripped) and transport. The DNS-SD meta-names
/// (`_services._dns-sd._udp`, the browse-domain `b._dns-sd._udp`) are infrastructure, not a
/// service, so their pair does not count.
fn service_of<'a>(
    payload: &'a [u8],
    at: usize,
    budget: &mut Budget,
) -> Result<Option<(&'a [u8], Proto)>, Malformed> {
    let mut previous: Option<&[u8]> = None;
    let mut found = None;
    for label in Labels::new(payload, at, budget) {
        let label = label?;
        if let (Some(service), Some(proto)) = (previous, Proto::from_label(label))
            && let Some(service) = service.strip_prefix(b"_")
            && !service.eq_ignore_ascii_case(b"dns-sd")
        {
            found = Some((service, proto));
        }
        previous = Some(label);
    }
    Ok(found)
}

/// The service type `entry` falls under: a PTR's by its target, else by its owner.
fn entry_service<'a>(
    entry: Entry,
    payload: &'a [u8],
    budget: &mut Budget,
) -> Result<Option<(&'a [u8], Proto)>, Malformed> {
    if entry.rtype == TYPE_PTR
        && entry.rdata < entry.end
        && let Some(service) = service_of(payload, entry.rdata, budget)?
    {
        return Ok(Some(service));
    }
    service_of(payload, entry.name, budget)
}

fn allows(allowed: &[ServiceType], (service, proto): (&[u8], Proto)) -> bool {
    allowed
        .iter()
        .any(|a| a.proto == proto && a.service().eq_ignore_ascii_case(service))
}

#[cfg(test)]
mod tests;
