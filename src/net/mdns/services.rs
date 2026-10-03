//! The DNS-SD service-type allow-list an mDNS entry can carry (`mdns_services`).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer};
use thiserror::Error;

use super::{
    ANCOUNT_AT, ARCOUNT_AT, DNS_HEADER_LEN, MdnsKind, NSCOUNT_AT, QDCOUNT_AT, classify, skip_name,
};
use crate::unique_list::{ListRule, UniqueList};

/// The longest service label: a DNS label (63 octets, RFC 1035 §2.3.4) less its underscore.
/// RFC 6335 §5.1 caps a registered service name at 15, but unregistered ones run longer in the
/// wild (`_androidtvremote2`), so only the DNS limit is enforced.
const MAX_SERVICE_LEN: usize = 62;

/// A name spans at most 255 octets (RFC 1035 §3.1).
const MAX_NAME_LEN: usize = 255;
/// Each hop must add a label to stay under [`MAX_NAME_LEN`], so more hops than that can only loop.
const MAX_POINTER_HOPS: usize = MAX_NAME_LEN / 2;

const TYPE_NS: u16 = 2;
const TYPE_MD: u16 = 3;
const TYPE_MF: u16 = 4;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_MB: u16 = 7;
const TYPE_MG: u16 = 8;
const TYPE_MR: u16 = 9;
const TYPE_PTR: u16 = 12;
const TYPE_MINFO: u16 = 14;
const TYPE_MX: u16 = 15;
const TYPE_RP: u16 = 17;
const TYPE_AFSDB: u16 = 18;
const TYPE_RT: u16 = 21;
const TYPE_PX: u16 = 26;
const TYPE_SRV: u16 = 33;
const TYPE_KX: u16 = 36;
const TYPE_DNAME: u16 = 39;
const TYPE_NSEC: u16 = 47;

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
    /// Nothing service-scoped in it is refused: relay it verbatim.
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
    /// or more work than its length allows. Never relayed while a list is set.
    Malformed,
}

/// The decision before any rewrite; see [`ServiceFilter::decide`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Pass,
    Refuse,
    Trim,
}

/// A message this module cannot walk: truncated, a reserved label type, a looping or overlong
/// name, or one over its [`Budget`]. The filter fails closed on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Malformed;

/// Label and pointer steps one pass over a message may cost. Real traffic stays under 1.5 per
/// byte; a crafted message whose records all point into one long chain would cost dozens, so it
/// is refused as malformed before it can starve the reactor.
const STEPS_PER_BYTE: usize = 4;

/// The steps left for one pass over a message; see [`STEPS_PER_BYTE`].
struct Budget(usize);

impl Budget {
    fn for_message(payload: &[u8]) -> Self {
        Self(payload.len().saturating_mul(STEPS_PER_BYTE))
    }

    fn spend(&mut self) -> Result<(), Malformed> {
        self.0 = self.0.checked_sub(1).ok_or(Malformed)?;
        Ok(())
    }
}

/// A name's labels in order, compression pointers followed (RFC 1035 §4.1.4). Yields one error and
/// then ends.
struct Labels<'a, 'b> {
    payload: &'a [u8],
    at: usize,
    hops: usize,
    len: usize,
    done: bool,
    budget: &'b mut Budget,
}

impl<'a, 'b> Labels<'a, 'b> {
    fn new(payload: &'a [u8], at: usize, budget: &'b mut Budget) -> Self {
        Self {
            payload,
            at,
            hops: 0,
            len: 0,
            done: false,
            budget,
        }
    }

    fn step(&mut self) -> Result<Option<&'a [u8]>, Malformed> {
        loop {
            self.budget.spend()?;
            let len = *self.payload.get(self.at).ok_or(Malformed)?;
            match len {
                0 => return Ok(None),
                1..=0x3f => {
                    let start = self.at + 1;
                    let label = self
                        .payload
                        .get(start..start + usize::from(len))
                        .ok_or(Malformed)?;
                    self.len += 1 + label.len();
                    if self.len >= MAX_NAME_LEN {
                        return Err(Malformed);
                    }
                    self.at = start + label.len();
                    return Ok(Some(label));
                }
                0xc0..=0xff => {
                    let low = *self.payload.get(self.at + 1).ok_or(Malformed)?;
                    self.hops += 1;
                    if self.hops > MAX_POINTER_HOPS {
                        return Err(Malformed);
                    }
                    self.at = usize::from(len & 0x3f) << 8 | usize::from(low);
                }
                _ => return Err(Malformed),
            }
        }
    }
}

impl<'a> Iterator for Labels<'a, '_> {
    type Item = Result<&'a [u8], Malformed>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let step = self.step();
        self.done = !matches!(step, Ok(Some(_)));
        step.transpose()
    }
}

/// A message section (RFC 1035 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Question,
    Answer,
    Authority,
    Additional,
}

/// Where the names sit in a record's rdata: `count` of them back to back, after `offset` fixed
/// octets. See [`rdata_names`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RdataNames {
    offset: usize,
    count: usize,
}

/// One question or resource record, as offsets into the message (RFC 1035 §4.1.2 / §4.1.3).
/// A question has no rdata: `rdata == end`.
#[derive(Debug, Clone, Copy)]
struct Entry {
    section: Section,
    /// The owner name.
    name: usize,
    /// Just past the owner name's inline octets: TYPE and CLASS, then (records) TTL and RDLENGTH.
    fixed: usize,
    rtype: u16,
    rdata: usize,
    end: usize,
}

impl Entry {
    /// The names in the entry's rdata, if it has any.
    fn rdata_names(self) -> Option<RdataNames> {
        rdata_names(self.rtype).filter(|_| self.rdata < self.end)
    }

    /// Every name the entry carries is walkable, and each inline part ends inside its rdata.
    fn check_names(self, payload: &[u8], budget: &mut Budget) -> Result<(), Malformed> {
        check_name(payload, self.name, budget)?;
        let Some(names) = self.rdata_names() else {
            return Ok(());
        };
        let mut at = self.rdata + names.offset;
        for _ in 0..names.count {
            check_name(payload, at, budget)?;
            at = skip_name(payload, at).ok_or(Malformed)?;
            if at > self.end {
                return Err(Malformed);
            }
        }
        Ok(())
    }

    /// The service type the entry falls under: a PTR's by its target, else by its owner.
    fn service<'a>(
        self,
        payload: &'a [u8],
        budget: &mut Budget,
    ) -> Result<Option<(&'a [u8], Proto)>, Malformed> {
        if self.rtype == TYPE_PTR
            && self.rdata < self.end
            && let Some(service) = service_of(payload, self.rdata, budget)?
        {
            return Ok(Some(service));
        }
        service_of(payload, self.name, budget)
    }
}

/// The message's entries in wire order, questions first. Yields one error and then ends.
struct Entries<'a> {
    payload: &'a [u8],
    at: usize,
    /// Entries still to come per section, in wire order.
    remaining: [(Section, usize); 4],
    done: bool,
}

impl<'a> Entries<'a> {
    fn new(payload: &'a [u8]) -> Self {
        let count = |at: usize| {
            payload
                .get(at..at + 2)
                .map_or(0, |n| usize::from(u16::from_be_bytes([n[0], n[1]])))
        };
        Self {
            payload,
            at: DNS_HEADER_LEN,
            remaining: [
                (Section::Question, count(QDCOUNT_AT)),
                (Section::Answer, count(ANCOUNT_AT)),
                (Section::Authority, count(NSCOUNT_AT)),
                (Section::Additional, count(ARCOUNT_AT)),
            ],
            done: payload.len() < DNS_HEADER_LEN,
        }
    }

    fn step(&mut self, section: Section) -> Result<Entry, Malformed> {
        let payload = self.payload;
        let name = self.at;
        let fixed = skip_name(payload, name).ok_or(Malformed)?;
        let (rdata, end) = if section == Section::Question {
            payload.get(fixed..fixed + 4).ok_or(Malformed)?;
            (fixed + 4, fixed + 4)
        } else {
            let head = payload.get(fixed..fixed + 10).ok_or(Malformed)?;
            let rdata = fixed + 10;
            let end = rdata + usize::from(u16::from_be_bytes([head[8], head[9]]));
            if end > payload.len() {
                return Err(Malformed);
            }
            (rdata, end)
        };
        self.at = end;
        Ok(Entry {
            section,
            name,
            fixed,
            rtype: u16::from_be_bytes([payload[fixed], payload[fixed + 1]]),
            rdata,
            end,
        })
    }
}

impl Iterator for Entries<'_> {
    type Item = Result<Entry, Malformed>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let Some(slot) = self.remaining.iter_mut().find(|(_, left)| *left > 0) else {
            self.done = true;
            return None;
        };
        slot.1 -= 1;
        let section = slot.0;
        let step = self.step(section);
        self.done = step.is_err();
        Some(step)
    }
}

/// No new offset for this original one: `placed` holds only offsets a pointer can name, and a
/// pointer is 14 bits.
const UNPLACED: u16 = u16::MAX;
const MAX_POINTER_TARGET: usize = 0x3fff;

/// An entry's allow-list over the messages of one leg: one [`decide`](Self::decide) per message,
/// into buffers it keeps between messages.
///
/// A trim re-encodes names label by label while `placed` maps each original label offset to where
/// it landed, so a pointer to a label already written becomes a pointer to its new offset, and one
/// to a label that was dropped (or not yet written) is spelled out from the original.
pub(crate) struct ServiceFilter {
    allowed: ServiceList,
    out: Vec<u8>,
    placed: Vec<u16>,
    refused: Vec<ServiceType>,
}

impl ServiceFilter {
    pub(crate) fn new(allowed: ServiceList) -> Self {
        Self {
            allowed,
            out: Vec::new(),
            placed: Vec::new(),
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
        match scope {
            Scope::Pass => Decision::Pass,
            Scope::Refuse => Decision::Refuse(RefusedServices(&self.refused)),
            // `assess` walked every name the rewrite does, within the same budget, so a failure
            // here is not expected; it fails closed like any other malformed message.
            Scope::Trim => match self.rewrite(payload) {
                Ok(removed) => Decision::Trim {
                    payload: &self.out,
                    removed,
                    refused: RefusedServices(&self.refused),
                },
                Err(Malformed) => Decision::Malformed,
            },
        }
    }

    /// `payload` less its refused records, into `out`; returns how many it removed. Bounds-checked
    /// throughout, so input `assess` did not vet ends in an error rather than a panic.
    fn rewrite(&mut self, payload: &[u8]) -> Result<usize, Malformed> {
        let mut budget = Budget::for_message(payload);
        self.out.clear();
        self.out
            .extend_from_slice(payload.get(..DNS_HEADER_LEN).ok_or(Malformed)?);
        self.placed.clear();
        self.placed.resize(payload.len(), UNPLACED);
        let mut counts = [0u16; 4];
        let mut removed = 0;
        for entry in Entries::new(payload) {
            let entry = entry?;
            let keep = entry.section == Section::Question
                || entry
                    .service(payload, &mut budget)?
                    .is_none_or(|service| allows(&self.allowed, service));
            if !keep {
                removed += 1;
                continue;
            }
            self.write_entry(payload, entry, &mut budget)?;
            counts[entry.section as usize] += 1;
        }
        for (count, at) in counts
            .into_iter()
            .zip([QDCOUNT_AT, ANCOUNT_AT, NSCOUNT_AT, ARCOUNT_AT])
        {
            self.out[at..at + 2].copy_from_slice(&count.to_be_bytes());
        }
        Ok(removed)
    }

    fn write_entry(
        &mut self,
        payload: &[u8],
        entry: Entry,
        budget: &mut Budget,
    ) -> Result<(), Malformed> {
        let span = |from: usize, to: usize| payload.get(from..to).ok_or(Malformed);
        self.write_name(payload, entry.name, budget)?;
        if entry.section == Section::Question {
            self.out.extend_from_slice(span(entry.fixed, entry.end)?);
            return Ok(());
        }
        // TYPE, CLASS and TTL; RDLENGTH is patched once the rdata is written.
        self.out
            .extend_from_slice(span(entry.fixed, entry.fixed + 8)?);
        let length_at = self.out.len();
        self.out.extend_from_slice(&[0, 0]);
        match entry.rdata_names() {
            Some(names) => {
                let mut at = entry.rdata + names.offset;
                self.out.extend_from_slice(span(entry.rdata, at)?);
                for _ in 0..names.count {
                    self.write_name(payload, at, budget)?;
                    at = skip_name(payload, at).ok_or(Malformed)?;
                }
                self.out.extend_from_slice(span(at, entry.end)?);
            }
            None => self.out.extend_from_slice(span(entry.rdata, entry.end)?),
        }
        let length = u16::try_from(self.out.len() - length_at - 2).map_err(|_| Malformed)?;
        self.out[length_at..length_at + 2].copy_from_slice(&length.to_be_bytes());
        Ok(())
    }

    fn write_name(
        &mut self,
        payload: &[u8],
        mut at: usize,
        budget: &mut Budget,
    ) -> Result<(), Malformed> {
        let mut hops = 0;
        loop {
            budget.spend()?;
            let placed = self.placed.get(at).copied().unwrap_or(UNPLACED);
            if placed != UNPLACED {
                self.out.extend_from_slice(&(0xc000 | placed).to_be_bytes());
                return Ok(());
            }
            let len = *payload.get(at).ok_or(Malformed)?;
            match len {
                0 => {
                    self.out.push(0);
                    return Ok(());
                }
                1..=0x3f => {
                    let label = payload
                        .get(at..at + 1 + usize::from(len))
                        .ok_or(Malformed)?;
                    if let Ok(here) = u16::try_from(self.out.len())
                        && usize::from(here) <= MAX_POINTER_TARGET
                    {
                        self.placed[at] = here;
                    }
                    self.out.extend_from_slice(label);
                    at += label.len();
                }
                0xc0..=0xff => {
                    let low = *payload.get(at + 1).ok_or(Malformed)?;
                    hops += 1;
                    if hops > MAX_POINTER_HOPS {
                        return Err(Malformed);
                    }
                    at = usize::from(len & 0x3f) << 8 | usize::from(low);
                }
                _ => return Err(Malformed),
            }
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
        match entry.service(payload, &mut budget)? {
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

fn allows(allowed: &[ServiceType], (service, proto): (&[u8], Proto)) -> bool {
    allowed
        .iter()
        .any(|a| a.proto == proto && a.service().eq_ignore_ascii_case(service))
}

/// Where names sit in the rdata of the types that may compress them. RFC 6762 §18.14 lists them for
/// mDNS (NS, CNAME, PTR, DNAME, SOA, MX, AFSDB, RT, KX, RP, PX, SRV, NSEC); RFC 3597 §4 adds the
/// obsolete RFC 1035 types. Any other rdata holds no compressed name, so it is opaque octets.
fn rdata_names(rtype: u16) -> Option<RdataNames> {
    let (offset, count) = match rtype {
        TYPE_NS | TYPE_MD | TYPE_MF | TYPE_CNAME | TYPE_MB | TYPE_MG | TYPE_MR | TYPE_PTR
        | TYPE_DNAME | TYPE_NSEC => (0, 1),
        TYPE_SOA | TYPE_MINFO | TYPE_RP => (0, 2),
        TYPE_MX | TYPE_AFSDB | TYPE_RT | TYPE_KX => (2, 1),
        TYPE_PX => (2, 2),
        TYPE_SRV => (6, 1),
        _ => return None,
    };
    Some(RdataNames { offset, count })
}

fn check_name(payload: &[u8], at: usize, budget: &mut Budget) -> Result<(), Malformed> {
    Labels::new(payload, at, budget).try_for_each(|label| label.map(|_| ()))
}

#[cfg(test)]
mod tests;
