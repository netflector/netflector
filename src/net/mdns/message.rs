//! A DNS message's questions and records (RFC 1035 §4.1), walked within a budget, and re-encoded
//! without the records a filter drops.

use super::DNS_HEADER_LEN;

/// Where the header holds each section's entry count (RFC 1035 §4.1.1).
const QDCOUNT_AT: usize = 4;
const ANCOUNT_AT: usize = 6;
const NSCOUNT_AT: usize = 8;
const ARCOUNT_AT: usize = 10;

/// A name spans at most 255 octets (RFC 1035 §3.1).
const MAX_NAME_LEN: usize = 255;
/// Each hop must add a label to stay under [`MAX_NAME_LEN`], so more hops than that can only loop.
const MAX_POINTER_HOPS: usize = MAX_NAME_LEN / 2;

/// A message this module cannot walk: truncated, a reserved label type, a looping or overlong
/// name, or one over its [`Budget`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Malformed;

/// Label and pointer steps one pass over a message may cost. Real traffic stays under 1.5 per
/// byte; a crafted message whose records all point into one long chain would cost dozens, so it
/// is refused as malformed before it can starve the reactor.
const STEPS_PER_BYTE: usize = 4;

/// The steps left for one pass over a message; see [`STEPS_PER_BYTE`].
pub(super) struct Budget(usize);

impl Budget {
    pub(super) fn for_message(payload: &[u8]) -> Self {
        Self(payload.len().saturating_mul(STEPS_PER_BYTE))
    }

    fn spend(&mut self) -> Result<(), Malformed> {
        self.0 = self.0.checked_sub(1).ok_or(Malformed)?;
        Ok(())
    }
}

/// A name's labels in order, compression pointers followed (RFC 1035 §4.1.4). Yields one error and
/// then ends.
pub(super) struct Labels<'a, 'b> {
    payload: &'a [u8],
    at: usize,
    hops: usize,
    len: usize,
    done: bool,
    budget: &'b mut Budget,
}

impl<'a, 'b> Labels<'a, 'b> {
    pub(super) fn new(payload: &'a [u8], at: usize, budget: &'b mut Budget) -> Self {
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
pub(super) enum Section {
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
pub(super) struct Entry {
    pub(super) section: Section,
    /// The owner name.
    pub(super) name: usize,
    /// Just past the owner name's inline octets: TYPE and CLASS, then (records) TTL and RDLENGTH.
    fixed: usize,
    pub(super) rtype: u16,
    pub(super) rdata: usize,
    pub(super) end: usize,
}

impl Entry {
    /// The names in the entry's rdata, if it has any.
    fn rdata_names(self) -> Option<RdataNames> {
        rdata_names(self.rtype).filter(|_| self.rdata < self.end)
    }

    /// Every name the entry carries is walkable, and each inline part ends inside its rdata.
    pub(super) fn check_names(self, payload: &[u8], budget: &mut Budget) -> Result<(), Malformed> {
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
}

/// The message's entries in wire order, questions first. Yields one error and then ends.
pub(super) struct Entries<'a> {
    payload: &'a [u8],
    at: usize,
    /// Entries still to come per section, in wire order.
    remaining: [(Section, usize); 4],
    done: bool,
}

impl<'a> Entries<'a> {
    pub(super) fn new(payload: &'a [u8]) -> Self {
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

/// Re-encodes messages without the entries a filter drops, into buffers it keeps between messages.
///
/// Names are re-encoded label by label while `placed` maps each original label offset to where it
/// landed, so a pointer to a label already written becomes a pointer to its new offset, and one to
/// a label that was dropped (or not yet written) is spelled out from the original.
#[derive(Default)]
pub(super) struct Trimmer {
    out: Vec<u8>,
    placed: Vec<u16>,
}

impl Trimmer {
    /// `payload` without the entries `keep` rejects, and how many those were. When the trim leaves
    /// no answer, the authority and additional entries `refill` picks move into the answer section
    /// without passing `keep`, so `refill` must pick only entries `keep` would keep. Bounds-checked
    /// throughout, so input nobody vetted ends in an error rather than a panic.
    pub(super) fn trim(
        &mut self,
        payload: &[u8],
        mut keep: impl FnMut(Entry, &mut Budget) -> Result<bool, Malformed>,
        refill: impl Fn(Entry) -> bool,
    ) -> Result<(&[u8], usize), Malformed> {
        let mut budget = Budget::for_message(payload);
        self.out.clear();
        self.out
            .extend_from_slice(payload.get(..DNS_HEADER_LEN).ok_or(Malformed)?);
        self.placed.clear();
        self.placed.resize(payload.len(), UNPLACED);
        let refills = |entry: Entry| {
            matches!(entry.section, Section::Authority | Section::Additional) && refill(entry)
        };
        let mut counts = [0u16; 4];
        let mut removed = 0;
        // Whether the walk is past the answer section, and whether that section came out empty and
        // took what `refill` picks.
        let (mut answered, mut refilled) = (false, false);
        for entry in Entries::new(payload) {
            let entry = entry?;
            if !answered && matches!(entry.section, Section::Authority | Section::Additional) {
                answered = true;
                refilled = counts[Section::Answer as usize] == 0;
                if refilled {
                    for candidate in Entries::new(payload) {
                        let candidate = candidate?;
                        if refills(candidate) {
                            self.write_entry(payload, candidate, &mut budget)?;
                            counts[Section::Answer as usize] = counts[Section::Answer as usize]
                                .checked_add(1)
                                .ok_or(Malformed)?;
                        }
                    }
                }
            }
            if refilled && refills(entry) {
                continue;
            }
            if !keep(entry, &mut budget)? {
                removed += 1;
                continue;
            }
            self.write_entry(payload, entry, &mut budget)?;
            counts[entry.section as usize] += 1;
        }
        // Dropping records only shrinks a message: growth means names spelled out from bytes no
        // kept name owns, such as opaque rdata.
        if self.out.len() > payload.len() {
            return Err(Malformed);
        }
        for (count, at) in counts
            .into_iter()
            .zip([QDCOUNT_AT, ANCOUNT_AT, NSCOUNT_AT, ARCOUNT_AT])
        {
            self.out[at..at + 2].copy_from_slice(&count.to_be_bytes());
        }
        Ok((&self.out, removed))
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
        let start = self.out.len();
        let mut hops = 0;
        loop {
            budget.spend()?;
            let placed = self.placed.get(at).copied().unwrap_or(UNPLACED);
            if placed != UNPLACED {
                // A pointer into the name being written makes it loop.
                if usize::from(placed) >= start {
                    return Err(Malformed);
                }
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

const TYPE_NS: u16 = 2;
const TYPE_MD: u16 = 3;
const TYPE_MF: u16 = 4;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_MB: u16 = 7;
const TYPE_MG: u16 = 8;
const TYPE_MR: u16 = 9;
pub(super) const TYPE_PTR: u16 = 12;
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

/// The offset just past the (possibly compressed) name at `at`.
fn skip_name(payload: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *payload.get(at)?;
        // The top two bits tag the label (RFC 1035 §3.1 / §4.1.4): 00 a plain length, 0 ending
        // the name; 11 a 2-byte compression pointer, which ends the name in place (the record's
        // fixed fields follow the 2 bytes, so skipping never chases it); 01 / 10 never shipped.
        match len {
            0 => return Some(at + 1),
            1..=0x3f => at += 1 + usize::from(len),
            0xc0..=0xff => {
                payload.get(at + 1)?;
                return Some(at + 2);
            }
            _ => return None,
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::fmt::Write as _;

    use super::*;
    use crate::test_support::dns::{TYPE_TXT, header, raw_response, record, response};

    /// Each record as `(section, owner, type, rdata)`, the rdata's names spelled out so a
    /// recompressed message compares equal to its original.
    pub(in crate::net::mdns) fn decode(payload: &[u8]) -> Vec<(Section, String, u16, String)> {
        let text = |at: usize| {
            Labels::new(payload, at, &mut Budget::for_message(payload))
                .map(|label| String::from_utf8_lossy(label.unwrap()).into_owned())
                .collect::<Vec<_>>()
                .join(".")
        };
        let hex = |bytes: &[u8]| {
            bytes.iter().fold(String::new(), |mut out, b| {
                write!(out, "{b:02x}").unwrap();
                out
            })
        };
        Entries::new(payload)
            .map(|entry| {
                let e = entry.unwrap();
                let rdata = match e.rdata_names() {
                    Some(RdataNames { offset, count }) => {
                        let mut parts = vec![hex(&payload[e.rdata..e.rdata + offset])];
                        let mut at = e.rdata + offset;
                        for _ in 0..count {
                            parts.push(text(at));
                            at = skip_name(payload, at).unwrap();
                        }
                        parts.push(hex(&payload[at..e.end]));
                        parts.join("|")
                    }
                    None => hex(&payload[e.rdata..e.end]),
                };
                (e.section, text(e.name), e.rtype, rdata)
            })
            .collect()
    }

    #[test]
    fn only_an_answer_section_left_empty_is_refilled() {
        let txt = |owner: &str| record(owner, TYPE_TXT, b"\x01x");
        let m = raw_response(&[txt("a.local")], &[txt("b.local"), txt("c.local")]);
        let last = m.len() - txt("c.local").len();
        let mut trimmer = Trimmer::default();
        let (out, _) = trimmer
            .trim(&m, |_, _| Ok(true), |entry| entry.name == last)
            .unwrap();
        assert_eq!(out, m);
        let (out, removed) = trimmer
            .trim(
                &m,
                |entry, _| Ok(entry.section != Section::Answer),
                |entry| entry.name == last,
            )
            .unwrap();
        assert_eq!(out, raw_response(&[txt("c.local")], &[txt("b.local")]));
        assert_eq!(removed, 1);
        // So is one that came empty.
        let bare = raw_response(&[], &[txt("b.local"), txt("c.local")]);
        let last = bare.len() - txt("c.local").len();
        let (out, _) = trimmer
            .trim(&bare, |_, _| Ok(true), |entry| entry.name == last)
            .unwrap();
        assert_eq!(out, raw_response(&[txt("c.local")], &[txt("b.local")]));
    }

    #[test]
    fn a_refill_draws_on_the_authority_section_too() {
        let txt = |owner: &str| record(owner, TYPE_TXT, b"\x01x");
        // No answer; `a` and `b` as authority records, `c` as additional data.
        let mut m = header(true, 0, 0);
        m[NSCOUNT_AT + 1] = 2;
        m[ARCOUNT_AT + 1] = 1;
        let b = m.len() + txt("a.local").len();
        m.extend([txt("a.local"), txt("b.local"), txt("c.local")].concat());
        let mut trimmer = Trimmer::default();
        let (out, _) = trimmer
            .trim(&m, |_, _| Ok(true), |entry| entry.name == b)
            .unwrap();
        let mut expected = header(true, 0, 1);
        expected[NSCOUNT_AT + 1] = 1;
        expected[ARCOUNT_AT + 1] = 1;
        expected.extend([txt("b.local"), txt("a.local"), txt("c.local")].concat());
        assert_eq!(out, expected);
    }

    #[test]
    fn a_trim_errs_rather_than_panics_on_unvetted_input() {
        let mut trimmer = Trimmer::default();
        // An SRV whose RDLENGTH is shorter than its fixed fields.
        let mut m = response(&[("_ipp._tcp.local", TYPE_SRV, vec![0, 0])]);
        assert!(trimmer.trim(&m, |_, _| Ok(true), |_| false).is_err());
        m.truncate(5);
        assert!(trimmer.trim(&m, |_, _| Ok(true), |_| false).is_err());
    }
}
