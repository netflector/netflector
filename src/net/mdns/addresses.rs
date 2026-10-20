//! The addresses an mDNS response advertises, as the response leg judges them: one offering only
//! unreachable addresses is dropped, and one offering a usable address too loses the unreachable
//! ones.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::message::{Entries, Entry, Malformed, Trimmer};
use crate::net::{is_link_local, is_never_a_peer};

#[derive(Debug, Clone, Copy, Default)]
struct Advertised {
    usable: bool,
    unreachable: bool,
}

/// Strips a response's unreachable address records while it advertises a usable one, so a client
/// on the other link is offered only addresses it can reach.
///
/// When the strip leaves no answer, the usable addresses move into the answer section from the
/// others: Avahi and Android clients discard a response without answers, and relaying the
/// unreachable answer would put an address the client cannot reach in its cache.
#[derive(Default)]
pub(crate) struct AddressFilter {
    trimmer: Trimmer,
}

impl AddressFilter {
    /// `payload` without its unreachable address records, and how many those were. `None` leaves
    /// it as it is: nothing to strip, nothing usable to keep (that one is
    /// [`advertises_only_unreachable`]'s to drop), or a message it cannot walk or re-encode.
    pub(crate) fn strip(&mut self, payload: &[u8]) -> Option<(&[u8], usize)> {
        let advertised = advertised(payload).ok()?;
        if !(advertised.usable && advertised.unreachable) {
            return None;
        }
        self.trimmer
            .trim(
                payload,
                |entry, _| Ok(!address(payload, entry).is_some_and(is_unreachable)),
                |entry| address(payload, entry).is_some_and(|ip| !is_unreachable(ip)),
            )
            .ok()
    }
}

/// At least one A/AAAA record, and every one [`is_unreachable`]. For responses only: a query's
/// records are known-answer cache state, not an advertisement. No address records or a malformed
/// message reads as `false`.
pub(crate) fn advertises_only_unreachable(payload: &[u8]) -> bool {
    advertised(payload).is_ok_and(|advertised| advertised.unreachable && !advertised.usable)
}

/// Link-local, valid only on the link it came from, or [`is_never_a_peer`].
fn is_unreachable(ip: IpAddr) -> bool {
    is_link_local(ip) || is_never_a_peer(ip)
}

fn advertised(payload: &[u8]) -> Result<Advertised, Malformed> {
    let mut advertised = Advertised::default();
    for entry in Entries::new(payload) {
        let ip = address(payload, entry?);
        let unreachable = ip.is_some_and(is_unreachable);
        advertised.usable |= ip.is_some() && !unreachable;
        advertised.unreachable |= unreachable;
    }
    Ok(advertised)
}

/// The A / AAAA record types (RFC 1035 §3.4.1 / RFC 3596 §2.1).
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

fn address(payload: &[u8], entry: Entry) -> Option<IpAddr> {
    let rdata = payload.get(entry.rdata..entry.end)?;
    match entry.rtype {
        TYPE_A => <[u8; 4]>::try_from(rdata)
            .ok()
            .map(|a| Ipv4Addr::from(a).into()),
        TYPE_AAAA => <[u8; 16]>::try_from(rdata)
            .ok()
            .map(|a| Ipv6Addr::from(a).into()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::DNS_HEADER_LEN;
    use super::super::message::tests::decode;
    use super::super::tests::{MDNS_RESPONSE_BONJOUR, MDNS_RESPONSE_RAOP};
    use super::*;
    use crate::test_support::dns;

    fn record(owner: &str, (rtype, rdata): (u16, &[u8])) -> Vec<u8> {
        dns::record(owner, rtype, rdata)
    }

    /// [`record`] with its owner a pointer to `at` instead.
    fn compressed(owner: &str, at: u8, rr: (u16, &[u8])) -> Vec<u8> {
        let mut r = vec![0xc0, at];
        r.extend_from_slice(&record(owner, rr)[dns::name(owner).len()..]);
        r
    }

    /// A response whose answers are `records`, each under the name `x.`.
    fn response_with_records(records: &[(u16, &[u8])]) -> Vec<u8> {
        let answers: Vec<_> = records.iter().map(|&rr| record("x", rr)).collect();
        dns::raw_response(&answers, &[])
    }

    const A_LINK_LOCAL: (u16, &[u8]) = (TYPE_A, &[169, 254, 1, 2]);
    const A_ROUTABLE: (u16, &[u8]) = (TYPE_A, &[192, 168, 1, 9]);
    const AAAA_LINK_LOCAL: (u16, &[u8]) = (
        TYPE_AAAA,
        &[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    );
    const AAAA_ROUTABLE: (u16, &[u8]) = (
        TYPE_AAAA,
        &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    );
    const A_LOOPBACK: (u16, &[u8]) = (TYPE_A, &[127, 0, 0, 1]);
    const A_UNSPECIFIED: (u16, &[u8]) = (TYPE_A, &[0, 0, 0, 0]);
    const TXT: (u16, &[u8]) = (dns::TYPE_TXT, b"vers=1");

    #[test]
    fn suppresses_only_when_every_address_is_unreachable() {
        assert!(advertises_only_unreachable(&response_with_records(&[
            A_LINK_LOCAL
        ])));
        assert!(advertises_only_unreachable(&response_with_records(&[
            AAAA_LINK_LOCAL
        ])));
        assert!(advertises_only_unreachable(&response_with_records(&[
            A_LINK_LOCAL,
            AAAA_LINK_LOCAL
        ])));
        // One routable address of either family rescues the message: the client can use it.
        assert!(!advertises_only_unreachable(&response_with_records(&[
            A_LINK_LOCAL,
            A_ROUTABLE
        ])));
        assert!(!advertises_only_unreachable(&response_with_records(&[
            AAAA_LINK_LOCAL,
            AAAA_ROUTABLE
        ])));
        // The never-a-peer classes suppress like link-local, and a routable address rescues them too.
        assert!(advertises_only_unreachable(&response_with_records(&[
            A_LOOPBACK
        ])));
        assert!(advertises_only_unreachable(&response_with_records(&[
            A_UNSPECIFIED,
            AAAA_LINK_LOCAL
        ])));
        assert!(!advertises_only_unreachable(&response_with_records(&[
            A_LOOPBACK, A_ROUTABLE
        ])));
        // Other record types don't veto: a bundled advertisement (PTR/SRV/TXT beside the
        // addresses) whose only addresses are link-local is exactly the dead-service case.
        assert!(advertises_only_unreachable(&response_with_records(&[
            TXT,
            A_LINK_LOCAL
        ])));
        // No address records at all is not an advertisement of dead endpoints.
        assert!(!advertises_only_unreachable(&response_with_records(&[TXT])));
        assert!(!advertises_only_unreachable(&response_with_records(&[])));
    }

    #[test]
    fn suppression_skips_names_with_compression_pointers() {
        // The second record's name is a pointer to the first's: the walker must step the 2-byte
        // pointer, not chase it into the TXT and read that again.
        let m = dns::raw_response(&[record("x", TXT), compressed("x", 12, A_LINK_LOCAL)], &[]);
        assert!(advertises_only_unreachable(&m));
    }

    #[test]
    fn a_malformed_message_is_never_suppressed() {
        // Truncated rdata: the record claims 4 bytes and the payload ends.
        let mut m = response_with_records(&[A_LINK_LOCAL]);
        m.truncate(m.len() - 2);
        assert!(!advertises_only_unreachable(&m));
        // An undefined label type (0x40) aborts the walk.
        let mut m = response_with_records(&[A_LINK_LOCAL]);
        m[DNS_HEADER_LEN] = 0x40;
        assert!(!advertises_only_unreachable(&m));
        assert!(!advertises_only_unreachable(b""));
    }

    #[test]
    fn real_responses_with_a_routable_address_are_not_suppressed() {
        // Bonjour: fe80:: AAAA + routable A + global AAAA (mixed); RAOP: one routable A.
        assert!(!advertises_only_unreachable(&MDNS_RESPONSE_BONJOUR));
        assert!(!advertises_only_unreachable(&MDNS_RESPONSE_RAOP));
    }

    fn strip(payload: &[u8]) -> Option<(Vec<u8>, usize)> {
        AddressFilter::default()
            .strip(payload)
            .map(|(stripped, removed)| (stripped.to_vec(), removed))
    }

    #[test]
    fn a_response_loses_its_unreachable_addresses_while_a_usable_one_remains() {
        assert_eq!(
            strip(&response_with_records(&[
                A_LINK_LOCAL,
                A_ROUTABLE,
                AAAA_LINK_LOCAL,
                TXT,
                AAAA_ROUTABLE
            ])),
            Some((response_with_records(&[A_ROUTABLE, TXT, AAAA_ROUTABLE]), 2))
        );
        // A family with nothing usable goes entirely.
        assert_eq!(
            strip(&response_with_records(&[
                A_LOOPBACK,
                A_UNSPECIFIED,
                AAAA_ROUTABLE
            ])),
            Some((response_with_records(&[AAAA_ROUTABLE]), 2))
        );
    }

    #[test]
    fn the_usable_address_may_be_another_hosts() {
        let m = dns::raw_response(
            &[
                record("a.local", A_ROUTABLE),
                record("b.local", A_LINK_LOCAL),
            ],
            &[],
        );
        assert_eq!(
            strip(&m),
            Some((dns::raw_response(&[record("a.local", A_ROUTABLE)], &[]), 1))
        );
    }

    #[test]
    fn an_address_record_of_the_wrong_length_is_no_address() {
        // A 6-byte A record is neither usable nor unreachable: kept, and no reason to strip.
        let odd = record("x", (TYPE_A, &[169, 254, 1, 2, 0, 0]));
        let m = dns::raw_response(&[odd.clone(), record("x", A_ROUTABLE)], &[]);
        assert_eq!(strip(&m), None);
        let m = dns::raw_response(
            &[
                odd.clone(),
                record("x", A_ROUTABLE),
                record("x", A_LINK_LOCAL),
            ],
            &[],
        );
        assert_eq!(
            strip(&m),
            Some((dns::raw_response(&[odd, record("x", A_ROUTABLE)], &[]), 1))
        );
    }

    #[test]
    fn a_response_without_both_usable_and_unreachable_addresses_is_left_whole() {
        for records in [&[A_ROUTABLE, AAAA_ROUTABLE][..], &[TXT], &[]] {
            assert_eq!(strip(&response_with_records(records)), None);
        }
        // Nothing usable would remain: the suppression drops these whole, other records included.
        for records in [
            &[A_LINK_LOCAL, AAAA_LINK_LOCAL][..],
            &[TXT, A_LINK_LOCAL],
            &[TXT, A_LINK_LOCAL, AAAA_LINK_LOCAL],
        ] {
            let response = response_with_records(records);
            assert_eq!(strip(&response), None);
            assert!(advertises_only_unreachable(&response));
        }
    }

    #[test]
    fn a_response_the_strip_cannot_read_is_left_whole() {
        let mut truncated = response_with_records(&[A_ROUTABLE, A_LINK_LOCAL]);
        truncated.truncate(truncated.len() - 2);
        assert_eq!(strip(&truncated), None);
        // Walkable record by record, but a name that points back at itself cannot be re-encoded,
        // whether the pointer is all of it or follows a label.
        let answers = vec![record("x", A_ROUTABLE), record("x", A_LINK_LOCAL)];
        let at = u8::try_from(dns::raw_response(&answers, &[]).len()).unwrap();
        let tail = &record("x", TXT)[dns::name("x").len()..];
        for owner in [&[0xc0, at][..], &[1, b'y', 0xc0, at]] {
            let looped = [answers.clone(), vec![[owner, tail].concat()]].concat();
            assert_eq!(strip(&dns::raw_response(&looped, &[])), None, "{owner:?}");
        }
    }

    #[test]
    fn a_question_is_no_address() {
        // An AAAA question has no rdata: neither usable nor unreachable, and kept.
        let mut question = dns::name("host.local");
        question.extend_from_slice(&TYPE_AAAA.to_be_bytes());
        question.extend_from_slice(&[0x00, 0x01]);
        let message = |answers: &[Vec<u8>]| {
            let mut m = dns::header(true, 1, answers.len());
            m.extend_from_slice(&question);
            m.extend(answers.concat());
            m
        };
        assert!(advertises_only_unreachable(&message(&[record(
            "host.local",
            AAAA_LINK_LOCAL
        )])));
        assert_eq!(
            strip(&message(&[
                record("host.local", A_ROUTABLE),
                record("host.local", AAAA_LINK_LOCAL)
            ])),
            Some((message(&[record("host.local", A_ROUTABLE)]), 1))
        );
    }

    #[test]
    fn the_usable_addresses_answer_when_the_strip_empties_the_answers() {
        // An AAAA question answered with fe80:: alone, the A and a TXT as additional data (RFC 6762
        // §6.2): the A moves up, the TXT stays.
        let txt = record("host.local", TXT);
        assert_eq!(
            strip(&dns::raw_response(
                &[record("host.local", AAAA_LINK_LOCAL)],
                &[txt.clone(), record("host.local", A_ROUTABLE)]
            )),
            Some((
                dns::raw_response(
                    &[record("host.local", A_ROUTABLE)],
                    std::slice::from_ref(&txt)
                ),
                1
            ))
        );
        // Its name a pointer into the stripped answer, the A spells it out where it lands.
        assert_eq!(
            strip(&dns::raw_response(
                &[record("host.local", AAAA_LINK_LOCAL)],
                &[compressed("host.local", 12, A_ROUTABLE)]
            )),
            Some((
                dns::raw_response(&[record("host.local", A_ROUTABLE)], &[]),
                1
            ))
        );
        // A kept record the moved one points to now points to it.
        let first = dns::raw_response(&[record("other.local", AAAA_LINK_LOCAL)], &[]).len();
        let at = u8::try_from(first).unwrap();
        assert_eq!(
            strip(&dns::raw_response(
                &[record("other.local", AAAA_LINK_LOCAL)],
                &[
                    record("host.local", TXT),
                    compressed("host.local", at, A_ROUTABLE)
                ]
            )),
            Some((
                dns::raw_response(
                    &[record("host.local", A_ROUTABLE)],
                    &[compressed("host.local", 12, TXT)]
                ),
                1
            ))
        );
        // A response that came without answers gets them too.
        assert_eq!(
            strip(&dns::raw_response(
                &[],
                &[
                    record("host.local", A_LINK_LOCAL),
                    record("host.local", A_ROUTABLE)
                ]
            )),
            Some((
                dns::raw_response(&[record("host.local", A_ROUTABLE)], &[]),
                1
            ))
        );
        // An answer the strip keeps leaves the sections as they are.
        assert_eq!(
            strip(&dns::raw_response(
                &[record("host.local", AAAA_LINK_LOCAL), txt.clone()],
                &[record("host.local", A_ROUTABLE)]
            )),
            Some((
                dns::raw_response(&[txt], &[record("host.local", A_ROUTABLE)]),
                1
            ))
        );
    }

    #[test]
    fn a_name_pointing_into_a_stripped_record_is_spelled_out() {
        // The link-local AAAA spells out the host name, and the A after it points there.
        let m = dns::raw_response(
            &[
                record("host.local", AAAA_LINK_LOCAL),
                compressed("host.local", 12, A_ROUTABLE),
            ],
            &[],
        );
        assert_eq!(
            strip(&m),
            Some((
                dns::raw_response(&[record("host.local", A_ROUTABLE)], &[]),
                1
            ))
        );
    }

    #[test]
    fn a_real_response_keeps_every_record_but_its_link_local_address() {
        let (stripped, removed) = strip(&MDNS_RESPONSE_BONJOUR).expect("routable addresses remain");
        assert_eq!(removed, 1);
        let kept: Vec<_> = decode(&MDNS_RESPONSE_BONJOUR)
            .into_iter()
            .filter(|(_, _, _, rdata)| !rdata.starts_with("fe80"))
            .collect();
        assert_eq!(decode(&stripped), kept);
        assert!(stripped.len() < MDNS_RESPONSE_BONJOUR.len());
    }
}
