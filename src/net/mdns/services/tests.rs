use std::fmt::Write as _;

use super::super::tests::{MDNS_RESPONSE_BONJOUR, MDNS_RESPONSE_RAOP};
use super::*;
use crate::test_support::dns::{
    TYPE_A, TYPE_TXT, header, name, query, response, response_with_additional, srv,
};
use crate::unique_list::ListError;

fn allow(list: &str) -> ServiceList {
    list.parse().unwrap()
}

/// The scope before any rewrite, refused names discarded.
fn scope(payload: &[u8], allowed: &[ServiceType]) -> Result<Scope, Malformed> {
    assess(payload, allowed, &mut Vec::new())
}

/// The trimmed message when `allowed` trims `payload`.
fn trim(allowed: &str, payload: &[u8]) -> Option<Vec<u8>> {
    match ServiceFilter::new(allow(allowed)).decide(payload) {
        Decision::Trim { payload, .. } => Some(payload.to_vec()),
        _ => None,
    }
}

#[test]
fn a_service_type_parses_case_insensitively_and_displays_lowercased() {
    for (text, shown) in [
        ("_ipp._tcp", "_ipp._tcp"),
        ("_IPP._TCP", "_ipp._tcp"),
        ("_companion-link._tcp", "_companion-link._tcp"),
        ("_hap._udp", "_hap._udp"),
        ("_androidtvremote2._tcp", "_androidtvremote2._tcp"),
        // mDNS lives under `local`, so the domain and a trailing root dot are accepted and
        // dropped: they are how Avahi users write the type.
        ("_ipp._tcp.local", "_ipp._tcp"),
        ("_ipp._tcp.local.", "_ipp._tcp"),
        ("_ipp._tcp.", "_ipp._tcp"),
        ("_ipp._tcp.LOCAL", "_ipp._tcp"),
    ] {
        let service: ServiceType = text.parse().unwrap();
        assert_eq!(service.to_string(), shown);
    }
    assert_eq!(
        "_Hap._Udp".parse::<ServiceType>(),
        "_hap._udp".parse::<ServiceType>()
    );
}

#[test]
fn a_service_type_must_be_an_underscored_label_and_a_transport() {
    for bad in [
        "",
        "ipp._tcp",          // no underscore on the service
        "_ipp.tcp",          // no underscore on the transport
        "_ipp._sctp",        // not a DNS-SD transport label
        "_ipp",              // no transport
        "_._tcp",            // empty service
        "_ipp._tcp.example", // mDNS names live under `local` only
        "_ipp._tcp..",
        "_ipp._tcp.local..",
        " _ipp._tcp",
        "_ip p._tcp",
        "_ipp.x._tcp",
    ] {
        assert_eq!(
            bad.parse::<ServiceType>(),
            Err(ParseServiceTypeError),
            "{bad:?}"
        );
    }
    // A DNS label is at most 63 octets, underscore included.
    let longest = format!("_{}._tcp", "a".repeat(MAX_SERVICE_LEN));
    assert!(longest.parse::<ServiceType>().is_ok());
    let too_long = format!("_{}._tcp", "a".repeat(MAX_SERVICE_LEN + 1));
    assert_eq!(too_long.parse::<ServiceType>(), Err(ParseServiceTypeError));
}

#[test]
fn a_service_list_refuses_a_case_variant_duplicate() {
    let list: ServiceList = "_ipp._tcp, _airplay._tcp".parse().unwrap();
    assert_eq!(list.len(), 2);
    assert!(matches!(
        "_ipp._tcp,_IPP._tcp".parse::<ServiceList>(),
        Err(ListError::Duplicate { .. })
    ));
    assert!(matches!(
        "_ipp._tcp,ipp".parse::<ServiceList>(),
        Err(ListError::Invalid { .. })
    ));
    // DNS-SD's own meta-names are not a record's service, so an entry for them could not match.
    for meta in ["_dns-sd._udp", "_DNS-SD._tcp.local"] {
        assert!(
            matches!(meta.parse::<ServiceList>(), Err(ListError::Refused { .. })),
            "{meta}"
        );
    }
}

#[test]
fn a_query_is_refused_only_when_every_question_is_a_refused_service() {
    let allowed = allow("_ipp._tcp");
    assert_eq!(
        scope(&query(&["_airplay._tcp.local"]), &allowed),
        Ok(Scope::Refuse)
    );
    assert_eq!(
        scope(
            &query(&["_airplay._tcp.local", "_raop._tcp.local"]),
            &allowed
        ),
        Ok(Scope::Refuse)
    );
    assert_eq!(
        scope(&query(&["_ipp._tcp.local"]), &allowed),
        Ok(Scope::Pass)
    );
    // A mixed query goes out whole; its answer is trimmed on the way back.
    assert_eq!(
        scope(
            &query(&["_airplay._tcp.local", "_ipp._tcp.local"]),
            &allowed
        ),
        Ok(Scope::Pass)
    );
    // Not service-scoped: a hostname, a reverse lookup, the DNS-SD enumeration.
    for unscoped in [
        "printer.local",
        "9.1.168.192.in-addr.arpa",
        "_services._dns-sd._udp.local",
    ] {
        assert_eq!(
            scope(&query(&[unscoped]), &allowed),
            Ok(Scope::Pass),
            "{unscoped}"
        );
    }
    assert_eq!(scope(&query(&[]), &allowed), Ok(Scope::Pass));
}

#[test]
fn a_response_passes_when_nothing_in_it_is_refused() {
    let allowed = allow("_ipp._tcp, _airplay._tcp");
    // Address records alone are not service-scoped: hostname resolution keeps working.
    let host = response(&[("printer.local", TYPE_A, vec![192, 0, 2, 9])]);
    assert_eq!(scope(&host, &allowed), Ok(Scope::Pass));
    let ipp = response(&[
        ("_ipp._tcp.local", TYPE_PTR, name("Laser._ipp._tcp.local")),
        ("Laser._ipp._tcp.local", TYPE_SRV, srv("printer.local")),
        ("Laser._ipp._tcp.local", TYPE_TXT, b"\x06txtvers=1".to_vec()),
        ("printer.local", TYPE_A, vec![192, 0, 2, 9]),
    ]);
    assert_eq!(scope(&ipp, &allowed), Ok(Scope::Pass));
    // DNS names compare case-insensitively.
    let shouted = response(&[(
        "_AirPlay._TCP.local",
        TYPE_PTR,
        name("TV._AirPlay._TCP.local"),
    )]);
    assert_eq!(scope(&shouted, &allowed), Ok(Scope::Pass));
}

#[test]
fn a_response_is_refused_when_no_service_in_it_is_allowed() {
    let allowed = allow("_ipp._tcp");
    // An announcement: the address record is an answer beside the refused service's, and goes
    // with it rather than out alone.
    let airplay = response(&[
        (
            "_airplay._tcp.local",
            TYPE_PTR,
            name("TV._airplay._tcp.local"),
        ),
        ("TV._airplay._tcp.local", TYPE_SRV, srv("tv.local")),
        ("tv.local", TYPE_A, vec![192, 0, 2, 10]),
    ]);
    assert_eq!(scope(&airplay, &allowed), Ok(Scope::Refuse));
    // The enumeration is scoped by the type it names.
    let listing = response(&[(
        "_services._dns-sd._udp.local",
        TYPE_PTR,
        name("_hap._tcp.local"),
    )]);
    assert_eq!(scope(&listing, &allowed), Ok(Scope::Refuse));
}

#[test]
fn the_answers_decide_a_response_that_carries_refused_services() {
    let allowed = allow("_ipp._tcp");
    let hap = || ("_hap._tcp.local", TYPE_PTR, name("Lock._hap._tcp.local"));
    // A hostname answer carrying a refused service as additional data: the answer stands, and
    // only the extra goes.
    let hostname =
        response_with_additional(&[("printer.local", TYPE_A, vec![192, 0, 2, 9])], &[hap()]);
    assert_eq!(scope(&hostname, &allowed), Ok(Scope::Trim));
    assert_eq!(
        trim("_ipp._tcp", &hostname).unwrap(),
        response(&[("printer.local", TYPE_A, vec![192, 0, 2, 9])])
    );
    // Every answer is a refused service: an allowed one among the additional data does not keep
    // it, since a client after that service asks for it.
    let extra = response_with_additional(
        &[hap()],
        &[("_ipp._tcp.local", TYPE_PTR, name("Laser._ipp._tcp.local"))],
    );
    assert_eq!(scope(&extra, &allowed), Ok(Scope::Refuse));
    // No answers: a refused service and its host's address as additional data are refused, as
    // they are in the answer section, rather than trimmed to the address alone.
    let unanswered =
        response_with_additional(&[], &[hap(), ("lock.local", TYPE_A, vec![192, 0, 2, 10])]);
    assert_eq!(scope(&unanswered, &allowed), Ok(Scope::Refuse));
    let bare = response_with_additional(&[], &[hap()]);
    assert_eq!(scope(&bare, &allowed), Ok(Scope::Refuse));
    // With nothing refused, a response without answers still passes as it is.
    let addresses = response_with_additional(&[], &[("lock.local", TYPE_A, vec![192, 0, 2, 10])]);
    assert_eq!(scope(&addresses, &allowed), Ok(Scope::Pass));
}

#[test]
fn a_response_mixing_allowed_and_refused_services_is_trimmed() {
    let allowed = allow("_ipp._tcp");
    let mixed = response(&[
        ("_ipp._tcp.local", TYPE_PTR, name("Laser._ipp._tcp.local")),
        (
            "_airplay._tcp.local",
            TYPE_PTR,
            name("TV._airplay._tcp.local"),
        ),
    ]);
    assert_eq!(scope(&mixed, &allowed), Ok(Scope::Trim));
    let listing = response(&[
        (
            "_services._dns-sd._udp.local",
            TYPE_PTR,
            name("_ipp._tcp.local"),
        ),
        (
            "_services._dns-sd._udp.local",
            TYPE_PTR,
            name("_hap._tcp.local"),
        ),
    ]);
    assert_eq!(scope(&listing, &allowed), Ok(Scope::Trim));
}

#[test]
fn the_service_is_the_pair_nearest_the_domain() {
    // A subtype browse (RFC 6763 §7.1) is scoped by its parent type.
    let subtype = response(&[(
        "_I0123456789ABCDEF._sub._matter._tcp.local",
        TYPE_PTR,
        name("0123456789ABCDEF-00000000000000A1._matter._tcp.local"),
    )]);
    assert_eq!(scope(&subtype, &allow("_matter._tcp")), Ok(Scope::Pass));
    assert_eq!(scope(&subtype, &allow("_hap._tcp")), Ok(Scope::Refuse));
    // An instance label that looks like a service type does not make it one.
    let decoy = response(&[("_ipp._http._tcp.local", TYPE_SRV, srv("box.local"))]);
    assert_eq!(scope(&decoy, &allow("_ipp._tcp")), Ok(Scope::Refuse));
    assert_eq!(scope(&decoy, &allow("_http._tcp")), Ok(Scope::Pass));
}

#[test]
fn real_bundled_responses_are_scoped() {
    // One Bonjour response bundles `_smb._tcp` and `_afpovertcp._tcp` with the host's
    // addresses and NSECs.
    assert_eq!(
        scope(&MDNS_RESPONSE_BONJOUR, &allow("_smb._tcp")),
        Ok(Scope::Trim)
    );
    assert_eq!(
        scope(
            &MDNS_RESPONSE_BONJOUR,
            &allow("_smb._tcp, _afpovertcp._tcp")
        ),
        Ok(Scope::Pass)
    );
    assert_eq!(
        scope(&MDNS_RESPONSE_BONJOUR, &allow("_ipp._tcp")),
        Ok(Scope::Refuse)
    );
    assert_eq!(
        scope(&MDNS_RESPONSE_RAOP, &allow("_raop._tcp")),
        Ok(Scope::Pass)
    );
    assert_eq!(
        scope(&MDNS_RESPONSE_RAOP, &allow("_airplay._tcp")),
        Ok(Scope::Refuse)
    );
}

#[test]
fn a_malformed_message_is_its_own_scope() {
    let allowed = allow("_ipp._tcp");
    let mut truncated = response(&[("_ipp._tcp.local", TYPE_PTR, name("L._ipp._tcp.local"))]);
    truncated.truncate(truncated.len() - 3);
    assert_eq!(scope(&truncated, &allowed), Err(Malformed));
    // A compression pointer to itself.
    let mut looped = header(true, 0, 1);
    looped.extend_from_slice(&[0xc0, 12]);
    looped.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0, 120, 0, 0]);
    assert_eq!(scope(&looped, &allowed), Err(Malformed));
    assert_eq!(scope(b"", &allowed), Err(Malformed));
}

/// A response whose every record names one long chain of compression pointers: legal hop by
/// hop, but walking it for each record costs far more than the message is long.
fn pointer_chain_response(hops: usize, records: usize) -> Vec<u8> {
    let mut m = header(true, 0, 0);
    // `_ipp._tcp.local`, then `hops` one-label names, each pointing at the one before.
    let base = m.len();
    m.extend(name("_ipp._tcp.local"));
    let mut tail = base;
    for _ in 0..hops {
        let here = m.len();
        m.extend_from_slice(&[
            1,
            b'x',
            0xc0 | u8::try_from(tail >> 8).unwrap(),
            u8::try_from(tail & 0xff).unwrap(),
        ]);
        tail = here;
    }
    // The chain is not itself a record: move it inside the first record's rdata so the
    // message stays well formed, then point every record's owner at its far end.
    let chain = m.split_off(base);
    let mut out = header(true, 0, records);
    let offset = out.len() + 12;
    let shift = |p: usize| p - base + offset;
    let mut rdata = chain.clone();
    let mut at = 0;
    while at < rdata.len() {
        let n = rdata[at];
        if n & 0xc0 == 0xc0 {
            let target = shift((usize::from(n & 0x3f) << 8) | usize::from(rdata[at + 1]));
            rdata[at] = 0xc0 | u8::try_from(target >> 8).unwrap();
            rdata[at + 1] = u8::try_from(target & 0xff).unwrap();
            at += 2;
        } else if n == 0 {
            at += 1;
        } else {
            at += 1 + usize::from(n);
        }
    }
    let far_end = shift(tail);
    for i in 0..records {
        out.extend_from_slice(&[
            0xc0 | u8::try_from(far_end >> 8).unwrap(),
            u8::try_from(far_end & 0xff).unwrap(),
        ]);
        out.extend_from_slice(&[0, 16, 0, 1, 0, 0, 0, 120]);
        let rd: &[u8] = if i == 0 { &rdata } else { &[] };
        out.extend_from_slice(&u16::try_from(rd.len()).unwrap().to_be_bytes());
        out.extend_from_slice(rd);
    }
    out
}

#[test]
fn the_work_per_message_is_bounded() {
    let allowed = allow("_ipp._tcp");
    // A handful of records over a short chain is ordinary and still scoped.
    assert_eq!(
        scope(&pointer_chain_response(3, 4), &allowed),
        Ok(Scope::Pass)
    );
    // Hundreds of records over a 120-hop chain would walk ~40 steps per byte: refused as
    // malformed long before, whatever the allow-list says.
    let heavy = pointer_chain_response(120, 300);
    assert_eq!(scope(&heavy, &allowed), Err(Malformed));
    assert!(matches!(
        ServiceFilter::new(allowed).decide(&heavy),
        Decision::Malformed
    ));
}

#[test]
fn a_dname_target_pointing_into_a_dropped_record_is_spelled_out() {
    // Record 1 (refused) owns `local`; record 2 (allowed) keeps the message a trim; record 3 is
    // a DNAME whose target is a pointer to record 1's `local`.
    let mut m = header(true, 0, 3);
    let first = m.len();
    m.extend(name("_hap._tcp.local"));
    m.extend_from_slice(&[0, 12, 0x80, 1, 0, 0, 0, 120]);
    let target = name("L._hap._tcp.local");
    m.extend_from_slice(&u16::try_from(target.len()).unwrap().to_be_bytes());
    m.extend(target);
    m.extend(name("_ipp._tcp.local"));
    m.extend_from_slice(&[0, 12, 0x80, 1, 0, 0, 0, 120]);
    let target = name("L._ipp._tcp.local");
    m.extend_from_slice(&u16::try_from(target.len()).unwrap().to_be_bytes());
    m.extend(target);
    let local = u8::try_from(first + 1 + 4 + 1 + 4).unwrap(); // past `_hap` and `_tcp`
    m.extend(name("alias.example"));
    m.extend_from_slice(&[0, 39, 0x80, 1, 0, 0, 0, 120, 0, 2, 0xc0, local]);
    let trimmed = trim("_ipp._tcp", &m).unwrap();
    let dname = decode(&trimmed).into_iter().find(|r| r.2 == 39).unwrap();
    assert_eq!(dname.3, "|local|");
}

#[test]
fn the_rewrite_errs_rather_than_panics_on_unvetted_input() {
    let mut filter = ServiceFilter::new(allow("_ipp._tcp"));
    // An SRV whose RDLENGTH is shorter than its fixed fields.
    let mut m = response(&[("_ipp._tcp.local", TYPE_SRV, vec![0, 0])]);
    assert!(filter.rewrite(&m).is_err());
    m.truncate(5);
    assert!(filter.rewrite(&m).is_err());
}

/// Each record as `(section, owner, type, rdata)`, the rdata's names spelled out so a
/// recompressed message compares equal to its original.
fn decode(payload: &[u8]) -> Vec<(Section, String, u16, String)> {
    let text = |at: usize| {
        Labels::new(payload, at, &mut Budget(usize::MAX))
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
fn a_mixed_response_is_trimmed_to_its_allowed_and_unscoped_records() {
    let original = response(&[
        ("_ipp._tcp.local", TYPE_PTR, name("Laser._ipp._tcp.local")),
        (
            "_airplay._tcp.local",
            TYPE_PTR,
            name("TV._airplay._tcp.local"),
        ),
        ("Laser._ipp._tcp.local", TYPE_SRV, srv("printer.local")),
        ("TV._airplay._tcp.local", TYPE_SRV, srv("tv.local")),
        ("printer.local", TYPE_A, vec![192, 0, 2, 9]),
    ]);
    let trimmed = trim("_ipp._tcp", &original).expect("a mixed response is trimmed");
    let kept: Vec<_> = decode(&original)
        .into_iter()
        .filter(|(_, owner, _, rdata)| !owner.contains("airplay") && !rdata.contains("airplay"))
        .collect();
    assert_eq!(decode(&trimmed), kept);
    assert_eq!(kept.len(), 3);
    // The ID and flags carry over.
    assert_eq!(trimmed[..4], original[..4]);
}

#[test]
fn a_real_bundled_response_keeps_every_record_but_the_refused_services() {
    let trimmed = trim("_smb._tcp", &MDNS_RESPONSE_BONJOUR).unwrap();
    let original = decode(&MDNS_RESPONSE_BONJOUR);
    let kept: Vec<_> = original
        .iter()
        .filter(|(_, owner, _, _)| !owner.contains("_afpovertcp"))
        .cloned()
        .collect();
    // The `_afpovertcp` SRV in the answers and its NSEC in the additionals.
    assert_eq!(original.len() - kept.len(), 2);
    assert_eq!(decode(&trimmed), kept);
    // Recompressed, not spelled out: dropping records shrinks this message.
    assert!(trimmed.len() < MDNS_RESPONSE_BONJOUR.len());
}

#[test]
fn a_kept_name_pointing_into_a_dropped_record_is_spelled_out() {
    // The second record's owner is `_ipp` plus a pointer to `_tcp.local` inside the first
    // record's owner, which the trim drops.
    let mut m = header(true, 0, 2);
    m.extend(name("_airplay._tcp.local"));
    m.extend_from_slice(&[0, 12, 0x80, 1, 0, 0, 0, 120]);
    let target = name("TV._airplay._tcp.local");
    m.extend_from_slice(&u16::try_from(target.len()).unwrap().to_be_bytes());
    m.extend(target);
    m.extend_from_slice(&[4, b'_', b'i', b'p', b'p', 0xc0, 12 + 9]);
    m.extend_from_slice(&[0, 12, 0x80, 1, 0, 0, 0, 120]);
    let target = name("L._ipp._tcp.local");
    m.extend_from_slice(&u16::try_from(target.len()).unwrap().to_be_bytes());
    m.extend(target);
    assert_eq!(decode(&m)[1].1, "_ipp._tcp.local");

    let trimmed = trim("_ipp._tcp", &m).unwrap();
    assert_eq!(
        decode(&trimmed),
        [(
            Section::Answer,
            "_ipp._tcp.local".to_owned(),
            TYPE_PTR,
            "|L._ipp._tcp.local|".to_owned()
        )]
    );
}

#[test]
fn only_a_mixed_response_is_rewritten() {
    let mut filter = ServiceFilter::new(allow("_smb._tcp, _afpovertcp._tcp"));
    assert!(
        matches!(filter.decide(&MDNS_RESPONSE_BONJOUR), Decision::Pass),
        "nothing refused"
    );
    let mut filter = ServiceFilter::new(allow("_ipp._tcp"));
    assert!(
        matches!(filter.decide(&MDNS_RESPONSE_BONJOUR), Decision::Refuse(_)),
        "nothing allowed"
    );
    assert!(
        matches!(
            filter.decide(&query(&["_ipp._tcp.local", "_hap._tcp.local"])),
            Decision::Pass
        ),
        "a query is not rewritten"
    );
}

#[test]
fn a_decision_names_the_refused_services() {
    let mut filter = ServiceFilter::new(allow("_smb._tcp"));
    let Decision::Trim {
        removed, refused, ..
    } = filter.decide(&MDNS_RESPONSE_BONJOUR)
    else {
        panic!("a mixed response is trimmed");
    };
    // The `_afpovertcp` SRV in the answers and its NSEC in the additionals.
    assert_eq!(removed, 2);
    assert_eq!(refused.to_string(), "_afpovertcp._tcp");
    let mut filter = ServiceFilter::new(allow("_ipp._tcp"));
    let Decision::Refuse(refused) = filter.decide(&MDNS_RESPONSE_BONJOUR) else {
        panic!("nothing in it is allowed");
    };
    assert_eq!(refused.to_string(), "_smb._tcp, _afpovertcp._tcp");
}

#[test]
fn a_wire_service_label_displays_escaped() {
    // Configured types are ASCII by construction; one named on the wire may be anything.
    let odd = ServiceType::from_wire(b"Odd\x01", Proto::Udp).unwrap();
    assert_eq!(odd.to_string(), "_odd\\x01._udp");
    assert_eq!(ServiceType::from_wire(b"", Proto::Tcp), None);
    assert_eq!(
        ServiceType::from_wire(&[b'a'; MAX_SERVICE_LEN + 1], Proto::Tcp),
        None
    );
}
