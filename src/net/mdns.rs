//! mDNS wire constants and the query/response classifier that acts as the reflector's directional gate.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::is_link_local;

/// RFC 6762.
pub(crate) const MDNS_PORT: u16 = 5353;
/// mDNS is sent at IP TTL 255: a send-side SHOULD in RFC 6762 §11, kept for old queriers that
/// checked the TTL on receipt (current receivers check the source address instead). The reflector
/// re-emits a fresh link-local message, so it sets 255 rather than preserving the captured TTL.
pub(crate) const MDNS_TTL: u8 = 255;
pub(crate) const MDNS_GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// Link-local scope (`ff02::`), not site-local.
pub(crate) const MDNS_GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

/// An mDNS message is a query or a response, per the QR bit of its DNS header. Unsolicited
/// announcements count as responses (RFC 6762 §8.3). This split is the reflector's directional
/// gate: queries reflect source → target, responses target → source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MdnsKind {
    Query,
    Response,
}

/// The fixed DNS header is 12 bytes (RFC 1035 §4.1.1).
const DNS_HEADER_LEN: usize = 12;
/// The high byte of the flags field (header offset 2); the QR bit is its top bit.
const FLAGS_HIGH: usize = 2;
const QR_BIT: u8 = 0x80;
/// The header's four section-count fields, by offset.
const QDCOUNT_AT: usize = 4;
const ANCOUNT_AT: usize = 6;
const NSCOUNT_AT: usize = 8;
const ARCOUNT_AT: usize = 10;

/// Classify a payload by the QR bit of its fixed 12-byte DNS header. `None` when the payload is too
/// short to hold that header; that is anomalous on the dedicated mDNS group, so the caller surfaces
/// it. Header-only: no question or record parsing.
pub(crate) fn classify(payload: &[u8]) -> Option<MdnsKind> {
    if payload.len() < DNS_HEADER_LEN {
        return None;
    }
    Some(if payload[FLAGS_HIGH] & QR_BIT != 0 {
        MdnsKind::Response
    } else {
        MdnsKind::Query
    })
}

/// The A / AAAA record types (RFC 1035 §3.4.1 / RFC 3596 §2.1).
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

/// Whether the message carries at least one A/AAAA record and every one is link-local. Callers
/// apply it to responses only: a query's records are known-answer cache state, not an
/// advertisement. No address records, a routable address, or malformation all read as `false`.
pub(crate) fn advertises_only_link_local(payload: &[u8]) -> bool {
    only_link_local_records(payload).unwrap_or(false)
}

/// The record walk behind [`advertises_only_link_local`]: `None` on truncation or an undefined
/// label type.
fn only_link_local_records(payload: &[u8]) -> Option<bool> {
    if payload.len() < DNS_HEADER_LEN {
        return None;
    }
    let count = |at: usize| usize::from(u16::from_be_bytes([payload[at], payload[at + 1]]));
    let mut at = DNS_HEADER_LEN;
    // The question section leads and carries no rdata; walk over it to reach the records.
    for _ in 0..count(QDCOUNT_AT) {
        at = skip_name(payload, at)?;
        at += 4; // QTYPE + QCLASS
    }
    // Answer + authority + additional: address records may sit in any of them.
    let mut saw_address = false;
    for _ in 0..count(ANCOUNT_AT) + count(NSCOUNT_AT) + count(ARCOUNT_AT) {
        // A record is its name, 10 fixed bytes - TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) - and then
        // RDLENGTH bytes of rdata (RFC 1035 §4.1.3). Only TYPE and RDLENGTH are read here; an
        // A / AAAA rdata is the bare address.
        at = skip_name(payload, at)?;
        let fixed = payload.get(at..at + 10)?;
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let rdlength = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        at += 10;
        let rdata = payload.get(at..at + rdlength)?;
        at += rdlength;
        let ip: IpAddr = match (rtype, rdata.len()) {
            (TYPE_A, 4) => {
                Ipv4Addr::from(<[u8; 4]>::try_from(rdata).expect("length checked")).into()
            }
            (TYPE_AAAA, 16) => {
                Ipv6Addr::from(<[u8; 16]>::try_from(rdata).expect("length checked")).into()
            }
            // Any other type, or an A/AAAA whose rdata is not address-sized, holds no address.
            _ => continue,
        };
        if !is_link_local(ip) {
            return Some(false);
        }
        saw_address = true;
    }
    Some(saw_address)
}

/// Advance past the (possibly compressed) domain name at `at`, returning the offset just after it.
/// `None` on truncation or an undefined label type.
fn skip_name(payload: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *payload.get(at)?;
        // A name is a run of labels, and each label's first byte tags its type in the top two bits
        // (RFC 1035 §3.1 / §4.1.4): 00 = a plain length (1-63) followed by that many bytes, with
        // length 0 ending the name; 11 = a 2-byte compression pointer, which ends the name in
        // place (the target holds the rest, so the record's fixed fields follow the 2 bytes, and
        // skipping never chases it); 01 / 10 = extension types that never shipped.
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
mod tests {
    use super::*;

    /// 12-byte header with `flags_high` at offset 2, plus `tail`.
    fn message(flags_high: u8, tail: &[u8]) -> Vec<u8> {
        let mut m = vec![0u8; DNS_HEADER_LEN];
        m[FLAGS_HIGH] = flags_high;
        m.extend_from_slice(tail);
        m
    }

    #[test]
    fn classifies_by_the_qr_bit_only() {
        assert_eq!(classify(&message(0x00, b"")), Some(MdnsKind::Query)); // QR=0
        assert_eq!(classify(&message(0x84, b"q")), Some(MdnsKind::Response)); // QR=1, AA
        // Only the QR bit is read; the other flag bits don't change the verdict.
        assert_eq!(classify(&message(0x7f, b"")), Some(MdnsKind::Query));
        assert_eq!(classify(&message(0xff, b"")), Some(MdnsKind::Response));
    }

    #[test]
    fn rejects_a_payload_too_short_for_a_dns_header() {
        assert_eq!(classify(b""), None);
        assert_eq!(classify(&[0u8; DNS_HEADER_LEN - 1]), None);
        // Exactly the header length suffices (an all-zero header is a query).
        assert_eq!(classify(&[0u8; DNS_HEADER_LEN]), Some(MdnsKind::Query));
    }

    // --- Real on-the-wire packets, verbatim from captures ---

    /// Real mDNS reverse-PTR query for a link-local IPv6 address (Wireshark `test/captures/
    /// dns-mdns.pcap`, frame 22). QR=0.
    const MDNS_QUERY_PTR_LINKLOCAL: [u8; 90] = [
        0x5f, 0x1d, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x35, 0x01,
        0x65, 0x01, 0x63, 0x01, 0x31, 0x01, 0x34, 0x01, 0x39, 0x01, 0x65, 0x01, 0x66, 0x01, 0x66,
        0x01, 0x66, 0x01, 0x61, 0x01, 0x64, 0x01, 0x39, 0x01, 0x30, 0x01, 0x32, 0x01, 0x62, 0x01,
        0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30,
        0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x38, 0x01, 0x65, 0x01,
        0x66, 0x03, 0x69, 0x70, 0x36, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00, 0x00, 0x0c, 0x00, 0x01,
    ];

    /// Real Apple/Bonjour mDNS response advertising `_smb._tcp` + `_afpovertcp._tcp` for host
    /// "Gourmandise" (scapy `test/scapy/layers/dns.uts`, stored as the bare DNS message). QR=1.
    const MDNS_RESPONSE_BONJOUR: [u8; 249] = [
        0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x0b, 0x47, 0x6f,
        0x75, 0x72, 0x6d, 0x61, 0x6e, 0x64, 0x69, 0x73, 0x65, 0x04, 0x5f, 0x73, 0x6d, 0x62, 0x04,
        0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x21, 0x80, 0x01,
        0x00, 0x00, 0x00, 0x78, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x01, 0xbd, 0x0b, 0x47, 0x6f,
        0x75, 0x72, 0x6d, 0x61, 0x6e, 0x64, 0x69, 0x73, 0x65, 0xc0, 0x22, 0x0b, 0x47, 0x6f, 0x75,
        0x72, 0x6d, 0x61, 0x6e, 0x64, 0x69, 0x73, 0x65, 0x0b, 0x5f, 0x61, 0x66, 0x70, 0x6f, 0x76,
        0x65, 0x72, 0x74, 0x63, 0x70, 0xc0, 0x1d, 0x00, 0x21, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78,
        0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x02, 0x24, 0xc0, 0x39, 0xc0, 0x39, 0x00, 0x1c, 0x80,
        0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x10, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x73, 0x23, 0x99, 0xca, 0xf7, 0xea, 0xdc, 0xc0, 0x39, 0x00, 0x01, 0x80, 0x01, 0x00,
        0x00, 0x00, 0x78, 0x00, 0x04, 0xc0, 0xa8, 0x01, 0x78, 0xc0, 0x39, 0x00, 0x1c, 0x80, 0x01,
        0x00, 0x00, 0x00, 0x78, 0x00, 0x10, 0x2a, 0x01, 0xcb, 0x00, 0x0b, 0x44, 0x1f, 0x00, 0x18,
        0x6b, 0xb1, 0x99, 0x90, 0xdf, 0x84, 0x2e, 0xc0, 0x0c, 0x00, 0x2f, 0x80, 0x01, 0x00, 0x00,
        0x00, 0x78, 0x00, 0x09, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x00, 0x80, 0x00, 0x40, 0xc0, 0x47,
        0x00, 0x2f, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x09, 0xc0, 0x47, 0x00, 0x05, 0x00,
        0x00, 0x80, 0x00, 0x40, 0xc0, 0x39, 0x00, 0x2f, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00,
        0x08, 0xc0, 0x39, 0x00, 0x04, 0x40, 0x00, 0x00, 0x08,
    ];

    /// Real AirPlay/RAOP mDNS response for `_raop._tcp.local` "Freebox Server" (scapy
    /// `test/scapy/layers/dns.uts`, the Ethernet/IPv4/UDP frame prefix stripped to the UDP
    /// payload). QR=1.
    const MDNS_RESPONSE_RAOP: [u8; 295] = [
        0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x05, 0x5f, 0x72,
        0x61, 0x6f, 0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
        0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x11, 0x94, 0x00, 0x1e, 0x1b, 0x31, 0x34, 0x30, 0x43,
        0x37, 0x36, 0x38, 0x46, 0x46, 0x45, 0x32, 0x38, 0x40, 0x46, 0x72, 0x65, 0x65, 0x62, 0x6f,
        0x78, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0xc0, 0x0c, 0xc0, 0x28, 0x00, 0x10, 0x80,
        0x01, 0x00, 0x00, 0x11, 0x94, 0x00, 0xa0, 0x09, 0x74, 0x78, 0x74, 0x76, 0x65, 0x72, 0x73,
        0x3d, 0x31, 0x08, 0x76, 0x73, 0x3d, 0x31, 0x39, 0x30, 0x2e, 0x39, 0x04, 0x63, 0x68, 0x3d,
        0x32, 0x08, 0x73, 0x72, 0x3d, 0x34, 0x34, 0x31, 0x30, 0x30, 0x05, 0x73, 0x73, 0x3d, 0x31,
        0x36, 0x08, 0x70, 0x77, 0x3d, 0x66, 0x61, 0x6c, 0x73, 0x65, 0x06, 0x65, 0x74, 0x3d, 0x30,
        0x2c, 0x31, 0x04, 0x65, 0x6b, 0x3d, 0x31, 0x0a, 0x74, 0x70, 0x3d, 0x54, 0x43, 0x50, 0x2c,
        0x55, 0x44, 0x50, 0x13, 0x61, 0x6d, 0x3d, 0x46, 0x72, 0x65, 0x65, 0x62, 0x6f, 0x78, 0x53,
        0x65, 0x72, 0x76, 0x65, 0x72, 0x31, 0x2c, 0x32, 0x0a, 0x63, 0x6e, 0x3d, 0x30, 0x2c, 0x31,
        0x2c, 0x32, 0x2c, 0x33, 0x06, 0x6d, 0x64, 0x3d, 0x30, 0x2c, 0x32, 0x07, 0x73, 0x66, 0x3d,
        0x30, 0x78, 0x34, 0x34, 0x0b, 0x66, 0x74, 0x3d, 0x30, 0x78, 0x42, 0x46, 0x30, 0x41, 0x30,
        0x30, 0x08, 0x73, 0x76, 0x3d, 0x66, 0x61, 0x6c, 0x73, 0x65, 0x07, 0x64, 0x61, 0x3d, 0x74,
        0x72, 0x75, 0x65, 0x08, 0x76, 0x6e, 0x3d, 0x36, 0x35, 0x35, 0x33, 0x37, 0x04, 0x76, 0x76,
        0x3d, 0x32, 0xc0, 0x28, 0x00, 0x21, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x19, 0x00,
        0x00, 0x00, 0x00, 0x13, 0x88, 0x10, 0x46, 0x72, 0x65, 0x65, 0x62, 0x6f, 0x78, 0x2d, 0x53,
        0x65, 0x72, 0x76, 0x65, 0x72, 0x2d, 0x33, 0xc0, 0x17, 0xc1, 0x04, 0x00, 0x01, 0x80, 0x01,
        0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0xc0, 0xa8, 0x00, 0xfe,
    ];

    #[test]
    fn classifies_real_on_the_wire_packets() {
        // classify reads only the QR bit of the header: queries carry QR=0, responses QR=1.
        assert_eq!(classify(&MDNS_QUERY_PTR_LINKLOCAL), Some(MdnsKind::Query));
        assert_eq!(classify(&MDNS_RESPONSE_BONJOUR), Some(MdnsKind::Response));
        assert_eq!(classify(&MDNS_RESPONSE_RAOP), Some(MdnsKind::Response));
    }

    /// A response whose answer section holds `records`, each `(rtype, rdata)` under the name `x.`,
    /// IN class, TTL 120.
    fn response_with_records(records: &[(u16, &[u8])]) -> Vec<u8> {
        let mut m = vec![0u8; DNS_HEADER_LEN];
        m[FLAGS_HIGH] = QR_BIT;
        m[ANCOUNT_AT + 1] =
            u8::try_from(records.len()).expect("test record count fits ANCOUNT's low byte");
        for (rtype, rdata) in records {
            m.extend_from_slice(&[0x01, b'x', 0x00]);
            m.extend_from_slice(&rtype.to_be_bytes());
            m.extend_from_slice(&[0x00, 0x01]);
            m.extend_from_slice(&[0, 0, 0, 120]);
            m.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
            m.extend_from_slice(rdata);
        }
        m
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
    const TXT: (u16, &[u8]) = (16, b"vers=1");

    #[test]
    fn suppresses_only_when_every_address_is_link_local() {
        assert!(advertises_only_link_local(&response_with_records(&[
            A_LINK_LOCAL
        ])));
        assert!(advertises_only_link_local(&response_with_records(&[
            AAAA_LINK_LOCAL
        ])));
        assert!(advertises_only_link_local(&response_with_records(&[
            A_LINK_LOCAL,
            AAAA_LINK_LOCAL
        ])));
        // One routable address of either family rescues the message: the client can use it.
        assert!(!advertises_only_link_local(&response_with_records(&[
            A_LINK_LOCAL,
            A_ROUTABLE
        ])));
        assert!(!advertises_only_link_local(&response_with_records(&[
            AAAA_LINK_LOCAL,
            AAAA_ROUTABLE
        ])));
        // Other record types don't veto: a bundled advertisement (PTR/SRV/TXT beside the
        // addresses) whose only addresses are link-local is exactly the dead-service case.
        assert!(advertises_only_link_local(&response_with_records(&[
            TXT,
            A_LINK_LOCAL
        ])));
        // No address records at all is not an advertisement of dead endpoints.
        assert!(!advertises_only_link_local(&response_with_records(&[TXT])));
        assert!(!advertises_only_link_local(&response_with_records(&[])));
    }

    #[test]
    fn suppression_skips_names_with_compression_pointers() {
        // Second record's name is a pointer to the first's (offset 12): the walker must step the
        // 2-byte pointer, not chase it.
        let mut m = response_with_records(&[A_LINK_LOCAL]);
        m[ANCOUNT_AT + 1] = 2;
        m.extend_from_slice(&[0xc0, 0x0c]);
        m.extend_from_slice(&TYPE_A.to_be_bytes());
        m.extend_from_slice(&[0x00, 0x01, 0, 0, 0, 120, 0x00, 0x04, 169, 254, 3, 4]);
        assert!(advertises_only_link_local(&m));
    }

    #[test]
    fn a_malformed_message_is_never_suppressed() {
        // Truncated rdata: the record claims 4 bytes and the payload ends.
        let mut m = response_with_records(&[A_LINK_LOCAL]);
        m.truncate(m.len() - 2);
        assert!(!advertises_only_link_local(&m));
        // An undefined label type (0x40) aborts the walk.
        let mut m = response_with_records(&[A_LINK_LOCAL]);
        m[DNS_HEADER_LEN] = 0x40;
        assert!(!advertises_only_link_local(&m));
        assert!(!advertises_only_link_local(b""));
    }

    #[test]
    fn real_responses_with_a_routable_address_are_not_suppressed() {
        // Bonjour: fe80:: AAAA + routable A + global AAAA (mixed); RAOP: one routable A.
        assert!(!advertises_only_link_local(&MDNS_RESPONSE_BONJOUR));
        assert!(!advertises_only_link_local(&MDNS_RESPONSE_RAOP));
        // The reverse-PTR query carries no address records.
        assert!(!advertises_only_link_local(&MDNS_QUERY_PTR_LINKLOCAL));
    }
}
