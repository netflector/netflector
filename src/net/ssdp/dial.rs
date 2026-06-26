//! DIAL (Discovery and Launch) discovery detection and `LOCATION`-authority parsing — the SSDP-side
//! inputs the DIAL proxy hook needs.

use std::net::{Ipv4Addr, SocketAddrV4};

use super::strip_prefix_ignore_ascii_case;

/// The DIAL service-type URN; the trailing `:1` version is dropped so any version matches.
const DIAL_SERVICE_TYPE: &[u8] = b"urn:dial-multiscreen-org:service:dial";

/// Whether `payload` is a DIAL discovery message — the service-type URN appears anywhere (`ST` /
/// `NT` / `USN`), ASCII-case-insensitively. The SSDP path uses this to gate a `LOCATION` rewrite.
pub(crate) fn is_dial_service_message(payload: &[u8]) -> bool {
    contains_ignore_ascii_case(payload, DIAL_SERVICE_TYPE)
}

/// A device HTTP authority parsed from a header value, plus the byte span of its `host[:port]` text
/// within the payload it came from — so a caller splices a replacement over exactly that span. DIAL
/// is IPv4-only, so the endpoint is a [`SocketAddrV4`].
pub(crate) struct Authority {
    pub(crate) endpoint: SocketAddrV4,
    pub(crate) offset: usize,
    pub(crate) len: usize,
}

/// Parse a device authority from `value`. `bare` (a `Host` header) treats the whole value as the
/// authority; else `value` must be an `http://host[:port]...` URL (no `https`). The host must be an
/// IPv4 literal (a hostname or IPv6 is rejected — DIAL is IPv4-only); the port defaults to 80, or an
/// explicit one must be the whole field and in `1..=65535`. `offset`/`len` are relative to `value`.
pub(crate) fn parse_authority(value: &[u8], bare: bool) -> Option<Authority> {
    let (rest, auth_offset) = if bare {
        (value, 0)
    } else {
        let rest = strip_prefix_ignore_ascii_case(value, b"http://")?;
        (rest, value.len() - rest.len())
    };
    let len = rest
        .iter()
        .position(|&b| matches!(b, b'/' | b' ' | b'\t' | b'\r'))
        .unwrap_or(rest.len());
    let authority = &rest[..len];
    let (host, port) = match authority.iter().rposition(|&b| b == b':') {
        Some(colon) => {
            let port = std::str::from_utf8(&authority[colon + 1..])
                .ok()?
                .parse::<u16>()
                .ok()?;
            if port == 0 {
                return None;
            }
            (&authority[..colon], port)
        }
        None => (authority, 80),
    };
    let addr = std::str::from_utf8(host).ok()?.parse::<Ipv4Addr>().ok()?;
    Some(Authority {
        endpoint: SocketAddrV4::new(addr, port),
        offset: auth_offset,
        len,
    })
}

/// Parse the device authority from a DIAL discovery message's `LOCATION:` header, the byte span
/// mapped into the whole `payload` so the SSDP path splices a reflector authority over it. The
/// `LOCATION` must be a rewritable `http://ipv4[:port]` URL; `None` otherwise (forward unchanged).
pub(crate) fn parse_dial_location_authority(payload: &[u8]) -> Option<Authority> {
    for line in payload.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(url) = strip_prefix_ignore_ascii_case(line, b"LOCATION:") else {
            continue;
        };
        let url = url.trim_ascii_start();
        if url.is_empty() {
            return None;
        }
        let found = parse_authority(url, false)?;
        // `url` is a subslice of `payload`, so the distance between their starts is `url`'s offset
        // within `payload`; add the authority's offset within `url`.
        let url_offset = url.as_ptr().addr() - payload.as_ptr().addr();
        return Some(Authority {
            endpoint: found.endpoint,
            offset: url_offset + found.offset,
            len: found.len,
        });
    }
    None
}

/// Whether `haystack` contains `needle` as an ASCII-case-insensitive substring.
fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_the_dial_service_urn_case_insensitively() {
        assert!(is_dial_service_message(
            b"NOTIFY * HTTP/1.1\r\nNT: urn:dial-multiscreen-org:service:dial:1\r\n\r\n"
        ));
        // Case-insensitive and version-agnostic (any trailing version).
        assert!(is_dial_service_message(
            b"ST: URN:Dial-MultiScreen-Org:Service:Dial:2\r\n"
        ));
        assert!(!is_dial_service_message(
            b"ST: urn:schemas-upnp-org:device:MediaServer:1\r\n"
        ));
        assert!(!is_dial_service_message(b""));
    }

    #[test]
    fn parses_a_location_authority_with_a_payload_relative_span() {
        let payload =
            b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.50:8080/dd.xml\r\nST: x\r\n\r\n";
        let a = parse_dial_location_authority(payload).expect("a rewritable http LOCATION");
        assert_eq!(a.endpoint, "192.168.1.50:8080".parse().unwrap());
        // The span covers exactly the host:port text within the whole payload.
        assert_eq!(&payload[a.offset..a.offset + a.len], b"192.168.1.50:8080");
    }

    #[test]
    fn location_port_defaults_to_80_when_omitted() {
        let payload = b"NOTIFY * HTTP/1.1\r\nLOCATION:http://10.0.0.7/dd.xml\r\n\r\n";
        let a = parse_dial_location_authority(payload).unwrap();
        assert_eq!(a.endpoint, "10.0.0.7:80".parse().unwrap());
        assert_eq!(&payload[a.offset..a.offset + a.len], b"10.0.0.7");
    }

    #[test]
    fn rejects_unrewritable_locations() {
        // Not http; not an IPv4 literal; IPv6 (DIAL is IPv4-only); bad port; absent.
        assert!(parse_dial_location_authority(b"LOCATION: https://10.0.0.1/x\r\n").is_none());
        assert!(parse_dial_location_authority(b"LOCATION: http://tv.local/x\r\n").is_none());
        assert!(parse_dial_location_authority(b"LOCATION: http://[fe80::1]:8/x\r\n").is_none());
        assert!(parse_dial_location_authority(b"LOCATION: http://10.0.0.1:0/x\r\n").is_none());
        assert!(parse_dial_location_authority(b"LOCATION: http://10.0.0.1:80x/x\r\n").is_none());
        assert!(parse_dial_location_authority(b"NOTIFY * HTTP/1.1\r\nNT: foo\r\n\r\n").is_none());
    }

    #[test]
    fn parse_authority_handles_a_bare_host_value() {
        let a = parse_authority(b"192.168.1.5:1900", true).unwrap();
        assert_eq!(a.endpoint, "192.168.1.5:1900".parse().unwrap());
        assert_eq!((a.offset, a.len), (0, "192.168.1.5:1900".len()));
    }
}
