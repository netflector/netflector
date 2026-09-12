//! HTTP/1.1 message helpers shared by the DIAL proxy's header rewrites and the SSDP `LOCATION`
//! rewrite (SSDP is HTTP-over-UDP). Streaming framer in [`framing`].

pub(crate) mod framing;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4};

/// A parsed authority and the byte span of its `host[:port]` text within the source value, for a
/// caller to splice a replacement over.
pub(crate) struct Authority {
    pub(crate) endpoint: SocketAddrV4,
    pub(crate) offset: usize,
    pub(crate) len: usize,
}

/// `bare` (a `Host` header) takes the whole value as the authority; otherwise `value` must be an
/// `http://` URL. Hostnames and IPv6 are rejected: DIAL is IPv4-only.
pub(crate) fn parse_authority(value: &[u8], bare: bool) -> Option<Authority> {
    let (rest, auth_offset) = if bare {
        (value, 0)
    } else {
        let rest = strip_prefix_ignore_ascii_case(value, b"http://")?;
        (rest, value.len() - rest.len())
    };
    let len = rest
        .iter()
        .position(|&b| matches!(b, b'/' | b'?' | b'#' | b' ' | b'\t' | b'\r'))
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

/// The IP-literal host of an `http://` / `https://` URL; `None` for a hostname. A bracketed IPv6
/// host may carry a zone suffix (`%` or URL-encoded `%25`, as WSDAPI advertises), cut before the
/// parse.
pub(crate) fn url_host_ip(url: &[u8]) -> Option<IpAddr> {
    let rest = strip_prefix_ignore_ascii_case(url, b"http://")
        .or_else(|| strip_prefix_ignore_ascii_case(url, b"https://"))?;
    if let Some(v6) = rest.strip_prefix(b"[") {
        let host = &v6[..v6.iter().position(|&b| b == b']')?];
        let host = &host[..host.iter().position(|&b| b == b'%').unwrap_or(host.len())];
        return std::str::from_utf8(host)
            .ok()?
            .parse::<Ipv6Addr>()
            .ok()
            .map(IpAddr::V6);
    }
    let host = &rest[..rest
        .iter()
        .position(|&b| matches!(b, b':' | b'/' | b'?' | b'#' | b' ' | b'\t' | b'\r'))
        .unwrap_or(rest.len())];
    std::str::from_utf8(host)
        .ok()?
        .parse::<Ipv4Addr>()
        .ok()
        .map(IpAddr::V4)
}

/// The value of the first header named `name`, case-insensitively.
pub(crate) fn header_value<'a>(message: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    message
        .split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .find_map(|line| strip_prefix_ignore_ascii_case(line, name)?.strip_prefix(b":"))
        .map(<[u8]>::trim_ascii_start)
}

pub(crate) fn strip_prefix_ignore_ascii_case<'a>(
    line: &'a [u8],
    prefix: &[u8],
) -> Option<&'a [u8]> {
    let (head, rest) = line.split_at_checked(prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then_some(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_http_url_authority() {
        let a = parse_authority(b"http://10.0.0.7/dd.xml", false).unwrap();
        assert_eq!(a.endpoint, "10.0.0.7:80".parse().unwrap());
        assert_eq!(
            &b"http://10.0.0.7/dd.xml"[a.offset..a.offset + a.len],
            b"10.0.0.7"
        );
        let a = parse_authority(b"http://192.168.1.50:8080/x", false).unwrap();
        assert_eq!(a.endpoint, "192.168.1.50:8080".parse().unwrap());
    }

    #[test]
    fn authority_terminates_at_space_or_cr() {
        let a = parse_authority(b"http://10.0.0.7:8080 HTTP/1.1", false).unwrap();
        assert_eq!(a.endpoint, "10.0.0.7:8080".parse().unwrap());
        assert_eq!(a.len, "10.0.0.7:8080".len());
        assert_eq!(
            parse_authority(b"http://10.0.0.7\r", false)
                .unwrap()
                .endpoint,
            "10.0.0.7:80".parse().unwrap()
        );
    }

    #[test]
    fn authority_terminates_at_query_or_fragment() {
        // A pathless URL with a query or fragment: the authority ends at '?'/'#' (RFC 3986), so the
        // host:port is still parsed and rewritten instead of poisoning the port parse.
        let a = parse_authority(b"http://10.0.0.7:8008?token=x", false).unwrap();
        assert_eq!(a.endpoint, "10.0.0.7:8008".parse().unwrap());
        assert_eq!(a.len, "10.0.0.7:8008".len());
        let a = parse_authority(b"http://10.0.0.7#frag", false).unwrap();
        assert_eq!(a.endpoint, "10.0.0.7:80".parse().unwrap());
        assert_eq!(a.len, "10.0.0.7".len());
    }

    #[test]
    fn url_host_ip_reads_both_schemes_and_families() {
        assert_eq!(
            url_host_ip(b"http://169.254.1.2:8080/desc.xml"),
            Some("169.254.1.2".parse().unwrap())
        );
        assert_eq!(
            url_host_ip(b"https://192.168.0.2:5357/x"),
            Some("192.168.0.2".parse().unwrap())
        );
        assert_eq!(
            url_host_ip(b"HTTP://10.0.0.7"),
            Some("10.0.0.7".parse().unwrap())
        );
        assert_eq!(
            url_host_ip(b"http://[fe80::1]:5357/a"),
            Some("fe80::1".parse().unwrap())
        );
    }

    #[test]
    fn url_host_ip_terminates_at_query_or_fragment() {
        // A pathless URL with a query or fragment, as in the parse_authority case above.
        assert_eq!(
            url_host_ip(b"http://169.254.1.2?token=x"),
            Some("169.254.1.2".parse().unwrap())
        );
        assert_eq!(
            url_host_ip(b"http://10.0.0.7#frag"),
            Some("10.0.0.7".parse().unwrap())
        );
        // With a port, the port ends at the same delimiters; the host is unaffected.
        assert_eq!(
            url_host_ip(b"http://10.0.0.7:8008?token=x"),
            Some("10.0.0.7".parse().unwrap())
        );
    }

    #[test]
    fn url_host_ip_cuts_an_ipv6_zone_before_the_parse() {
        // WSDAPI advertises zoned link-local XAddrs; both the raw and the URL-encoded percent cut.
        assert_eq!(
            url_host_ip(b"http://[fe80::1%25eth0]:5357/a"),
            Some("fe80::1".parse().unwrap())
        );
        assert_eq!(
            url_host_ip(b"http://[fe80::1%eth0]/a"),
            Some("fe80::1".parse().unwrap())
        );
    }

    #[test]
    fn url_host_ip_rejects_hostnames_and_non_urls() {
        assert_eq!(url_host_ip(b"http://printer.local:80/x"), None);
        assert_eq!(url_host_ip(b"urn:uuid:1234"), None);
        assert_eq!(url_host_ip(b"http://"), None);
        assert_eq!(url_host_ip(b"http://[fe80::1"), None); // unclosed bracket
        assert_eq!(url_host_ip(b""), None);
    }

    #[test]
    fn parse_authority_handles_a_bare_host_value() {
        let a = parse_authority(b"192.168.1.5:1900", true).unwrap();
        assert_eq!(a.endpoint, "192.168.1.5:1900".parse().unwrap());
        assert_eq!((a.offset, a.len), (0, "192.168.1.5:1900".len()));
    }

    #[test]
    fn rejects_non_http_non_ipv4_or_malformed_authorities() {
        assert!(parse_authority(b"https://10.0.0.1/x", false).is_none()); // not http
        assert!(parse_authority(b"http://tv.local/x", false).is_none()); // hostname, not IPv4
        assert!(parse_authority(b"http://10.0.0.1:0/x", false).is_none()); // port 0
        assert!(parse_authority(b"http://10.0.0.1:80x/x", false).is_none()); // trailing junk on port
    }

    #[test]
    fn strip_prefix_matches_case_insensitively() {
        assert_eq!(
            strip_prefix_ignore_ascii_case(b"Host: x", b"host:"),
            Some(&b" x"[..])
        );
        assert!(strip_prefix_ignore_ascii_case(b"X", b"host:").is_none()); // shorter than the prefix
        assert!(strip_prefix_ignore_ascii_case(b"HosX: x", b"host:").is_none()); // mismatch
    }
}
