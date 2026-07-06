//! WS-Discovery (WSD) wire helpers: the multicast group / port / TTL and a classifier that sorts a
//! SOAP-over-UDP datagram into an announcement (`Hello` / `Bye`) or a search (`Probe` / `Resolve`) by
//! its WS-Addressing `Action` URI. WSD is structurally SSDP-without-DIAL: announcements reflect device
//! → client, searches client → device with unicast `ProbeMatches` / `ResolveMatches` replies routed
//! back through a per-searcher session.

use std::net::{Ipv4Addr, Ipv6Addr};

/// WSD runs SOAP-over-UDP on port 3702, re-emitted at TTL 1. The re-emit is a single hop onto the
/// egress link, matching the link scope of the groups it serves.
pub(crate) const WSD_PORT: u16 = 3702;
pub(crate) const WSD_TTL: u8 = 1;
/// The WS-Discovery multicast groups: IPv4 `239.255.255.250` (shared with SSDP) and IPv6 `ff02::c`.
/// Unlike SSDP, WSD uses only the link-local IPv6 scope (no site-local `ff05::c`).
pub(crate) const WSD_GROUP_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
pub(crate) const WSD_GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0c);

/// What a WSD datagram on the group is, by its `Action` message type. The unicast reply types
/// (`ProbeMatches` / `ResolveMatches`) never reach the group, so they classify as neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WsdKind {
    /// A device presence announcement: `Hello` or `Bye`.
    Announcement,
    /// A client discovery request: `Probe` or `Resolve`.
    Search,
}

/// Classify a WSD SOAP-over-UDP datagram by the final path segment of its WS-Addressing `Action` URI
/// (namespace-agnostic: the 2005/04 and 2009/01 discovery namespaces differ only in the URI prefix).
/// `None` for a reply type (`ProbeMatches` / `ResolveMatches`, unicast and not expected on the group), a
/// missing `Action`, or non-WSD junk.
pub(crate) fn classify(payload: &[u8]) -> Option<WsdKind> {
    match action_segment(payload)? {
        b"Hello" | b"Bye" => Some(WsdKind::Announcement),
        b"Probe" | b"Resolve" => Some(WsdKind::Search),
        _ => None,
    }
}

/// The final `/`-delimited segment of the first `Action` element's URI (the WS-Addressing message
/// type), or `None` when there is no such element. Walks the payload element by element so the match is
/// scoped to the `Action` tag: tolerant of the namespace prefix (`a:` / `wsa:` / none) and of tag
/// attributes (ONVIF sends `mustUnderstand`), and never fooled by the token appearing in the body.
fn action_segment(payload: &[u8]) -> Option<&[u8]> {
    let mut rest = payload;
    while let Some(open) = rest.iter().position(|&b| b == b'<') {
        rest = &rest[open + 1..];
        let close = rest.iter().position(|&b| b == b'>')?;
        let (tag, after) = rest.split_at(close);
        rest = &after[1..]; // past the '>'
        // A closing tag (`</…>`), the XML declaration (`<?…`), or a comment/doctype (`<!…`) is not an
        // opening element.
        if matches!(tag.first().copied(), Some(b'/' | b'?' | b'!')) {
            continue;
        }
        // The element name runs up to the first whitespace or self-close '/'; drop any `prefix:`.
        let name = tag
            .split(|&b| b.is_ascii_whitespace() || b == b'/')
            .next()
            .unwrap_or(tag);
        let local = name.rsplit(|&b| b == b':').next().unwrap_or(name);
        if local.eq_ignore_ascii_case(b"Action") {
            let end = rest.iter().position(|&b| b == b'<').unwrap_or(rest.len());
            let uri = rest[..end].trim_ascii();
            return uri.rsplit(|&b| b == b'/').next().filter(|s| !s.is_empty());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The WS-Discovery Action namespaces: the 2005/04 draft (ONVIF) and the 2009/01 standard.
    const NS_2005: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery";
    const NS_2009: &str = "http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01";

    /// A minimal SOAP envelope carrying `action` as its WS-Addressing `Action`.
    fn envelope(action: &str) -> Vec<u8> {
        format!(
            "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" \
             xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">\
             <s:Header>\
             <a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>\
             <a:Action>{action}</a:Action>\
             <a:MessageID>urn:uuid:0a-b</a:MessageID>\
             </s:Header><s:Body/></s:Envelope>"
        )
        .into_bytes()
    }

    #[test]
    fn probe_and_resolve_are_searches() {
        assert_eq!(
            classify(&envelope(&format!("{NS_2005}/Probe"))),
            Some(WsdKind::Search)
        );
        assert_eq!(
            classify(&envelope(&format!("{NS_2009}/Resolve"))),
            Some(WsdKind::Search)
        );
    }

    #[test]
    fn hello_and_bye_are_announcements() {
        assert_eq!(
            classify(&envelope(&format!("{NS_2005}/Hello"))),
            Some(WsdKind::Announcement)
        );
        assert_eq!(
            classify(&envelope(&format!("{NS_2009}/Bye"))),
            Some(WsdKind::Announcement)
        );
    }

    #[test]
    fn reply_types_are_not_classified() {
        // ProbeMatches / ResolveMatches are unicast replies; the segment must not collapse to the
        // Probe / Resolve prefix it starts with.
        assert_eq!(
            classify(&envelope(&format!("{NS_2005}/ProbeMatches"))),
            None
        );
        assert_eq!(
            classify(&envelope(&format!("{NS_2009}/ResolveMatches"))),
            None
        );
    }

    #[test]
    fn tolerates_prefixes_attributes_and_whitespace() {
        // No namespace prefix on the element.
        assert_eq!(
            classify(b"<Envelope><Header><Action>http://x/Probe</Action></Header></Envelope>"),
            Some(WsdKind::Search)
        );
        // An attribute on the Action tag (ONVIF sends mustUnderstand).
        assert_eq!(
            classify(
                b"<s:Header><a:Action a:mustUnderstand=\"1\">http://x/Hello</a:Action></s:Header>"
            ),
            Some(WsdKind::Announcement)
        );
        // Whitespace around the URI.
        assert_eq!(
            classify(b"<a:Action>  http://x/Bye  </a:Action>"),
            Some(WsdKind::Announcement)
        );
    }

    #[test]
    fn scoped_to_the_action_element() {
        // "Probe" in the body must not turn a Hello announcement into a search.
        assert_eq!(
            classify(
                b"<s:Header><a:Action>http://x/Hello</a:Action></s:Header>\
                  <s:Body><d:Types>dn:Probe</d:Types></s:Body>"
            ),
            Some(WsdKind::Announcement)
        );
    }

    #[test]
    fn junk_and_missing_action_are_none() {
        assert_eq!(classify(b""), None);
        assert_eq!(classify(b"not xml at all"), None);
        // A well-formed envelope with no Action element.
        assert_eq!(
            classify(b"<s:Envelope><s:Header><a:To>urn:x</a:To></s:Header></s:Envelope>"),
            None
        );
        // An SSDP M-SEARCH mistakenly on the WSD port carries no Action element.
        assert_eq!(classify(b"M-SEARCH * HTTP/1.1\r\nMX: 2\r\n\r\n"), None);
    }

    // --- Real on-the-wire messages, verbatim from captures and specs (see each provenance) ---

    /// OASIS WS-Discovery 1.1 spec (docs.oasis-open.org), 2009/01 namespace, ad hoc Hello. The
    /// Action URI is wrapped in whitespace, as the spec prints it.
    const HELLO_OASIS_2009: &str = r#"<s:Envelope
  xmlns:a="http://www.w3.org/2005/08/addressing"
  xmlns:d="http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01"
  xmlns:s="http://www.w3.org/2003/05/soap-envelope" >
  <s:Header>
    <a:Action>
      http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01/Hello
    </a:Action>
    <a:MessageID>
      urn:uuid:73948edc-3204-4455-bae2-7c7d0ff6c37c
    </a:MessageID>
    <a:To>urn:docs-oasis-open-org:ws-dd:ns:discovery:2009:01</a:To>
    <d:AppSequence InstanceId="1077004800" MessageNumber="1" />
  </s:Header>
  <s:Body>
    <d:Hello>
      <a:EndpointReference>
        <a:Address>
          urn:uuid:98190dc2-0890-4ef8-ac9a-5940995e6119
        </a:Address>
      </a:EndpointReference>
      <d:MetadataVersion>75965</d:MetadataVersion>
    </d:Hello>
  </s:Body>
</s:Envelope>"#;

    /// OASIS WS-Discovery 1.1 spec, 2009/01 namespace, ad hoc Bye.
    const BYE_OASIS_2009: &str = r#"<s:Envelope
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:d="http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01"
    xmlns:s="http://www.w3.org/2003/05/soap-envelope" >
  <s:Header>
    <a:Action>
      http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01/Bye
    </a:Action>
    <a:MessageID>
      urn:uuid:337497fa-3b10-43a5-95c2-186461d72c9e
    </a:MessageID>
    <a:To>urn:docs-oasis-open-org:ws-dd:ns:discovery:2009:01</a:To>
    <d:AppSequence InstanceId="1077004800" MessageNumber="4" />
  </s:Header>
  <s:Body>
    <d:Bye>
      <a:EndpointReference>
        <a:Address>
          urn:uuid:98190dc2-0890-4ef8-ac9a-5940995e6119
        </a:Address>
      </a:EndpointReference>
    </d:Bye>
  </s:Body>
</s:Envelope>"#;

    /// Real ONVIF discovery Probe (docs.edgexfoundry.org device-onvif-camera), 2005/04 namespace,
    /// `soap-env:` envelope, `mustUnderstand="1"` on the Action.
    const PROBE_ONVIF_EDGEX: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<soap-env:Envelope
        xmlns:soap-env="http://www.w3.org/2003/05/soap-envelope"
        xmlns:soap-enc="http://www.w3.org/2003/05/soap-encoding"
        xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
    <soap-env:Header>
        <a:Action mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>
        <a:MessageID>uuid:a86f9421-b764-4256-8762-5ed0d8602a9c</a:MessageID>
        <a:ReplyTo>
            <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
        </a:ReplyTo>
        <a:To mustUnderstand="1">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
    </soap-env:Header>
    <soap-env:Body>
        <Probe
                xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery"/>
    </soap-env:Body>
</soap-env:Envelope>"#;

    /// Resolve from Microsoft's `WsdApi` docs (learn.microsoft.com win32). Their docs render the
    /// namespaces as `https://`; the classifier only reads the final `/Resolve` segment.
    const RESOLVE_MS_WSDAPI: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<soap:Envelope
    xmlns:soap="https://www.w3.org/2003/05/soap-envelope"
    xmlns:wsa="https://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:wsd="https://schemas.xmlsoap.org/ws/2005/04/discovery">
<soap:Header>
    <wsa:To>
urn:schemas-xmlsoap-org:ws:2005:04:discovery
</wsa:To>
    <wsa:Action>
        https://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve
    </wsa:Action>
    <wsa:MessageID>
        urn:uuid:38d1c3d9-8d73-4424-8861-6b7ee2af24d3
    </wsa:MessageID>
</soap:Header>
<soap:Body>
    <wsd:Resolve>
        <wsa:EndpointReference>
            <wsa:Address>
                urn:uuid:37f86d35-e6ac-4241-964f-1d9ae46fb366
            </wsa:Address>
        </wsa:EndpointReference>
    </wsd:Resolve>
</soap:Body>
</soap:Envelope>"#;

    /// Real Uniview IP-camera `ProbeMatches` capture (brownfinesecurity.com): genuine IP/MAC/ONVIF
    /// scopes, `SOAP-ENV:` prefix, `SOAP-ENV:mustUnderstand="true"`. The final segment is
    /// `ProbeMatches`, which must NOT collapse to a `Probe` search.
    const PROBEMATCHES_ONVIF_UNIVIEW: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope
    xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
    xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:xop="http://www.w3.org/2004/08/xop/include"
    xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:tns="http://schemas.xmlsoap.org/ws/2005/04/discovery"
    xmlns:dn="http://www.onvif.org/ver10/network/wsdl"
    xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
    xmlns:wsa5="http://www.w3.org/2005/08/addressing">
    <SOAP-ENV:Header>
        <tns:AppSequence MessageNumber="10002" InstanceId="1"></tns:AppSequence>
        <wsa:MessageID>10002</wsa:MessageID>
        <wsa:RelatesTo>urn:uuid:a6ab1bb7-7d49-418d-ba2a-a7f930a7dce7</wsa:RelatesTo>
        <wsa:To SOAP-ENV:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To>
        <wsa:Action SOAP-ENV:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action>
    </SOAP-ENV:Header>
    <SOAP-ENV:Body>
        <tns:ProbeMatches>
            <tns:ProbeMatch>
                <wsa:EndpointReference>
                    <wsa:Address>urn:uuid:00010010-0001-1020-8000-e4f14c776608</wsa:Address>
                </wsa:EndpointReference>
                <tns:Types>dn:NetworkVideoTransmitter tds:Device</tns:Types>
                <tns:Scopes>onvif://www.onvif.org/Profile/G onvif://www.onvif.org/Profile/Streaming onvif://www.onvif.org/Profile/T onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/type/audio_encoder onvif://www.onvif.org/max_resolution/2688*1520 onvif://www.onvif.org/register_status/offline  onvif://www.onvif.org/register_server/0.0.0.0:5060  onvif://www.onvif.org/regist_id/34020000001320000001  onvif://www.onvif.org/type/IPC onvif://www.onvif.org/manufacturer/NONE onvif://www.onvif.org/VideoSourceNumber/1 onvif://www.onvif.org/version/GIPC-B6215.1.68.NB.240617 onvif://www.onvif.org/serial/210235UEDW3247000013 onvif://www.onvif.org/macaddr/e4f14c776608  onvif://www.onvif.org/hardware/SC-3243-IWPS-F28 onvif://www.onvif.org/location/  onvif://www.onvif.org/name/SC-3243-IWPS-F28 </tns:Scopes>
                <tns:XAddrs>http://192.168.100.26:80/onvif/device_service</tns:XAddrs>
                <tns:MetadataVersion>1</tns:MetadataVersion>
            </tns:ProbeMatch>
        </tns:ProbeMatches>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"#;

    /// `ResolveMatches` from Microsoft's `WsdApi` docs: the `ResolveMatches` segment must not collapse
    /// to a `Resolve` search.
    const RESOLVEMATCHES_MS_WSDAPI: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<soap:Envelope
    xmlns:soap="https://www.w3.org/2003/05/soap-envelope"
    xmlns:wsa="https://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:wsd="https://schemas.xmlsoap.org/ws/2005/04/discovery"
    xmlns:wsdp="https://schemas.xmlsoap.org/ws/2006/02/devprof">
<soap:Header>
    <wsa:To>
        https://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous
    </wsa:To>
    <wsa:Action>
        https://schemas.xmlsoap.org/ws/2005/04/discovery/ResolveMatches
    </wsa:Action>
    <wsa:MessageID>
        urn:uuid:64ddd01c-b0d6-4afd-aba6-6f1f161ce9d4
    </wsa:MessageID>
    <wsa:RelatesTo>
        urn:uuid:38d1c3d9-8d73-4424-8861-6b7ee2af24d3
    </wsa:RelatesTo>
    <wsd:AppSequence InstanceId="1"
        SequenceId="urn:uuid:369a7d7b-5f87-48a4-aa9a-189edf2a8772"
        MessageNumber="6">
    </wsd:AppSequence>
</soap:Header>
<soap:Body>
    <wsd:ResolveMatches>
        <wsd:ResolveMatch>
            <wsa:EndpointReference>
                <wsa:Address>
                    urn:uuid:37f86d35-e6ac-4241-964f-1d9ae46fb366
                </wsa:Address>
            </wsa:EndpointReference>
            <wsd:Types>wsdp:Device</wsd:Types>
            <wsd:XAddrs>
                https://192.168.0.2:5357/37f86d35-e6ac-4241-964f-1d9ae46fb366
            </wsd:XAddrs>
            <wsd:MetadataVersion>2</wsd:MetadataVersion>
        </wsd:ResolveMatch>
    </wsd:ResolveMatches>
</soap:Body>
</soap:Envelope>"#;

    #[test]
    fn classifies_real_on_the_wire_messages() {
        let cases: &[(&str, Option<WsdKind>)] = &[
            (HELLO_OASIS_2009, Some(WsdKind::Announcement)),
            (BYE_OASIS_2009, Some(WsdKind::Announcement)),
            (PROBE_ONVIF_EDGEX, Some(WsdKind::Search)),
            (RESOLVE_MS_WSDAPI, Some(WsdKind::Search)),
            (PROBEMATCHES_ONVIF_UNIVIEW, None),
            (RESOLVEMATCHES_MS_WSDAPI, None),
        ];
        for (msg, expected) in cases {
            assert_eq!(classify(msg.as_bytes()), *expected, "misclassified: {msg}");
        }
    }
}
