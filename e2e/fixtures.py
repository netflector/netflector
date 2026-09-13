"""Canonical packet fixtures and protocol constants for the E2E case catalogs."""

from __future__ import annotations

CONFIGURED_MAC = "02:42:ac:11:00:09"
# A second address in wol-mac's `macs` allow-set, to prove the list admits every member, not just the first.
SECOND_CONFIGURED_MAC = "02:42:ac:11:00:0c"
WRONG_MAC = "02:42:ac:11:00:0a"
# Below every platform's ephemeral range (Linux 32768+, FreeBSD 10000+, macOS 49152+): a fixed
# test port inside it can collide with a kernel-assigned port in the same namespace -- seen once
# in CI as EADDRINUSE on the receiver's bind, from an engine-side socket in a fresh container.
CONFIGURED_PORT = 9009
UNCONFIGURED_PORT = 9010
ANY_MAC_PORT = 9011
MALFORMED_MAGIC_PAYLOAD_HEX = "ff" * 6 + "0242ac11000a" * 15 + "0242ac11000b"
# --- mDNS (RFC 6762): multicast group 224.0.0.251 / ff02::fb on UDP 5353. ---
MDNS_GROUP_V4 = "224.0.0.251"
MDNS_GROUP_V6 = "ff02::fb"
MDNS_PORT = 5353
MDNS_WRONG_PORT = 5354
# A 12-byte DNS header + "test". The query has QR=0 (flags 0x0000); the response sets QR+AA
# (flags 0x8400). netflector classifies on the QR bit alone.
MDNS_QUERY_HEX = "00000000000100000000000074657374"
MDNS_RESPONSE_HEX = "00008400000100010000000074657374"
# 8 bytes: below the 12-byte DNS-header minimum, so classify() returns None and drops it.
MDNS_SHORT_QUERY_HEX = "0000000000010000"
# Well-formed responses for the advertisement suppression: QR+AA header, ANCOUNT=2, both answers
# under the name "x." (each record: 3-byte name, TYPE, IN, TTL 120, RDLENGTH, rdata). A response is
# suppressed only when every A/AAAA it carries is unreachable (here link-local); one routable
# address rescues it.
MDNS_RESPONSE_MIXED_HEX = (
    "000084000000000200000000"  # header
    "01780000010001000000780004a9fe0102"  # A x. -> 169.254.1.2 (link-local)
    "01780000010001000000780004c0a80909"  # A x. -> 192.168.9.9 (routable)
)
MDNS_RESPONSE_LINK_LOCAL_HEX = (
    "000084000000000200000000"  # header
    "01780000010001000000780004a9fe0102"  # A x. -> 169.254.1.2
    "017800001c0001000000780010fe800000000000000000000000000001"  # AAAA x. -> fe80::1
)
# --- SSDP (UPnP discovery, HTTPU): multicast group 239.255.255.250 / ff02::c on UDP 1900. ---
SSDP_GROUP_V4 = "239.255.255.250"
SSDP_GROUP_V6 = "ff02::c"
SSDP_GROUP_V6_SITE = "ff05::c"  # site-local SSDP scope — forwarded from a routable source, not link-local
SSDP_PORT = 1900
# A non-SSDP UDP port: the dispatcher filter pins dst_port=1900, so a datagram to the group on this
# port is captured but never dispatched to the reflector.
SSDP_WRONG_PORT = 1901
# SSDP discovery messages (HTTPU). netflector classifies on the leading method token only and relays
# the bytes verbatim, so the receiver expects exactly what was sent; the HOST line is immaterial here.
SSDP_MSEARCH_HEX = (
    (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n\r\n"
    )
    .encode()
    .hex()
)
# An M-SEARCH with the maximum MX (clamped to 5s by netflector), so its session lives ~7s (MX + the
# 2s reply grace). The interface-recreate round trip needs that width: it destroys and recreates the
# target between the searcher's two sends, and the second must land while the first's session is alive.
SSDP_MSEARCH_MX5_HEX = (
    (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 5\r\n"
        "ST: ssdp:all\r\n\r\n"
    )
    .encode()
    .hex()
)
SSDP_NOTIFY_HEX = (
    (
        "NOTIFY * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "NT: upnp:rootdevice\r\n"
        "NTS: ssdp:alive\r\n\r\n"
    )
    .encode()
    .hex()
)
# LOCATION variants for the link-local suppression: an advertisement whose LOCATION names a
# link-local literal is suppressed; a routable literal reflects.
SSDP_NOTIFY_ROUTABLE_LOCATION_HEX = (
    (
        "NOTIFY * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "NT: upnp:rootdevice\r\n"
        "NTS: ssdp:alive\r\n"
        "LOCATION: http://192.168.9.9:1900/desc.xml\r\n\r\n"
    )
    .encode()
    .hex()
)
SSDP_NOTIFY_LINK_LOCAL_LOCATION_HEX = (
    (
        "NOTIFY * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "NT: upnp:rootdevice\r\n"
        "NTS: ssdp:alive\r\n"
        "LOCATION: http://169.254.9.9:1900/desc.xml\r\n\r\n"
    )
    .encode()
    .hex()
)
# A search response that strayed onto the group: neither M-SEARCH nor NOTIFY, so netflector
# classifies it as non-SSDP and drops it.
SSDP_HTTP_RESPONSE_HEX = ("HTTP/1.1 200 OK\r\nST: ssdp:all\r\n\r\n").encode().hex()
# The unicast 200 OK a device sends back to an M-SEARCH; the round-trip responder replies with this and
# the searcher asserts it arrives verbatim after netflector proxies it across segments.
SSDP_OK_HEX = (
    (
        "HTTP/1.1 200 OK\r\n"
        "CACHE-CONTROL: max-age=1800\r\n"
        "ST: ssdp:all\r\n"
        "USN: uuid:device::ssdp:all\r\n"
        "LOCATION: http://device.invalid/desc.xml\r\n\r\n"
    )
    .encode()
    .hex()
)
SEARCHER_SOURCE_PORT = 9012  # below the ephemeral range, like the WoL ports above

# DIAL discovery: a DIAL-targeted M-SEARCH (ST is the DIAL service type). The emulator answers it with a
# 200 OK whose LOCATION points at its own target-side HTTP description endpoint.
DIAL_SERVICE_TYPE = "urn:dial-multiscreen-org:service:dial:1"
SSDP_DIAL_MSEARCH_HEX = (
    (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        f"ST: {DIAL_SERVICE_TYPE}\r\n\r\n"
    )
    .encode()
    .hex()
)
DIAL_CLIENT_SOURCE_PORT = 9013
# --- WSD (WS-Discovery): SOAP-over-UDP. Groups 239.255.255.250 / ff02::c (shared with SSDP) on UDP
# 3702 -- the port distinguishes it from SSDP. netflector classifies on the <Action> URI segment and
# relays the bytes verbatim, so the receiver expects exactly what was sent. Real ONVIF-style envelopes
# (2005/04 namespace). ---
WSD_GROUP_V4 = SSDP_GROUP_V4
WSD_GROUP_V6 = SSDP_GROUP_V6
WSD_PORT = 3702
WSD_HELLO_HEX = (
    (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
        ' xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        "<s:Header>"
        "<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello</a:Action>"
        "<a:MessageID>urn:uuid:hello-0001</a:MessageID>"
        "<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>"
        "</s:Header>"
        "<s:Body><d:Hello>"
        "<a:EndpointReference><a:Address>urn:uuid:camera-0001</a:Address></a:EndpointReference>"
        "<d:Types>dn:NetworkVideoTransmitter</d:Types><d:MetadataVersion>1</d:MetadataVersion>"
        "</d:Hello></s:Body></s:Envelope>"
    )
    .encode()
    .hex()
)


# A Hello carrying the given XAddrs, for the advertisement suppression: suppressed only when every
# XAddrs URI names an unreachable literal (here link-local). (WSD_HELLO_HEX above has no XAddrs at
# all and must keep reflecting; resolution then happens via Resolve.)
def wsd_hello_with_xaddrs(xaddrs: str) -> str:
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
        ' xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        "<s:Header>"
        "<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello</a:Action>"
        "<a:MessageID>urn:uuid:hello-0002</a:MessageID>"
        "<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>"
        "</s:Header>"
        "<s:Body><d:Hello>"
        "<a:EndpointReference><a:Address>urn:uuid:camera-0001</a:Address></a:EndpointReference>"
        "<d:Types>dn:NetworkVideoTransmitter</d:Types>"
        f"<d:XAddrs>{xaddrs}</d:XAddrs>"
        "<d:MetadataVersion>1</d:MetadataVersion>"
        "</d:Hello></s:Body></s:Envelope>"
    ).encode().hex()


WSD_HELLO_MIXED_XADDRS_HEX = wsd_hello_with_xaddrs(
    "http://[fe80::1]:5357/dev http://192.168.9.9:5357/dev"
)
WSD_HELLO_LINK_LOCAL_XADDRS_HEX = wsd_hello_with_xaddrs("http://169.254.7.7:5357/dev")
WSD_BYE_HEX = (
    (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
        ' xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        "<s:Header>"
        "<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Bye</a:Action>"
        "<a:MessageID>urn:uuid:bye-0001</a:MessageID>"
        "<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>"
        "</s:Header>"
        "<s:Body><d:Bye>"
        "<a:EndpointReference><a:Address>urn:uuid:camera-0001</a:Address></a:EndpointReference>"
        "</d:Bye></s:Body></s:Envelope>"
    )
    .encode()
    .hex()
)
WSD_PROBE_HEX = (
    (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
        ' xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        "<s:Header>"
        "<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>"
        "<a:MessageID>urn:uuid:probe-0001</a:MessageID>"
        "<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>"
        "</s:Header>"
        "<s:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></s:Body>"
        "</s:Envelope>"
    )
    .encode()
    .hex()
)
WSD_RESOLVE_HEX = (
    (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
        ' xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        "<s:Header>"
        "<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</a:Action>"
        "<a:MessageID>urn:uuid:resolve-0001</a:MessageID>"
        "<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>"
        "</s:Header>"
        "<s:Body><d:Resolve>"
        "<a:EndpointReference><a:Address>urn:uuid:camera-0001</a:Address></a:EndpointReference>"
        "</d:Resolve></s:Body></s:Envelope>"
    )
    .encode()
    .hex()
)
# The unicast ProbeMatches a device answers a Probe with; the round-trip responder replies with this and
# the searcher asserts it arrives verbatim after netflector proxies it back across segments.
WSD_PROBEMATCHES_HEX = (
    (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
        ' xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        "<s:Header>"
        "<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</a:Action>"
        "<a:MessageID>urn:uuid:match-0001</a:MessageID>"
        "<a:RelatesTo>urn:uuid:probe-0001</a:RelatesTo>"
        "<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>"
        "</s:Header>"
        "<s:Body><d:ProbeMatches><d:ProbeMatch>"
        "<a:EndpointReference><a:Address>urn:uuid:camera-0001</a:Address></a:EndpointReference>"
        "<d:Types>dn:NetworkVideoTransmitter</d:Types>"
        "<d:XAddrs>http://device.invalid/onvif/device_service</d:XAddrs>"
        "<d:MetadataVersion>1</d:MetadataVersion>"
        "</d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>"
    )
    .encode()
    .hex()
)
# The unicast ResolveMatches a device answers a Resolve with.
WSD_RESOLVEMATCHES_HEX = (
    (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
        ' xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        "<s:Header>"
        "<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ResolveMatches</a:Action>"
        "<a:MessageID>urn:uuid:resolvematch-0001</a:MessageID>"
        "<a:RelatesTo>urn:uuid:resolve-0001</a:RelatesTo>"
        "<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>"
        "</s:Header>"
        "<s:Body><d:ResolveMatches><d:ResolveMatch>"
        "<a:EndpointReference><a:Address>urn:uuid:camera-0001</a:Address></a:EndpointReference>"
        "<d:Types>dn:NetworkVideoTransmitter</d:Types>"
        "<d:XAddrs>http://device.invalid/onvif/device_service</d:XAddrs>"
        "<d:MetadataVersion>1</d:MetadataVersion>"
        "</d:ResolveMatch></d:ResolveMatches></s:Body></s:Envelope>"
    )
    .encode()
    .hex()
)
RELAY_PORT = 9003
RELAY_ONE_WAY_PORT = 9004
RELAY_UNLISTED_PORT = 9005
RELAY_GROUP_V4 = "239.255.90.90"
RELAY_GROUP_V6 = "ff02::5a5a"
RELAY_UNLISTED_GROUP_V4 = "239.255.91.91"
RELAY_SOURCE_PORT = 9014  # below the ephemeral range, like the ports above


def sood_query_hex(properties: dict[str, str]) -> str:
    # A Roon SOOD query: `SOOD` 0x02 'Q', then per property a 1-byte key length, the key, a
    # 2-byte big-endian value length and the value.
    frame = b"SOOD\x02Q"
    for key, value in properties.items():
        frame += bytes([len(key)]) + key.encode() + len(value).to_bytes(2, "big") + value.encode()
    return frame.hex()


SOOD_QUERY_HEX = sood_query_hex(
    {
        "query_service_id": "00720724-5143-4a9b-abac-0e50cba674bb",
        "_tid": "5a1c2e3d-4f60-4b7a-9c8d-0e1f2a3b4c5d",
    }
)

IPV6_ALL_NODES = "ff02::1"


def magic_packet_hex(mac: str) -> str:
    octets = bytes(int(part, 16) for part in mac.split(":"))
    return (b"\xff" * 6 + octets * 16).hex()
