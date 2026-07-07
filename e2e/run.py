#!/usr/bin/env python3
#
# End-to-end tests for the (Rust) reflector, runnable on two backends.
#
# Each case stands up two isolated dual-stack segments (a source and a target), runs the reflector
# straddling both with its interface names pinned to wol_src / wol_dst, then runs a sender prober on
# one segment and a receiver prober on the other and asserts the traffic is (or is not) reflected
# across. The default docker backend realizes segments as bridge networks and participants as
# containers (reflector image built from ./Dockerfile, CAP_NET_RAW on that container only; probers
# run unprivileged). The native backend (root; Linux or FreeBSD) uses plain processes over netns +
# veth pairs (Linux) or vnet jails + epairs (FreeBSD) instead -- same cases, no Docker:
#
#   python3 e2e/run.py
#   python3 e2e/run.py --case reflects_matching_magic_packet
#   python3 e2e/run.py --skip-build --image reflector:e2e
#   sudo python3 e2e/run.py --backend native --binary target/release/reflector

from __future__ import annotations

import argparse
import ast
import dataclasses
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
E2E_DIR = Path(__file__).resolve().parent

DEFAULT_REFLECTOR_IMAGE = "reflector:e2e"
VALGRIND_REFLECTOR_IMAGE = "reflector:e2e-valgrind"
DEFAULT_HELPER_IMAGE = "python:3.13-alpine"
CONFIGURED_MAC = "02:42:ac:11:00:09"
# A second address in wol-mac's `macs` allow-set, to prove the list admits every member, not just the first.
SECOND_CONFIGURED_MAC = "02:42:ac:11:00:0c"
WRONG_MAC = "02:42:ac:11:00:0a"
CONFIGURED_PORT = 40009
UNCONFIGURED_PORT = 40010
ANY_MAC_PORT = 40011
MALFORMED_MAGIC_PAYLOAD_HEX = "ff" * 6 + "0242ac11000a" * 15 + "0242ac11000b"
# --- mDNS (RFC 6762): multicast group 224.0.0.251 / ff02::fb on UDP 5353. ---
MDNS_GROUP_V4 = "224.0.0.251"
MDNS_GROUP_V6 = "ff02::fb"
MDNS_PORT = 5353
MDNS_WRONG_PORT = 5354
# A 12-byte DNS header + "test". The query has QR=0 (flags 0x0000); the response sets QR+AA
# (flags 0x8400). The reflector classifies on the QR bit alone.
MDNS_QUERY_HEX = "00000000000100000000000074657374"
MDNS_RESPONSE_HEX = "00008400000100010000000074657374"
# 8 bytes: below the 12-byte DNS-header minimum, so classify() returns None and drops it.
MDNS_SHORT_QUERY_HEX = "0000000000010000"
# --- SSDP (UPnP discovery, HTTPU): multicast group 239.255.255.250 / ff02::c on UDP 1900. ---
SSDP_GROUP_V4 = "239.255.255.250"
SSDP_GROUP_V6 = "ff02::c"
SSDP_GROUP_V6_SITE = "ff05::c"  # site-local SSDP scope — forwarded from a routable source, not link-local
SSDP_PORT = 1900
# A non-SSDP UDP port: the dispatcher filter pins dst_port=1900, so a datagram to the group on this
# port is captured but never dispatched to the reflector.
SSDP_WRONG_PORT = 1901
# SSDP discovery messages (HTTPU). The reflector classifies on the leading method token only and relays
# the bytes verbatim, so the receiver expects exactly what was sent; the HOST line is immaterial here.
SSDP_MSEARCH_HEX = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode().hex()
SSDP_NOTIFY_HEX = (
    "NOTIFY * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "NT: upnp:rootdevice\r\n"
    "NTS: ssdp:alive\r\n\r\n"
).encode().hex()
# A search response that strayed onto the group: neither M-SEARCH nor NOTIFY, so the reflector
# classifies it as non-SSDP and drops it.
SSDP_HTTP_RESPONSE_HEX = (
    "HTTP/1.1 200 OK\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode().hex()
# The unicast 200 OK a device sends back to an M-SEARCH; the round-trip responder replies with this and
# the searcher asserts it arrives verbatim after the reflector proxies it across segments.
SSDP_OK_HEX = (
    "HTTP/1.1 200 OK\r\n"
    "CACHE-CONTROL: max-age=1800\r\n"
    "ST: ssdp:all\r\n"
    "USN: uuid:device::ssdp:all\r\n"
    "LOCATION: http://device.invalid/desc.xml\r\n\r\n"
).encode().hex()
SEARCHER_SOURCE_PORT = 49152

# DIAL discovery: a DIAL-targeted M-SEARCH (ST is the DIAL service type). The emulator answers it with a
# 200 OK whose LOCATION points at its own target-side HTTP description endpoint.
DIAL_SERVICE_TYPE = "urn:dial-multiscreen-org:service:dial:1"
SSDP_DIAL_MSEARCH_HEX = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    f"ST: {DIAL_SERVICE_TYPE}\r\n\r\n"
).encode().hex()
DIAL_CLIENT_SOURCE_PORT = 49153
# --- WSD (WS-Discovery): SOAP-over-UDP. Groups 239.255.255.250 / ff02::c (shared with SSDP) on UDP
# 3702 -- the port distinguishes it from SSDP. The reflector classifies on the <Action> URI segment and
# relays the bytes verbatim, so the receiver expects exactly what was sent. Real ONVIF-style envelopes
# (2005/04 namespace). ---
WSD_GROUP_V4 = SSDP_GROUP_V4
WSD_GROUP_V6 = SSDP_GROUP_V6
WSD_PORT = 3702
WSD_HELLO_HEX = (
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
).encode().hex()
WSD_BYE_HEX = (
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
).encode().hex()
WSD_PROBE_HEX = (
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
).encode().hex()
WSD_RESOLVE_HEX = (
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
).encode().hex()
# The unicast ProbeMatches a device answers a Probe with; the round-trip responder replies with this and
# the searcher asserts it arrives verbatim after the reflector proxies it back across segments.
WSD_PROBEMATCHES_HEX = (
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
).encode().hex()
# The unicast ResolveMatches a device answers a Resolve with.
WSD_RESOLVEMATCHES_HEX = (
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
).encode().hex()
# --- Address-change cases: knock out one (interface, family) source on the reflector, prove
# reflection of that family stops, then restore it and prove it resumes. The reflector reacts on
# its own event loop after the netlink notification, so each check polls across that async window.
ADDR_CHANGE_REFLECTED_WINDOW = 4.0
ADDR_CHANGE_SILENCE_WINDOW = 2.5
ADDR_CHANGE_SILENCE_CONSECUTIVE = 2
ADDR_CHANGE_POLL_DEADLINE = 60.0
# A substring of the line the daemon logs immediately before entering its event loop.
REFLECTOR_READY_LOG = "running; press Ctrl-C or send SIGTERM to stop"
RECEIVER_READY_LOG = "receiver ready: UDP socket bound"
CONTAINER_READY_TIMEOUT_SECONDS = 15.0
# A clean SIGTERM exit triggers valgrind's leak analysis; give `docker stop` this much grace before it
# SIGKILLs, so the analysis (which can take tens of seconds) finishes and its exit code is read.
VALGRIND_STOP_GRACE_SECONDS = 60
REFLECTOR_SOURCE_IFNAME = "wol_src"
REFLECTOR_TARGET_IFNAME = "wol_dst"
RECEIVER_IFNAME = "probe0"

IPV6_ALL_NODES = "ff02::1"


class CommandError(RuntimeError):
    def __init__(self, command: list[str], result: subprocess.CompletedProcess[str]) -> None:
        self.command = command
        self.result = result
        super().__init__(f"command failed with exit code {result.returncode}: {format_command(command)}")


@dataclasses.dataclass(frozen=True)
class TestCase:
    name: str
    send_port: int
    receive_port: int
    expect_mac: str | None
    timeout_seconds: float
    send_mac: str | None = None
    send_payload_hex: str | None = None
    # IP version exercised end to end. The reflector runs both pipelines from one config; each case
    # drives just one of them.
    family: int = 4
    # Reflection direction. "forward" sends from the source network and receives on the target (WoL);
    # "reverse" swaps them. Carried so non-WoL protocols (mDNS responses, etc.) re-add as small diffs.
    direction: str = "forward"
    # Multicast group to send to and join on the receiver. None keeps the WoL broadcast / all-nodes path.
    group: str | None = None
    # Exact payload the receiver must see, for protocols relayed verbatim. None falls back to the
    # magic-packet / expect-none expectation.
    expect_payload_hex: str | None = None
    # Also require the reflected packet's source to be routable (non-link-local) — the per-scope v6
    # source selection: a site-local group (ff05::c) must not be sourced from a link-local address.
    expect_routable_source: bool = False
    # Reflector config file (relative to e2e/) mounted into the reflector container. Most cases share
    # config.toml; a case needing a distinct reflector set (e.g. single-family) names its own.
    config: str = "config.toml"

    @property
    def send_address(self) -> str:
        if self.group is not None:
            return self.group
        return IPV6_ALL_NODES if self.family == 6 else "255.255.255.255"


TEST_CASES = [
    TestCase(
        name="reflects_matching_magic_packet",
        send_port=CONFIGURED_PORT,
        receive_port=CONFIGURED_PORT,
        expect_mac=CONFIGURED_MAC,
        timeout_seconds=5.0,
        send_mac=CONFIGURED_MAC,
    ),
    TestCase(
        name="reflects_matching_magic_packet_ipv6",
        send_port=CONFIGURED_PORT,
        receive_port=CONFIGURED_PORT,
        expect_mac=CONFIGURED_MAC,
        timeout_seconds=5.0,
        send_mac=CONFIGURED_MAC,
        family=6,
    ),
    TestCase(
        name="reflects_second_configured_mac",
        send_port=CONFIGURED_PORT,
        receive_port=CONFIGURED_PORT,
        expect_mac=SECOND_CONFIGURED_MAC,
        timeout_seconds=5.0,
        send_mac=SECOND_CONFIGURED_MAC,
    ),
    TestCase(
        name="ignores_wrong_mac",
        send_port=CONFIGURED_PORT,
        receive_port=CONFIGURED_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_mac=WRONG_MAC,
    ),
    TestCase(
        name="ignores_unconfigured_port",
        send_port=UNCONFIGURED_PORT,
        receive_port=UNCONFIGURED_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_mac=CONFIGURED_MAC,
    ),
    TestCase(
        name="reflects_magic_packet_without_configured_mac",
        send_port=ANY_MAC_PORT,
        receive_port=ANY_MAC_PORT,
        expect_mac=WRONG_MAC,
        timeout_seconds=5.0,
        send_mac=WRONG_MAC,
    ),
    TestCase(
        name="ignores_malformed_packet_without_configured_mac",
        send_port=ANY_MAC_PORT,
        receive_port=ANY_MAC_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=MALFORMED_MAGIC_PAYLOAD_HEX,
    ),
]

# mDNS reflection is directional: queries relay source->target ("forward"), responses
# target->source ("reverse"). Both are relayed verbatim, so the receiver asserts the exact bytes
# it sent. The drop cases assert nothing arrives (the wrong direction, a too-short payload, or a
# port the dispatcher filter never passes).
MDNS_CASES = [
    TestCase(
        name="reflects_mdns_query",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=MDNS_QUERY_HEX,
        expect_payload_hex=MDNS_QUERY_HEX,
        group=MDNS_GROUP_V4,
        direction="forward",
    ),
    TestCase(
        name="reflects_mdns_response",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=MDNS_RESPONSE_HEX,
        expect_payload_hex=MDNS_RESPONSE_HEX,
        group=MDNS_GROUP_V4,
        direction="reverse",
    ),
    TestCase(
        name="reflects_mdns_query_ipv6",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=MDNS_QUERY_HEX,
        expect_payload_hex=MDNS_QUERY_HEX,
        group=MDNS_GROUP_V6,
        family=6,
        direction="forward",
    ),
    TestCase(
        name="reflects_mdns_response_ipv6",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=MDNS_RESPONSE_HEX,
        expect_payload_hex=MDNS_RESPONSE_HEX,
        group=MDNS_GROUP_V6,
        family=6,
        direction="reverse",
    ),
    # A query sent target->source hits the target's response-only handler and is dropped.
    TestCase(
        name="ignores_mdns_query_in_response_direction",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=MDNS_QUERY_HEX,
        group=MDNS_GROUP_V4,
        direction="reverse",
    ),
    # A response sent source->target hits the source's query-only handler and is dropped.
    TestCase(
        name="ignores_mdns_response_in_query_direction",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=MDNS_RESPONSE_HEX,
        group=MDNS_GROUP_V4,
        direction="forward",
    ),
    # 8 bytes < the 12-byte DNS header, so classify() returns None and drops it.
    TestCase(
        name="ignores_mdns_too_short_query",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=MDNS_SHORT_QUERY_HEX,
        group=MDNS_GROUP_V4,
        direction="forward",
    ),
    # The dispatcher filter pins dst_port=5353, so a 5354 datagram never reaches a handler.
    TestCase(
        name="ignores_mdns_wrong_port",
        send_port=MDNS_WRONG_PORT,
        receive_port=MDNS_WRONG_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=MDNS_QUERY_HEX,
        group=MDNS_GROUP_V4,
        direction="forward",
    ),
    # Single-family gating (address_family = "ipv4"): the reflector reflects v4 mDNS but never joins
    # the v6 group or registers a v6 handler, so v6 is ignored. The v4 case is the positive control —
    # it proves the reflector is live, so the v6 expect-none is a real "gated out", not a dead reflector.
    TestCase(
        name="ipv4_only_reflector_reflects_mdns_query",
        config="config-family.toml",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=MDNS_QUERY_HEX,
        expect_payload_hex=MDNS_QUERY_HEX,
        group=MDNS_GROUP_V4,
        direction="forward",
    ),
    TestCase(
        name="ipv4_only_reflector_ignores_mdns_query_ipv6",
        config="config-family.toml",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=2.0,
        send_payload_hex=MDNS_QUERY_HEX,
        group=MDNS_GROUP_V6,
        family=6,
        direction="forward",
    ),
]

# SSDP one-way reflection is directional: M-SEARCH searches relay source->target ("forward"), NOTIFY
# advertisements relay target->source ("reverse"). Both are relayed verbatim, so the receiver asserts
# the exact bytes it sent. The drop cases assert nothing arrives (the wrong direction, a non-SSDP
# payload, or a port the dispatcher filter never passes). The M-SEARCH round trip -- search out, 200 OK
# proxied back -- is a RoundTripCase below, not a one-way TestCase.
SSDP_CASES = [
    TestCase(
        name="reflects_ssdp_msearch",
        send_port=SSDP_PORT,
        receive_port=SSDP_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=SSDP_MSEARCH_HEX,
        expect_payload_hex=SSDP_MSEARCH_HEX,
        group=SSDP_GROUP_V4,
        direction="forward",
    ),
    TestCase(
        name="reflects_ssdp_msearch_ipv6",
        send_port=SSDP_PORT,
        receive_port=SSDP_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=SSDP_MSEARCH_HEX,
        expect_payload_hex=SSDP_MSEARCH_HEX,
        group=SSDP_GROUP_V6,
        family=6,
        direction="forward",
    ),
    TestCase(
        name="reflects_ssdp_notify",
        send_port=SSDP_PORT,
        receive_port=SSDP_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=SSDP_NOTIFY_HEX,
        expect_payload_hex=SSDP_NOTIFY_HEX,
        group=SSDP_GROUP_V4,
        direction="reverse",
    ),
    TestCase(
        name="reflects_ssdp_notify_ipv6",
        send_port=SSDP_PORT,
        receive_port=SSDP_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=SSDP_NOTIFY_HEX,
        expect_payload_hex=SSDP_NOTIFY_HEX,
        group=SSDP_GROUP_V6,
        family=6,
        direction="reverse",
    ),
    # Site-local SSDP (ff05::c) reflects like ff02::c, but must be sourced from the routable address
    # (the per-scope v6 source selection), not the link-local one a link-local group is sourced from.
    TestCase(
        name="reflects_ssdp_notify_site_local_from_routable_source",
        send_port=SSDP_PORT,
        receive_port=SSDP_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=SSDP_NOTIFY_HEX,
        expect_payload_hex=SSDP_NOTIFY_HEX,
        group=SSDP_GROUP_V6_SITE,
        family=6,
        direction="reverse",
        expect_routable_source=True,
    ),
    # An M-SEARCH sent target->source hits the target's NOTIFY-only handler and is dropped.
    TestCase(
        name="ignores_ssdp_msearch_in_notify_direction",
        send_port=SSDP_PORT,
        receive_port=SSDP_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=SSDP_MSEARCH_HEX,
        group=SSDP_GROUP_V4,
        direction="reverse",
    ),
    # A NOTIFY sent source->target hits the source's M-SEARCH-only handler and is dropped.
    TestCase(
        name="ignores_ssdp_notify_in_msearch_direction",
        send_port=SSDP_PORT,
        receive_port=SSDP_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=SSDP_NOTIFY_HEX,
        group=SSDP_GROUP_V4,
        direction="forward",
    ),
    # Neither M-SEARCH nor NOTIFY: classified as non-SSDP and dropped.
    TestCase(
        name="ignores_ssdp_http_response_on_group",
        send_port=SSDP_PORT,
        receive_port=SSDP_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=SSDP_HTTP_RESPONSE_HEX,
        group=SSDP_GROUP_V4,
        direction="forward",
    ),
    # The dispatcher filter pins dst_port=1900. Listen on the SEND port, not 1900: the reflector
    # re-emits to the captured dest port verbatim, so a regression that dispatched this 1901 datagram
    # would re-emit it to the group on 1901 -- invisible to a 1900-bound receiver. Binding the send
    # port keeps the "not reflected" assertion able to observe a misforward.
    TestCase(
        name="ignores_ssdp_wrong_port",
        send_port=SSDP_WRONG_PORT,
        receive_port=SSDP_WRONG_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=SSDP_MSEARCH_HEX,
        group=SSDP_GROUP_V4,
        direction="forward",
    ),
    # Single-family gating, the IPv6 mirror of the IPv4-only mDNS cases (a different protocol on
    # purpose): an address_family = "ipv6" SSDP reflector reflects v6 NOTIFY but never joins the v4
    # group or registers a v4 handler, so v4 is ignored. The v6 case is the positive control.
    TestCase(
        name="ipv6_only_reflector_reflects_ssdp_notify",
        config="config-family-v6.toml",
        send_port=SSDP_PORT,
        receive_port=SSDP_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=SSDP_NOTIFY_HEX,
        expect_payload_hex=SSDP_NOTIFY_HEX,
        group=SSDP_GROUP_V6,
        family=6,
        direction="reverse",
    ),
    TestCase(
        name="ipv6_only_reflector_ignores_ssdp_notify_ipv4",
        config="config-family-v6.toml",
        send_port=SSDP_PORT,
        receive_port=SSDP_PORT,
        expect_mac=None,
        timeout_seconds=2.0,
        send_payload_hex=SSDP_NOTIFY_HEX,
        group=SSDP_GROUP_V4,
        direction="reverse",
    ),
]

WSD_CASES = [
    # Hello/Bye announcements reflect device (target) -> client (source). A Hello sent on the target is
    # relayed verbatim to the source. (Announcement direction = "reverse".)
    TestCase(
        name="reflects_wsd_hello",
        config="config-wsd.toml",
        send_port=WSD_PORT,
        receive_port=WSD_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=WSD_HELLO_HEX,
        expect_payload_hex=WSD_HELLO_HEX,
        group=WSD_GROUP_V4,
        direction="reverse",
    ),
    # The IPv6 mirror: WSD uses the link-local ff02::c group.
    TestCase(
        name="reflects_wsd_hello_ipv6",
        config="config-wsd.toml",
        send_port=WSD_PORT,
        receive_port=WSD_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=WSD_HELLO_HEX,
        expect_payload_hex=WSD_HELLO_HEX,
        group=WSD_GROUP_V6,
        family=6,
        direction="reverse",
    ),
    # Bye relays through the same announcement path as Hello (both classify as an announcement).
    TestCase(
        name="reflects_wsd_bye",
        config="config-wsd.toml",
        send_port=WSD_PORT,
        receive_port=WSD_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=WSD_BYE_HEX,
        expect_payload_hex=WSD_BYE_HEX,
        group=WSD_GROUP_V4,
        direction="reverse",
    ),
    # A Probe on the target hits the announcement handler, which classifies it as the search direction
    # and skips it -- never relayed to the source.
    TestCase(
        name="ignores_wsd_probe_in_announcement_direction",
        config="config-wsd.toml",
        send_port=WSD_PORT,
        receive_port=WSD_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=WSD_PROBE_HEX,
        group=WSD_GROUP_V4,
        direction="reverse",
    ),
    # A Hello on the source hits the search handler, which classifies it as the announcement direction
    # and skips it -- never relayed to the target.
    TestCase(
        name="ignores_wsd_hello_in_search_direction",
        config="config-wsd.toml",
        send_port=WSD_PORT,
        receive_port=WSD_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=WSD_HELLO_HEX,
        group=WSD_GROUP_V4,
        direction="forward",
    ),
    # A non-WSD payload on the WSD group (an SSDP M-SEARCH carries no <Action>): classified as junk and
    # dropped.
    TestCase(
        name="ignores_non_wsd_on_wsd_group",
        config="config-wsd.toml",
        send_port=WSD_PORT,
        receive_port=WSD_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=SSDP_MSEARCH_HEX,
        group=WSD_GROUP_V4,
        direction="reverse",
    ),
]


@dataclasses.dataclass(frozen=True)
class RoundTripCase:
    name: str
    family: int  # 4 or 6
    group: str
    timeout_seconds: float = 8.0
    # When False, no responder is started and the searcher must receive nothing -- the reflector must
    # not fabricate or loop back a reply to a search no device answered.
    expect_reply: bool = True
    # Protocol parameters, defaulting to SSDP's M-SEARCH round trip; WSD overrides them (its Probe ->
    # ProbeMatches uses the same session machinery on a different port / with different payloads).
    port: int = SSDP_PORT
    probe_hex: str = SSDP_MSEARCH_HEX
    reply_hex: str = SSDP_OK_HEX
    config: str = "config.toml"
    evict_log: str = "evicted SSDP session"


ROUNDTRIP_CASES = [
    RoundTripCase(name="ssdp_msearch_roundtrip", family=4, group=SSDP_GROUP_V4),
    RoundTripCase(name="ssdp_msearch_roundtrip_ipv6", family=6, group=SSDP_GROUP_V6),
    # Site-local (ff05::c) round trip: the M-SEARCH is relayed from the routable source, so the device
    # replies there -- the searcher only hears the 200 OK if the reserved port and response capture were
    # placed on that same routable address, not the link-local one. Guards the scope-matched `our_addr`.
    RoundTripCase(name="ssdp_msearch_roundtrip_ipv6_site_local", family=6, group=SSDP_GROUP_V6_SITE),
    RoundTripCase(name="ssdp_msearch_no_responder_no_reply", family=4, group=SSDP_GROUP_V4,
        timeout_seconds=2.0, expect_reply=False),
    # WSD Probe -> ProbeMatches: the same per-searcher session machinery on port 3702, replies relayed
    # verbatim (no DIAL). Eviction fires after the fixed 5s WSD window.
    RoundTripCase(name="wsd_probe_roundtrip", family=4, group=WSD_GROUP_V4, port=WSD_PORT,
        probe_hex=WSD_PROBE_HEX, reply_hex=WSD_PROBEMATCHES_HEX, config="config-wsd.toml",
        evict_log="evicted WSD session"),
    # Resolve -> ResolveMatches: the same search-session path as Probe (both classify as a search).
    RoundTripCase(name="wsd_resolve_roundtrip", family=4, group=WSD_GROUP_V4, port=WSD_PORT,
        probe_hex=WSD_RESOLVE_HEX, reply_hex=WSD_RESOLVEMATCHES_HEX, config="config-wsd.toml",
        evict_log="evicted WSD session"),
]

@dataclasses.dataclass(frozen=True)
class DialCase:
    name: str
    family: int          # 4 (DIAL is IPv4-only by spec; kept as a field for symmetry)
    group: str
    timeout_seconds: float = 8.0
    serve_seconds: float = 6.0
    passive: bool = False      # passive discovery (device advertises NOTIFY; client listens) vs active M-SEARCH
    unreachable: bool = False  # device advertises a dead HTTP port; the proxied fetch must fail, not hang


DIAL_CASES = [
    DialCase(name="dial_launch_roundtrip", family=4, group=SSDP_GROUP_V4),
    DialCase(name="dial_passive_notify_roundtrip", family=4, group=SSDP_GROUP_V4, passive=True),
    DialCase(name="dial_upstream_unreachable", family=4, group=SSDP_GROUP_V4, unreachable=True),
]


@dataclasses.dataclass(frozen=True)
class DialAddressChangeCase:
    # A full DIAL pass, then the same pass again after the reflector's source IPv4 changes, then again
    # after its target IPv4 changes -- to a *different* address each time. A passing re-run is the 7d
    # proof: a proxy not evicted on the change would re-advertise a LOCATION on the vanished source
    # address (the fetch can't reach it) or bind the vanished target on its upstream connect. The device
    # advertises NOTIFY throughout (passive discovery), so each phase's fresh client rediscovers and the
    # reflector re-mints against the current addresses.
    name: str
    family: int = 4
    group: str = SSDP_GROUP_V4
    timeout_seconds: float = 8.0
    serve_seconds: float = 60.0  # device keeps advertising + serving across all three passes
    passive: bool = True
    unreachable: bool = False


DIAL_ADDRESS_CHANGE_CASES = [
    DialAddressChangeCase(name="dial_address_change"),
]

# Per-protocol probe parameters for the address-change phases: wol sends a magic packet (no payload
# or group); mdns sends a query to its family's group, relayed verbatim.
PROBE_SPECS = {
    "wol": {"port": CONFIGURED_PORT, "payload": None, "group_v4": None, "group_v6": None},
    "mdns": {
        "port": MDNS_PORT,
        "payload": MDNS_QUERY_HEX,
        "group_v4": MDNS_GROUP_V4,
        "group_v6": MDNS_GROUP_V6,
    },
}


@dataclasses.dataclass(frozen=True)
class Phase:
    # One knock-out within an address-change case: take down a single (interface, family) source
    # address on the reflector, prove reflection of `protocol`/`family` stops, then restore it and
    # prove reflection resumes -- all via real traffic.
    label: str
    protocol: str  # "wol" | "mdns" -> PROBE_SPECS
    family: int  # 4 | 6
    interface: str  # "source" (wol_src) | "target" (wol_dst): which reflector interface to toggle


@dataclasses.dataclass(frozen=True)
class AddressChangeCase:
    name: str
    config: str  # config file (relative to e2e/), defining a dual-family reflector set
    phases: tuple[Phase, ...]


ADDRESS_CHANGE_CASES = [
    AddressChangeCase(
        name="mdns_address_change",
        config="config-addrchange.toml",
        phases=(
            # source IPv4: the source is the egress for mDNS responses, so knocking out its v4 makes the
            # per-packet source-address gate drop the v4 response re-emit -- reflection stops at the
            # egress; the monitor refreshes source addrs on restore. target IPv6: the target is the
            # egress for queries, so the gate drops the v6 re-emit; the monitor refreshes egress addrs.
            Phase(label="source IPv4", protocol="mdns", family=4, interface="source"),
            Phase(label="target IPv6", protocol="mdns", family=6, interface="target"),
        ),
    ),
]

ALL_CASES: list[TestCase | RoundTripCase | DialCase | DialAddressChangeCase | AddressChangeCase] = [
    *TEST_CASES, *MDNS_CASES, *SSDP_CASES, *WSD_CASES, *ROUNDTRIP_CASES, *DIAL_CASES,
    *DIAL_ADDRESS_CHANGE_CASES, *ADDRESS_CHANGE_CASES]


def format_command(command: list[str]) -> str:
    return " ".join(command)


def run_command(
    command: list[str],
    *,
    cwd: Path = REPO_ROOT,
    check: bool = True,
    capture: bool = True,
    echo: bool = True,
) -> subprocess.CompletedProcess[str]:
    if echo:
        print(f"+ {format_command(command)}", flush=True)
    stdout = subprocess.PIPE if capture else None
    stderr = subprocess.PIPE if capture else None
    result = subprocess.run(command, cwd=cwd, text=True, stdout=stdout, stderr=stderr, check=False)
    if check and result.returncode != 0:
        raise CommandError(command, result)
    return result


def docker(
    args: list[str],
    *,
    check: bool = True,
    capture: bool = True,
    echo: bool = True,
) -> subprocess.CompletedProcess[str]:
    return run_command(["docker", *args], check=check, capture=capture, echo=echo)


def require_command(command: str) -> None:
    if shutil.which(command) is None:
        raise RuntimeError(f"required command not found: {command}")


def magic_packet_hex(mac: str) -> str:
    octets = bytes(int(part, 16) for part in mac.split(":"))
    return (b"\xff" * 6 + octets * 16).hex()


SEGMENTS = ("source", "target")


class Backend:
    # The execution environment for one case: two isolated dual-stack segments, the reflector
    # straddling both, and single-homed probe helpers referenced by role name ("receiver",
    # "sender", "device", ...). Docker realizes segments as bridge networks and participants as
    # containers; native (Linux) as netns + veth pairs and plain processes. Runners hold case
    # logic only and drive everything through this interface, so every case runs identically
    # under both backends.

    def __init__(self, args: argparse.Namespace, prefix: str) -> None:
        self.args = args
        self.prefix = prefix

    def setup_segments(self) -> None:
        raise NotImplementedError

    def cleanup(self) -> None:
        raise NotImplementedError

    def keep_artifacts(self) -> str:
        # What --keep-on-failure leaves behind, for the "keeping ..." message.
        raise NotImplementedError

    def abandon(self) -> None:
        # Called instead of cleanup() on --keep-on-failure. Docker containers stay inspectable
        # (and visible in `docker ps`) so the default keeps everything; the native backend kills
        # its otherwise-invisible root processes -- the namespaces and log files hold the
        # debuggable state.
        pass

    def start_reflector(self, config_path: Path) -> None:
        raise NotImplementedError

    def start_probe(
        self, role: str, segment: str, ifname: str, probe_args: list[str], *, detach: bool = True
    ) -> None:
        # Run probe.py with `probe_args` single-homed on `segment`. detach=False blocks until
        # exit and raises on a non-zero code.
        raise NotImplementedError

    def helper_ifname(self, requested: str) -> str:
        # The interface name a helper on a segment actually sees (passed as probe --interface).
        # Docker pins the requested name per container; native names every far end probe0.
        raise NotImplementedError

    def wait(self, role: str) -> int:
        raise NotImplementedError

    def logs(self, role: str) -> tuple[str, str]:
        raise NotImplementedError

    def status(self, role: str) -> tuple[bool, str]:
        # (still running?, human-readable state) -- state is "unknown" when unavailable.
        raise NotImplementedError

    def remove(self, role: str) -> None:
        raise NotImplementedError

    def stop_reflector(self, grace_seconds: int) -> int:
        # SIGTERM the reflector, allow `grace_seconds` for a clean exit (valgrind's leak
        # analysis needs it), then kill; returns the exit code.
        raise NotImplementedError

    def admin(self, script: str, *, capture: bool = False) -> str:
        # Run a shell script inside the reflector's network view (addr/route/sysctl mutation).
        raise NotImplementedError

    def set_address(self, ifname: str, family: int, *, up: bool, cidr: str | None = None) -> str | None:
        # Bring one (interface, family) source address down or back up in the reflector's
        # network view. IPv6 drops every v6 address and, on re-enable, has the kernel regenerate
        # a usable link-local; v4 deletes and later re-adds the exact CIDR (returned on removal
        # so the caller can restore it). This base implementation speaks Linux (ip + /proc
        # sysctls), shared by the docker and native Linux backends; FreeBSD overrides it with
        # ifconfig verbs.
        if family == 6:
            self.admin(f"echo {0 if up else 1} > /proc/sys/net/ipv6/conf/{ifname}/disable_ipv6")
            return None
        if up:
            if cidr is None:
                raise RuntimeError("restoring an IPv4 address requires the CIDR captured on removal")
            self.admin(f"ip addr add {cidr} dev {ifname}")
            return cidr
        captured = self.admin(
            f"ip -o -4 addr show dev {ifname} | awk '/inet /{{print $4; exit}}'", capture=True
        )
        if not captured:
            raise RuntimeError(f"no IPv4 address on {ifname} to remove")
        self.admin(f"ip addr del {captured} dev {ifname}")
        return captured

    def add_decoy_route(self, dest_ip: str, ifname: str) -> bool:
        # Plant a host route to `dest_ip` via the (wrong) `ifname` in the reflector's network
        # view; returns whether it was armed. Linux-shaped: the DIAL egress pin there is
        # SO_BINDTODEVICE, which constrains the route lookup and so defeats the decoy. FreeBSD
        # has no pin primitive (net/tcp.rs relies on the source-address bind alone), so an armed
        # decoy would legitimately break the flow -- its backend skips this.
        self.admin(f"ip route add {dest_ip}/32 dev {ifname}")
        return True

    def reflector_ip(self, segment: str) -> str:
        raise NotImplementedError

    def probe_ip(self, role: str, segment: str) -> str:
        raise NotImplementedError

    def print_diagnostics(self) -> None:
        raise NotImplementedError


class DockerBackend(Backend):
    def __init__(self, args: argparse.Namespace, prefix: str) -> None:
        super().__init__(args, prefix)
        self.networks = {segment: f"{prefix}-{segment}" for segment in SEGMENTS}
        self.roles: dict[str, str] = {}  # role -> container name, in start order

    @staticmethod
    def require_available() -> None:
        require_command("docker")

    def setup_segments(self) -> None:
        # Both networks are dual-stack: IPv4 cases are unaffected, and IPv6 cases need the
        # bridges to carry IPv6 so the reflector can listen on / emit to ff02::1.
        for segment in SEGMENTS:
            docker(["network", "create", "--driver", "bridge", "--ipv6", self.networks[segment]])

    def cleanup(self) -> None:
        for container in reversed(self.roles.values()):
            docker(["rm", "-f", container], check=False)
        self.roles.clear()
        for network in self.networks.values():
            docker(["network", "rm", network], check=False)

    def keep_artifacts(self) -> str:
        return f"Docker resources {self.prefix}"

    def start_reflector(self, config_path: Path) -> None:
        container = f"{self.prefix}-reflector"
        self.roles["reflector"] = container
        # Pin in-container interface names per network. Without this, Docker's interface naming
        # at start time is non-deterministic when multiple endpoints are attached, which made the
        # reflector's SO_BINDTODEVICE land on the wrong bridge ~16% of runs. Using a non-"eth"
        # prefix avoids the prefix-collision caveat in moby/moby#49155. Requires Docker 28.0+
        # (the com.docker.network.endpoint.ifname driver-opt).
        docker(
            [
                "create",
                "--name",
                container,
                "--network",
                f"name={self.networks['source']},driver-opt=com.docker.network.endpoint.ifname={REFLECTOR_SOURCE_IFNAME}",
                "--network",
                f"name={self.networks['target']},driver-opt=com.docker.network.endpoint.ifname={REFLECTOR_TARGET_IFNAME}",
                # Skip Duplicate Address Detection on the link-local addresses. Without this the
                # kernel's autogenerated fe80:: is tentative (unusable) when the reflector resolves
                # at startup, so it falls back to the Docker-assigned ULA as its sole v6 source and
                # never distinguishes link-local from routable -- masking the per-scope source
                # selection. With DAD off the fe80:: is usable immediately, so v6 (link-local) and
                # v6-routable (ULA) differ, as on a real interface.
                "--sysctl",
                "net.ipv6.conf.default.accept_dad=0",
                "--cap-add",
                "NET_RAW",
                "--mount",
                f"type=bind,source={config_path},target=/etc/reflector/config.toml,readonly",
                self.args.image,
                "/etc/reflector/config.toml",
            ]
        )
        docker(["start", container])

    def start_probe(
        self, role: str, segment: str, ifname: str, probe_args: list[str], *, detach: bool = True
    ) -> None:
        container = f"{self.prefix}-{role}"
        self.roles[role] = container
        command = ["run"]
        if detach:
            command.append("-d")
        command += [
            "--name",
            container,
            # Pin the helper's interface name so the probe can scope multicast egress / group
            # joins to it deterministically (see start_reflector for the rationale).
            "--network",
            f"name={self.networks[segment]},driver-opt=com.docker.network.endpoint.ifname={ifname}",
            "--mount",
            f"type=bind,source={E2E_DIR},target=/e2e,readonly",
            self.args.helper_image,
            "python3",
            "/e2e/probe.py",
            *probe_args,
        ]
        docker(command)

    def helper_ifname(self, requested: str) -> str:
        return requested

    def wait(self, role: str) -> int:
        return int(docker(["wait", self.roles[role]], echo=False).stdout.strip())

    def logs(self, role: str) -> tuple[str, str]:
        result = docker(["logs", self.roles[role]], check=False, echo=False)
        return result.stdout, result.stderr

    def status(self, role: str) -> tuple[bool, str]:
        result = docker(
            ["inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", self.roles[role]],
            check=False,
            echo=False,
        )
        if result.returncode != 0:
            return True, "unknown"
        state = result.stdout.strip()
        return not state.startswith("false "), state

    def remove(self, role: str) -> None:
        container = self.roles.pop(role, None)
        if container is not None:
            docker(["rm", "-f", container], check=False, echo=False)

    def stop_reflector(self, grace_seconds: int) -> int:
        docker(["stop", "-t", str(grace_seconds), self.roles["reflector"]])
        return self.wait("reflector")

    def admin(self, script: str, *, capture: bool = False) -> str:
        # Address/route changes need CAP_NET_ADMIN and a writable /proc/sys, which the reflector
        # container (scratch image, NET_RAW only) has by neither. Run a throwaway privileged
        # container in the reflector's network namespace, so `ip addr` / the disable_ipv6 sysctl
        # act on the very interfaces the reflector watches -- without widening the reflector's
        # own privileges.
        result = docker([
            "run", "--rm", "--privileged", "--network", f"container:{self.roles['reflector']}",
            self.args.helper_image, "sh", "-ec", script,
        ])
        return result.stdout.strip() if capture else ""

    def _container_ip(self, container: str, network: str) -> str:
        fmt = '{{(index .NetworkSettings.Networks "' + network + '").IPAddress}}'
        ip = docker(["inspect", "-f", fmt, container]).stdout.strip()
        if not ip:
            raise RuntimeError(f"no IPv4 address for {container} on {network}")
        return ip

    def reflector_ip(self, segment: str) -> str:
        return self._container_ip(self.roles["reflector"], self.networks[segment])

    def probe_ip(self, role: str, segment: str) -> str:
        return self._container_ip(self.roles[role], self.networks[segment])

    def print_diagnostics(self) -> None:
        for role, container in self.roles.items():
            inspect = docker(
                ["inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", container], check=False
            )
            if inspect.returncode == 0:
                print(f"{container}: {inspect.stdout.strip()}", file=sys.stderr, flush=True)

            out, err = self.logs(role)
            if out or err:
                print(f"--- logs: {container} ---", file=sys.stderr, flush=True)
                if out:
                    print(out, end="", file=sys.stderr, flush=True)
                if err:
                    print(err, end="", file=sys.stderr, flush=True)

        for network in self.networks.values():
            inspect = docker(["network", "inspect", network], check=False)
            if inspect.returncode == 0 and inspect.stdout:
                print(f"--- network: {network} ---", file=sys.stderr, flush=True)
                print(inspect.stdout, end="", file=sys.stderr, flush=True)


# Native segment addressing: the RFC 5737 test networks for v4 and a ULA /64 per segment for
# routable v6 (Docker's --ipv6 IPAM provided that implicitly; the kernel adds fe80:: itself).
# The reflector is always host 1 and a segment's helper host 2, replacing Docker's IPAM
# discovery with a fixed plan.
NATIVE_V4_SUBNET = {"source": "192.0.2", "target": "198.51.100"}
NATIVE_V6_PREFIX = {"source": "fd00:e2e0:1", "target": "fd00:e2e0:2"}
NATIVE_REFLECTOR_HOST = 1
NATIVE_HELPER_HOST = 2


class NativeBackend(Backend):
    # Shared mechanics for the native fabrics (Linux netns, FreeBSD vnet jails): participants
    # are plain processes with stdout/stderr teed to per-role files in a case tmpdir (the
    # docker-logs replacement), and addressing follows the fixed plan above instead of IPAM
    # discovery. Subclasses provide the fabric: segment construction/teardown, the exec prefix
    # that places a probe in a segment's stack, and the reflector's launch.
    #
    # Fidelity gap vs the docker backend: the reflector runs here with the harness's full root
    # privileges, not the CAP_NET_RAW-only confinement of the scratch container -- a change that
    # grows a privilege requirement passes natively and only fails in the docker lane. CI runs
    # both, so the docker lane stays the privilege-contract gate.
    REFLECTOR_IFNAMES = {"source": REFLECTOR_SOURCE_IFNAME, "target": REFLECTOR_TARGET_IFNAME}

    def __init__(self, args: argparse.Namespace, prefix: str) -> None:
        super().__init__(args, prefix)
        self.procs: dict[str, subprocess.Popen[bytes]] = {}
        self.logdir = Path(tempfile.mkdtemp(prefix=f"{prefix}-"))

    @staticmethod
    def require_available() -> None:
        raise NotImplementedError

    @staticmethod
    def _require_native_basics() -> None:
        if os.geteuid() != 0:
            raise RuntimeError("--backend native requires root (fabric setup, raw sockets)")
        # probe.py catches socket timeouts as TimeoutError, which socket.timeout only aliases
        # from 3.10 on; the docker backend pins python:3.13 but here probes run on this
        # interpreter.
        if sys.version_info < (3, 10):
            raise RuntimeError("--backend native requires Python >= 3.10")

    def _probe_exec(self, segment: str) -> list[str]:
        # The command prefix that places a probe process in `segment`'s network stack.
        raise NotImplementedError

    def _reflector_command(self, config_path: Path) -> list[str]:
        raise NotImplementedError

    def _teardown_fabric(self) -> None:
        raise NotImplementedError

    def _print_fabric_diagnostics(self) -> None:
        raise NotImplementedError

    def _kill_procs(self) -> None:
        for proc in self.procs.values():
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        self.procs.clear()

    def cleanup(self) -> None:
        self._kill_procs()
        self._teardown_fabric()
        shutil.rmtree(self.logdir, ignore_errors=True)

    def abandon(self) -> None:
        # Keep the fabric and logs, but don't leave root daemons running unwatched.
        self._kill_procs()

    def _spawn(self, role: str, command: list[str]) -> None:
        self.remove(role)
        print(f"+ {format_command(command)}", flush=True)
        # Scrub REFLECTOR_* so the daemon sees only its config file, as it would in the docker
        # backend's clean container env -- a stray host REFLECTOR_LOG_LEVEL (or worse, an env
        # reflector entry) must not alter the system under test.
        env = {key: value for key, value in os.environ.items() if not key.startswith("REFLECTOR_")}
        out = open(self.logdir / f"{role}.out", "wb")
        err = open(self.logdir / f"{role}.err", "wb")
        try:
            self.procs[role] = subprocess.Popen(command, cwd=REPO_ROOT, stdout=out, stderr=err, env=env)
        finally:
            out.close()
            err.close()

    def start_reflector(self, config_path: Path) -> None:
        self._spawn("reflector", self._reflector_command(config_path))

    def start_probe(
        self, role: str, segment: str, ifname: str, probe_args: list[str], *, detach: bool = True
    ) -> None:
        del ifname  # the far end is always probe0; the caller got that from helper_ifname()
        command = [*self._probe_exec(segment), sys.executable, str(E2E_DIR / "probe.py"), *probe_args]
        self._spawn(role, command)
        if not detach:
            code = self.procs[role].wait()
            if code != 0:
                out, err = self.logs(role)
                raise RuntimeError(f"{role} failed with exit code {code}\n{out}{err}")

    def helper_ifname(self, requested: str) -> str:
        del requested
        return RECEIVER_IFNAME

    def wait(self, role: str) -> int:
        return self.procs[role].wait()

    def logs(self, role: str) -> tuple[str, str]:
        def read(suffix: str) -> str:
            path = self.logdir / f"{role}.{suffix}"
            return path.read_text(errors="replace") if path.exists() else ""

        return read("out"), read("err")

    def status(self, role: str) -> tuple[bool, str]:
        proc = self.procs.get(role)
        if proc is None:
            return True, "unknown"
        if proc.poll() is None:
            return True, "running"
        return False, f"exited {proc.returncode}"

    def remove(self, role: str) -> None:
        proc = self.procs.pop(role, None)
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait()

    def stop_reflector(self, grace_seconds: int) -> int:
        proc = self.procs["reflector"]
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=grace_seconds)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        return proc.returncode

    def reflector_ip(self, segment: str) -> str:
        return f"{NATIVE_V4_SUBNET[segment]}.{NATIVE_REFLECTOR_HOST}"

    def probe_ip(self, role: str, segment: str) -> str:
        del role  # one helper per segment; the plan gives them all the same host number
        return f"{NATIVE_V4_SUBNET[segment]}.{NATIVE_HELPER_HOST}"

    def print_diagnostics(self) -> None:
        for logfile in sorted(self.logdir.iterdir()):
            text = logfile.read_text(errors="replace")
            if text:
                print(f"--- logs: {logfile.name} ---", file=sys.stderr, flush=True)
                print(text, end="", file=sys.stderr, flush=True)
        self._print_fabric_diagnostics()


class NativeLinuxBackend(NativeBackend):
    # Segments as veth pairs between per-participant network namespaces: a dut namespace holds
    # wol_src + wol_dst (so the checked-in configs work unchanged), and one persistent far
    # namespace per segment holds the peer end, always named probe0. Every participant gets its
    # own namespace for the same reasons Docker gave them one: wildcard binds and --expect-none
    # windows must only see the segment's traffic, unicast to the reflector must cross the wire
    # rather than short-circuit via lo, and the host's daemons (systemd-resolved speaks mDNS)
    # must not reach the test wires. Successive probe processes for a case run inside the same
    # far namespace: the reflector caches its ifindexes at startup, so the veth ends on its side
    # must never be recreated -- probes respawn, namespaces persist.

    def __init__(self, args: argparse.Namespace, prefix: str) -> None:
        super().__init__(args, prefix)
        self.ns = {"dut": f"{prefix}-dut", "source": f"{prefix}-src", "target": f"{prefix}-dst"}

    @staticmethod
    def require_available() -> None:
        if sys.platform != "linux":
            raise RuntimeError("the Linux native backend requires Linux (netns + veth)")
        require_command("ip")
        NativeBackend._require_native_basics()

    def _ip(self, args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return run_command(["ip", *args], **kwargs)  # type: ignore[arg-type]

    def setup_segments(self) -> None:
        for ns in self.ns.values():
            self._ip(["netns", "add", ns])
            # DAD off before any interface exists, so both the fe80:: and the ULA are usable the
            # moment they appear (the Docker backend does the same via --sysctl; here the probes
            # get it too, removing the startup race for their v6 sends).
            run_command([
                "ip", "netns", "exec", ns, "sh", "-ec",
                "echo 0 > /proc/sys/net/ipv6/conf/default/accept_dad; "
                "echo 0 > /proc/sys/net/ipv6/conf/all/accept_dad",
            ])
            self._ip(["-n", ns, "link", "set", "lo", "up"])

        for segment in SEGMENTS:
            dut_ifname = self.REFLECTOR_IFNAMES[segment]
            self._ip([
                "link", "add", dut_ifname, "netns", self.ns["dut"],
                "type", "veth", "peer", "name", RECEIVER_IFNAME, "netns", self.ns[segment],
            ])
            v4, v6 = NATIVE_V4_SUBNET[segment], NATIVE_V6_PREFIX[segment]
            dut, far = self.ns["dut"], self.ns[segment]
            self._ip(["-n", dut, "addr", "add", f"{v4}.{NATIVE_REFLECTOR_HOST}/24", "dev", dut_ifname])
            self._ip(["-n", dut, "addr", "add", f"{v6}::{NATIVE_REFLECTOR_HOST}/64", "dev", dut_ifname])
            self._ip(["-n", far, "addr", "add", f"{v4}.{NATIVE_HELPER_HOST}/24", "dev", RECEIVER_IFNAME])
            self._ip(["-n", far, "addr", "add", f"{v6}::{NATIVE_HELPER_HOST}/64", "dev", RECEIVER_IFNAME])
            self._ip(["-n", dut, "link", "set", dut_ifname, "up"])
            self._ip(["-n", far, "link", "set", RECEIVER_IFNAME, "up"])
            # The probe's 255.255.255.255 sends are routed, not interface-pinned; single-homed
            # plus this default route pins them to the segment (Docker's IPAM gateway did this).
            self._ip(["-n", far, "route", "add", "default", "dev", RECEIVER_IFNAME])

        self._wait_carrier()

    def _wait_carrier(self) -> None:
        # A veth reports operstate "up" only once BOTH ends are up; don't start the reflector
        # (or probes) on a link that hasn't settled.
        pending = [(self.ns["dut"], ifname) for ifname in self.REFLECTOR_IFNAMES.values()]
        pending += [(self.ns[segment], RECEIVER_IFNAME) for segment in SEGMENTS]
        deadline = time.monotonic() + 5.0
        for ns, ifname in pending:
            while True:
                state = run_command(
                    ["ip", "netns", "exec", ns, "cat", f"/sys/class/net/{ifname}/operstate"],
                    echo=False,
                ).stdout.strip()
                if state == "up":
                    break
                if time.monotonic() > deadline:
                    raise RuntimeError(f"{ns}/{ifname} never reached operstate up (last: {state})")
                time.sleep(0.05)

    def _teardown_fabric(self) -> None:
        for ns in self.ns.values():
            run_command(["ip", "netns", "del", ns], check=False, echo=False)

    def keep_artifacts(self) -> str:
        return f"namespaces {', '.join(self.ns.values())} and logs in {self.logdir}"

    def _probe_exec(self, segment: str) -> list[str]:
        return ["ip", "netns", "exec", self.ns[segment]]

    def _reflector_command(self, config_path: Path) -> list[str]:
        return ["ip", "netns", "exec", self.ns["dut"], str(self.args.binary), str(config_path)]

    def admin(self, script: str, *, capture: bool = False) -> str:
        # The harness already runs as root, so the reflector's network view is one netns exec
        # away -- no privileged sidecar needed.
        result = run_command(["ip", "netns", "exec", self.ns["dut"], "sh", "-ec", script])
        return result.stdout.strip() if capture else ""

    def _print_fabric_diagnostics(self) -> None:
        for ns in self.ns.values():
            result = run_command(["ip", "-n", ns, "addr", "show"], check=False, echo=False)
            if result.returncode == 0 and result.stdout:
                print(f"--- netns: {ns} ---", file=sys.stderr, flush=True)
                print(result.stdout, end="", file=sys.stderr, flush=True)


class NativeFreeBSDBackend(NativeBackend):
    # Segments as epair(4) pairs -- FreeBSD's veth -- between persistent vnet jails, one per
    # participant, mirroring the Linux namespaces: a dut jail holds the renamed a ends
    # (wol_src/wol_dst), each probe jail owns a b end (renamed probe0). A vnet jail is
    # FreeBSD's network namespace: its own stack, with interfaces, routes, PF_ROUTE events,
    # and /dev/bpf attachment all per-vnet, and the host filesystem shared via path=/. Per-jail
    # stacks keep every probe packet on the wire (nothing short-circuits over lo0), and jailing
    # the daemon too means its address monitor hears only test-interface events -- the same
    # shape as the Linux dut namespace.

    def __init__(self, args: argparse.Namespace, prefix: str) -> None:
        super().__init__(args, prefix)
        # Jail names: play safe with the allowed character set.
        base = prefix.replace("-", "_")
        self.jails = {"dut": f"{base}_dut", "source": f"{base}_src", "target": f"{base}_dst"}

    @staticmethod
    def require_available() -> None:
        if not sys.platform.startswith("freebsd"):
            raise RuntimeError("the FreeBSD native backend requires FreeBSD (epair + vnet jails)")
        for command in ("ifconfig", "jail", "jexec", "sysctl"):
            require_command(command)
        NativeBackend._require_native_basics()
        vimage = run_command(["sysctl", "-n", "kern.features.vimage"], check=False, echo=False)
        if vimage.returncode != 0 or vimage.stdout.strip() != "1":
            raise RuntimeError("--backend native requires a VIMAGE kernel (vnet jails); "
                               "stock GENERIC has it since FreeBSD 12")

    def _make_jail(self, jail: str, *interfaces: str) -> None:
        # persist keeps the (process-less) jail alive; each vnet.interface moves that interface
        # into its stack; path=/ shares the host filesystem, so the pkg python3 and probe.py
        # are visible inside without building a jail root. DAD off before any address, as on
        # the other backends; a fresh vnet starts with lo0 down.
        run_command([
            "jail", "-c", f"name={jail}", "persist", "vnet",
            *[f"vnet.interface={ifname}" for ifname in interfaces], "path=/",
        ])
        run_command(["jexec", jail, "sysctl", "net.inet6.ip6.dad_count=0"])
        run_command(["jexec", jail, "ifconfig", "lo0", "up"])

    def setup_segments(self) -> None:
        ends = {}
        for segment in SEGMENTS:
            a_end = run_command(["ifconfig", "epair", "create"]).stdout.strip()
            if not a_end.endswith("a"):
                raise RuntimeError(f"unexpected epair name: {a_end}")
            ends[segment] = (a_end, f"{a_end[:-1]}b")

        dut = self.jails["dut"]
        self._make_jail(dut, *(a_end for a_end, _ in ends.values()))
        for segment in SEGMENTS:
            a_end, b_end = ends[segment]
            dut_ifname = self.REFLECTOR_IFNAMES[segment]
            self._make_jail(self.jails[segment], b_end)
            jexec_dut = ["jexec", dut]
            jexec_far = ["jexec", self.jails[segment]]
            run_command([*jexec_dut, "ifconfig", a_end, "name", dut_ifname])
            run_command([*jexec_far, "ifconfig", b_end, "name", RECEIVER_IFNAME])
            v4, v6 = NATIVE_V4_SUBNET[segment], NATIVE_V6_PREFIX[segment]
            run_command([*jexec_dut, "ifconfig", dut_ifname, "inet", f"{v4}.{NATIVE_REFLECTOR_HOST}/24"])
            run_command([*jexec_dut, "ifconfig", dut_ifname, "inet6", f"{v6}::{NATIVE_REFLECTOR_HOST}/64"])
            run_command([*jexec_dut, "ifconfig", dut_ifname, "up"])
            run_command([*jexec_far, "ifconfig", RECEIVER_IFNAME, "inet", f"{v4}.{NATIVE_HELPER_HOST}/24"])
            run_command([*jexec_far, "ifconfig", RECEIVER_IFNAME, "inet6", f"{v6}::{NATIVE_HELPER_HOST}/64"])
            run_command([*jexec_far, "ifconfig", RECEIVER_IFNAME, "up"])
            # The probe's 255.255.255.255 sends are routed, not interface-pinned; single-homed
            # plus this default route pins them to the segment.
            run_command([*jexec_far, "route", "add", "default", "-interface", RECEIVER_IFNAME])

    def _teardown_fabric(self) -> None:
        # Destroy the a ends (from inside the dut jail) first: killing one end tears down the
        # whole pair, including the b end inside its probe jail -- so no jail removal can return
        # a probe0 to a stack where the other jail's probe0 already sits. The host-side destroy
        # covers a setup that failed before the interfaces moved into the dut jail.
        for ifname in self.REFLECTOR_IFNAMES.values():
            run_command(["jexec", self.jails["dut"], "ifconfig", ifname, "destroy"],
                        check=False, echo=False)
            run_command(["ifconfig", ifname, "destroy"], check=False, echo=False)
        for jail in self.jails.values():
            run_command(["jail", "-r", jail], check=False, echo=False)

    def keep_artifacts(self) -> str:
        return f"jails {', '.join(self.jails.values())} (+ their epairs) and logs in {self.logdir}"

    def _probe_exec(self, segment: str) -> list[str]:
        return ["jexec", self.jails[segment]]

    def _reflector_command(self, config_path: Path) -> list[str]:
        return ["jexec", self.jails["dut"], str(self.args.binary), str(config_path)]

    def admin(self, script: str, *, capture: bool = False) -> str:
        result = run_command(["jexec", self.jails["dut"], "sh", "-ec", script])
        return result.stdout.strip() if capture else ""

    def set_address(self, ifname: str, family: int, *, up: bool, cidr: str | None = None) -> str | None:
        # The base implementation's semantics in ifconfig verbs. v6 down deletes every address
        # (the monitor sees RTM_DELADDR and the resolver a family with no source); v6 up
        # regenerates the auto link-local by toggling ifdisabled.
        if family == 6:
            if up:
                self.admin(f"ifconfig {ifname} inet6 ifdisabled; ifconfig {ifname} inet6 -ifdisabled")
            else:
                self.admin(
                    f"for a in $(ifconfig {ifname} inet6 | awk '/inet6/{{print $2}}'); do "
                    f"ifconfig {ifname} inet6 ${{a%%\\%*}} delete; done"
                )
            return None
        if up:
            if cidr is None:
                raise RuntimeError("restoring an IPv4 address requires the CIDR captured on removal")
            self.admin(f"ifconfig {ifname} inet {cidr}")
            return cidr
        captured = self.admin(
            f"ifconfig -f inet:cidr {ifname} inet | awk '/inet /{{print $2; exit}}'", capture=True
        )
        if not captured:
            raise RuntimeError(f"no IPv4 address on {ifname} to remove")
        self.admin(f"ifconfig {ifname} inet {captured.split('/')[0]} -alias")
        return captured

    def add_decoy_route(self, dest_ip: str, ifname: str) -> bool:
        # No egress-pin primitive on FreeBSD (see Backend.add_decoy_route): the pin under test
        # there is the source-address bind, which the device-peer assertion validates on its own.
        del dest_ip, ifname
        return False

    def _print_fabric_diagnostics(self) -> None:
        result = run_command(["ifconfig", "-a"], check=False, echo=False)
        if result.returncode == 0 and result.stdout:
            print("--- host ifconfig -a ---", file=sys.stderr, flush=True)
            print(result.stdout, end="", file=sys.stderr, flush=True)
        for jail in self.jails.values():
            result = run_command(["jexec", jail, "ifconfig", "-a"], check=False, echo=False)
            if result.returncode == 0 and result.stdout:
                print(f"--- jail {jail} ifconfig -a ---", file=sys.stderr, flush=True)
                print(result.stdout, end="", file=sys.stderr, flush=True)


def native_backend_class() -> type[NativeBackend]:
    # "native" resolves to the platform's one possible fabric: a native backend is host-bound,
    # so a per-OS flag value would only add ways to ask for the impossible.
    if sys.platform == "linux":
        return NativeLinuxBackend
    if sys.platform.startswith("freebsd"):
        return NativeFreeBSDBackend
    raise RuntimeError(f"--backend native is not supported on {sys.platform} (Linux and FreeBSD are)")


def make_backend(args: argparse.Namespace, prefix: str) -> Backend:
    if args.backend == "native":
        return native_backend_class()(args, prefix)
    return DockerBackend(args, prefix)


class CaseRunner:
    def __init__(self, args: argparse.Namespace, case: TestCase) -> None:
        self.args = args
        self.case = case
        self.prefix = f"reflector-e2e-{case.name.replace('_', '-')}-{uuid.uuid4().hex[:8]}"
        self.backend = make_backend(args, self.prefix)
        self.config_path = E2E_DIR / case.config

        self._select_direction(case.direction)

    def _select_direction(self, direction: str) -> None:
        # The sender lives on the segment the traffic originates from and the receiver on the
        # other; "reverse" swaps which is which. The receiver's interface is pinned so the probe
        # can join the multicast group on it. The address-change runner re-selects per phase (its
        # phases differ in direction), so this stays a method rather than inline __init__ code.
        if direction == "reverse":
            self.sender_segment, self.sender_ifname = "target", REFLECTOR_TARGET_IFNAME
            self.receiver_segment = "source"
        else:
            self.sender_segment, self.sender_ifname = "source", REFLECTOR_SOURCE_IFNAME
            self.receiver_segment = "target"
        self.receiver_ifname = RECEIVER_IFNAME

    def __enter__(self) -> CaseRunner:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        if exc_type is not None:
            self.print_diagnostics()

        if exc_type is not None and self.args.keep_on_failure:
            self.backend.abandon()
            print(
                f"keeping resources for failed case {self.case.name}: {self.backend.keep_artifacts()}",
                flush=True,
            )
            return False

        self.backend.cleanup()
        return False

    def check_reflector_valgrind(self) -> None:
        # SIGTERM the reflector so it shuts down cleanly and valgrind runs its leak analysis, then
        # read its exit code: the image's --error-exitcode=1 fires on any leak, leaked fd, or
        # memcheck error.
        exit_code = self.backend.stop_reflector(VALGRIND_STOP_GRACE_SECONDS)
        if exit_code != 0:
            print(f"\n--- valgrind report: {self.case.name} ---", file=sys.stderr, flush=True)
            _, err = self.backend.logs("reflector")
            if err:
                print(err, end="", file=sys.stderr, flush=True)
            raise RuntimeError(
                f"valgrind reported errors in case {self.case.name} (reflector exited {exit_code})"
            )

    def start_reflector(self) -> None:
        self.backend.start_reflector(self.config_path)
        self.wait_for_reflector()

    def wait_for_log(self, role: str, marker: str, description: str) -> None:
        deadline = time.monotonic() + CONTAINER_READY_TIMEOUT_SECONDS
        last_state = "unknown"
        while time.monotonic() < deadline:
            out, err = self.backend.logs(role)
            if marker in f"{out}{err}":
                return

            running, state = self.backend.status(role)
            if state != "unknown":
                last_state = state
            if not running:
                raise RuntimeError(f"{description} exited before becoming ready: {last_state}")

            time.sleep(0.1)

        raise RuntimeError(
            f"timed out waiting for {description} readiness marker ({marker}); last state: {last_state}"
        )

    def wait_for_reflector(self) -> None:
        self.wait_for_log("reflector", REFLECTOR_READY_LOG, "reflector")

    def start_receiver(self, case: TestCase | None = None) -> None:
        case = case or self.case
        ifname = self.backend.helper_ifname(self.receiver_ifname)
        probe_args = [
            "receive",
            "--port",
            str(case.receive_port),
            "--timeout",
            str(case.timeout_seconds),
        ]
        if case.expect_payload_hex is not None:
            probe_args.extend(["--expect-payload-hex", case.expect_payload_hex])
        elif case.expect_mac is not None:
            probe_args.extend(["--expect-mac", case.expect_mac])
        else:
            probe_args.append("--expect-none")

        probe_args.extend(["--family", str(case.family)])
        if case.group is not None:
            probe_args.extend(["--join-group", case.group, "--interface", ifname])
        if case.expect_routable_source:
            probe_args.append("--expect-source-not-link-local")

        self.backend.start_probe("receiver", self.receiver_segment, ifname, probe_args)
        self.wait_for_receiver()

    def wait_for_receiver(self) -> None:
        self.wait_for_log("receiver", RECEIVER_READY_LOG, "receiver")

    def run_sender(self, case: TestCase | None = None) -> None:
        case = case or self.case
        if case.send_payload_hex is not None:
            payload_args = ["--payload-hex", case.send_payload_hex]
        elif case.send_mac is not None:
            payload_args = ["--mac", case.send_mac]
        else:
            raise RuntimeError(f"case {case.name} has no send payload")

        ifname = self.backend.helper_ifname(self.sender_ifname)
        self.backend.start_probe(
            "sender",
            self.sender_segment,
            ifname,
            [
                "send",
                *payload_args,
                "--port",
                str(case.send_port),
                "--address",
                case.send_address,
                "--interface",
                ifname,
            ],
            detach=False,
        )

    def wait_for_result(self) -> None:
        exit_code = self.backend.wait("receiver")
        out, err = self.backend.logs("receiver")
        if out:
            print(out, end="", flush=True)
        if err:
            print(err, end="", file=sys.stderr, flush=True)

        if exit_code != 0:
            raise RuntimeError(f"receiver failed with exit code {exit_code}")

    def print_reflector_logs(self) -> None:
        out, err = self.backend.logs("reflector")
        print(f"--- reflector logs: {self.case.name} ---", flush=True)
        if out:
            print(out, end="", flush=True)
        if err:
            print(err, end="", file=sys.stderr, flush=True)
        if not out and not err:
            print("<empty>", flush=True)

    def _set_address(
        self, interface: str, family: int, *, up: bool, cidr: str | None = None
    ) -> str | None:
        # Bring one (interface, family) source address down or back up; the verbs live in the
        # backend (Linux vs FreeBSD). Returns the removed v4 CIDR so the caller can restore it.
        ifname = REFLECTOR_SOURCE_IFNAME if interface == "source" else REFLECTOR_TARGET_IFNAME
        return self.backend.set_address(ifname, family, up=up, cidr=cidr)

    def print_diagnostics(self) -> None:
        print(f"\n--- diagnostics for {self.case.name} ({self.prefix}) ---", file=sys.stderr, flush=True)
        self.backend.print_diagnostics()

    def run(self) -> None:
        print(f"\n=== {self.case.name} ===", flush=True)
        self.backend.setup_segments()
        self.start_reflector()
        self.start_receiver()
        self.run_sender()
        self.wait_for_result()
        print(f"PASS {self.case.name}", flush=True)
        if self.args.show_reflector_logs:
            time.sleep(0.5)
            self.print_reflector_logs()


class RoundTripRunner(CaseRunner):
    # The SSDP M-SEARCH round trip: a searcher on the source segment sends an M-SEARCH; the
    # reflector relays it to the group on the target from a reserved port; a responder (device)
    # on the target unicasts a 200 OK back to that reserved port; the reflector proxies the reply
    # to the searcher. The negative case (expect_reply=False) starts no responder and asserts the
    # searcher hears nothing -- the reflector must not fabricate a reply.
    def __init__(self, args: argparse.Namespace, case: RoundTripCase) -> None:
        # The base __init__ only reads case.name and case.direction; a TestCase shim reuses all
        # its segment/reflector setup + cleanup with no duplication.
        shim = TestCase(name=case.name, send_port=case.port, receive_port=case.port,
            expect_mac=None, timeout_seconds=case.timeout_seconds, family=case.family,
            group=case.group, direction="forward", config=case.config)
        super().__init__(args, shim)
        self.rt = case

    def start_responder(self) -> None:
        ifname = self.backend.helper_ifname(RECEIVER_IFNAME)
        self.backend.start_probe("responder", "target", ifname, [
            "respond",
            "--port", str(self.rt.port), "--timeout", str(self.rt.timeout_seconds),
            "--family", str(self.rt.family), "--join-group", self.rt.group,
            "--interface", ifname, "--reply-hex", self.rt.reply_hex,
        ])
        self.wait_for_log("responder", "responder ready", "responder")

    def run_searcher(self) -> None:
        expectation = ["--expect-payload-hex", self.rt.reply_hex] if self.rt.expect_reply else ["--expect-none"]
        ifname = self.backend.helper_ifname(REFLECTOR_SOURCE_IFNAME)
        self.backend.start_probe("searcher", "source", ifname, [
            "search",
            "--source-port", str(SEARCHER_SOURCE_PORT), "--port", str(self.rt.port),
            "--address", self.rt.group, "--interface", ifname,
            "--family", str(self.rt.family), "--payload-hex", self.rt.probe_hex,
            "--timeout", str(self.rt.timeout_seconds), *expectation,
        ])

    def wait_for_searcher(self) -> None:
        exit_code = self.backend.wait("searcher")
        out, err = self.backend.logs("searcher")
        if out:
            print(out, end="", flush=True)
        if err:
            print(err, end="", file=sys.stderr, flush=True)
        if exit_code != 0:
            raise RuntimeError(f"searcher failed with exit code {exit_code}")

    def run(self) -> None:
        print(f"\n=== {self.rt.name} ===", flush=True)
        self.backend.setup_segments()
        self.start_reflector()
        if self.rt.expect_reply:
            self.start_responder()  # must be listening before the search goes out
        self.run_searcher()
        self.wait_for_searcher()
        # The per-searcher session must be torn down once it expires (SSDP: MX 2 + 2s grace ~= 4s;
        # WSD: a fixed 5s window): the deadline timer sweeps it, drops its port reservation, and
        # unregisters its response capture -- logged by the reflector. wait_for_log raises if it
        # never fires.
        self.wait_for_log("reflector", self.rt.evict_log, "session eviction")
        print(f"{self.rt.name}: session evicted after expiry", flush=True)
        print(f"PASS {self.rt.name}", flush=True)
        if self.args.show_reflector_logs:
            time.sleep(0.5)
            self.print_reflector_logs()


class DialRunner(CaseRunner):
    def __init__(self, args: argparse.Namespace, case: DialCase) -> None:
        shim = TestCase(name=case.name, send_port=SSDP_PORT, receive_port=SSDP_PORT,
            expect_mac=None, timeout_seconds=case.timeout_seconds, family=case.family,
            group=case.group, direction="forward")
        super().__init__(args, shim)
        self.dial = case
        # The DIAL reflector loads a config with a single DIAL entry. The shared config's any-MAC
        # [reflectors.discovery] entry also reflects SSDP, which would double-reflect the device's
        # 200 OK (only one copy rewritten) -- so the DIAL case gets its own config to keep the
        # relayed reply unambiguous.
        self.config_path = E2E_DIR / "config-dial.toml"

    def start_device(self) -> None:
        # Single-homed on the target segment: the device's HTTP endpoints are reachable only via
        # the reflector's egress-pinned upstream connect, so the peer it records is the
        # reflector's target_if address -- never the source-side client (which cannot route to the
        # target subnet directly).
        ifname = self.backend.helper_ifname(RECEIVER_IFNAME)
        probe_args = [
            "dial-device",
            "--port", str(SSDP_PORT), "--join-group", self.dial.group,
            "--interface", ifname, "--family", str(self.dial.family),
            "--timeout", str(self.dial.timeout_seconds), "--serve-seconds", str(self.dial.serve_seconds),
        ]
        if self.dial.passive:
            probe_args.append("--notify")
        if self.dial.unreachable:
            probe_args.append("--unreachable")
        self.backend.start_probe("device", "target", ifname, probe_args)
        self.wait_for_log("device", "dial-device ready", "dial-device")

    def _client_args(self, reflector_authority: str, device_authority: str) -> list[str]:
        # The client is single-homed on the source segment. It is told the reflector's source_if
        # address (what the rewritten authorities must point at) and the device's true target_if
        # address (which must never leak through a rewrite).
        ifname = self.backend.helper_ifname(REFLECTOR_SOURCE_IFNAME)
        probe_args = [
            "dial-client",
            "--port", str(SSDP_PORT), "--address", self.dial.group, "--interface", ifname,
            "--family", str(self.dial.family), "--timeout", str(self.dial.timeout_seconds),
            "--reflector-authority", reflector_authority, "--device-authority", device_authority,
        ]
        if self.dial.passive:
            probe_args.append("--passive")  # listen for the relayed NOTIFY instead of sending an M-SEARCH
        else:
            probe_args += ["--source-port", str(DIAL_CLIENT_SOURCE_PORT), "--payload-hex", SSDP_DIAL_MSEARCH_HEX]
        if self.dial.unreachable:
            probe_args.append("--expect-fetch-failure")  # the device's upstream is dead; the fetch must fail
        return probe_args

    def run_client(self) -> None:
        device_target_ip = self.backend.probe_ip("device", "target")
        refl_source_ip = self.backend.reflector_ip("source")
        ifname = self.backend.helper_ifname(REFLECTOR_SOURCE_IFNAME)
        self.backend.start_probe(
            "client", "source", ifname, self._client_args(refl_source_ip, device_target_ip)
        )

    def wait_for_client(self) -> None:
        exit_code = self.backend.wait("client")
        out, err = self.backend.logs("client")
        if out:
            print(out, end="", flush=True)
        if err:
            print(err, end="", file=sys.stderr, flush=True)
        if exit_code != 0:
            raise RuntimeError(f"dial-client failed with exit code {exit_code}")

    def assert_device_verdicts(self) -> None:
        # Two device-side checks: (1) the device exits non-zero if any request reached it with a
        # Host that was not rewritten to its own authority (the reflector must rewrite Host
        # source->device); (2) the reflector's upstream connect is egress-pinned to target_if, so
        # the only peer the device recorded must be exactly the reflector's target_if address.
        refl_target_ip = self.backend.reflector_ip("target")
        exit_code = self.backend.wait("device")
        out, err = self.backend.logs("device")
        if out:
            print(out, end="", flush=True)
        if err:
            print(err, end="", file=sys.stderr, flush=True)
        if exit_code != 0:
            raise RuntimeError(f"dial-device failed with exit code {exit_code} "
                               f"(a request reached it with an unrewritten Host)")
        marker = "dial-device upstream peers seen: "
        line = next((ln for ln in out.splitlines() if marker in ln), None)
        if line is None:
            raise RuntimeError("dial-device did not report the upstream peers it saw")
        seen = ast.literal_eval(line.split(marker, 1)[1].strip())
        if seen != [refl_target_ip]:
            raise RuntimeError(f"device saw upstream peers {seen}, expected only the reflector's target_if "
                               f"address [{refl_target_ip!r}] (egress not pinned to target_if)")
        print(f"dial: every request's Host was rewritten to the device, and every upstream connection came "
              f"from the reflector's target_if address {refl_target_ip}", flush=True)

    def _force_upstream_egress_ambiguity(self) -> None:
        # Make the upstream egress pin load-bearing. The device is single-homed on the target
        # segment, so the reflector's connect reaches it via target_if by routing alone, and
        # SO_BINDTODEVICE (TcpSocket PinEgress) would be untestable -- assert_device_verdicts'
        # "peer == reflector target_if address" passes even if the pin were dropped. Plant a
        # more-specific host route to the device via the WRONG interface (source_if): an unpinned
        # connect now follows it, ARPs the device on the source segment (where it does not live)
        # and fails, so the whole DIAL flow breaks. Only the egress pin -- which constrains the
        # route lookup to target_if -- still reaches the device, so PASS now requires it.
        # (FreeBSD declines: no pin primitive there, see Backend.add_decoy_route.)
        device_ip = self.backend.probe_ip("device", "target")
        if not self.backend.add_decoy_route(device_ip, REFLECTOR_SOURCE_IFNAME):
            print(f"{self.dial.name}: no egress-pin primitive on this backend; decoy route skipped",
                  flush=True)

    def run(self) -> None:
        print(f"\n=== {self.dial.name} ===", flush=True)
        self.backend.setup_segments()
        self.start_reflector()
        self.start_device()      # must be serving before the client searches
        if not self.dial.unreachable:
            # The unreachable case asserts a PROMPT connect failure; a decoy route would change
            # the failure mode (ARP timeout vs refused), so only arm the ambiguity where we
            # assert success.
            self._force_upstream_egress_ambiguity()
        self.run_client()
        self.wait_for_client()        # client-side verdict: rewrites (or, for unreachable, the expected fail)
        if self.dial.unreachable:
            self.backend.wait("device")  # no HTTP server in this mode: nothing to assert
            out, _ = self.backend.logs("device")
            if out:
                print(out, end="", flush=True)
        else:
            self.assert_device_verdicts()  # device-side verdict: Host rewrite + egress-pinned upstream
        print(f"PASS {self.dial.name}", flush=True)
        if self.args.show_reflector_logs:
            time.sleep(0.5)
            self.print_reflector_logs()


class DialAddressChangeRunner(DialRunner):
    # A DIAL pass, then the same pass after the reflector's source IPv4 changes, then after its
    # target IPv4 changes -- each to a different same-subnet address. The device stays up (passive
    # NOTIFY + HTTP) across all three; a fresh client runs each pass. _set_address (base) does the
    # change in the reflector's network view; the reflector reacts on its own event loop, so each
    # change waits for the "gained IPv4 <new>" log before the next pass.
    def _different_cidr(self, cidr: str) -> str:
        # A different host on the same subnet: both backends hand out low addresses (Docker IPAM
        # .2, .3, ...; the native plan .1/.2), so .222 is free (and .221 if the interface somehow
        # already holds .222).
        host, prefix = cidr.split("/")
        octets = host.split(".")
        octets[-1] = "222" if octets[-1] != "222" else "221"
        return f"{'.'.join(octets)}/{prefix}"

    def _change_v4(self, interface: str) -> str:
        # Replace the reflector's IPv4 on `interface` with a different same-subnet address, then
        # wait for the reflector to observe it -- which is when 7d evicts the now-stale proxy.
        # Returns the new host.
        old_cidr = self._set_address(interface, 4, up=False)        # del old, capture its CIDR
        new_cidr = self._different_cidr(old_cidr)
        self._set_address(interface, 4, up=True, cidr=new_cidr)     # add the different one
        new_host = new_cidr.split("/")[0]
        print(f"{self.dial.name}: {interface} IPv4 {old_cidr} -> {new_cidr}", flush=True)
        self.wait_for_log("reflector", f"gained IPv4 {new_host}", f"{interface} IPv4 change")
        return new_host

    def _dial_pass(self, label: str, reflector_authority: str, device_authority: str) -> None:
        # One full DIAL flow through the reflector from a fresh client, asserting every rewrite
        # points at `reflector_authority` (the reflector's CURRENT source IPv4) and never leaks
        # `device_authority`.
        role = f"client-{label.replace(' ', '-')}"
        ifname = self.backend.helper_ifname(REFLECTOR_SOURCE_IFNAME)
        self.backend.start_probe(
            role, "source", ifname, self._client_args(reflector_authority, device_authority)
        )
        exit_code = self.backend.wait(role)
        out, err = self.backend.logs(role)
        if out:
            print(out, end="", flush=True)
        if err:
            print(err, end="", file=sys.stderr, flush=True)
        if exit_code != 0:
            raise RuntimeError(f"{self.dial.name}: DIAL pass '{label}' failed with exit code {exit_code}")
        print(f"{self.dial.name}: DIAL pass '{label}' succeeded (rewrites -> {reflector_authority})", flush=True)

    def run(self) -> None:
        print(f"\n=== {self.dial.name} ===", flush=True)
        self.backend.setup_segments()
        self.start_reflector()
        self.start_device()  # passive: advertises NOTIFY + serves HTTP for serve_seconds
        device_ip = self.backend.probe_ip("device", "target")
        source_ip = self.backend.reflector_ip("source")

        # Baseline, then re-run after each interface's IPv4 moves to a different address. A
        # passing re-run requires 7d to have evicted the proxy bound to the vanished address.
        self._dial_pass("baseline", source_ip, device_ip)
        source_ip = self._change_v4("source")
        self._dial_pass("after source IPv4 change", source_ip, device_ip)
        self._change_v4("target")  # the source authority is unchanged by a target move
        self._dial_pass("after target IPv4 change", source_ip, device_ip)

        print(f"PASS {self.dial.name}", flush=True)
        if self.args.show_reflector_logs:
            time.sleep(0.5)
            self.print_reflector_logs()


class AddressChangeRunner(CaseRunner):
    # Proves the dynamic family bring-up/teardown end to end: with a dual-family reflector
    # running, knock out one (interface, family) source address at a time and verify -- with real
    # traffic, not logs -- that reflection of exactly that family stops, then resumes once the
    # address returns. The reflector reacts on its own event loop after the netlink notification,
    # so every check polls across that async window. All phases probe forward (source -> target).
    def __init__(self, args: argparse.Namespace, case: AddressChangeCase) -> None:
        shim = TestCase(
            name=case.name,
            send_port=MDNS_PORT,
            receive_port=MDNS_PORT,
            expect_mac=None,
            timeout_seconds=ADDR_CHANGE_REFLECTED_WINDOW,
            direction="forward",
        )
        super().__init__(args, shim)
        self.ac = case
        self.config_path = E2E_DIR / case.config

    def _phase_case(self, phase: Phase, *, expect: bool, timeout: float) -> TestCase:
        spec = PROBE_SPECS[phase.protocol]
        is_wol = phase.protocol == "wol"
        # A direction stops when its re-emit (egress) interface loses the family -- the reliable,
        # guaranteed mechanism (the per-packet egress send-gate). The target is the egress for
        # forward queries (source->target); the source is the egress for reverse responses
        # (target->source). So probe the direction whose egress is the knocked-out interface.
        # (The ingress-membership path can't be exercised here: our raw capture taps below the IP
        # membership filter and both fabrics flood multicast, so losing the ingress membership
        # never blinds it.)
        reverse = not is_wol and phase.interface == "source"
        direction = "reverse" if reverse else "forward"
        group = None if is_wol else (spec["group_v6"] if phase.family == 6 else spec["group_v4"])
        # mDNS queries flow forward, responses reverse: send the kind the probed direction relays.
        payload = None if is_wol else (MDNS_RESPONSE_HEX if reverse else spec["payload"])
        return TestCase(
            name=self.ac.name,
            send_port=spec["port"],
            receive_port=spec["port"],
            expect_mac=(CONFIGURED_MAC if (expect and is_wol) else None),
            timeout_seconds=timeout,
            send_mac=(CONFIGURED_MAC if is_wol else None),
            send_payload_hex=payload,
            family=phase.family,
            direction=direction,
            group=group,
            expect_payload_hex=(payload if (expect and not is_wol) else None),
        )

    def _probe(self, phase: Phase, *, expect: bool, timeout: float) -> bool:
        # One round trip: (re)start a fresh receiver and sender for the phase's family/group,
        # then report whether the receiver saw the expected packet within `timeout`.
        self.backend.remove("receiver")
        self.backend.remove("sender")
        case = self._phase_case(phase, expect=expect, timeout=timeout)
        self._select_direction(case.direction)
        self.start_receiver(case)
        self.run_sender(case)
        return self.backend.wait("receiver") == 0

    def _poll_reflected(self, phase: Phase) -> bool:
        deadline = time.monotonic() + ADDR_CHANGE_POLL_DEADLINE
        while time.monotonic() < deadline:
            if self._probe(phase, expect=True, timeout=ADDR_CHANGE_REFLECTED_WINDOW):
                return True
        return False

    def _poll_not_reflected(self, phase: Phase) -> bool:
        # Require consecutive silent windows: while reflection is still up the probe returns
        # quickly (the reflected packet arrives, failing --expect-none), resetting the streak;
        # only a genuine teardown yields an unbroken run of silences before the deadline.
        deadline = time.monotonic() + ADDR_CHANGE_POLL_DEADLINE
        consecutive = 0
        while time.monotonic() < deadline:
            if self._probe(phase, expect=False, timeout=ADDR_CHANGE_SILENCE_WINDOW):
                consecutive += 1
                if consecutive >= ADDR_CHANGE_SILENCE_CONSECUTIVE:
                    return True
            else:
                consecutive = 0
        return False

    def _run_phase(self, phase: Phase) -> None:
        desc = f"{self.ac.name} / {phase.label}"
        print(f"--- phase: {desc} ({phase.protocol} IPv{phase.family}) ---", flush=True)

        if not self._poll_reflected(phase):
            raise RuntimeError(f"{desc}: no baseline reflection before the change")
        print(f"{desc}: baseline reflected", flush=True)

        cidr = self._set_address(phase.interface, phase.family, up=False)
        if not self._poll_not_reflected(phase):
            raise RuntimeError(
                f"{desc}: reflection continued after the {phase.interface} IPv{phase.family} "
                f"address was removed"
            )
        print(f"{desc}: reflection stopped after address removal", flush=True)

        self._set_address(phase.interface, phase.family, up=True, cidr=cidr)
        if not self._poll_reflected(phase):
            raise RuntimeError(
                f"{desc}: reflection did not resume after the {phase.interface} IPv{phase.family} "
                f"address was restored"
            )
        print(f"{desc}: reflection resumed after address restore", flush=True)

    def _assert_address_changes_logged(self) -> None:
        # Full-parity log check (the Rust equivalent of the C++'s capability-down assertion):
        # every phase removed then restored a source address, so the reflector's AddressMonitor
        # must have logged both transitions -- with the monitor off it logs neither. And no
        # reflect-failure WARN may appear: a send attempted on an addressless egress would mean
        # the per-packet gate failed to catch the drop.
        out, err = self.backend.logs("reflector")
        text = f"{out}\n{err}"
        for phase in self.ac.phases:
            ifname = REFLECTOR_SOURCE_IFNAME if phase.interface == "source" else REFLECTOR_TARGET_IFNAME
            family = f"IPv{phase.family}"
            for verb in ("lost", "gained"):
                needle = f"interface {ifname}: {verb} {family}"
                if needle not in text:
                    raise RuntimeError(
                        f"{self.ac.name}: reflector never logged \"{needle}\" -- the address monitor "
                        f"did not observe the change"
                    )
        if "cannot reflect" in text:
            raise RuntimeError(
                f"{self.ac.name}: reflector logged a reflect failure -- a send was attempted on an "
                f"addressless egress (the gate did not catch the drop)"
            )

    def run(self) -> None:
        print(f"\n=== {self.ac.name} ===", flush=True)
        self.backend.setup_segments()
        self.start_reflector()
        for phase in self.ac.phases:
            self._run_phase(phase)
        self._assert_address_changes_logged()
        print(f"PASS {self.ac.name}", flush=True)
        if self.args.show_reflector_logs:
            time.sleep(0.5)
            self.print_reflector_logs()


def make_runner(args: argparse.Namespace,
        case: TestCase | RoundTripCase | DialCase | DialAddressChangeCase | AddressChangeCase) -> CaseRunner:
    if isinstance(case, RoundTripCase):
        return RoundTripRunner(args, case)
    if isinstance(case, DialAddressChangeCase):
        return DialAddressChangeRunner(args, case)
    if isinstance(case, DialCase):
        return DialRunner(args, case)
    if isinstance(case, AddressChangeCase):
        return AddressChangeRunner(args, case)
    return CaseRunner(args, case)


def build_reflector_image(image: str, target: str | None = None) -> None:
    target_args = ["--target", target] if target is not None else []
    docker(["build", *target_args, "-t", image, "."], capture=False)


def select_cases(case_names: list[str]) -> list[TestCase | RoundTripCase | DialCase | DialAddressChangeCase | AddressChangeCase]:
    if not case_names:
        return ALL_CASES

    cases_by_name = {case.name: case for case in ALL_CASES}
    unknown = sorted(set(case_names) - set(cases_by_name))
    if unknown:
        available = ", ".join(sorted(cases_by_name))
        raise RuntimeError(f"unknown e2e case(s): {', '.join(unknown)}. Available cases: {available}")

    return [cases_by_name[name] for name in case_names]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run reflector e2e tests (Docker or native backend)")
    parser.add_argument("--backend", choices=["docker", "native"], default="docker",
        help="execution environment: Docker bridge networks + containers, or (Linux, root) "
             "netns + veth pairs + plain processes (default: docker)")
    parser.add_argument("--image", default=DEFAULT_REFLECTOR_IMAGE,
        help="reflector image tag to run (default: reflector:e2e; docker backend only)")
    parser.add_argument("--skip-build", action="store_true",
        help="use --image without building it first (docker backend only)")
    parser.add_argument("--valgrind", action="store_true",
        help="run the reflector under Valgrind memcheck (the runtime-valgrind image; fails on any leak, fd leak, or memcheck error)")
    parser.add_argument("--helper-image", default=DEFAULT_HELPER_IMAGE,
        help="Python image used for UDP probes (docker backend only)")
    parser.add_argument("--binary", type=Path, default=None,
        help="reflector binary to run (native backend, required); build it unprivileged first, "
             "e.g. cargo build --release --locked")
    parser.add_argument("--keep-on-failure", action="store_true", help="leave resources behind after a failure")
    parser.add_argument("--show-reflector-logs", action="store_true", help="print reflector logs after each passing case")
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        choices=[case.name for case in ALL_CASES],
        help="e2e case to run; may be passed more than once",
    )
    args = parser.parse_args()

    if args.backend == "native" and args.valgrind:
        parser.error("--valgrind is not supported with --backend native yet")
    if args.backend == "native" and args.binary is None:
        # No implicit `cargo build` here: the native harness runs as root, so a build would leave
        # root-owned target/ artifacts -- or die outright, since sudo's PATH lacks a rustup cargo.
        parser.error("--backend native requires --binary; build unprivileged first "
                     "(cargo build --release --locked)")
    if args.backend == "docker" and args.binary is not None:
        parser.error("--binary only applies to --backend native")
    return args


def main() -> int:
    args = parse_args()
    if args.backend == "native":
        native_backend_class().require_available()
    else:
        DockerBackend.require_available()
        # --valgrind selects the valgrind image unless one was passed explicitly.
        if args.valgrind and args.image == DEFAULT_REFLECTOR_IMAGE:
            args.image = VALGRIND_REFLECTOR_IMAGE

    cases = select_cases(args.case)
    print(f"expected magic payload: {magic_packet_hex(CONFIGURED_MAC)}", flush=True)

    if args.backend == "native":
        # Resolve now, against the invoker's cwd: the spawns run with cwd=REPO_ROOT, so a relative
        # path that validated here would otherwise point somewhere else at exec time.
        args.binary = args.binary.resolve()
        if not args.binary.is_file():
            raise RuntimeError(f"reflector binary not found: {args.binary}")
    elif not args.skip_build:
        build_reflector_image(args.image, "runtime-valgrind" if args.valgrind else None)

    for case in cases:
        with make_runner(args, case) as runner:
            runner.run()
            if args.valgrind:
                runner.check_reflector_valgrind()

    suffix = " under valgrind" if args.valgrind else ""
    print(f"\nPASS {len(cases)} e2e case(s){suffix}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CommandError as exc:
        print(str(exc), file=sys.stderr)
        if exc.result.stdout:
            print(exc.result.stdout, end="", file=sys.stderr)
        if exc.result.stderr:
            print(exc.result.stderr, end="", file=sys.stderr)
        raise SystemExit(1)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
