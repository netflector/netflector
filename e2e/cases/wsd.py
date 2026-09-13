from __future__ import annotations

from cases.models import TestCase
from fixtures import (
    SSDP_MSEARCH_HEX,
    WSD_BYE_HEX,
    WSD_GROUP_V4,
    WSD_GROUP_V6,
    WSD_HELLO_HEX,
    WSD_HELLO_LINK_LOCAL_XADDRS_HEX,
    WSD_HELLO_MIXED_XADDRS_HEX,
    WSD_PORT,
    WSD_PROBE_HEX,
)

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
    # Announcements from the source segment, which the one-way entry drops.
    TestCase(
        name="bidirectional_reflects_wsd_hello_from_source",
        config="config-bidirectional.toml",
        send_port=WSD_PORT,
        receive_port=WSD_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=WSD_HELLO_HEX,
        expect_payload_hex=WSD_HELLO_HEX,
        group=WSD_GROUP_V4,
        direction="forward",
    ),
    TestCase(
        name="bidirectional_reflects_wsd_bye_from_source",
        config="config-bidirectional.toml",
        send_port=WSD_PORT,
        receive_port=WSD_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=WSD_BYE_HEX,
        expect_payload_hex=WSD_BYE_HEX,
        group=WSD_GROUP_V4,
        direction="forward",
    ),
    # A routable XAddrs URI beside the link-local one rescues the Hello from suppression.
    TestCase(
        name="reflects_wsd_hello_with_mixed_xaddrs",
        config="config-wsd.toml",
        send_port=WSD_PORT,
        receive_port=WSD_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=WSD_HELLO_MIXED_XADDRS_HEX,
        expect_payload_hex=WSD_HELLO_MIXED_XADDRS_HEX,
        group=WSD_GROUP_V4,
        direction="reverse",
    ),
    # Every XAddrs URI is link-local, so the Hello is suppressed rather than relayed.
    TestCase(
        name="ignores_wsd_link_local_only_xaddrs",
        config="config-wsd.toml",
        send_port=WSD_PORT,
        receive_port=WSD_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=WSD_HELLO_LINK_LOCAL_XADDRS_HEX,
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
