from __future__ import annotations

from cases.models import TestCase
from fixtures import (
    ANY_MAC_PORT,
    CONFIGURED_MAC,
    CONFIGURED_PORT,
    MALFORMED_MAGIC_PAYLOAD_HEX,
    SECOND_CONFIGURED_MAC,
    UNCONFIGURED_PORT,
    WRONG_MAC,
)

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
    # A wake to the source segment's directed broadcast re-emits to the target's own, not the
    # limited broadcast; one to the limited broadcast stays limited.
    TestCase(
        name="reflects_magic_packet_to_directed_broadcast",
        send_port=ANY_MAC_PORT,
        receive_port=ANY_MAC_PORT,
        expect_mac=WRONG_MAC,
        timeout_seconds=5.0,
        send_mac=WRONG_MAC,
        send_to="192.0.2.255",
        expect_netflector_log=f"to 198.51.100.255:{ANY_MAC_PORT}",
    ),
    TestCase(
        name="reflects_magic_packet_to_limited_broadcast_as_sent",
        send_port=ANY_MAC_PORT,
        receive_port=ANY_MAC_PORT,
        expect_mac=WRONG_MAC,
        timeout_seconds=5.0,
        send_mac=WRONG_MAC,
        expect_netflector_log=f"to 255.255.255.255:{ANY_MAC_PORT}",
    ),
    # The same wake sent target->source, which the one-way entry would drop.
    TestCase(
        name="bidirectional_reflects_magic_packet_from_target",
        send_port=ANY_MAC_PORT,
        receive_port=ANY_MAC_PORT,
        expect_mac=WRONG_MAC,
        timeout_seconds=5.0,
        send_mac=WRONG_MAC,
        direction="reverse",
        config="config-bidirectional.toml",
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
