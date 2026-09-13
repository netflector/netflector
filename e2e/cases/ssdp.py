from __future__ import annotations

from cases.models import TestCase
from fixtures import (
    SSDP_GROUP_V4,
    SSDP_GROUP_V6,
    SSDP_GROUP_V6_SITE,
    SSDP_HTTP_RESPONSE_HEX,
    SSDP_MSEARCH_HEX,
    SSDP_NOTIFY_HEX,
    SSDP_NOTIFY_LINK_LOCAL_LOCATION_HEX,
    SSDP_NOTIFY_ROUTABLE_LOCATION_HEX,
    SSDP_PORT,
    SSDP_WRONG_PORT,
)

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
    # A NOTIFY from the source segment, which the one-way entry drops.
    TestCase(
        name="bidirectional_reflects_ssdp_notify_from_source",
        send_port=SSDP_PORT,
        receive_port=SSDP_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=SSDP_NOTIFY_HEX,
        expect_payload_hex=SSDP_NOTIFY_HEX,
        group=SSDP_GROUP_V4,
        direction="forward",
        config="config-bidirectional.toml",
    ),
    # A routable LOCATION literal reflects; a link-local one is suppressed rather than relayed.
    TestCase(
        name="reflects_ssdp_notify_with_routable_location",
        send_port=SSDP_PORT,
        receive_port=SSDP_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=SSDP_NOTIFY_ROUTABLE_LOCATION_HEX,
        expect_payload_hex=SSDP_NOTIFY_ROUTABLE_LOCATION_HEX,
        group=SSDP_GROUP_V4,
        direction="reverse",
    ),
    TestCase(
        name="ignores_ssdp_link_local_location_notify",
        send_port=SSDP_PORT,
        receive_port=SSDP_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=SSDP_NOTIFY_LINK_LOCAL_LOCATION_HEX,
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
    # The dispatcher filter pins dst_port=1900. Listen on the SEND port, not 1900: netflector
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
