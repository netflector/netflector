from __future__ import annotations

from cases.models import TestCase
from fixtures import (
    ANY_MAC_PORT,
    MDNS_GROUP_V4,
    MDNS_GROUP_V6,
    MDNS_PORT,
    MDNS_QUERY_HEX,
    MDNS_RESPONSE_HEX,
    RELAY_GROUP_V4,
    RELAY_GROUP_V6,
    RELAY_ONE_WAY_PORT,
    RELAY_PORT,
    RELAY_UNLISTED_GROUP_V4,
    RELAY_UNLISTED_PORT,
    SOOD_QUERY_HEX,
    SSDP_GROUP_V4,
    SSDP_MSEARCH_HEX,
    SSDP_NOTIFY_HEX,
    SSDP_PORT,
    WRONG_MAC,
    WSD_GROUP_V4,
    WSD_HELLO_HEX,
    WSD_PORT,
    WSD_PROBE_HEX,
)

# The UDP relay carries a datagram on a listed port to a listed group or a broadcast across as
# sent: payload, source ip:port and all. config-relay.toml relays port 9003 both ways and port
# 9004 source->target only.
RELAY_CASES = [
    TestCase(
        name="relays_udp_to_group",
        send_port=RELAY_PORT,
        receive_port=RELAY_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=SOOD_QUERY_HEX,
        expect_payload_hex=SOOD_QUERY_HEX,
        group=RELAY_GROUP_V4,
        config="config-relay.toml",
        expect_source_preserved=True,
        expect_netflector_log=f"to {RELAY_GROUP_V4}:{RELAY_PORT}",
    ),
    TestCase(
        name="relays_udp_to_group_ipv6",
        send_port=RELAY_PORT,
        receive_port=RELAY_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=SOOD_QUERY_HEX,
        expect_payload_hex=SOOD_QUERY_HEX,
        family=6,
        group=RELAY_GROUP_V6,
        config="config-relay.toml",
        expect_netflector_log=f"to [{RELAY_GROUP_V6}]:{RELAY_PORT}",
    ),
    # The broadcast cases check the destination only: the docker host masquerades a bridged
    # broadcast (bridge-nf-call-iptables), so the receiver sees its gateway as the source there.
    TestCase(
        name="relays_udp_to_directed_broadcast",
        send_port=RELAY_PORT,
        receive_port=RELAY_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=SOOD_QUERY_HEX,
        expect_payload_hex=SOOD_QUERY_HEX,
        config="config-relay.toml",
        send_to="192.0.2.255",
        expect_netflector_log=f"to 198.51.100.255:{RELAY_PORT}",
    ),
    TestCase(
        name="relays_udp_to_limited_broadcast_as_sent",
        send_port=RELAY_PORT,
        receive_port=RELAY_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=SOOD_QUERY_HEX,
        expect_payload_hex=SOOD_QUERY_HEX,
        config="config-relay.toml",
        expect_netflector_log=f"to 255.255.255.255:{RELAY_PORT}",
    ),
    TestCase(
        name="relays_udp_from_target",
        send_port=RELAY_PORT,
        receive_port=RELAY_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=SOOD_QUERY_HEX,
        expect_payload_hex=SOOD_QUERY_HEX,
        group=RELAY_GROUP_V4,
        direction="reverse",
        config="config-relay.toml",
        expect_source_preserved=True,
    ),
    TestCase(
        name="relays_udp_one_way",
        send_port=RELAY_ONE_WAY_PORT,
        receive_port=RELAY_ONE_WAY_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=SOOD_QUERY_HEX,
        expect_payload_hex=SOOD_QUERY_HEX,
        group=RELAY_GROUP_V4,
        config="config-relay.toml",
    ),
    TestCase(
        name="ignores_udp_one_way_from_target",
        send_port=RELAY_ONE_WAY_PORT,
        receive_port=RELAY_ONE_WAY_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=SOOD_QUERY_HEX,
        group=RELAY_GROUP_V4,
        direction="reverse",
        config="config-relay.toml",
    ),
    TestCase(
        name="ignores_udp_on_unlisted_port",
        send_port=RELAY_UNLISTED_PORT,
        receive_port=RELAY_UNLISTED_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=SOOD_QUERY_HEX,
        group=RELAY_GROUP_V4,
        config="config-relay.toml",
    ),
    TestCase(
        name="ignores_udp_to_unlisted_group",
        send_port=RELAY_PORT,
        receive_port=RELAY_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=SOOD_QUERY_HEX,
        group=RELAY_UNLISTED_GROUP_V4,
        config="config-relay.toml",
    ),
]


# The probe on a segment named as that segment's peer, on the target only, the source only, or
# both (config-peers-*.toml). On a side with peers the re-emit that would go to the group or
# broadcast arrives as a unicast copy, which only a socket bound to the probe's own address can
# prove; on a side without, it still goes to the group or broadcast. Every protocol, both legs,
# every config: the forward leg sends on the target, the reverse one (a response, an
# announcement, or a bidirectional entry's second leg) on the source.
PEERS_CONFIGS = {
    "target": ("config-peers-target.toml", {"target"}),
    "source": ("config-peers-source.toml", {"source"}),
    "both": ("config-peers-both.toml", {"source", "target"}),
}

# (protocol, forward leg, reverse leg): a leg is (message name, its TestCase fields).
PEERS_LEGS = [
    (
        "wol",
        (
            "wake",
            dict(
                send_port=ANY_MAC_PORT,
                receive_port=ANY_MAC_PORT,
                expect_mac=WRONG_MAC,
                send_mac=WRONG_MAC,
            ),
        ),
        (
            "wake",
            dict(
                send_port=ANY_MAC_PORT,
                receive_port=ANY_MAC_PORT,
                expect_mac=WRONG_MAC,
                send_mac=WRONG_MAC,
            ),
        ),
    ),
    (
        "mdns",
        (
            "query",
            dict(
                send_port=MDNS_PORT,
                receive_port=MDNS_PORT,
                expect_mac=None,
                group=MDNS_GROUP_V4,
                send_payload_hex=MDNS_QUERY_HEX,
                expect_payload_hex=MDNS_QUERY_HEX,
            ),
        ),
        (
            "response",
            dict(
                send_port=MDNS_PORT,
                receive_port=MDNS_PORT,
                expect_mac=None,
                group=MDNS_GROUP_V4,
                send_payload_hex=MDNS_RESPONSE_HEX,
                expect_payload_hex=MDNS_RESPONSE_HEX,
                send_source_port=MDNS_PORT,
            ),
        ),
    ),
    (
        "ssdp",
        (
            "msearch",
            dict(
                send_port=SSDP_PORT,
                receive_port=SSDP_PORT,
                expect_mac=None,
                group=SSDP_GROUP_V4,
                send_payload_hex=SSDP_MSEARCH_HEX,
                expect_payload_hex=SSDP_MSEARCH_HEX,
            ),
        ),
        (
            "notify",
            dict(
                send_port=SSDP_PORT,
                receive_port=SSDP_PORT,
                expect_mac=None,
                group=SSDP_GROUP_V4,
                send_payload_hex=SSDP_NOTIFY_HEX,
                expect_payload_hex=SSDP_NOTIFY_HEX,
            ),
        ),
    ),
    (
        "wsd",
        (
            "probe",
            dict(
                send_port=WSD_PORT,
                receive_port=WSD_PORT,
                expect_mac=None,
                group=WSD_GROUP_V4,
                send_payload_hex=WSD_PROBE_HEX,
                expect_payload_hex=WSD_PROBE_HEX,
            ),
        ),
        (
            "hello",
            dict(
                send_port=WSD_PORT,
                receive_port=WSD_PORT,
                expect_mac=None,
                group=WSD_GROUP_V4,
                send_payload_hex=WSD_HELLO_HEX,
                expect_payload_hex=WSD_HELLO_HEX,
            ),
        ),
    ),
    # The relay's unicast copies keep the sender's source; the receiver does not check it, since
    # the copy travels in a broadcast frame and the docker host masquerades it like a broadcast
    # (see the relay broadcast cases). The native fabrics deliver it as sent.
    (
        "relay",
        (
            "datagram",
            dict(
                send_port=RELAY_PORT,
                receive_port=RELAY_PORT,
                expect_mac=None,
                group=RELAY_GROUP_V4,
                send_payload_hex=SOOD_QUERY_HEX,
                expect_payload_hex=SOOD_QUERY_HEX,
            ),
        ),
        (
            "datagram",
            dict(
                send_port=RELAY_PORT,
                receive_port=RELAY_PORT,
                expect_mac=None,
                group=RELAY_GROUP_V4,
                send_payload_hex=SOOD_QUERY_HEX,
                expect_payload_hex=SOOD_QUERY_HEX,
            ),
        ),
    ),
]


def _peers_cases() -> list[TestCase]:
    cases = []
    for label, (config, sides) in PEERS_CONFIGS.items():
        for protocol, forward, reverse in PEERS_LEGS:
            # An mDNS entry may not list source peers (its answers go there), so the configs with
            # source peers leave mDNS out.
            if protocol == "mdns" and "source" in sides:
                continue
            for direction, (message, fields), side in (("forward", forward, "target"), ("reverse", reverse, "source")):
                unicast = side in sides
                reach = "peers" if unicast else ("broadcast" if protocol == "wol" else "group")
                cases.append(TestCase(
                    name=f"{protocol}_{message}_to_{side}_{reach}_with_{label}_peers",
                    timeout_seconds=5.0, config=config, direction=direction, expect_unicast=unicast,
                    **fields,
                ))
    return cases


PEERS_CASES = [
    *_peers_cases(),
    # A copy to a routable IPv6 peer, for a query sent to the link-local group.
    TestCase(
        name="mdns_query_to_target_peers_ipv6_with_target_peers",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=MDNS_QUERY_HEX,
        expect_payload_hex=MDNS_QUERY_HEX,
        group=MDNS_GROUP_V6,
        family=6,
        config="config-peers-target.toml",
        expect_unicast=True,
    ),
]
