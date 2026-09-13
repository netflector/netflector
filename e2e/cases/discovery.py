from __future__ import annotations

from cases.models import AnswerCase, RoundTripCase, SearchRecreateCase
from cases.udp import PEERS_CONFIGS
from fixtures import (
    MDNS_GROUP_V4,
    MDNS_PORT,
    MDNS_QUERY_HEX,
    MDNS_RESPONSE_HEX,
    SSDP_GROUP_V4,
    SSDP_GROUP_V6,
    SSDP_GROUP_V6_SITE,
    WSD_GROUP_V4,
    WSD_PORT,
    WSD_PROBE_HEX,
    WSD_PROBEMATCHES_HEX,
    WSD_RESOLVE_HEX,
    WSD_RESOLVEMATCHES_HEX,
)

ROUNDTRIP_CASES = [
    RoundTripCase(name="ssdp_msearch_roundtrip", family=4, group=SSDP_GROUP_V4),
    RoundTripCase(name="ssdp_msearch_roundtrip_ipv6", family=6, group=SSDP_GROUP_V6),
    # Site-local (ff05::c) round trip: the M-SEARCH is relayed from the routable source, so the device
    # replies there -- the searcher only hears the 200 OK if the reserved port and response capture were
    # placed on that same routable address, not the link-local one. Guards the scope-matched `our_addr`.
    RoundTripCase(
        name="ssdp_msearch_roundtrip_ipv6_site_local",
        family=6,
        group=SSDP_GROUP_V6_SITE,
    ),
    RoundTripCase(
        name="ssdp_msearch_no_responder_no_reply",
        family=4,
        group=SSDP_GROUP_V4,
        timeout_seconds=2.0,
        expect_reply=False,
    ),
    # WSD Probe -> ProbeMatches: the same per-searcher session machinery on port 3702, replies relayed
    # verbatim (no DIAL). Eviction fires after the fixed 5s WSD window.
    RoundTripCase(
        name="wsd_probe_roundtrip",
        family=4,
        group=WSD_GROUP_V4,
        port=WSD_PORT,
        probe_hex=WSD_PROBE_HEX,
        reply_hex=WSD_PROBEMATCHES_HEX,
        config="config-wsd.toml",
        evict_log="evicted WSD session",
    ),
    # Searches from the target segment with the device on the source: the sessions a bidirectional
    # entry's second leg opens, reserving its port on the source side.
    RoundTripCase(
        name="bidirectional_ssdp_msearch_roundtrip_from_target",
        family=4,
        group=SSDP_GROUP_V4,
        config="config-bidirectional.toml",
        direction="reverse",
    ),
    RoundTripCase(
        name="bidirectional_wsd_probe_roundtrip_from_target",
        family=4,
        group=WSD_GROUP_V4,
        port=WSD_PORT,
        probe_hex=WSD_PROBE_HEX,
        reply_hex=WSD_PROBEMATCHES_HEX,
        config="config-bidirectional.toml",
        evict_log="evicted WSD session",
        direction="reverse",
    ),
    # Resolve -> ResolveMatches: the same search-session path as Probe (both classify as a search).
    RoundTripCase(
        name="wsd_resolve_roundtrip",
        family=4,
        group=WSD_GROUP_V4,
        port=WSD_PORT,
        probe_hex=WSD_RESOLVE_HEX,
        reply_hex=WSD_RESOLVEMATCHES_HEX,
        config="config-wsd.toml",
        evict_log="evicted WSD session",
    ),
    # Searches with peers: on a target with peers the copy reaches the responder at its own
    # address and its reply finds the session; on one without, the search still goes to the
    # group. The IPv6 case sends to the link-local group while the peer is a routable address,
    # so the session must listen on netflector's routable address, not its link-local one.
    *(
        RoundTripCase(
            name=f"ssdp_msearch_roundtrip_to_target_{'peers' if 'target' in sides else 'group'}_with_{label}_peers",
            family=4,
            group=SSDP_GROUP_V4,
            config=config,
            responder_unicast="target" in sides,
        )
        for label, (config, sides) in PEERS_CONFIGS.items()
    ),
    *(
        RoundTripCase(
            name=f"wsd_probe_roundtrip_to_target_{'peers' if 'target' in sides else 'group'}_with_{label}_peers",
            family=4,
            group=WSD_GROUP_V4,
            port=WSD_PORT,
            probe_hex=WSD_PROBE_HEX,
            reply_hex=WSD_PROBEMATCHES_HEX,
            config=config,
            evict_log="evicted WSD session",
            responder_unicast="target" in sides,
        )
        for label, (config, sides) in PEERS_CONFIGS.items()
    ),
    RoundTripCase(
        name="ssdp_msearch_roundtrip_to_target_peers_ipv6_with_target_peers",
        family=6,
        group=SSDP_GROUP_V6,
        config="config-peers-target.toml",
        responder_unicast=True,
    ),
]


ANSWER_CASES = [
    AnswerCase(
        name="mdns_answer_from_target_peer_reaches_source_group_with_target_peers",
        group=MDNS_GROUP_V4,
        port=MDNS_PORT,
        query_hex=MDNS_QUERY_HEX,
        answer_hex=MDNS_RESPONSE_HEX,
    ),
]


SEARCH_RECREATE_CASES = [
    SearchRecreateCase(
        name="ssdp_search_interface_recreate_source", interface="source"
    ),
    SearchRecreateCase(
        name="ssdp_search_interface_recreate_target", interface="target"
    ),
    SearchRecreateCase(
        name="ssdp_search_interface_recreate_source_decoy",
        interface="source",
        decoy=True,
    ),
    SearchRecreateCase(
        name="ssdp_search_interface_recreate_target_decoy",
        interface="target",
        decoy=True,
    ),
]
