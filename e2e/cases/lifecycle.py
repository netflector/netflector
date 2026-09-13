from __future__ import annotations

from cases.models import AddressChangeCase, Phase, RecreateCase
from fixtures import (
    CONFIGURED_PORT,
    MDNS_GROUP_V4,
    MDNS_GROUP_V6,
    MDNS_PORT,
    MDNS_QUERY_HEX,
)

# Per-protocol probe parameters for the address-change phases: wol sends a magic packet (no payload
# or group); mdns sends a query to its family's group, relayed verbatim.
PROBE_SPECS = {
    "wol": {
        "port": CONFIGURED_PORT,
        "payload": None,
        "group_v4": None,
        "group_v6": None,
    },
    "mdns": {
        "port": MDNS_PORT,
        "payload": MDNS_QUERY_HEX,
        "group_v4": MDNS_GROUP_V4,
        "group_v6": MDNS_GROUP_V6,
    },
}


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


# One case per (interface, decoy) so a failure names the exact scenario. All probe forward
# (source -> target): recreating the source kills the forward INGRESS (queries no longer enter),
# the target the forward EGRESS (re-emits no longer leave), proving both halves of the capture
# rebind. The decoy flavor forces a different-index recreation on FreeBSD, where the plain flavors
# reuse the freed index (see Phase.decoy) -- pinning both detection paths (index comparison vs the
# capture attachment probe).
RECREATE_CASES = [
    RecreateCase(
        name="mdns_interface_recreate_source",
        config="config-addrchange.toml",
        phases=(
            Phase(
                label="source recreate", protocol="mdns", family=4, interface="source"
            ),
        ),
    ),
    RecreateCase(
        name="mdns_interface_recreate_target",
        config="config-addrchange.toml",
        phases=(
            Phase(
                label="target recreate", protocol="mdns", family=4, interface="target"
            ),
        ),
    ),
    RecreateCase(
        name="mdns_interface_recreate_source_decoy",
        config="config-addrchange.toml",
        phases=(
            Phase(
                label="source recreate",
                protocol="mdns",
                family=4,
                interface="source",
                decoy=True,
            ),
        ),
    ),
    RecreateCase(
        name="mdns_interface_recreate_target_decoy",
        config="config-addrchange.toml",
        phases=(
            Phase(
                label="target recreate",
                protocol="mdns",
                family=4,
                interface="target",
                decoy=True,
            ),
        ),
    ),
]
