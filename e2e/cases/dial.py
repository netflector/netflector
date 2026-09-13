from __future__ import annotations

from cases.models import DialAddressChangeCase, DialCase, DialRecreateCase
from fixtures import SSDP_GROUP_V4

DIAL_CASES = [
    DialCase(name="dial_launch_roundtrip", family=4, group=SSDP_GROUP_V4),
    DialCase(
        name="dial_passive_notify_roundtrip",
        family=4,
        group=SSDP_GROUP_V4,
        passive=True,
    ),
    DialCase(
        name="dial_upstream_unreachable",
        family=4,
        group=SSDP_GROUP_V4,
        unreachable=True,
    ),
    # The mirrored pair storms without the dispatcher's echo drop: each side proxies the other's
    # re-emit. The counter assertion keeps the case from passing vacuously on a bridge that
    # stopped echoing, and pins the native fabrics as non-echoing.
    DialCase(
        name="dial_launch_roundtrip_mirrored",
        family=4,
        group=SSDP_GROUP_V4,
        config="config-dial-mirrored.toml",
        expect_echoed=True,
    ),
    DialCase(
        name="dial_passive_notify_roundtrip_mirrored",
        family=4,
        group=SSDP_GROUP_V4,
        passive=True,
        config="config-dial-mirrored.toml",
        expect_echoed=True,
    ),
    # The second leg end to end: client on the target, device on the source, proxies minted on the
    # target side.
    DialCase(
        name="bidirectional_dial_launch_roundtrip_from_target",
        family=4,
        group=SSDP_GROUP_V4,
        config="config-dial-mirrored.toml",
        expect_echoed=True,
        direction="reverse",
    ),
    DialCase(
        name="bidirectional_dial_passive_notify_roundtrip_from_target",
        family=4,
        group=SSDP_GROUP_V4,
        passive=True,
        config="config-dial-mirrored.toml",
        expect_echoed=True,
        direction="reverse",
    ),
]


DIAL_ADDRESS_CHANGE_CASES = [
    DialAddressChangeCase(name="dial_address_change"),
]


DIAL_RECREATE_CASES = [
    DialRecreateCase(name="dial_interface_recreate_source", interface="source"),
    DialRecreateCase(name="dial_interface_recreate_target", interface="target"),
    DialRecreateCase(
        name="dial_interface_recreate_source_decoy", interface="source", decoy=True
    ),
    DialRecreateCase(
        name="dial_interface_recreate_target_decoy", interface="target", decoy=True
    ),
]
