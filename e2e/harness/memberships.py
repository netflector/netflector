"""The multicast memberships a case's netflector should hold, from its config."""

from __future__ import annotations

import ipaddress
from pathlib import Path

# Each reflector joins its protocol's groups on both of its interfaces; a UDP relay joins its own
# groups on its ingress only, so on both when bidirectional.
PROTOCOL_GROUPS = {
    "mdns": ("224.0.0.251", "ff02::fb"),
    "ssdp": ("239.255.255.250", "ff02::c", "ff05::c"),
    "wsd": ("239.255.255.250", "ff02::c"),
}


def expected(config_path: Path) -> set[tuple[str, str]] | None:
    """(interface, group) pairs, or None where Python lacks tomllib (before 3.11)."""
    try:
        import tomllib
    except ModuleNotFoundError:
        return None
    with config_path.open("rb") as file:
        config = tomllib.load(file)
    wanted: set[tuple[str, str]] = set()
    for entry in config.get("reflectors", {}).values():
        family = entry.get("address_family", "default")

        def takes(group: str) -> bool:
            version = ipaddress.ip_address(group).version
            return family not in ("ipv4", "ipv6") or family == f"ipv{version}"

        ends = (entry["source_if"], entry["target_if"])
        for protocol, groups in PROTOCOL_GROUPS.items():
            if entry.get(protocol):
                wanted |= {(ifname, group) for ifname in ends for group in groups if takes(group)}
        relay_ends = ends if entry.get("bidirectional") else ends[:1]
        for group in entry.get("udp_groups", []):
            if takes(group):
                wanted |= {(ifname, str(ipaddress.ip_address(group))) for ifname in relay_ends}
    return wanted
