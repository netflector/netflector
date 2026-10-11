"""Linux interface mutations, shared by Docker and native Linux."""

from __future__ import annotations

import ipaddress
import socket
import struct
from collections.abc import Callable


def set_address(
    admin: Callable[..., str],
    ifname: str,
    family: int,
    *,
    up: bool,
    cidr: str | None = None,
) -> str | None:
    # Bring one (interface, family) source address down or back up in netflector's
    # network view. IPv6 drops every v6 address and, on re-enable, has the kernel regenerate
    # a usable link-local; v4 deletes and later re-adds the exact CIDR (returned on removal
    # so the caller can restore it). Docker and native Linux share these ip/proc operations;
    # FreeBSD uses its own ifconfig implementation.
    if family == 6:
        admin(f"echo {0 if up else 1} > /proc/sys/net/ipv6/conf/{ifname}/disable_ipv6")
        return None
    if up:
        if cidr is None:
            raise RuntimeError(
                "restoring an IPv4 address requires the CIDR captured on removal"
            )
        admin(f"ip addr add {cidr} dev {ifname}")
        return cidr
    captured = admin(
        f"ip -o -4 addr show dev {ifname} | awk '/inet /{{print $4; exit}}'",
        capture=True,
    )
    if not captured:
        raise RuntimeError(f"no IPv4 address on {ifname} to remove")
    admin(f"ip addr del {captured} dev {ifname}")
    return captured


def memberships(admin: Callable[..., str]) -> set[tuple[str, str]]:
    igmp, _, igmp6 = admin(
        "cat /proc/net/igmp; echo ---; cat /proc/net/igmp6", capture=True
    ).partition("---")
    return parse_memberships(igmp, igmp6)


def parse_memberships(igmp: str, igmp6: str) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    device = ""
    for line in igmp.splitlines()[1:]:
        if not line.strip():
            continue
        if not line.startswith("\t"):
            device = line.split()[1].rstrip(":")
            continue
        # The kernel prints the network-order address as a host-order integer.
        group = socket.inet_ntoa(struct.pack("=I", int(line.split()[0], 16)))
        found.add((device, group))
    for line in igmp6.splitlines():
        fields = line.split()
        if len(fields) >= 3:
            found.add((fields[1], str(ipaddress.IPv6Address(bytes.fromhex(fields[2])))))
    return found
