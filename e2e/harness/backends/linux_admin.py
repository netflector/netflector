"""Linux interface mutations, shared by Docker and native Linux."""

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
