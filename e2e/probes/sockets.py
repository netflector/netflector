"""Socket setup, payload parsing, and bounded receive windows."""

from __future__ import annotations

import argparse
import binascii
import errno
import ipaddress
import socket
import struct
import sys
import time


def parse_mac(value: str) -> bytes:
    parts = value.split(":")
    if len(parts) != 6:
        raise argparse.ArgumentTypeError(f"invalid MAC address: {value}")

    try:
        octets = bytes(int(part, 16) for part in parts)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid MAC address: {value}") from exc

    if any(len(part) != 2 for part in parts):
        raise argparse.ArgumentTypeError(f"invalid MAC address: {value}")

    return octets


def magic_packet(mac: str) -> bytes:
    mac_bytes = parse_mac(mac)
    return b"\xff" * 6 + mac_bytes * 16


def parse_payload_hex(value: str) -> bytes:
    try:
        return binascii.unhexlify(value)
    except (binascii.Error, ValueError) as exc:
        raise argparse.ArgumentTypeError(f"invalid hex payload: {value}") from exc


class WindowClosed(Exception):
    """SIGTERM: the harness closed an expect-none window once the sender had finished."""


def _close_window(signum, frame):
    del signum, frame
    # PEP 475 retries an interrupted recvfrom unless the handler raises, so raising is what
    # actually breaks the receive loop.
    raise WindowClosed


# How long a receiver keeps listening after its expected packet, to catch a second copy. A duplicate
# is near-simultaneous -- a doubled send, or an echo one reactor iteration later -- so this is jitter
# margin, sized for the emulated lanes where that iteration costs tens of milliseconds.
DUPLICATE_DRAIN_SECONDS = 0.5


def packet_hex(payload: bytes) -> str:
    return binascii.hexlify(payload).decode("ascii")


def is_ipv6(address: str) -> bool:
    return ":" in address


def is_ipv4_multicast(address: str) -> bool:
    return 224 <= int(address.split(".")[0]) <= 239


def bind_reporting_conflict(sock: socket.socket, address: str, port: int) -> None:
    # A conflict should be impossible (fresh namespace, REUSEADDR set), so name the squatter:
    # /proc/net/udp* lists every UDP socket in this namespace (Linux only).
    try:
        sock.bind((address, port))
    except OSError as err:
        if err.errno == errno.EADDRINUSE:
            for table in ("/proc/net/udp", "/proc/net/udp6"):
                try:
                    with open(table) as f:
                        sys.stderr.write(f"--- {table} ---\n{f.read()}")
                except OSError:
                    pass
        raise


def join_group(sock: socket.socket, family: int, group: str, interface: str) -> None:
    ifindex = socket.if_nametoindex(interface)
    if family == socket.AF_INET6:
        mreq = socket.inet_pton(socket.AF_INET6, group) + struct.pack("@I", ifindex)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
    else:
        mreq = struct.pack("@4s4si", socket.inet_aton(group), b"\x00\x00\x00\x00", ifindex)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)


def source_as_expected(args: argparse.Namespace, peer: tuple) -> bool:
    # The relay keeps the sender's own ip:port on the re-emit, so the receiver sees a peer from the
    # other segment at the port the sender bound, not netflector's egress address.
    address = ipaddress.ip_address(peer[0].split("%")[0])
    if args.expect_source_net is not None and address not in ipaddress.ip_network(args.expect_source_net):
        print(f"received from {peer[0]}; expected a source in {args.expect_source_net}", file=sys.stderr, flush=True)
        return False
    if args.expect_source_port is not None and peer[1] != args.expect_source_port:
        print(f"received from port {peer[1]}; expected {args.expect_source_port}", file=sys.stderr, flush=True)
        return False
    return True


def drain_for_duplicate(sock: socket.socket, expected: bytes) -> int:
    # One reflection per packet is the contract, and nothing else in the suite can see a second one:
    # a doubled emission on the correct egress, or the daemon's own re-emission echoed back to it
    # (the own-egress drop and the Verdict::Skip loop-breaker both prevent that). Every config keeps
    # its entries non-overlapping, so a second identical datagram is always a fault.
    deadline = time.monotonic() + DUPLICATE_DRAIN_SECONDS
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return 0
        sock.settimeout(remaining)
        try:
            payload, peer = sock.recvfrom(4096)
        except TimeoutError:
            return 0
        if payload == expected:
            print(
                f"received a second copy from {peer[0]}:{peer[1]}: the packet was reflected twice",
                file=sys.stderr,
                flush=True,
            )
            return 1
