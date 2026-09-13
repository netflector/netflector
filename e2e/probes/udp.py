"""Datagram send, receive, and discovery round-trip probes."""

from __future__ import annotations

import argparse
import signal
import socket
import struct
import sys
import time

from probes.sockets import (
    WindowClosed,
    _close_window,
    bind_reporting_conflict,
    drain_for_duplicate,
    is_ipv4_multicast,
    is_ipv6,
    join_group,
    magic_packet,
    packet_hex,
    source_as_expected,
)


def send(args: argparse.Namespace) -> int:
    payload = args.payload_hex if args.payload_hex is not None else magic_packet(args.mac)

    if is_ipv6(args.address):
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            if args.source_port is not None:
                sock.bind(("::", args.source_port))
            scope_id = 0
            if args.interface:
                scope_id = socket.if_nametoindex(args.interface)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, scope_id)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
            # The scope id in the address tuple disambiguates the link-local destination.
            sock.sendto(payload, (args.address, args.port, 0, scope_id))
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            if args.source_port is not None:
                sock.bind(("0.0.0.0", args.source_port))
            if is_ipv4_multicast(args.address):
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                if args.interface:
                    ifindex = socket.if_nametoindex(args.interface)
                    mreqn = struct.pack("@4s4si", b"\x00\x00\x00\x00", b"\x00\x00\x00\x00", ifindex)
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)
            else:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                if sys.platform.startswith("freebsd14") and args.address == "255.255.255.255":
                    # FreeBSD 14 puts the interface's directed broadcast on the wire for a send to
                    # the all-ones address; IP_ONESBCAST keeps 255.255.255.255, as Linux does.
                    # FreeBSD 15 sends all-ones as such and, with the option set, refuses the send
                    # with ENETUNREACH. Python exposes no constant for it.
                    IP_ONESBCAST = 23
                    sock.setsockopt(socket.IPPROTO_IP, IP_ONESBCAST, 1)
            sock.sendto(payload, (args.address, args.port))

    print(f"sent {len(payload)} bytes to {args.address}:{args.port}: {packet_hex(payload)}", flush=True)
    return 0


def expected_payload(args: argparse.Namespace) -> bytes | None:
    if args.expect_none:
        return None
    if args.expect_payload_hex is not None:
        return args.expect_payload_hex
    return magic_packet(args.expect_mac)


def receive(args: argparse.Namespace) -> int:
    expected = expected_payload(args)
    deadline = time.monotonic() + args.timeout

    family = socket.AF_INET6 if args.family == 6 else socket.AF_INET
    bind_address = args.bind_address or ("::" if family == socket.AF_INET6 else "0.0.0.0")

    try:
        return _receive(args, expected, deadline, family, bind_address)
    except WindowClosed:
        # Only an expect-none receiver arms the handler, and reaching here means no packet arrived
        # before the harness closed the window -- which it does only after the sender finished.
        print("no packets before the harness closed the window", flush=True)
        return 0


def _receive(args, expected, deadline, family, bind_address) -> int:
    with socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_reporting_conflict(sock, bind_address, args.port)
        if args.join_group is not None:
            # Multicast is only delivered to sockets that joined the group on the receiving
            # interface; broadcast/all-nodes (the WoL IPv4 path) needs no join.
            join_group(sock, family, args.join_group, args.interface)
        print(f"receiver ready: UDP socket bound on {bind_address} port {args.port}", flush=True)

        # An expect-none receiver outlives its own deadline: the harness stops it once the sender
        # has finished, so the window provably spans the send instead of racing it.
        if args.expect_none:
            signal.signal(signal.SIGTERM, _close_window)

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            sock.settimeout(remaining)
            try:
                payload, peer = sock.recvfrom(4096)
            except TimeoutError:
                break

            print(f"received {len(payload)} bytes from {peer[0]}:{peer[1]}: {packet_hex(payload)}", flush=True)

            if args.expect_none:
                print("expected no packets, but one was received", file=sys.stderr, flush=True)
                return 1

            if payload in args.ignore_payload_hex:
                print("ignored", flush=True)
                continue

            if payload == expected:
                if not source_as_expected(args, peer):
                    return 1
                if args.expect_source_not_link_local and peer[0].lower().startswith("fe80"):
                    print(
                        f"forwarded from link-local source {peer[0]}; expected a routable (non-fe80::) address",
                        file=sys.stderr,
                        flush=True,
                    )
                    return 1
                return drain_for_duplicate(sock, expected)

            print(
                f"received payload does not match the expected {packet_hex(expected)}",
                file=sys.stderr,
                flush=True,
            )
            return 1

    if args.expect_none:
        print(f"received no packets for {args.timeout:.3f}s", flush=True)
        return 0

    print(f"timed out waiting for expected packet after {args.timeout:.3f}s", file=sys.stderr, flush=True)
    return 1


def respond(args: argparse.Namespace) -> int:
    # The SSDP round-trip "device": wait for one (relayed) M-SEARCH on the group, then unicast a 200 OK
    # straight back to its sender. The sender is netflector's reserved port on the target segment,
    # which proxies the reply back to the searcher on the source segment.
    family = socket.AF_INET6 if args.family == 6 else socket.AF_INET
    bind_address = args.bind_address or ("::" if family == socket.AF_INET6 else "0.0.0.0")

    with socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_reporting_conflict(sock, bind_address, args.port)
        if args.join_group is not None:
            join_group(sock, family, args.join_group, args.interface)
        # Readiness marker so run.py can sequence the searcher after the responder is listening.
        print(f"responder ready: UDP socket bound on {bind_address} port {args.port}", flush=True)

        sock.settimeout(args.timeout)
        try:
            payload, peer = sock.recvfrom(4096)
        except TimeoutError:
            print(f"responder: no datagram for {args.timeout:.3f}s", file=sys.stderr, flush=True)
            return 1

        print(f"responder received {len(payload)} bytes from {peer[0]}:{peer[1]}", flush=True)
        # Reply straight back to the sender (netflector's target_if:P); it proxies to the searcher.
        # peer is the full tuple recvfrom returned (4-tuple for IPv6), preserving the link-local scope.
        sock.sendto(args.reply_hex, peer)
        print(f"responder replied {len(args.reply_hex)} bytes to {peer[0]}:{peer[1]}", flush=True)
        return 0


def search(args: argparse.Namespace) -> int:
    # The SSDP round-trip "searcher": send an M-SEARCH to the group from a known source port, then await
    # the proxied unicast 200 OK netflector relays back from the device on the target segment.
    family = socket.AF_INET6 if args.family == 6 else socket.AF_INET
    bind_address = "::" if family == socket.AF_INET6 else "0.0.0.0"

    with socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_reporting_conflict(sock, bind_address, args.source_port)  # the searcher's known source port

        scope_id = 0
        if family == socket.AF_INET6:
            if args.interface:
                scope_id = socket.if_nametoindex(args.interface)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, scope_id)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
            dest = (args.address, args.port, 0, scope_id)
        else:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            if args.interface:
                ifindex = socket.if_nametoindex(args.interface)
                mreqn = struct.pack("@4s4si", b"\x00\x00\x00\x00", b"\x00\x00\x00\x00", ifindex)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)
            dest = (args.address, args.port)

        print(f"searcher ready: bound source port {args.source_port}", flush=True)
        sock.sendto(args.payload_hex, dest)
        print(f"searcher sent {len(args.payload_hex)} bytes to {args.address}:{args.port}", flush=True)

        if args.no_wait:
            # Fire-and-forget: the caller only needs the M-SEARCH sent (e.g. to trigger a reflected
            # re-emit), not the reply -- which may be routed elsewhere (a reused session's cached MAC).
            print("searcher: not waiting for a reply", flush=True)
            return 0

        sock.settimeout(args.timeout)
        try:
            payload, peer = sock.recvfrom(4096)
        except TimeoutError:
            if args.expect_none:
                print(f"searcher: no reply for {args.timeout:.3f}s (as expected)", flush=True)
                return 0
            print(f"searcher: no reply for {args.timeout:.3f}s", file=sys.stderr, flush=True)
            return 1

        print(f"searcher received {len(payload)} bytes from {peer[0]}:{peer[1]}: {packet_hex(payload)}", flush=True)
        if args.expect_none:
            print("searcher: expected no reply, but one was received", file=sys.stderr, flush=True)
            return 1
        if payload == args.expect_payload_hex:
            return 0
        print("searcher: reply payload does not match expected 200 OK", file=sys.stderr, flush=True)
        return 1
