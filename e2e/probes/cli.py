from __future__ import annotations

import argparse

from probes.dial import dial_client, dial_device
from probes.sockets import parse_payload_hex
from probes.udp import receive, respond, search, send


def main() -> int:
    parser = argparse.ArgumentParser(description="UDP probe used by netflector Docker e2e tests")
    subparsers = parser.add_subparsers(dest="command", required=True)

    send_parser = subparsers.add_parser("send", help="send a Wake-on-LAN magic packet")
    payload = send_parser.add_mutually_exclusive_group(required=True)
    payload.add_argument("--mac", help="target MAC address")
    payload.add_argument("--payload-hex", type=parse_payload_hex, help="raw UDP payload encoded as hex")
    send_parser.add_argument("--port", required=True, type=int, help="destination UDP port")
    send_parser.add_argument("--address", default="255.255.255.255", help="destination IP address")
    send_parser.add_argument("--interface", help="egress interface (IPv6 link-local scope)")
    send_parser.add_argument("--source-port", type=int, help="UDP port to send from")
    send_parser.set_defaults(func=send)

    receive_parser = subparsers.add_parser("receive", help="receive or reject UDP packets")
    receive_parser.add_argument("--port", required=True, type=int, help="UDP port to bind")
    receive_parser.add_argument("--timeout", required=True, type=float, help="seconds to wait")
    receive_parser.add_argument("--family", default=4, type=int, choices=(4, 6), help="IP version to bind")
    receive_parser.add_argument("--join-group", help="multicast group to join on --interface")
    receive_parser.add_argument("--interface", help="interface to join the multicast group on")
    receive_parser.add_argument("--bind-address",
                                help="bind to this address instead of the wildcard: only a datagram sent to it arrives")
    receive_parser.add_argument("--ignore-payload-hex", type=parse_payload_hex, action="append", default=[],
                                help="a UDP payload to skip rather than fail on; may be passed more than once")

    expectation = receive_parser.add_mutually_exclusive_group(required=True)
    expectation.add_argument("--expect-mac", help="MAC address whose magic packet must be received")
    expectation.add_argument("--expect-payload-hex", type=parse_payload_hex, help="exact UDP payload that must be received")
    expectation.add_argument("--expect-none", action="store_true", help="fail if any UDP packet is received")
    receive_parser.add_argument("--expect-source-net", help="network the packet's source address must be in")
    receive_parser.add_argument("--expect-source-port", type=int, help="port the packet's source must be")
    receive_parser.add_argument("--expect-source-not-link-local", action="store_true",
                                help="also require the matched packet's source to be a routable (non-fe80::) address")
    receive_parser.set_defaults(func=receive)

    respond_parser = subparsers.add_parser("respond", help="receive one datagram, then unicast a reply to its sender")
    respond_parser.add_argument("--port", required=True, type=int, help="UDP port to bind")
    respond_parser.add_argument("--timeout", required=True, type=float, help="seconds to wait for the datagram")
    respond_parser.add_argument("--family", default=4, type=int, choices=(4, 6), help="IP version to bind")
    respond_parser.add_argument("--join-group", help="multicast group to join on --interface")
    respond_parser.add_argument("--interface", help="interface to join the multicast group on")
    respond_parser.add_argument("--bind-address",
                                help="bind to this address instead of the wildcard: only a datagram sent to it arrives")
    respond_parser.add_argument("--reply-hex", required=True, type=parse_payload_hex, help="UDP payload to unicast back")
    respond_parser.set_defaults(func=respond)

    search_parser = subparsers.add_parser("search", help="send an M-SEARCH from a bound port, then await the proxied reply")
    search_parser.add_argument("--source-port", required=True, type=int, help="UDP port to bind and send from")
    search_parser.add_argument("--port", required=True, type=int, help="destination UDP port (1900)")
    search_parser.add_argument("--address", required=True, help="multicast group to send to")
    search_parser.add_argument("--interface", help="egress interface for multicast")
    search_parser.add_argument("--family", default=4, type=int, choices=(4, 6), help="IP version")
    search_parser.add_argument("--payload-hex", required=True, type=parse_payload_hex, help="M-SEARCH payload")
    search_parser.add_argument("--timeout", required=True, type=float, help="seconds to await the reply")
    search_expectation = search_parser.add_mutually_exclusive_group(required=True)
    search_expectation.add_argument("--expect-payload-hex", type=parse_payload_hex, help="expected 200 OK payload")
    search_expectation.add_argument("--expect-none", action="store_true", help="fail if any reply is received")
    search_expectation.add_argument("--no-wait", action="store_true", help="send the M-SEARCH and exit without awaiting a reply")
    search_parser.set_defaults(func=search)

    device_parser = subparsers.add_parser(
        "dial-device", help="emulate a DIAL device: SSDP 200 OK + description + REST HTTP endpoints")
    device_parser.add_argument("--port", required=True, type=int, help="SSDP UDP port to bind (1900)")
    device_parser.add_argument("--join-group", required=True, help="SSDP multicast group to join")
    device_parser.add_argument("--interface", required=True, help="interface facing netflector")
    device_parser.add_argument("--family", default=4, type=int, choices=(4, 6), help="IP version")
    device_parser.add_argument("--timeout", required=True, type=float, help="seconds to await the M-SEARCH")
    device_parser.add_argument("--serve-seconds", required=True, type=float,
                               help="seconds to keep the HTTP endpoints up after answering discovery")
    device_parser.add_argument("--notify", action="store_true",
                               help="passive discovery: advertise periodic NOTIFY instead of awaiting an M-SEARCH")
    device_parser.add_argument("--unreachable", action="store_true",
                               help="advertise a dead HTTP port (no server) so netflector's upstream is refused")
    device_parser.set_defaults(func=dial_device)

    client_parser = subparsers.add_parser(
        "dial-client", help="run the DIAL flow through netflector and assert the rewrites")
    client_parser.add_argument("--source-port", type=int, help="M-SEARCH source port (active discovery only)")
    client_parser.add_argument("--port", required=True, type=int, help="SSDP destination/group port (1900)")
    client_parser.add_argument("--address", required=True, help="SSDP multicast group")
    client_parser.add_argument("--interface", required=True, help="egress interface for multicast")
    client_parser.add_argument("--family", default=4, type=int, choices=(4, 6), help="IP version")
    client_parser.add_argument("--payload-hex", type=parse_payload_hex, help="M-SEARCH payload (active only)")
    client_parser.add_argument("--timeout", required=True, type=float, help="seconds to await discovery")
    client_parser.add_argument("--passive", action="store_true",
                               help="passive discovery: listen for a NOTIFY instead of sending an M-SEARCH")
    client_parser.add_argument("--expect-fetch-failure", action="store_true",
                               help="expect the proxied description fetch to fail (upstream unreachable)")
    client_parser.add_argument("--netflector-authority", required=True,
                               help="netflector source_if address (host only; LOCATION ports are dynamic)")
    client_parser.add_argument("--device-authority", required=True,
                               help="device's true target-side host, asserted absent from the rewrites")
    client_parser.set_defaults(func=dial_client)

    args = parser.parse_args()
    return args.func(args)
