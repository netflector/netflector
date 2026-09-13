"""Typed traffic and lifecycle specifications, independent of execution backends."""

from __future__ import annotations

import dataclasses

from fixtures import (
    IPV6_ALL_NODES,
    SSDP_GROUP_V4,
    SSDP_MSEARCH_HEX,
    SSDP_MSEARCH_MX5_HEX,
    SSDP_OK_HEX,
    SSDP_PORT,
)


@dataclasses.dataclass(frozen=True)
class TestCase:
    name: str
    send_port: int
    receive_port: int
    expect_mac: str | None
    timeout_seconds: float
    send_mac: str | None = None
    send_payload_hex: str | None = None
    # IP version exercised end to end. netflector runs both pipelines from one config; each case
    # drives just one of them.
    family: int = 4
    # Reflection direction. "forward" sends from the source network and receives on the target (WoL);
    # "reverse" swaps them. Carried so non-WoL protocols (mDNS responses, etc.) re-add as small diffs.
    direction: str = "forward"
    # Multicast group to send to and join on the receiver. None keeps the WoL broadcast / all-nodes path.
    group: str | None = None
    # Exact payload the receiver must see, for protocols relayed verbatim. None falls back to the
    # magic-packet / expect-none expectation.
    expect_payload_hex: str | None = None
    # Also require the reflected packet's source to be routable (non-link-local) — the per-scope v6
    # source selection: a site-local group (ff05::c) must not be sourced from a link-local address.
    expect_routable_source: bool = False
    # netflector config file (relative to e2e/) mounted into the netflector container. Most cases share
    # config.toml; a case needing a distinct reflector set (e.g. single-family) names its own.
    config: str = "config.toml"
    # An explicit destination for the send, overriding the group / link-wide default.
    send_to: str | None = None
    # A line netflector must have logged by the time the receiver's verdict is in, e.g. the
    # destination it re-emitted to.
    expect_netflector_log: str | None = None
    # Send from a fixed port and require the reflected packet to come from that port and from
    # the sender's own segment: the UDP relay keeps the source as sent.
    expect_source_preserved: bool = False
    # The receiver binds to its own address, so only a unicast copy sent to it arrives: the
    # config names the probe as a peer of its segment.
    expect_unicast: bool = False
    # The port to send from; an mDNS response must come from 5353 to count as one.
    send_source_port: int | None = None

    @property
    def send_address(self) -> str:
        if self.send_to is not None:
            return self.send_to
        if self.group is not None:
            return self.group
        return IPV6_ALL_NODES if self.family == 6 else "255.255.255.255"


@dataclasses.dataclass(frozen=True)
class RoundTripCase:
    name: str
    family: int  # 4 or 6
    group: str
    timeout_seconds: float = 8.0
    # When False, no responder is started and the searcher must receive nothing -- netflector must
    # not fabricate or loop back a reply to a search no device answered.
    expect_reply: bool = True
    # Protocol parameters, defaulting to SSDP's M-SEARCH round trip; WSD overrides them (its Probe ->
    # ProbeMatches uses the same session machinery on a different port / with different payloads).
    port: int = SSDP_PORT
    probe_hex: str = SSDP_MSEARCH_HEX
    reply_hex: str = SSDP_OK_HEX
    config: str = "config.toml"
    evict_log: str = "evicted SSDP session"
    # "forward" searches from the source segment with the responder on the target; "reverse" swaps
    # them, the leg a bidirectional entry adds.
    direction: str = "forward"
    # The responder binds to its own address, so only a unicast copy of the search arrives: the
    # config names it as a peer of its segment.
    responder_unicast: bool = False


@dataclasses.dataclass(frozen=True)
class AnswerCase:
    # A query relayed to a peer as unicast is answered by unicast to netflector, and the answer
    # must come out on the source segment's group. A sender on the source queries the group; a
    # responder on the target, bound to its own address, answers whatever reaches it; a receiver
    # on the source, joined to the group, must see the answer once.
    name: str
    group: str
    port: int
    query_hex: str
    answer_hex: str
    family: int = 4
    timeout_seconds: float = 5.0
    config: str = "config-peers-target.toml"


@dataclasses.dataclass(frozen=True)
class SearchRecreateCase:
    # A search session across an interface recreation. One searcher opens a session; a netflector
    # interface is then destroyed and recreated. The session's reserved port and response registration
    # live on the TARGET, so recreating the target drops every session (logged, via on_iface_change) and
    # the retransmit opens a fresh one; recreating the SOURCE leaves the session intact (the reply leg
    # re-resolves the source at send time), so the retransmit re-reflects on the SAME reserved port. Run
    # each interface both without and with a decoy that grabs the freed index: on FreeBSD (which reuses
    # the lowest-free index) that is a same-index vs changed-index recreation, pinning both detection
    # paths (the attached() BIOCGDLT probe vs the index comparison); on Linux the index always changes,
    # so the decoy is inert there. The wide MX keeps the first session alive until the recreation. This
    # is the search-session path the passive mDNS and DIAL recreate cases never reach.
    name: str
    interface: str = "target"  # which netflector interface is destroyed + recreated
    family: int = 4
    group: str = SSDP_GROUP_V4
    port: int = SSDP_PORT
    probe_hex: str = SSDP_MSEARCH_MX5_HEX  # wide MX window: the first session must outlive the recreation
    reply_hex: str = SSDP_OK_HEX
    config: str = "config.toml"
    direction: str = "forward"
    timeout_seconds: float = 8.0
    decoy: bool = False  # plant a decoy on the freed index so the recreation lands on a different one
    responder_unicast: bool = False  # as RoundTripCase's; the responder is shared


@dataclasses.dataclass(frozen=True)
class DialCase:
    name: str
    family: int          # 4 (DIAL is IPv4-only by spec; kept as a field for symmetry)
    group: str
    timeout_seconds: float = 8.0
    serve_seconds: float = 6.0
    passive: bool = False      # passive discovery (device advertises NOTIFY; client listens) vs active M-SEARCH
    unreachable: bool = False  # device advertises a dead HTTP port; the proxied fetch must fail, not hang
    config: str = "config-dial.toml"
    expect_echoed: bool = False  # echo-drop verdict, per Backend.ECHOES_OWN_FRAMES
    # "forward" puts the client on the source segment and the device on the target; "reverse"
    # swaps them, the leg a bidirectional entry adds.
    direction: str = "forward"


@dataclasses.dataclass(frozen=True)
class DialAddressChangeCase:
    # A full DIAL pass, then the same pass again after netflector's source IPv4 changes, then again
    # after its target IPv4 changes -- to a *different* address each time. A passing re-run is the 7d
    # proof: a proxy not evicted on the change would re-advertise a LOCATION on the vanished source
    # address (the fetch can't reach it) or bind the vanished target on its upstream connect. The device
    # advertises NOTIFY throughout (passive discovery), so each phase's fresh client rediscovers and
    # netflector re-mints against the current addresses.
    name: str
    family: int = 4
    group: str = SSDP_GROUP_V4
    timeout_seconds: float = 8.0
    serve_seconds: float = 60.0  # device keeps advertising + serving across all three passes
    passive: bool = True
    unreachable: bool = False
    config: str = "config-dial.toml"
    expect_echoed: bool = False
    direction: str = "forward"


@dataclasses.dataclass(frozen=True)
class DialRecreateCase:
    # A full DIAL pass, then the same pass again after one netflector interface is destroyed and
    # recreated. The hardest DIAL recovery scenario: a recreation replaces the kernel objects
    # underneath the minted proxy -- its listener binds, target-address snapshot, and egress-pin all
    # belong to the dead interface's world -- so a passing re-run proves the recreation evicted the
    # proxy and re-minted against the recreated interface. One case per (interface, decoy): the decoy
    # forces a changed-index recreation (vs FreeBSD's same-index reuse), pinning both detection paths.
    name: str
    interface: str = "target"  # which netflector interface is destroyed + recreated
    decoy: bool = False  # plant a decoy on the freed index so the recreation lands on a different one
    family: int = 4
    group: str = SSDP_GROUP_V4
    timeout_seconds: float = 8.0
    serve_seconds: float = 120.0  # device serves across passes and the recreation waits
    passive: bool = True
    unreachable: bool = False
    config: str = "config-dial.toml"
    expect_echoed: bool = False
    direction: str = "forward"


@dataclasses.dataclass(frozen=True)
class Phase:
    # One knock-out within an address-change case: take down a single (interface, family) source
    # address on netflector, prove reflection of `protocol`/`family` stops, then restore it and
    # prove reflection resumes -- all via real traffic.
    label: str
    protocol: str  # "wol" | "mdns" -> PROBE_SPECS
    family: int  # 4 | 6
    interface: str  # "source" (nf_source) | "target" (nf_target): which netflector interface to toggle
    # Recreate cases only: plant a throwaway interface between the delete and the recreate. It
    # occupies the freed slot, so FreeBSD's lowest-free index allocator is forced to hand the
    # recreated interface a DIFFERENT index; without it the same index comes back. The two
    # flavors pin both detection paths (index comparison vs the capture attachment probe).
    decoy: bool = False


@dataclasses.dataclass(frozen=True)
class AddressChangeCase:
    name: str
    config: str  # config file (relative to e2e/), defining a dual-family reflector set
    phases: tuple[Phase, ...]


@dataclasses.dataclass(frozen=True)
class RecreateCase:
    name: str
    config: str  # config file (relative to e2e/), defining a dual-family reflector set
    phases: tuple[Phase, ...]  # interface = which netflector interface is destroyed+recreated
