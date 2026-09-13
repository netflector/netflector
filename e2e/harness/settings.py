"""Network layout, readiness markers, and timeout budgets shared by E2E scenarios."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
E2E_DIR = REPO_ROOT / "e2e"

DEFAULT_NETFLECTOR_IMAGE = "netflector:e2e"
VALGRIND_NETFLECTOR_IMAGE = "netflector:e2e-valgrind"
DEFAULT_HELPER_IMAGE = "python:3.13-alpine"
# --- Address-change cases: knock out one (interface, family) source on netflector, prove
# reflection of that family stops, then restore it and prove it resumes. netflector reacts on
# its own event loop after the netlink notification, so each check polls across that async window.
ADDR_CHANGE_REFLECTED_WINDOW = 4.0
# A silence probe is bounded by its send, not by a window, so only the count matters here: one
# silence proves reflection was down across that send, two proves it stayed down.
ADDR_CHANGE_SILENCE_CONSECUTIVE = 2
ADDR_CHANGE_POLL_DEADLINE = 60.0
# An expect-none receiver is stopped once the sender has finished, so its own deadline is only a
# backstop: it must outlast container startup on the slowest lane, never bound the assertion.
EXPECT_NONE_BACKSTOP_SECONDS = 60.0
# After the sender exits, how long the receiver keeps listening before the window is closed --
# the packet's flight time through the daemon, not a guess at when the sender got around to it.
EXPECT_NONE_FLIGHT_SECONDS = 1.5
# SIGTERM grace for a probe the harness stops; it only has to unwind and print.
PROBE_STOP_GRACE_SECONDS = 5
# A substring of the line the daemon logs immediately before entering its event loop.
NETFLECTOR_READY_LOG = "running; press Ctrl-C or send SIGTERM to stop"
RECEIVER_READY_LOG = "receiver ready: UDP socket bound"
CONTAINER_READY_TIMEOUT_SECONDS = 15.0
# Every resource a run creates is named with this prefix, so a sweep can find what a killed run left.
E2E_RESOURCE_PREFIX = "netflector-e2e-"
# A clean SIGTERM exit triggers valgrind's leak analysis; give `docker stop` this much grace before it
# SIGKILLs, so the analysis (which can take tens of seconds) finishes and its exit code is read.
VALGRIND_STOP_GRACE_SECONDS = 60

# Ceiling on one setup or teardown command. Well above the slowest of them (a probe run waits at most
# ~8s), so it only ever fires on a wedge; the emulated arm64 lanes are the slow case to clear.
COMMAND_TIMEOUT_SECONDS = 120.0

NETFLECTOR_SOURCE_IFNAME = "nf_source"
NETFLECTOR_TARGET_IFNAME = "nf_target"
RECEIVER_IFNAME = "probe0"
NETFLECTOR_IFNAMES = {
    "source": NETFLECTOR_SOURCE_IFNAME,
    "target": NETFLECTOR_TARGET_IFNAME,
}
DECOY_IFNAME = "nf_decoy"


SEGMENTS = ("source", "target")

# Fixed per-segment subnets: RFC 5737 test networks for v4, a ULA /64 for routable v6. The native
# fabrics assign hosts from these directly; the docker backend hands them to `network create` as
# user-configured subnets (required so the recreate cases can pin the same --ip/--ip6 on reconnect --
# docker rejects a static address on an IPAM-auto subnet).
SEGMENT_V4_SUBNET = {"source": "192.0.2", "target": "198.51.100"}
SEGMENT_V6_PREFIX = {"source": "fd00:e2e0:1", "target": "fd00:e2e0:2"}
# The host number of a segment's probe: what the native fabrics assign, and what docker pins when
# a case names the probe as a peer in its config (config-peers-*.toml). Past what docker's IPAM
# hands out on its own.
HELPER_HOST = 20


# Native segment addressing over SEGMENT_V4_SUBNET / SEGMENT_V6_PREFIX: netflector is always host 1
# and a segment's helper host 2, replacing Docker's IPAM discovery with a fixed plan (the kernel adds
# fe80:: itself).
NATIVE_NETFLECTOR_HOST = 1
