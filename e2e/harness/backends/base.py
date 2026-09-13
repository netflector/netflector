from __future__ import annotations

import argparse
from pathlib import Path

from harness.settings import HELPER_HOST, SEGMENT_V4_SUBNET, SEGMENT_V6_PREFIX


class Backend:
    # The execution environment for one case: two isolated dual-stack segments, netflector
    # straddling both, and single-homed probe helpers referenced by role name ("receiver",
    # "sender", "device", ...). Docker realizes segments as bridge networks and participants as
    # containers; native (Linux) as netns + veth pairs and plain processes. Runners hold case
    # logic only and drive everything through this interface, so every case runs identically
    # under both backends.

    # Whether the probe helpers keep working while a segment's netflector-side interface is
    # deleted. Docker probes own separate bridge endpoints, so yes; the native fabrics realize
    # a segment as one veth/epair pair, so deleting it takes the probe end with it and the
    # recreate case skips its silence probe there (there is no wire left to probe on).
    PROBES_SURVIVE_DELETE = False

    # Whether the fabric hands netflector's own re-emits back as received frames. Docker's
    # bridges do when their ports run in hairpin mode (Docker Desktop's default; Docker Engine
    # only with the userland proxy off); a veth/epair pair has no third port to reflect off, so
    # the mirrored DIAL cases assert the `echoed` count stays absent there.
    ECHOES_OWN_FRAMES = False

    def __init__(self, args: argparse.Namespace, prefix: str) -> None:
        self.args = args
        self.prefix = prefix

    @staticmethod
    def preflight_clean() -> None:
        # Remove what a killed run left behind, before the first case. Only the docker backend needs
        # it: a leaked netns, jail or epair is untidy but harmless, since every name carries a
        # per-run uuid and the epair allocator just takes the next free index.
        pass

    def setup_segments(self) -> None:
        raise NotImplementedError

    def cleanup(self) -> None:
        raise NotImplementedError

    def keep_artifacts(self) -> str:
        # What --keep-on-failure leaves behind, for the "keeping ..." message.
        raise NotImplementedError

    def abandon(self) -> None:
        # Called instead of cleanup() on --keep-on-failure. Docker containers stay inspectable
        # (and visible in `docker ps`) so the default keeps everything; the native backend kills
        # its otherwise-invisible root processes -- the namespaces and log files hold the
        # debuggable state.
        pass

    def start_netflector(self, config_path: Path) -> None:
        raise NotImplementedError

    def helper_address(self, segment: str, family: int) -> str:
        # The probe's own address on `segment`, from the plan both fabrics follow.
        if family == 6:
            return f"{SEGMENT_V6_PREFIX[segment]}::{HELPER_HOST}"
        return f"{SEGMENT_V4_SUBNET[segment]}.{HELPER_HOST}"

    def start_probe(
        self, role: str, segment: str, ifname: str, probe_args: list[str], *,
        detach: bool = True, pin_address: bool = False,
    ) -> None:
        # Run probe.py with `probe_args` single-homed on `segment`. detach=False blocks until
        # exit and raises on a non-zero code.
        raise NotImplementedError

    def helper_ifname(self, requested: str) -> str:
        # The interface name a helper on a segment actually sees (passed as probe --interface).
        # Docker pins the requested name per container; native names every far end probe0.
        raise NotImplementedError

    def wait(self, role: str) -> int:
        raise NotImplementedError

    def logs(self, role: str) -> tuple[str, str]:
        raise NotImplementedError

    def status(self, role: str) -> tuple[bool, str]:
        # (still running?, human-readable state) -- state is "unknown" when unavailable.
        raise NotImplementedError

    def remove(self, role: str) -> None:
        raise NotImplementedError

    def stop_netflector(self, grace_seconds: int) -> int:
        # SIGTERM netflector, allow `grace_seconds` for a clean exit (valgrind's leak
        # analysis needs it), then kill; returns the exit code.
        raise NotImplementedError

    def stop_probe(self, role: str, grace_seconds: int) -> None:
        raise NotImplementedError

    def admin(self, script: str, *, capture: bool = False) -> str:
        # Run a shell script inside netflector's network view (addr/route/sysctl mutation).
        raise NotImplementedError

    def set_address(
        self, ifname: str, family: int, *, up: bool, cidr: str | None = None
    ) -> str | None:
        raise NotImplementedError

    def add_decoy_route(self, dest_ip: str, ifname: str) -> bool:
        raise NotImplementedError

    def delete_interface(self, segment: str) -> None:
        # Destroy `segment`'s netflector-side interface outright (its far peer dies with it):
        # the first half of an interface recreation, as a PPPoE drop or bridge teardown would
        # produce. netflector's capture is left bound to a dead kernel object.
        raise NotImplementedError

    def recreate_interface(self, segment: str) -> None:
        # The second half: recreate the interface under the same name and addresses -- a fresh
        # kernel identity netflector must reconcile its capture onto.
        raise NotImplementedError

    def add_decoy_interface(self) -> None:
        # Plant a throwaway interface in netflector's network view, occupying the index a
        # just-deleted interface freed (see Phase.decoy). Removed with
        # [`remove_decoy_interface`]; the fabric teardown also covers it on failure.
        raise NotImplementedError

    def remove_decoy_interface(self) -> None:
        raise NotImplementedError

    def netflector_ip(self, segment: str) -> str:
        raise NotImplementedError

    def probe_ip(self, role: str, segment: str) -> str:
        raise NotImplementedError

    def print_diagnostics(self) -> None:
        raise NotImplementedError
