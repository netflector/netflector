from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

from harness.backends import linux_admin
from harness.backends.native import NativeBackend
from harness.commands import require_command, run_command
from harness.settings import (
    DECOY_IFNAME,
    HELPER_HOST,
    NATIVE_NETFLECTOR_HOST,
    NETFLECTOR_IFNAMES,
    RECEIVER_IFNAME,
    SEGMENT_V4_SUBNET,
    SEGMENT_V6_PREFIX,
    SEGMENTS,
)


class NativeLinuxBackend(NativeBackend):
    def set_address(
        self, ifname: str, family: int, *, up: bool, cidr: str | None = None
    ) -> str | None:
        return linux_admin.set_address(self.admin, ifname, family, up=up, cidr=cidr)

    def add_decoy_route(self, dest_ip: str, ifname: str) -> bool:
        # SO_BINDTODEVICE confines the route lookup despite this competing host route.
        self.admin(f"ip route add {dest_ip}/32 dev {ifname}")
        return True

    # Segments as veth pairs between per-participant network namespaces: a dut namespace holds
    # nf_source + nf_target (so the checked-in configs work unchanged), and one persistent far
    # namespace per segment holds the peer end, always named probe0. Every participant gets its
    # own namespace for the same reasons Docker gave them one: wildcard binds and --expect-none
    # windows must only see the segment's traffic, unicast to netflector must cross the wire
    # rather than short-circuit via lo, and the host's daemons (systemd-resolved speaks mDNS)
    # must not reach the test wires. Successive probe processes for a case run inside the same
    # far namespace: probes respawn, namespaces persist. The recreate cases delete and re-add
    # whole pairs (fresh kernel identities under the same names), which netflector survives
    # by reconciling its captures; the probes are immune, resolving interfaces fresh at spawn.

    def __init__(self, args: argparse.Namespace, prefix: str) -> None:
        super().__init__(args, prefix)
        self.ns = {"dut": f"{prefix}-dut", "source": f"{prefix}-src", "target": f"{prefix}-dst"}

    @staticmethod
    def require_available() -> None:
        if sys.platform != "linux":
            raise RuntimeError("the Linux native backend requires Linux (netns + veth)")
        require_command("ip")
        NativeBackend._require_native_basics()

    def _ip(self, args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return run_command(["ip", *args], **kwargs)  # type: ignore[arg-type]

    def setup_segments(self) -> None:
        for ns in self.ns.values():
            self._ip(["netns", "add", ns])
            # DAD off before any interface exists, so both the fe80:: and the ULA are usable the
            # moment they appear (the Docker backend does the same via --sysctl; here the probes
            # get it too, removing the startup race for their v6 sends).
            run_command([
                "ip", "netns", "exec", ns, "sh", "-ec",
                "echo 0 > /proc/sys/net/ipv6/conf/default/accept_dad; "
                "echo 0 > /proc/sys/net/ipv6/conf/all/accept_dad",
            ])
            self._ip(["-n", ns, "link", "set", "lo", "up"])

        for segment in SEGMENTS:
            self._setup_segment(segment)

        self._wait_carrier()

    def _setup_segment(self, segment: str) -> None:
        dut_ifname = NETFLECTOR_IFNAMES[segment]
        self._ip([
            "link", "add", dut_ifname, "netns", self.ns["dut"],
            "type", "veth", "peer", "name", RECEIVER_IFNAME, "netns", self.ns[segment],
        ])
        v4, v6 = SEGMENT_V4_SUBNET[segment], SEGMENT_V6_PREFIX[segment]
        dut, far = self.ns["dut"], self.ns[segment]
        self._ip(["-n", dut, "addr", "add", f"{v4}.{NATIVE_NETFLECTOR_HOST}/24", "dev", dut_ifname])
        self._ip(["-n", dut, "addr", "add", f"{v6}::{NATIVE_NETFLECTOR_HOST}/64", "dev", dut_ifname])
        self._ip(["-n", far, "addr", "add", f"{v4}.{HELPER_HOST}/24", "dev", RECEIVER_IFNAME])
        self._ip(["-n", far, "addr", "add", f"{v6}::{HELPER_HOST}/64", "dev", RECEIVER_IFNAME])
        self._ip(["-n", dut, "link", "set", dut_ifname, "up"])
        self._ip(["-n", far, "link", "set", RECEIVER_IFNAME, "up"])
        # The probe's 255.255.255.255 sends are routed, not interface-pinned; single-homed
        # plus this default route pins them to the segment (Docker's IPAM gateway did this).
        self._ip(["-n", far, "route", "add", "default", "dev", RECEIVER_IFNAME])

    def delete_interface(self, segment: str) -> None:
        # Deleting the dut end destroys the pair, the far probe0 included.
        self._ip(["-n", self.ns["dut"], "link", "del", NETFLECTOR_IFNAMES[segment]])

    def recreate_interface(self, segment: str) -> None:
        self._setup_segment(segment)
        self._wait_carrier()

    def add_decoy_interface(self) -> None:
        # Inert on Linux (indexes are never reused); runs to keep the case uniform.
        self._ip([
            "-n", self.ns["dut"], "link", "add", DECOY_IFNAME,
            "type", "veth", "peer", "name", f"{DECOY_IFNAME}p",
        ])

    def remove_decoy_interface(self) -> None:
        self._ip(["-n", self.ns["dut"], "link", "del", DECOY_IFNAME])

    def _wait_carrier(self) -> None:
        # A veth reports operstate "up" only once BOTH ends are up; don't start netflector
        # (or probes) on a link that hasn't settled.
        pending = [(self.ns["dut"], ifname) for ifname in NETFLECTOR_IFNAMES.values()]
        pending += [(self.ns[segment], RECEIVER_IFNAME) for segment in SEGMENTS]
        deadline = time.monotonic() + 5.0
        for ns, ifname in pending:
            while True:
                state = run_command(
                    ["ip", "netns", "exec", ns, "cat", f"/sys/class/net/{ifname}/operstate"],
                    echo=False,
                ).stdout.strip()
                if state == "up":
                    break
                if time.monotonic() > deadline:
                    raise RuntimeError(f"{ns}/{ifname} never reached operstate up (last: {state})")
                time.sleep(0.05)

    def _teardown_fabric(self) -> None:
        for ns in self.ns.values():
            run_command(["ip", "netns", "del", ns], check=False, echo=False)

    def keep_artifacts(self) -> str:
        return f"namespaces {', '.join(self.ns.values())} and logs in {self.logdir}"

    def _probe_exec(self, segment: str) -> list[str]:
        return ["ip", "netns", "exec", self.ns[segment]]

    def _netflector_command(self, config_path: Path) -> list[str]:
        return ["ip", "netns", "exec", self.ns["dut"], *self._netflector_args(config_path)]

    def admin(self, script: str, *, capture: bool = False) -> str:
        # The harness already runs as root, so netflector's network view is one netns exec
        # away -- no privileged sidecar needed.
        result = run_command(["ip", "netns", "exec", self.ns["dut"], "sh", "-ec", script])
        return result.stdout.strip() if capture else ""

    def _print_fabric_diagnostics(self) -> None:
        for ns in self.ns.values():
            result = run_command(["ip", "-n", ns, "addr", "show"], check=False, echo=False)
            if result.returncode == 0 and result.stdout:
                print(f"--- netns: {ns} ---", file=sys.stderr, flush=True)
                print(result.stdout, end="", file=sys.stderr, flush=True)
