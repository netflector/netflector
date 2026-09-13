from __future__ import annotations

import argparse
import sys
from pathlib import Path

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


class NativeFreeBSDBackend(NativeBackend):
    # Segments as epair(4) pairs -- FreeBSD's veth -- between persistent vnet jails, one per
    # participant, mirroring the Linux namespaces: a dut jail holds the renamed a ends
    # (nf_source/nf_target), each probe jail owns a b end (renamed probe0). A vnet jail is
    # FreeBSD's network namespace: its own stack, with interfaces, routes, PF_ROUTE events,
    # and /dev/bpf attachment all per-vnet, and the host filesystem shared via path=/. Per-jail
    # stacks keep every probe packet on the wire (nothing short-circuits over lo0), and jailing
    # the daemon too means its interface monitor hears only test-interface events -- the same
    # shape as the Linux dut namespace.

    def __init__(self, args: argparse.Namespace, prefix: str) -> None:
        super().__init__(args, prefix)
        # Jail names: play safe with the allowed character set.
        base = prefix.replace("-", "_")
        self.jails = {"dut": f"{base}_dut", "source": f"{base}_src", "target": f"{base}_dst"}
        # The host-side end of a live decoy epair (see add_decoy_interface), for teardown.
        self._decoy_host_end: str | None = None
        # Every epair a end ever created, by its raw name, so teardown can reach a pair that a
        # setup failure stranded before its rename.
        self._epair_a_ends: list[str] = []

    @staticmethod
    def require_available() -> None:
        if not sys.platform.startswith("freebsd"):
            raise RuntimeError("the FreeBSD native backend requires FreeBSD (epair + vnet jails)")
        for command in ("ifconfig", "jail", "jexec", "sysctl"):
            require_command(command)
        NativeBackend._require_native_basics()
        vimage = run_command(["sysctl", "-n", "kern.features.vimage"], check=False, echo=False)
        if vimage.returncode != 0 or vimage.stdout.strip() != "1":
            raise RuntimeError("--backend native requires a VIMAGE kernel (vnet jails); "
                               "stock GENERIC has it since FreeBSD 12")

    def _make_jail(self, jail: str, *interfaces: str) -> None:
        # persist keeps the (process-less) jail alive; each vnet.interface moves that interface
        # into its stack; path=/ shares the host filesystem, so the pkg python3 and probe.py
        # are visible inside without building a jail root. DAD off before any address, as on
        # the other backends; a fresh vnet starts with lo0 down.
        run_command([
            "jail", "-c", f"name={jail}", "persist", "vnet",
            *[f"vnet.interface={ifname}" for ifname in interfaces], "path=/",
        ])
        run_command(["jexec", jail, "sysctl", "net.inet6.ip6.dad_count=0"])
        run_command(["jexec", jail, "ifconfig", "lo0", "up"])

    def _create_epair(self) -> tuple[str, str]:
        a_end = run_command(["ifconfig", "epair", "create"]).stdout.strip()
        if not a_end.endswith("a"):
            raise RuntimeError(f"unexpected epair name: {a_end}")
        self._epair_a_ends.append(a_end)
        return a_end, f"{a_end[:-1]}b"

    def setup_segments(self) -> None:
        ends = {}
        for segment in SEGMENTS:
            ends[segment] = self._create_epair()

        dut = self.jails["dut"]
        self._make_jail(dut, *(a_end for a_end, _ in ends.values()))
        for segment in SEGMENTS:
            a_end, b_end = ends[segment]
            self._make_jail(self.jails[segment], b_end)
            self._configure_segment(segment, a_end, b_end)

    def _configure_segment(self, segment: str, a_end: str, b_end: str) -> None:
        # The epair ends already sit inside the dut/far jails; rename, address, and route them.
        dut_ifname = NETFLECTOR_IFNAMES[segment]
        jexec_dut = ["jexec", self.jails["dut"]]
        jexec_far = ["jexec", self.jails[segment]]
        run_command([*jexec_dut, "ifconfig", a_end, "name", dut_ifname])
        run_command([*jexec_far, "ifconfig", b_end, "name", RECEIVER_IFNAME])
        v4, v6 = SEGMENT_V4_SUBNET[segment], SEGMENT_V6_PREFIX[segment]
        run_command([*jexec_dut, "ifconfig", dut_ifname, "inet", f"{v4}.{NATIVE_NETFLECTOR_HOST}/24"])
        run_command([*jexec_dut, "ifconfig", dut_ifname, "inet6", f"{v6}::{NATIVE_NETFLECTOR_HOST}/64"])
        run_command([*jexec_dut, "ifconfig", dut_ifname, "up"])
        run_command([*jexec_far, "ifconfig", RECEIVER_IFNAME, "inet", f"{v4}.{HELPER_HOST}/24"])
        run_command([*jexec_far, "ifconfig", RECEIVER_IFNAME, "inet6", f"{v6}::{HELPER_HOST}/64"])
        run_command([*jexec_far, "ifconfig", RECEIVER_IFNAME, "up"])
        # The probe's 255.255.255.255 sends are routed, not interface-pinned; single-homed
        # plus this default route pins them to the segment.
        run_command([*jexec_far, "route", "add", "default", "-interface", RECEIVER_IFNAME])

    def delete_interface(self, segment: str) -> None:
        # Destroying the dut end tears down the pair, the far probe0 included.
        run_command(["jexec", self.jails["dut"], "ifconfig", NETFLECTOR_IFNAMES[segment], "destroy"])

    def recreate_interface(self, segment: str) -> None:
        # A fresh epair, moved into the LIVE jails -- setup assigns interfaces at jail
        # creation (vnet.interface=...); this is the move-into-a-running-vnet path -- then
        # configured exactly as setup did.
        a_end, b_end = self._create_epair()
        run_command(["ifconfig", a_end, "vnet", self.jails["dut"]])
        run_command(["ifconfig", b_end, "vnet", self.jails[segment]])
        self._configure_segment(segment, a_end, b_end)

    def add_decoy_interface(self) -> None:
        # The move into the dut vnet is what occupies the freed index there: FreeBSD's
        # per-vnet allocator hands the mover the lowest free slot, exactly where the deleted
        # interface sat. The b end stays on the host (destroyed with the pair later).
        a_end, b_end = self._create_epair()
        run_command(["ifconfig", a_end, "vnet", self.jails["dut"]])
        run_command(["jexec", self.jails["dut"], "ifconfig", a_end, "name", DECOY_IFNAME])
        self._decoy_host_end = b_end

    def remove_decoy_interface(self) -> None:
        # Destroying the dut-side end tears down the pair, the host b end included.
        run_command(["jexec", self.jails["dut"], "ifconfig", DECOY_IFNAME, "destroy"])
        self._decoy_host_end = None

    def _teardown_fabric(self) -> None:
        # Destroy the a ends (from inside the dut jail) first: killing one end tears down the
        # whole pair, including the b end inside its probe jail -- so no jail removal can return
        # a probe0 to a stack where the other jail's probe0 already sits.
        for ifname in NETFLECTOR_IFNAMES.values():
            run_command(["jexec", self.jails["dut"], "ifconfig", ifname, "destroy"],
                        check=False, echo=False)
        # A setup failure before the renames strands pairs under their raw epair names, on the
        # host or already inside the dut jail; try both, either end tears down the pair.
        for a_end in self._epair_a_ends:
            run_command(["jexec", self.jails["dut"], "ifconfig", a_end, "destroy"],
                        check=False, echo=False)
            run_command(["ifconfig", a_end, "destroy"], check=False, echo=False)
        if self._decoy_host_end is not None:  # a case failed mid-decoy; free the pair
            run_command(["ifconfig", self._decoy_host_end, "destroy"], check=False, echo=False)
        for jail in self.jails.values():
            run_command(["jail", "-r", jail], check=False, echo=False)

    def keep_artifacts(self) -> str:
        return f"jails {', '.join(self.jails.values())} (+ their epairs) and logs in {self.logdir}"

    def _probe_exec(self, segment: str) -> list[str]:
        return ["jexec", self.jails[segment]]

    def _netflector_command(self, config_path: Path) -> list[str]:
        return ["jexec", self.jails["dut"], *self._netflector_args(config_path)]

    def admin(self, script: str, *, capture: bool = False) -> str:
        result = run_command(["jexec", self.jails["dut"], "sh", "-ec", script])
        return result.stdout.strip() if capture else ""

    def set_address(self, ifname: str, family: int, *, up: bool, cidr: str | None = None) -> str | None:
        # The base implementation's semantics in ifconfig verbs. v6 down deletes every address
        # (the monitor sees RTM_DELADDR and the resolver a family with no source); v6 up
        # regenerates the auto link-local by toggling ifdisabled.
        if family == 6:
            if up:
                self.admin(f"ifconfig {ifname} inet6 ifdisabled; ifconfig {ifname} inet6 -ifdisabled")
            else:
                self.admin(
                    f"for a in $(ifconfig {ifname} inet6 | awk '/inet6/{{print $2}}'); do "
                    f"ifconfig {ifname} inet6 ${{a%%\\%*}} delete; done"
                )
            return None
        if up:
            if cidr is None:
                raise RuntimeError("restoring an IPv4 address requires the CIDR captured on removal")
            self.admin(f"ifconfig {ifname} inet {cidr}")
            return cidr
        captured = self.admin(
            f"ifconfig -f inet:cidr {ifname} inet | awk '/inet /{{print $2; exit}}'", capture=True
        )
        if not captured:
            raise RuntimeError(f"no IPv4 address on {ifname} to remove")
        self.admin(f"ifconfig {ifname} inet {captured.split('/')[0]} -alias")
        return captured

    def add_decoy_route(self, dest_ip: str, ifname: str) -> bool:
        # No egress-pin primitive on FreeBSD (see Backend.add_decoy_route): the pin under test
        # there is the source-address bind, which the device-peer assertion validates on its own.
        del dest_ip, ifname
        return False

    def _print_fabric_diagnostics(self) -> None:
        result = run_command(["ifconfig", "-a"], check=False, echo=False)
        if result.returncode == 0 and result.stdout:
            print("--- host ifconfig -a ---", file=sys.stderr, flush=True)
            print(result.stdout, end="", file=sys.stderr, flush=True)
        for jail in self.jails.values():
            result = run_command(["jexec", jail, "ifconfig", "-a"], check=False, echo=False)
            if result.returncode == 0 and result.stdout:
                print(f"--- jail {jail} ifconfig -a ---", file=sys.stderr, flush=True)
                print(result.stdout, end="", file=sys.stderr, flush=True)
