from __future__ import annotations

import ast
import sys
import time

from cases.models import DialAddressChangeCase, DialCase, DialRecreateCase

from fixtures import DIAL_CLIENT_SOURCE_PORT, SSDP_DIAL_MSEARCH_HEX, SSDP_PORT
from harness.environment import Environment
from harness.settings import (
    NETFLECTOR_IFNAMES,
    NETFLECTOR_SOURCE_IFNAME,
    RECEIVER_IFNAME,
)


class DialRunner:
    def __init__(
        self,
        env: Environment,
        case: DialCase | DialAddressChangeCase | DialRecreateCase,
    ) -> None:
        self.env = env
        self.dial = case
        self.client_seg, self.device_seg = (
            ("source", "target")
            if case.direction == "forward"
            else ("target", "source")
        )

    def start_device(self) -> None:
        # Single-homed on its segment: the device's HTTP endpoints are reachable only via
        # netflector's egress-pinned upstream connect, so the peer it records is netflector's
        # address on that segment -- never the client (which cannot route to the device's subnet
        # directly).
        ifname = self.env.backend.helper_ifname(RECEIVER_IFNAME)
        probe_args = [
            "dial-device",
            "--port",
            str(SSDP_PORT),
            "--join-group",
            self.dial.group,
            "--interface",
            ifname,
            "--family",
            str(self.dial.family),
            "--timeout",
            str(self.dial.timeout_seconds),
            "--serve-seconds",
            str(self.dial.serve_seconds),
        ]
        if self.dial.passive:
            probe_args.append("--notify")
        if self.dial.unreachable:
            probe_args.append("--unreachable")
        self.env.backend.start_probe("device", self.device_seg, ifname, probe_args)
        self.env.wait_for_log("device", "dial-device ready", "dial-device")

    def _client_args(
        self, netflector_authority: str, device_authority: str
    ) -> list[str]:
        # The client is single-homed on its segment. It is told netflector's address there (what
        # the rewritten authorities must point at) and the device's true address (which must never
        # leak through a rewrite).
        ifname = self.env.backend.helper_ifname(NETFLECTOR_IFNAMES[self.client_seg])
        probe_args = [
            "dial-client",
            "--port",
            str(SSDP_PORT),
            "--address",
            self.dial.group,
            "--interface",
            ifname,
            "--family",
            str(self.dial.family),
            "--timeout",
            str(self.dial.timeout_seconds),
            "--netflector-authority",
            netflector_authority,
            "--device-authority",
            device_authority,
        ]
        if self.dial.passive:
            # Listen for the relayed NOTIFY instead of sending an M-SEARCH.
            probe_args.append("--passive")
        else:
            probe_args += [
                "--source-port",
                str(DIAL_CLIENT_SOURCE_PORT),
                "--payload-hex",
                SSDP_DIAL_MSEARCH_HEX,
            ]
        if self.dial.unreachable:
            # The device's upstream is dead; the fetch must fail.
            probe_args.append("--expect-fetch-failure")
        return probe_args

    def run_client(self) -> None:
        device_ip = self.env.backend.probe_ip("device", self.device_seg)
        refl_client_side_ip = self.env.backend.netflector_ip(self.client_seg)
        ifname = self.env.backend.helper_ifname(NETFLECTOR_IFNAMES[self.client_seg])
        self.env.backend.start_probe(
            "client",
            self.client_seg,
            ifname,
            self._client_args(refl_client_side_ip, device_ip),
        )

    def wait_for_client(self) -> None:
        exit_code = self.env.backend.wait("client")
        out, err = self.env.backend.logs("client")
        if out:
            print(out, end="", flush=True)
        if err:
            print(err, end="", file=sys.stderr, flush=True)
        if exit_code != 0:
            raise RuntimeError(f"dial-client failed with exit code {exit_code}")

    def assert_device_verdicts(self) -> None:
        # Two device-side checks: (1) the device exits non-zero if any request reached it with a
        # Host that was not rewritten to its own authority (netflector must rewrite Host
        # client->device); (2) netflector's upstream connect is egress-pinned to the device's
        # interface, so the only peer the device recorded must be exactly netflector's address there.
        refl_target_ip = self.env.backend.netflector_ip(self.device_seg)
        exit_code = self.env.backend.wait("device")
        out, err = self.env.backend.logs("device")
        if out:
            print(out, end="", flush=True)
        if err:
            print(err, end="", file=sys.stderr, flush=True)
        if exit_code != 0:
            raise RuntimeError(
                f"dial-device failed with exit code {exit_code} "
                f"(a request reached it with an unrewritten Host)"
            )
        marker = "dial-device upstream peers seen: "
        line = next((ln for ln in out.splitlines() if marker in ln), None)
        if line is None:
            raise RuntimeError("dial-device did not report the upstream peers it saw")
        seen = ast.literal_eval(line.split(marker, 1)[1].strip())
        if seen != [refl_target_ip]:
            raise RuntimeError(
                f"device saw upstream peers {seen}, expected only netflector's "
                f"{self.device_seg}-side address [{refl_target_ip!r}] (egress not pinned)"
            )
        print(
            f"dial: every request's Host was rewritten to the device, and every upstream connection came "
            f"from netflector's {self.device_seg}-side address {refl_target_ip}",
            flush=True,
        )

    def _force_upstream_egress_ambiguity(self) -> None:
        # Make the upstream egress pin load-bearing. The device is single-homed on the target
        # segment, so netflector's connect reaches it via target_if by routing alone, and
        # SO_BINDTODEVICE (TcpSocket PinEgress) would be untestable -- assert_device_verdicts'
        # "peer == netflector target_if address" passes even if the pin were dropped. Plant a
        # more-specific host route to the device via the WRONG interface (the client's side): an
        # unpinned connect now follows it, ARPs the device on the client's segment (where it does
        # not live) and fails, so the whole DIAL flow breaks. Only the egress pin -- which
        # constrains the route lookup to the device's interface -- still reaches the device, so
        # PASS now requires it. (FreeBSD declines: no pin primitive there, see
        # Backend.add_decoy_route.)
        device_ip = self.env.backend.probe_ip("device", self.device_seg)
        if not self.env.backend.add_decoy_route(
            device_ip, NETFLECTOR_IFNAMES[self.client_seg]
        ):
            print(
                f"{self.dial.name}: no egress-pin primitive on this backend; decoy route skipped",
                flush=True,
            )

    def run(self) -> None:
        self.start_device()  # must be serving before the client searches
        if not self.dial.unreachable:
            # The unreachable case asserts a PROMPT connect failure; a decoy route would change
            # the failure mode (ARP timeout vs refused), so only arm the ambiguity where we
            # assert success.
            self._force_upstream_egress_ambiguity()
        self.run_client()
        self.wait_for_client()  # client-side verdict: rewrites (or, for unreachable, the expected fail)
        if self.dial.unreachable:
            self.env.backend.wait(
                "device"
            )  # no HTTP server in this mode: nothing to assert
            out, _ = self.env.backend.logs("device")
            if out:
                print(out, end="", flush=True)
        else:
            self.assert_device_verdicts()  # device-side verdict: Host rewrite + egress-pinned upstream
        if self.dial.expect_echoed:
            if self.env.backend.ECHOES_OWN_FRAMES:
                self.env.wait_for_log(
                    "netflector", "echoed=", "netflector echo counter"
                )
            else:
                out, err = self.env.backend.logs("netflector")
                if "echoed=" in out + err:
                    raise RuntimeError(
                        f"{self.dial.name}: echoes on a fabric that hands no frame back"
                    )
        print(f"PASS {self.dial.name}", flush=True)
        if self.env.args.show_netflector_logs:
            time.sleep(0.5)
            self.env.print_netflector_logs()


class DialAddressChangeRunner(DialRunner):
    # A DIAL pass, then the same pass after netflector's source IPv4 changes, then after its
    # target IPv4 changes -- each to a different same-subnet address. The device stays up (passive
    # NOTIFY + HTTP) across all three; a fresh client runs each pass. _set_address (base) does the
    # change in netflector's network view; netflector reacts on its own event loop, so each
    # change waits for the "gained IPv4 <new>" log before the next pass.
    def _different_cidr(self, cidr: str) -> str:
        # A different host on the same subnet: both backends hand out low addresses (Docker IPAM
        # .2, .3, ...; the native plan .1/.2), so .222 is free (and .221 if the interface somehow
        # already holds .222).
        host, prefix = cidr.split("/")
        octets = host.split(".")
        octets[-1] = "222" if octets[-1] != "222" else "221"
        return f"{'.'.join(octets)}/{prefix}"

    def _change_v4(self, interface: str) -> str:
        # Replace netflector's IPv4 on `interface` with a different same-subnet address, then
        # wait for netflector to observe it -- which is when 7d evicts the now-stale proxy.
        # Returns the new host.
        old_cidr = self.env.set_address(
            interface, 4, up=False
        )  # del old, capture its CIDR
        new_cidr = self._different_cidr(old_cidr)
        self.env.set_address(
            interface, 4, up=True, cidr=new_cidr
        )  # add the different one
        new_host = new_cidr.split("/")[0]
        print(
            f"{self.dial.name}: {interface} IPv4 {old_cidr} -> {new_cidr}", flush=True
        )
        self.env.wait_for_log(
            "netflector", f"gained IPv4 {new_host}", f"{interface} IPv4 change"
        )
        return new_host

    def _dial_pass(
        self, label: str, netflector_authority: str, device_authority: str
    ) -> None:
        # One full DIAL flow through netflector from a fresh client, asserting every rewrite
        # points at `netflector_authority` (netflector's CURRENT source IPv4) and never leaks
        # `device_authority`.
        role = f"client-{label.replace(' ', '-')}"
        ifname = self.env.backend.helper_ifname(NETFLECTOR_SOURCE_IFNAME)
        self.env.backend.start_probe(
            role,
            "source",
            ifname,
            self._client_args(netflector_authority, device_authority),
        )
        exit_code = self.env.backend.wait(role)
        out, err = self.env.backend.logs(role)
        if out:
            print(out, end="", flush=True)
        if err:
            print(err, end="", file=sys.stderr, flush=True)
        if exit_code != 0:
            raise RuntimeError(
                f"{self.dial.name}: DIAL pass '{label}' failed with exit code {exit_code}"
            )
        print(
            f"{self.dial.name}: DIAL pass '{label}' succeeded (rewrites -> {netflector_authority})",
            flush=True,
        )

    def run(self) -> None:
        self.start_device()  # passive: advertises NOTIFY + serves HTTP for serve_seconds
        device_ip = self.env.backend.probe_ip("device", "target")
        source_ip = self.env.backend.netflector_ip("source")

        # Baseline, then re-run after each interface's IPv4 moves to a different address. A
        # passing re-run requires 7d to have evicted the proxy bound to the vanished address.
        self._dial_pass("baseline", source_ip, device_ip)
        source_ip = self._change_v4("source")
        self._dial_pass("after source IPv4 change", source_ip, device_ip)
        self._change_v4("target")  # the source authority is unchanged by a target move
        self._dial_pass("after target IPv4 change", source_ip, device_ip)

        print(f"PASS {self.dial.name}", flush=True)
        if self.env.args.show_netflector_logs:
            time.sleep(0.5)
            self.env.print_netflector_logs()


class DialRecreateRunner(DialAddressChangeRunner):
    # See DialRecreateCase. Inherits the pass machinery; only the mutation differs: instead of
    # replacing addresses, it destroys and recreates one netflector interface (optionally behind a
    # decoy), synchronized on the daemon's own parking/recreation log lines.

    def _recreate(self, interface: str) -> None:
        ifname = NETFLECTOR_IFNAMES[interface]
        self.env.backend.delete_interface(interface)
        self.env.wait_for_log(
            "netflector", f"interface {ifname} is gone", f"{interface} deletion"
        )
        if self.dial.decoy:
            self.env.backend.add_decoy_interface()
        self.env.backend.recreate_interface(interface)
        self.env.wait_for_log(
            "netflector",
            f"interface {ifname}: returned as ifindex",
            f"{interface} recreation",
        )
        if self.dial.decoy:
            self.env.backend.remove_decoy_interface()

    def run(self) -> None:
        self.start_device()  # passive: advertises NOTIFY + serves HTTP
        device_ip = self.env.backend.probe_ip("device", "target")
        source_ip = self.env.backend.netflector_ip("source")

        self._dial_pass("baseline", source_ip, device_ip)

        # Recreate one interface; the baseline's proxy -- listeners on the source, egress-pin and
        # target-address snapshot on the target -- must be evicted and the fresh pass re-mint.
        interface = self.dial.interface
        self._recreate(interface)
        if interface == "target":
            # The device sits on the target segment: on the native fabrics its wire died with the
            # interface (Docker keeps its endpoint; a fresh device is harmless and uniform).
            self.env.backend.remove("device")
            self.start_device()
            device_ip = self.env.backend.probe_ip("device", "target")
        else:
            source_ip = self.env.backend.netflector_ip(
                "source"
            )  # re-pinned to the same address
        self._dial_pass(f"after {interface} recreation", source_ip, device_ip)

        print(f"PASS {self.dial.name}", flush=True)
        if self.env.args.show_netflector_logs:
            time.sleep(0.5)
            self.env.print_netflector_logs()
