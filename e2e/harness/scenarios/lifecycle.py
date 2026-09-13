from __future__ import annotations

import time

from cases.lifecycle import PROBE_SPECS
from cases.models import AddressChangeCase, Phase, RecreateCase, TestCase

from fixtures import CONFIGURED_MAC, MDNS_PORT, MDNS_RESPONSE_HEX
from harness.environment import Environment
from harness.scenarios.datagram import DatagramScenario
from harness.settings import (
    ADDR_CHANGE_POLL_DEADLINE,
    ADDR_CHANGE_REFLECTED_WINDOW,
    ADDR_CHANGE_SILENCE_CONSECUTIVE,
    EXPECT_NONE_BACKSTOP_SECONDS,
    NETFLECTOR_IFNAMES,
    NETFLECTOR_SOURCE_IFNAME,
    NETFLECTOR_TARGET_IFNAME,
)


class AddressChangeRunner:
    # Proves the dynamic family bring-up/teardown end to end: with a dual-family reflector
    # running, knock out one (interface, family) source address at a time and verify -- with real
    # traffic, not logs -- that reflection of exactly that family stops, then resumes once the
    # address returns. netflector reacts on its own event loop after the netlink notification,
    # so every check polls across that async window. All phases probe forward (source -> target).
    def __init__(
        self, env: Environment, case: AddressChangeCase | RecreateCase
    ) -> None:
        self.env = env
        self.ac = case

    def _phase_case(self, phase: Phase, *, expect: bool, timeout: float) -> TestCase:
        spec = PROBE_SPECS[phase.protocol]
        is_wol = phase.protocol == "wol"
        # A direction stops when its re-emit (egress) interface loses the family -- the reliable,
        # guaranteed mechanism (the per-packet egress send-gate). The target is the egress for
        # forward queries (source->target); the source is the egress for reverse responses
        # (target->source). So probe the direction whose egress is the knocked-out interface.
        # (The ingress-membership path can't be exercised here: our raw capture taps below the IP
        # membership filter and both fabrics flood multicast, so losing the ingress membership
        # never blinds it.)
        reverse = not is_wol and phase.interface == "source"
        direction = "reverse" if reverse else "forward"
        group = None if is_wol else (spec["group_v6"] if phase.family == 6 else spec["group_v4"])
        # mDNS queries flow forward, responses reverse: send the kind the probed direction relays.
        payload = None if is_wol else (MDNS_RESPONSE_HEX if reverse else spec["payload"])
        return TestCase(
            name=self.ac.name,
            send_port=spec["port"],
            receive_port=spec["port"],
            expect_mac=(CONFIGURED_MAC if (expect and is_wol) else None),
            timeout_seconds=timeout,
            send_mac=(CONFIGURED_MAC if is_wol else None),
            send_payload_hex=payload,
            send_source_port=(MDNS_PORT if reverse else None),
            family=phase.family,
            direction=direction,
            group=group,
            expect_payload_hex=(payload if (expect and not is_wol) else None),
        )

    def _probe(self, phase: Phase, *, expect: bool, timeout: float) -> bool:
        # One round trip: (re)start a fresh receiver and sender for the phase's family/group,
        # then report whether the receiver saw the expected packet within `timeout`.
        self.env.backend.remove("receiver")
        self.env.backend.remove("sender")
        case = self._phase_case(phase, expect=expect, timeout=timeout)
        probe = DatagramScenario(self.env, case)
        probe.start_receiver()
        probe.run_sender()
        if not expect:
            probe.close_expect_none_window()
        return self.env.backend.wait("receiver") == 0

    def _poll_reflected(self, phase: Phase) -> bool:
        deadline = time.monotonic() + ADDR_CHANGE_POLL_DEADLINE
        while time.monotonic() < deadline:
            if self._probe(phase, expect=True, timeout=ADDR_CHANGE_REFLECTED_WINDOW):
                return True
        return False

    def _poll_not_reflected(self, phase: Phase) -> bool:
        # Poll until the daemon has reacted to the address change: while reflection is still up the
        # probe sees the packet and fails --expect-none, resetting the streak. Each probe now spans
        # its own send, so a silence is evidence rather than a window that may have missed it.
        deadline = time.monotonic() + ADDR_CHANGE_POLL_DEADLINE
        consecutive = 0
        while time.monotonic() < deadline:
            if self._probe(phase, expect=False, timeout=EXPECT_NONE_BACKSTOP_SECONDS):
                consecutive += 1
                if consecutive >= ADDR_CHANGE_SILENCE_CONSECUTIVE:
                    return True
            else:
                consecutive = 0
        return False

    def _run_phase(self, phase: Phase) -> None:
        desc = f"{self.ac.name} / {phase.label}"
        print(f"--- phase: {desc} ({phase.protocol} IPv{phase.family}) ---", flush=True)

        if not self._poll_reflected(phase):
            raise RuntimeError(f"{desc}: no baseline reflection before the change")
        print(f"{desc}: baseline reflected", flush=True)

        cidr = self.env.set_address(phase.interface, phase.family, up=False)
        if not self._poll_not_reflected(phase):
            raise RuntimeError(
                f"{desc}: reflection continued after the {phase.interface} IPv{phase.family} "
                f"address was removed"
            )
        print(f"{desc}: reflection stopped after address removal", flush=True)

        self.env.set_address(phase.interface, phase.family, up=True, cidr=cidr)
        if not self._poll_reflected(phase):
            raise RuntimeError(
                f"{desc}: reflection did not resume after the {phase.interface} IPv{phase.family} "
                f"address was restored"
            )
        print(f"{desc}: reflection resumed after address restore", flush=True)

    def _assert_address_changes_logged(self) -> None:
        # Full-parity log check (the Rust equivalent of the C++'s capability-down assertion):
        # every phase removed then restored a source address, so netflector's InterfaceMonitor
        # must have logged both transitions -- with the monitor off it logs neither. And no
        # reflect-failure WARN may appear: a send attempted on an addressless egress would mean
        # the per-packet gate failed to catch the drop.
        out, err = self.env.backend.logs("netflector")
        text = f"{out}\n{err}"
        for phase in self.ac.phases:
            ifname = (
                NETFLECTOR_SOURCE_IFNAME
                if phase.interface == "source"
                else NETFLECTOR_TARGET_IFNAME
            )
            family = f"IPv{phase.family}"
            for verb in ("lost", "gained"):
                needle = f"interface {ifname}: {verb} {family}"
                if needle not in text:
                    raise RuntimeError(
                        f'{self.ac.name}: netflector never logged "{needle}" -- the interface monitor '
                        f"did not observe the change"
                    )
        if "cannot reflect" in text:
            raise RuntimeError(
                f"{self.ac.name}: netflector logged a reflect failure -- a send was attempted on an "
                f"addressless egress (the gate did not catch the drop)"
            )

    def run(self) -> None:
        for phase in self.ac.phases:
            self._run_phase(phase)
        self._assert_address_changes_logged()
        print(f"PASS {self.ac.name}", flush=True)
        if self.env.args.show_netflector_logs:
            time.sleep(0.5)
            self.env.print_netflector_logs()


class RecreateRunner(AddressChangeRunner):
    # Proves interface hot-swap recovery end to end: destroy and recreate one netflector-side
    # interface (same name and addresses, fresh kernel identity -- a PPPoE reconnect or bridge
    # rebuild in miniature) and verify with real traffic that reflection through it resumes
    # once the reconcile re-binds the capture. Inherits the probe/poll machinery; only the
    # mutation (delete/recreate instead of address toggles), the always-forward probe
    # direction, and the log assertion differ.

    def _phase_case(self, phase: Phase, *, expect: bool, timeout: float) -> TestCase:
        # Always probe forward, with the query payload: the recreated interface is the forward
        # ingress (source phase) or the forward egress (target phase); the base runner's
        # egress-derived direction flip does not apply.
        spec = PROBE_SPECS[phase.protocol]
        return TestCase(
            name=self.ac.name,
            send_port=spec["port"],
            receive_port=spec["port"],
            expect_mac=None,
            timeout_seconds=timeout,
            send_payload_hex=spec["payload"],
            family=phase.family,
            direction="forward",
            group=spec["group_v6"] if phase.family == 6 else spec["group_v4"],
            expect_payload_hex=(spec["payload"] if expect else None),
        )

    def _run_phase(self, phase: Phase) -> None:
        desc = f"{self.ac.name} / {phase.label}"
        print(f"--- phase: {desc} ({phase.protocol} IPv{phase.family}) ---", flush=True)

        if not self._poll_reflected(phase):
            raise RuntimeError(f"{desc}: no baseline reflection before the recreation")
        print(f"{desc}: baseline reflected", flush=True)

        self.env.backend.delete_interface(phase.interface)
        if phase.decoy:
            # Occupy the freed index before the recreation claims it (see Phase.decoy).
            self.env.backend.add_decoy_interface()
        if self.env.backend.PROBES_SURVIVE_DELETE:
            if not self._poll_not_reflected(phase):
                raise RuntimeError(
                    f"{desc}: reflection continued after the {phase.interface} interface was "
                    f"deleted"
                )
            print(f"{desc}: reflection stopped after interface deletion", flush=True)
        else:
            # The segment's wire died with the interface, so there is nothing to probe on. Wait
            # for netflector to say it parked: the name must not return before it noticed the
            # departure, or it would (correctly) log only the recreation.
            print(f"{desc}: segment wire gone; skipping the silence probe", flush=True)
            ifname = NETFLECTOR_IFNAMES[phase.interface]
            self.env.wait_for_log(
                "netflector",
                f"interface {ifname} is gone",
                f"{phase.interface} parking",
            )

        self.env.backend.recreate_interface(phase.interface)
        if phase.decoy:
            self.env.backend.remove_decoy_interface()
        if not self._poll_reflected(phase):
            raise RuntimeError(
                f"{desc}: reflection did not resume after the {phase.interface} interface was "
                f"recreated"
            )
        print(f"{desc}: reflection resumed after interface recreation", flush=True)

    def _assert_recreations_logged(self) -> None:
        # netflector must have observed each phase as a real hot-swap, in its parts: the
        # parking line when the interface vanished, the address losses parking implies (the
        # egress gate closing), the recreation line when its capture re-bound, and the address
        # gains of the re-resolve. Their absence would mean reflection "recovered" some other
        # way than the reconcile.
        out, err = self.env.backend.logs("netflector")
        text = f"{out}\n{err}"
        for phase in self.ac.phases:
            ifname = NETFLECTOR_IFNAMES[phase.interface]
            needles = (
                f"interface {ifname} is gone",
                f"interface {ifname}: returned as ifindex",
                f"interface {ifname}: lost IPv4",
                f"interface {ifname}: gained IPv4",
            )
            for needle in needles:
                if needle not in text:
                    raise RuntimeError(
                        f'{self.ac.name}: netflector never logged "{needle}" -- the reconcile '
                        f"did not drive the recovery"
                    )

    def run(self) -> None:
        for phase in self.ac.phases:
            self._run_phase(phase)
        self._assert_recreations_logged()
        print(f"PASS {self.ac.name}", flush=True)
        if self.env.args.show_netflector_logs:
            time.sleep(0.5)
            self.env.print_netflector_logs()
