from __future__ import annotations

import time

from cases.models import TestCase

from fixtures import RELAY_SOURCE_PORT
from harness.environment import Environment
from harness.settings import (
    EXPECT_NONE_BACKSTOP_SECONDS,
    EXPECT_NONE_FLIGHT_SECONDS,
    NETFLECTOR_SOURCE_IFNAME,
    NETFLECTOR_TARGET_IFNAME,
    PROBE_STOP_GRACE_SECONDS,
    RECEIVER_IFNAME,
    RECEIVER_READY_LOG,
    SEGMENT_V4_SUBNET,
)


class DatagramScenario:
    def __init__(self, env: Environment, case: TestCase) -> None:
        self.env = env
        self.case = case
        self._select_direction(case.direction)

    def _select_direction(self, direction: str) -> None:
        # The sender lives on the segment the traffic originates from and the receiver on the
        # other; "reverse" swaps which is which. The receiver's interface is pinned so the probe
        # can join the multicast group on it. Lifecycle scenarios create a traffic scenario for
        # each phase, whose direction can differ from the preceding phase.
        if direction == "reverse":
            self.sender_segment, self.sender_ifname = "target", NETFLECTOR_TARGET_IFNAME
            self.receiver_segment = "source"
        else:
            self.sender_segment, self.sender_ifname = "source", NETFLECTOR_SOURCE_IFNAME
            self.receiver_segment = "target"
        self.receiver_ifname = RECEIVER_IFNAME

    def start_receiver(self) -> None:
        case = self.case
        ifname = self.env.backend.helper_ifname(self.receiver_ifname)
        expect_none = case.expect_payload_hex is None and case.expect_mac is None
        probe_args = [
            "receive",
            "--port",
            str(case.receive_port),
            "--timeout",
            # A positive receiver exits on its packet, so its window is the failure deadline. A
            # negative one is closed by the harness at the send instead (see close_expect_none_window).
            str(EXPECT_NONE_BACKSTOP_SECONDS if expect_none else case.timeout_seconds),
        ]
        if case.expect_payload_hex is not None:
            probe_args.extend(["--expect-payload-hex", case.expect_payload_hex])
        elif case.expect_mac is not None:
            probe_args.extend(["--expect-mac", case.expect_mac])
        else:
            probe_args.append("--expect-none")

        probe_args.extend(["--family", str(case.family)])
        if case.expect_unicast:
            address = self.env.backend.helper_address(
                self.receiver_segment, case.family
            )
            probe_args.extend(["--bind-address", address])
        elif case.group is not None:
            probe_args.extend(["--join-group", case.group, "--interface", ifname])
        if case.expect_routable_source:
            probe_args.append("--expect-source-not-link-local")
        if case.expect_source_preserved:
            # v4 only: a send to a link-local v6 group is sourced from the sender's fe80::.
            subnet = f"{SEGMENT_V4_SUBNET[self.sender_segment]}.0/24"
            probe_args.extend(
                [
                    "--expect-source-net",
                    subnet,
                    "--expect-source-port",
                    str(RELAY_SOURCE_PORT),
                ]
            )

        self.env.backend.start_probe(
            "receiver",
            self.receiver_segment,
            ifname,
            probe_args,
            pin_address=case.expect_unicast,
        )
        self.wait_for_receiver()

    def wait_for_receiver(self) -> None:
        self.env.wait_for_log("receiver", RECEIVER_READY_LOG, "receiver")

    def run_sender(self) -> None:
        case = self.case
        if case.send_payload_hex is not None:
            payload_args = ["--payload-hex", case.send_payload_hex]
        elif case.send_mac is not None:
            payload_args = ["--mac", case.send_mac]
        else:
            raise RuntimeError(f"case {case.name} has no send payload")

        ifname = self.env.backend.helper_ifname(self.sender_ifname)
        source_port = (
            RELAY_SOURCE_PORT if case.expect_source_preserved else case.send_source_port
        )
        source_args = (
            ["--source-port", str(source_port)] if source_port is not None else []
        )
        self.env.backend.start_probe(
            "sender",
            self.sender_segment,
            ifname,
            [
                "send",
                *payload_args,
                *source_args,
                "--port",
                str(case.send_port),
                "--address",
                case.send_address,
                "--interface",
                ifname,
            ],
            detach=False,
        )

    def close_expect_none_window(self) -> None:
        # The sender has exited, so the packet -- if the daemon were going to relay one -- is either
        # already delivered or in flight. Give it that flight time, then stop the receiver and let it
        # report. Bounding the window by the send rather than by a fixed timeout is what keeps the
        # assertion from going vacuous when container startup outruns it, as it does under valgrind.
        running, state = self.env.backend.status("receiver")
        if not running:
            raise RuntimeError(
                f"receiver stopped before the sender finished ({state}); the expect-none result "
                f"would be vacuous"
            )
        time.sleep(EXPECT_NONE_FLIGHT_SECONDS)
        self.env.backend.stop_probe("receiver", PROBE_STOP_GRACE_SECONDS)

    def run(self) -> None:
        self.start_receiver()
        self.run_sender()
        if self.case.expect_payload_hex is None and self.case.expect_mac is None:
            self.close_expect_none_window()
        self.env.wait_for_result()
        if self.case.expect_netflector_log is not None:
            self.env.wait_for_log(
                "netflector", self.case.expect_netflector_log, "netflector log line"
            )
        print(f"PASS {self.case.name}", flush=True)
        if self.env.args.show_netflector_logs:
            time.sleep(0.5)
            self.env.print_netflector_logs()
