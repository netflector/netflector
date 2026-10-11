"""Failure-path checks that cannot be exercised by a successful packet run."""

from __future__ import annotations

import argparse
import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cases.models import DialRecreateCase, Phase, TestCase
from harness.backends.freebsd import NativeFreeBSDBackend
from harness.backends.linux import NativeLinuxBackend
from harness.environment import Environment
from harness.scenarios.datagram import DatagramScenario
from harness.scenarios.dial import DialRecreateRunner
from harness.scenarios.lifecycle import AddressChangeRunner, RecreateRunner
from harness.settings import RECEIVER_READY_LOG


class LifecycleTests(unittest.TestCase):
    def environment(self, backend: Mock, *, keep: bool = False) -> Environment:
        with patch("harness.environment.make_backend", return_value=backend):
            return Environment(
                argparse.Namespace(keep_on_failure=keep, show_netflector_logs=False),
                "failure",
                "config.toml",
            )

    def test_partial_setup_failure_cleans_up_even_when_diagnostics_fail(self) -> None:
        backend = Mock()
        failure = RuntimeError("second segment failed")
        backend.setup_segments.side_effect = failure
        backend.print_diagnostics.side_effect = RuntimeError("backend unavailable")
        env = self.environment(backend)
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(RuntimeError) as caught:
                with env:
                    self.fail("setup should not enter the scenario")
        self.assertIs(caught.exception, failure)
        backend.cleanup.assert_called_once_with()
        backend.start_netflector.assert_not_called()

    def test_keep_on_failure_releases_handles_but_preserves_fabric(self) -> None:
        backend = Mock()
        env = self.environment(backend, keep=True)
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertFalse(
                env.__exit__(RuntimeError, RuntimeError("probe failed"), None)
            )
        backend.abandon.assert_called_once_with()
        backend.cleanup.assert_not_called()

    def test_a_case_fails_when_netflector_stopped_during_it(self) -> None:
        backend = Mock()
        backend.status.return_value = (False, "exited (101)")
        env = self.environment(backend)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(RuntimeError):
            env.passed("crashed")
        backend.status.assert_called_with("netflector")
        self.assertNotIn("PASS", out.getvalue())

    def test_a_case_passes_while_netflector_runs(self) -> None:
        backend = Mock()
        backend.status.return_value = (True, "running")
        env = self.environment(backend)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            env.passed("fine")
        self.assertEqual(out.getvalue(), "PASS fine\n")

    def test_negative_window_rejects_receiver_that_exited_before_sender(self) -> None:
        backend = Mock()
        backend.status.return_value = (False, "exited")
        env = self.environment(backend)
        case = TestCase(
            name="negative",
            config="config.toml",
            send_mac="00:11:22:33:44:55",
            send_port=9,
            receive_port=9,
            timeout_seconds=1.0,
            expect_mac=None,
        )
        scenario = DatagramScenario(env, case)
        with self.assertRaises(RuntimeError):
            scenario.close_expect_none_window()
        backend.stop_probe.assert_not_called()

    def silence_probe(self, receiver_stderr: str) -> bool:
        backend = Mock()
        backend.status.return_value = (False, "exited (1)")
        backend.logs.return_value = (f"{RECEIVER_READY_LOG}\n", receiver_stderr)
        runner = AddressChangeRunner(self.environment(backend), SimpleNamespace(name="change"))
        phase = Phase(label="target IPv4", protocol="mdns", family=4, interface="target")
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            return runner._probe(phase, expect=False, timeout=1.0)

    def test_a_packet_while_polling_for_silence_means_still_reflected(self) -> None:
        self.assertFalse(self.silence_probe("expected no packets, but one was received\n"))

    def test_a_receiver_that_died_otherwise_still_fails_the_silence_poll(self) -> None:
        with self.assertRaises(RuntimeError):
            self.silence_probe("Traceback (most recent call last):\n")

    def run_phases(self, runner_type: type, phases: tuple[Phase, ...], backend: Mock) -> None:
        backend.status.return_value = (True, "running")
        runner = runner_type(
            self.environment(backend), SimpleNamespace(name="change", phases=phases)
        )
        with (
            patch.object(runner_type, "_poll_reflected", return_value=True),
            patch.object(runner_type, "_poll_not_reflected", return_value=True),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            runner.run()

    def address_change_run(self, *, restore_logged: bool) -> None:
        log = ["interface nf_target: gained IPv4 198.18.0.1"]

        def set_address(ifname: str, family: int, *, up: bool, cidr: str | None) -> str:
            if not up:
                log.append(f"interface {ifname}: lost IPv4 (was 198.18.0.1)")
            elif restore_logged:
                log.append(f"interface {ifname}: gained IPv4 198.18.0.1")
            return "198.18.0.1/24"

        backend = Mock()
        backend.logs.side_effect = lambda role: ("", "".join(f"{line}\n" for line in log))
        backend.set_address.side_effect = set_address
        phase = Phase(label="target IPv4", protocol="mdns", family=4, interface="target")
        self.run_phases(AddressChangeRunner, (phase,), backend)

    def test_a_restore_logged_only_at_startup_fails_the_case(self) -> None:
        with self.assertRaises(RuntimeError):
            self.address_change_run(restore_logged=False)

    def test_a_restore_logged_after_the_change_passes(self) -> None:
        self.address_change_run(restore_logged=True)

    def recreate_run(self, *, regain_logged: bool) -> None:
        log = ["interface nf_target: gained IPv4 198.18.0.1"]

        def delete_interface(interface: str) -> None:
            log.append("interface nf_target is gone (was ifindex 3); parking until it returns")
            log.append("interface nf_target: lost IPv4 (was 198.18.0.1)")

        def recreate_interface(interface: str) -> None:
            log.append("interface nf_target: returned as ifindex 4; re-bound")
            if regain_logged:
                log.append("interface nf_target: gained IPv4 198.18.0.1")

        backend = Mock()
        backend.logs.side_effect = lambda role: ("", "".join(f"{line}\n" for line in log))
        backend.delete_interface.side_effect = delete_interface
        backend.recreate_interface.side_effect = recreate_interface
        phase = Phase(label="target recreate", protocol="mdns", family=4, interface="target")
        self.run_phases(RecreateRunner, (phase,), backend)

    def test_a_regain_logged_only_at_startup_fails_the_recreation(self) -> None:
        with self.assertRaises(RuntimeError):
            self.recreate_run(regain_logged=False)

    def test_a_recreation_logged_in_full_passes(self) -> None:
        self.recreate_run(regain_logged=True)
    def dial_recreate_run(self, eviction_reason: str) -> None:
        log: list[str] = []

        def delete_interface(interface: str) -> None:
            log.append("interface nf_target is gone (was ifindex 3); parking until it returns")
            log.append(f"dial: evicted the proxy for 198.18.1.2:8008 {eviction_reason}")

        backend = Mock()
        backend.status.return_value = (True, "running")
        backend.logs.side_effect = lambda role: ("", "".join(f"{line}\n" for line in log))
        backend.delete_interface.side_effect = delete_interface
        backend.recreate_interface.side_effect = lambda interface: log.append(
            "interface nf_target: returned as ifindex 4; re-bound"
        )
        runner = DialRecreateRunner(self.environment(backend), DialRecreateCase(name="dial"))
        with (
            patch.object(DialRecreateRunner, "_dial_pass"),
            patch.object(DialRecreateRunner, "start_device"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            runner.run()

    def test_a_dial_recreation_that_did_not_evict_the_proxy_fails(self) -> None:
        with self.assertRaises(RuntimeError):
            self.dial_recreate_run("past its grace")

    def test_a_dial_recreation_that_evicted_the_proxy_passes(self) -> None:
        self.dial_recreate_run("after its interface was unbound")


class PreflightTests(unittest.TestCase):
    def preflight(self, backend: type, outputs: dict[tuple[str, ...], str]) -> list[list[str]]:
        calls: list[list[str]] = []

        def run_command(command: list[str], **kwargs: object) -> SimpleNamespace:
            calls.append(command)
            return SimpleNamespace(stdout=outputs.get(tuple(command), ""), returncode=0)

        with (
            patch(f"{backend.__module__}.run_command", run_command),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            backend.preflight_clean()
        return calls

    def test_linux_preflight_removes_only_e2e_namespaces_and_what_runs_in_them(self) -> None:
        ns = "netflector-e2e-wol-1a2b3c4d-dut"
        calls = self.preflight(
            NativeLinuxBackend,
            {
                ("ip", "netns", "list"): f"{ns} (id: 3)\nvpn\n",
                ("ip", "netns", "pids", ns): "4242\n",
            },
        )
        self.assertLess(
            calls.index(["kill", "-KILL", "4242"]), calls.index(["ip", "netns", "del", ns])
        )
        self.assertFalse(any("vpn" in call for call in calls))

    def test_freebsd_preflight_empties_e2e_jails_before_removing_them(self) -> None:
        jail = "netflector_e2e_wol_1a2b3c4d_dut"
        calls = self.preflight(
            NativeFreeBSDBackend,
            {
                ("jls", "name"): f"{jail}\nbuild\n",
                ("jexec", jail, "ifconfig", "-l"): "lo0 nf_source nf_target\n",
            },
        )
        destroys = [call for call in calls if call[-1] == "destroy"]
        self.assertEqual(
            destroys,
            [
                ["jexec", jail, "ifconfig", "nf_source", "destroy"],
                ["jexec", jail, "ifconfig", "nf_target", "destroy"],
            ],
        )
        self.assertGreater(calls.index(["jail", "-r", jail]), calls.index(destroys[-1]))
        self.assertFalse(any("build" in call for call in calls))


if __name__ == "__main__":
    unittest.main()
