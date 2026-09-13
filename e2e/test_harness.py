"""Failure-path checks that cannot be exercised by a successful packet run."""

import argparse
import contextlib
import io
import unittest
from unittest.mock import Mock, patch

from cases.models import TestCase
from harness.environment import Environment
from harness.scenarios.datagram import DatagramScenario


class LifecycleTests(unittest.TestCase):
    def environment(self, backend: Mock, *, keep: bool = False) -> Environment:
        with patch("harness.environment.make_backend", return_value=backend):
            return Environment(
                argparse.Namespace(keep_on_failure=keep), "failure", "config.toml"
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


if __name__ == "__main__":
    unittest.main()
