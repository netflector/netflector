"""Own one isolated test environment: processes, readiness, diagnostics, and cleanup."""

from __future__ import annotations

import argparse
import sys
import time
import uuid

from harness.backends import make_backend
from harness.settings import (
    CONTAINER_READY_TIMEOUT_SECONDS,
    E2E_DIR,
    E2E_RESOURCE_PREFIX,
    NETFLECTOR_READY_LOG,
    NETFLECTOR_SOURCE_IFNAME,
    NETFLECTOR_TARGET_IFNAME,
    VALGRIND_STOP_GRACE_SECONDS,
)


class Environment:
    def __init__(self, args: argparse.Namespace, name: str, config: str) -> None:
        self.args = args
        self.name = name
        self.prefix = (
            f"{E2E_RESOURCE_PREFIX}{name.replace('_', '-')}-{uuid.uuid4().hex[:8]}"
        )
        self.backend = make_backend(args, self.prefix)
        self.config_path = E2E_DIR / config

    def __enter__(self) -> Environment:
        print(f"\n=== {self.name} ===", flush=True)
        try:
            self.backend.setup_segments()
            self.start_netflector()
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        if exc_type is not None:
            try:
                self.print_diagnostics()
            except Exception as diagnostic_error:
                # A broken backend can prevent log collection too. Preserve the original failure
                # and still release anything created before setup or the scenario failed.
                print(
                    f"diagnostics failed: {diagnostic_error}",
                    file=sys.stderr,
                    flush=True,
                )

        if exc_type is not None and self.args.keep_on_failure:
            self.backend.abandon()
            print(
                f"keeping resources for failed case {self.name}: {self.backend.keep_artifacts()}",
                flush=True,
            )
            return False

        self.backend.cleanup()
        return False

    def check_netflector_valgrind(self) -> None:
        # SIGTERM netflector so it shuts down cleanly and valgrind runs its leak analysis, then
        # read its exit code: the image's --error-exitcode=1 fires on any leak, leaked fd, or
        # memcheck error.
        exit_code = self.backend.stop_netflector(VALGRIND_STOP_GRACE_SECONDS)
        if exit_code != 0:
            print(
                f"\n--- valgrind report: {self.name} ---", file=sys.stderr, flush=True
            )
            _, err = self.backend.logs("netflector")
            if err:
                print(err, end="", file=sys.stderr, flush=True)
            raise RuntimeError(
                f"valgrind reported errors in case {self.name} (netflector exited {exit_code})"
            )

    def start_netflector(self) -> None:
        self.backend.start_netflector(self.config_path)
        self.wait_for_netflector()

    def wait_for_log(
        self, role: str, marker: str, description: str, count: int = 1
    ) -> None:
        deadline = time.monotonic() + CONTAINER_READY_TIMEOUT_SECONDS
        last_state = "unknown"
        while time.monotonic() < deadline:
            out, err = self.backend.logs(role)
            if f"{out}{err}".count(marker) >= count:
                return

            running, state = self.backend.status(role)
            if state != "unknown":
                last_state = state
            if not running:
                raise RuntimeError(
                    f"{description} exited before becoming ready: {last_state}"
                )

            time.sleep(0.1)

        raise RuntimeError(
            f"timed out waiting for {description} readiness marker ({marker}); last state: {last_state}"
        )

    def wait_for_netflector(self) -> None:
        self.wait_for_log("netflector", NETFLECTOR_READY_LOG, "netflector")

    def wait_for_result(self, role: str = "receiver") -> None:
        exit_code = self.backend.wait(role)
        out, err = self.backend.logs(role)
        if out:
            print(out, end="", flush=True)
        if err:
            print(err, end="", file=sys.stderr, flush=True)

        if exit_code != 0:
            raise RuntimeError(f"{role} failed with exit code {exit_code}")

    def print_netflector_logs(self) -> None:
        out, err = self.backend.logs("netflector")
        print(f"--- netflector logs: {self.name} ---", flush=True)
        if out:
            print(out, end="", flush=True)
        if err:
            print(err, end="", file=sys.stderr, flush=True)
        if not out and not err:
            print("<empty>", flush=True)

    def set_address(
        self, interface: str, family: int, *, up: bool, cidr: str | None = None
    ) -> str | None:
        # Bring one (interface, family) source address down or back up; the verbs live in the
        # backend (Linux vs FreeBSD). Returns the removed v4 CIDR so the caller can restore it.
        ifname = (
            NETFLECTOR_SOURCE_IFNAME
            if interface == "source"
            else NETFLECTOR_TARGET_IFNAME
        )
        return self.backend.set_address(ifname, family, up=up, cidr=cidr)

    def print_diagnostics(self) -> None:
        print(
            f"\n--- diagnostics for {self.name} ({self.prefix}) ---",
            file=sys.stderr,
            flush=True,
        )
        self.backend.print_diagnostics()
