from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

from harness.backends.base import Backend
from harness.commands import format_command
from harness.settings import (
    E2E_DIR,
    HELPER_HOST,
    NATIVE_NETFLECTOR_HOST,
    RECEIVER_IFNAME,
    REPO_ROOT,
    SEGMENT_V4_SUBNET,
)


class NativeBackend(Backend):
    # Shared mechanics for the native fabrics (Linux netns, FreeBSD vnet jails): participants
    # are plain processes with stdout/stderr teed to per-role files in a case tmpdir (the
    # docker-logs replacement), and addressing follows the fixed plan above instead of IPAM
    # discovery. Subclasses provide the fabric: segment construction/teardown, the exec prefix
    # that places a probe in a segment's stack, and netflector's launch.
    #
    # Fidelity gap vs the docker backend: netflector runs here with the harness's full root
    # privileges, not the CAP_NET_RAW-only confinement of the scratch container -- a change that
    # grows a privilege requirement passes natively and only fails in the docker lane. CI runs
    # both, so the docker lane stays the privilege-contract gate.

    def __init__(self, args: argparse.Namespace, prefix: str) -> None:
        super().__init__(args, prefix)
        self.procs: dict[str, subprocess.Popen[bytes]] = {}
        self.logdir = Path(tempfile.mkdtemp(prefix=f"{prefix}-"))

    @staticmethod
    def require_available() -> None:
        raise NotImplementedError

    @staticmethod
    def _require_native_basics() -> None:
        if os.geteuid() != 0:
            raise RuntimeError("--backend native requires root (fabric setup, raw sockets)")
        # probe.py catches socket timeouts as TimeoutError, which socket.timeout only aliases
        # from 3.10 on; the docker backend pins python:3.13 but here probes run on this
        # interpreter.
        if sys.version_info < (3, 10):
            raise RuntimeError("--backend native requires Python >= 3.10")

    def _probe_exec(self, segment: str) -> list[str]:
        # The command prefix that places a probe process in `segment`'s network stack.
        raise NotImplementedError

    def _netflector_command(self, config_path: Path) -> list[str]:
        raise NotImplementedError

    def _netflector_args(self, config_path: Path) -> list[str]:
        flags = ["--no-join"] if self.args.no_join else []
        return [str(self.args.binary), *flags, str(config_path)]

    def _teardown_fabric(self) -> None:
        raise NotImplementedError

    def _print_fabric_diagnostics(self) -> None:
        raise NotImplementedError

    def _kill_procs(self) -> None:
        for proc in self.procs.values():
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        self.procs.clear()

    def cleanup(self) -> None:
        self._kill_procs()
        self._teardown_fabric()
        shutil.rmtree(self.logdir, ignore_errors=True)

    def abandon(self) -> None:
        # Keep the fabric and logs, but don't leave root daemons running unwatched.
        self._kill_procs()

    def _spawn(self, role: str, command: list[str]) -> None:
        self.remove(role)
        print(f"+ {format_command(command)}", flush=True)
        # Scrub NETFLECTOR_* so the daemon sees only its config file, as it would in the docker
        # backend's clean container env -- a stray host NETFLECTOR_LOG_LEVEL (or worse, an env
        # reflector entry) must not alter the system under test.
        env = {key: value for key, value in os.environ.items() if not key.startswith("NETFLECTOR_")}
        out = open(self.logdir / f"{role}.out", "wb")
        err = open(self.logdir / f"{role}.err", "wb")
        try:
            self.procs[role] = subprocess.Popen(command, cwd=REPO_ROOT, stdout=out, stderr=err, env=env)
        finally:
            out.close()
            err.close()

    def start_netflector(self, config_path: Path) -> None:
        self._spawn("netflector", self._netflector_command(config_path))

    def start_probe(
        self, role: str, segment: str, ifname: str, probe_args: list[str], *,
        detach: bool = True, pin_address: bool = False,
    ) -> None:
        del ifname  # the far end is always probe0; the caller got that from helper_ifname()
        del pin_address  # the fabric gives every probe the planned address
        command = [*self._probe_exec(segment), sys.executable, str(E2E_DIR / "probe.py"), *probe_args]
        self._spawn(role, command)
        if not detach:
            code = self.procs[role].wait()
            if code != 0:
                out, err = self.logs(role)
                raise RuntimeError(f"{role} failed with exit code {code}\n{out}{err}")

    def helper_ifname(self, requested: str) -> str:
        del requested
        return RECEIVER_IFNAME

    def wait(self, role: str) -> int:
        return self.procs[role].wait()

    def logs(self, role: str) -> tuple[str, str]:
        def read(suffix: str) -> str:
            path = self.logdir / f"{role}.{suffix}"
            return path.read_text(errors="replace") if path.exists() else ""

        return read("out"), read("err")

    def status(self, role: str) -> tuple[bool, str]:
        proc = self.procs.get(role)
        if proc is None:
            return True, "unknown"
        if proc.poll() is None:
            return True, "running"
        return False, f"exited {proc.returncode}"

    def remove(self, role: str) -> None:
        proc = self.procs.pop(role, None)
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait()

    def stop_netflector(self, grace_seconds: int) -> int:
        proc = self.procs["netflector"]
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=grace_seconds)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        return proc.returncode

    def stop_probe(self, role: str, grace_seconds: int) -> None:
        proc = self.procs.get(role)
        if proc is None or proc.poll() is not None:
            return
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    def netflector_ip(self, segment: str) -> str:
        return f"{SEGMENT_V4_SUBNET[segment]}.{NATIVE_NETFLECTOR_HOST}"

    def probe_ip(self, role: str, segment: str) -> str:
        del role  # one helper per segment; the plan gives them all the same host number
        return f"{SEGMENT_V4_SUBNET[segment]}.{HELPER_HOST}"

    def print_diagnostics(self) -> None:
        for logfile in sorted(self.logdir.iterdir()):
            text = logfile.read_text(errors="replace")
            if text:
                print(f"--- logs: {logfile.name} ---", file=sys.stderr, flush=True)
                print(text, end="", file=sys.stderr, flush=True)
        self._print_fabric_diagnostics()
