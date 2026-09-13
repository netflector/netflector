"""Bounded subprocess execution and command diagnostics."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from harness.settings import COMMAND_TIMEOUT_SECONDS, REPO_ROOT


class CommandError(RuntimeError):
    def __init__(self, command: list[str], result: subprocess.CompletedProcess[str]) -> None:
        self.command = command
        self.result = result
        super().__init__(f"command failed with exit code {result.returncode}: {format_command(command)}")


class CommandTimeout(RuntimeError):
    def __init__(self, command: list[str], timeout: float) -> None:
        self.command = command
        super().__init__(f"command hung for {timeout:g}s: {format_command(command)}")


def format_command(command: list[str]) -> str:
    return " ".join(command)


def run_command(
    command: list[str],
    *,
    cwd: Path = REPO_ROOT,
    check: bool = True,
    capture: bool = True,
    echo: bool = True,
    timeout: float = COMMAND_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    if echo:
        print(f"+ {format_command(command)}", flush=True)
    stdout = subprocess.PIPE if capture else None
    stderr = subprocess.PIPE if capture else None
    proc = subprocess.Popen(command, cwd=cwd, text=True, stdout=stdout, stderr=stderr)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        dump_stack(proc.pid)
        proc.kill()
        proc.communicate()
        raise CommandTimeout(command, timeout) from None
    result = subprocess.CompletedProcess(command, proc.returncode, out, err)
    if check and result.returncode != 0:
        raise CommandError(command, result)
    return result


def dump_stack(pid: int) -> None:
    """Print what `pid` is blocked on, best-effort.

    Linux exposes the wait channel through /proc, readable without root and untruncated, unlike the
    six characters `ps` prints (`hrtime` vs `hrtimer_nanosleep`). FreeBSD has no such procfs but does
    have procstat, whose kernel stack is better still. `ps` covers whatever is left; its `wchan:32`
    spelling would fix the truncation but BSD ps rejects it.
    """
    wchan = Path(f"/proc/{pid}/wchan")
    if wchan.exists():
        state = ""
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("State:"):
                state = line
        print(f"--- hung pid {pid} ---\n{state}\nwchan: {wchan.read_text()}", flush=True)
        return
    for probe in (["procstat", "-kk", str(pid)], ["ps", "-o", "pid,stat,wchan,args", "-p", str(pid)]):
        try:
            out = subprocess.run(probe, text=True, capture_output=True, timeout=15, check=False)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if out.returncode == 0 and out.stdout.strip():
            print(f"--- {probe[0]} for the hung pid {pid} ---\n{out.stdout}", flush=True)
            return
    print(f"--- no stack available for the hung pid {pid} ---", flush=True)


def docker(
    args: list[str],
    *,
    check: bool = True,
    capture: bool = True,
    echo: bool = True,
) -> subprocess.CompletedProcess[str]:
    return run_command(["docker", *args], check=check, capture=capture, echo=echo)


def require_command(command: str) -> None:
    if shutil.which(command) is None:
        raise RuntimeError(f"required command not found: {command}")
