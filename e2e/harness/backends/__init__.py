"""Select Docker or the native operating-system backend."""

from __future__ import annotations

import argparse
import sys

from harness.backends.base import Backend
from harness.backends.docker import DockerBackend
from harness.backends.freebsd import NativeFreeBSDBackend
from harness.backends.linux import NativeLinuxBackend
from harness.backends.native import NativeBackend


def native_backend_class() -> type[NativeBackend]:
    # "native" resolves to the platform's one possible fabric: a native backend is host-bound,
    # so a per-OS flag value would only add ways to ask for the impossible.
    if sys.platform == "linux":
        return NativeLinuxBackend
    if sys.platform.startswith("freebsd"):
        return NativeFreeBSDBackend
    raise RuntimeError(f"--backend native is not supported on {sys.platform} (Linux and FreeBSD are)")


def make_backend(args: argparse.Namespace, prefix: str) -> Backend:
    if args.backend == "native":
        return native_backend_class()(args, prefix)
    return DockerBackend(args, prefix)
