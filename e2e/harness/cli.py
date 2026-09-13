"""Argument parsing and orchestration for the E2E harness."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cases import ALL_CASES
from cases.models import (
    AddressChangeCase,
    AnswerCase,
    DialAddressChangeCase,
    DialCase,
    DialRecreateCase,
    RecreateCase,
    RoundTripCase,
    SearchRecreateCase,
    TestCase,
)

from fixtures import CONFIGURED_MAC, magic_packet_hex
from harness.backends import native_backend_class
from harness.backends.docker import DockerBackend
from harness.commands import CommandError, docker
from harness.environment import Environment
from harness.scenarios import make_runner
from harness.settings import (
    DEFAULT_HELPER_IMAGE,
    DEFAULT_NETFLECTOR_IMAGE,
    VALGRIND_NETFLECTOR_IMAGE,
)


def build_netflector_image(image: str, target: str | None = None) -> None:
    target_args = ["--target", target] if target is not None else []
    docker(["build", *target_args, "-t", image, "."], capture=False)


def select_cases(case_names: list[str]) -> list[
        TestCase | RoundTripCase | SearchRecreateCase | DialCase | DialAddressChangeCase
        | AddressChangeCase | RecreateCase | DialRecreateCase | AnswerCase]:
    if not case_names:
        return ALL_CASES

    cases_by_name = {case.name: case for case in ALL_CASES}
    unknown = sorted(set(case_names) - set(cases_by_name))
    if unknown:
        available = ", ".join(sorted(cases_by_name))
        raise RuntimeError(f"unknown e2e case(s): {', '.join(unknown)}. Available cases: {available}")

    return [cases_by_name[name] for name in case_names]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run netflector e2e tests (Docker or native backend)")
    parser.add_argument("--backend", choices=["docker", "native"], default="docker",
        help="execution environment: Docker bridge networks + containers, or (Linux, root) "
             "netns + veth pairs + plain processes (default: docker)")
    parser.add_argument("--image", default=DEFAULT_NETFLECTOR_IMAGE,
        help="netflector image tag to run (default: netflector:e2e; docker backend only)")
    parser.add_argument("--skip-build", action="store_true",
        help="use --image without building it first (docker backend only)")
    parser.add_argument("--valgrind", action="store_true",
        help="run netflector under Valgrind memcheck (the runtime-valgrind image; fails on any leak, fd leak, or memcheck error)")
    parser.add_argument("--helper-image", default=DEFAULT_HELPER_IMAGE,
        help="Python image used for UDP probes (docker backend only)")
    parser.add_argument("--binary", type=Path, default=None,
        help="netflector binary to run (native backend, required); build it unprivileged first, "
             "e.g. cargo build --release --locked")
    parser.add_argument("--no-join", action="store_true",
        help="run netflector with --no-join (native backend); for a fabric whose kernel cannot join "
             "groups but delivers their frames regardless, such as qemu-user")
    parser.add_argument("--keep-on-failure", action="store_true", help="leave resources behind after a failure")
    parser.add_argument("--keep-stale", action="store_true",
        help="skip the preflight sweep, keeping what an earlier --keep-on-failure run left behind")
    parser.add_argument("--show-netflector-logs", action="store_true", help="print netflector logs after each passing case")
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        choices=[case.name for case in ALL_CASES],
        help="e2e case to run; may be passed more than once",
    )
    args = parser.parse_args()

    if args.backend == "native" and args.valgrind:
        parser.error("--valgrind is not supported with --backend native yet")
    if args.backend == "native" and args.binary is None:
        # No implicit `cargo build` here: the native harness runs as root, so a build would leave
        # root-owned target/ artifacts -- or die outright, since sudo's PATH lacks a rustup cargo.
        parser.error("--backend native requires --binary; build unprivileged first "
                     "(cargo build --release --locked)")
    if args.backend == "docker" and args.binary is not None:
        parser.error("--binary only applies to --backend native")
    if args.backend == "docker" and args.no_join:
        parser.error("--no-join only applies to --backend native")
    return args


def main() -> int:
    args = parse_args()
    backend_cls = native_backend_class() if args.backend == "native" else DockerBackend
    backend_cls.require_available()
    if args.backend == "docker":
        # --valgrind selects the valgrind image unless one was passed explicitly.
        if args.valgrind and args.image == DEFAULT_NETFLECTOR_IMAGE:
            args.image = VALGRIND_NETFLECTOR_IMAGE
    if not args.keep_stale:
        backend_cls.preflight_clean()

    cases = select_cases(args.case)
    print(f"expected magic payload: {magic_packet_hex(CONFIGURED_MAC)}", flush=True)

    if args.backend == "native":
        # Resolve now, against the invoker's cwd: the spawns run with cwd=REPO_ROOT, so a relative
        # path that validated here would otherwise point somewhere else at exec time.
        args.binary = args.binary.resolve()
        if not args.binary.is_file():
            raise RuntimeError(f"netflector binary not found: {args.binary}")
    elif not args.skip_build:
        build_netflector_image(
            args.image, "runtime-valgrind" if args.valgrind else None
        )

    for case in cases:
        with Environment(args, case.name, case.config) as env:
            runner = make_runner(env, case)
            runner.run()
            if args.valgrind:
                env.check_netflector_valgrind()

    suffix = " under valgrind" if args.valgrind else ""
    print(f"\nPASS {len(cases)} e2e case(s){suffix}", flush=True)
    return 0


def entrypoint() -> None:
    try:
        raise SystemExit(main())
    except CommandError as exc:
        print(str(exc), file=sys.stderr)
        if exc.result.stdout:
            print(exc.result.stdout, end="", file=sys.stderr)
        if exc.result.stderr:
            print(exc.result.stderr, end="", file=sys.stderr)
        raise SystemExit(1)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
