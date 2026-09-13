#!/usr/bin/env python3
"""Which lanes a change needs: changed paths on stdin, one per line; one `<lane>=true|false`
line per lane on stdout, for GITHUB_OUTPUT.

The lists are the path filters the pipelines used to carry on their own triggers. `code` is the
complement of what the code lanes ignore, so a path no pipeline claims runs them: a new directory
is tested by default, not merged untested. A trailing slash claims a whole tree."""

import sys

import platforms

# The package pins follow the OPNsense series in the catalog; listing them here would drift.
PACKAGE_PINS = tuple(platforms.views(platforms.catalog())["package-pins"])

CATALOG = (
    "ci/platforms.toml",
    "ci/platforms.py",
    "ci/test_platforms.py",
    "ci/freebsd-ci-setup.sh",
)
OPNSENSE = CATALOG + (
    "dist/opnsense/",
    ".github/workflows/ci-opnsense.yml",
    *PACKAGE_PINS,
    "ci/freebsd-port-package.sh",
    "ci/freebsd-plugin-package.sh",
    "ci/freebsd-to-opnsense.sh",
    "ci/opnsense-exercise.sh",
    # Shared with the code lanes, which never reach its OPNsense-only paths (the cloud-init
    # seed and the extra NIC), so the pipeline runs on it as well.
    "ci/freebsd-vm.sh",
    "ci/pkg-published.sh",
)
PORT = CATALOG + (
    "dist/freebsd/",
    ".github/workflows/ci-port.yml",
    # --check runs only here; the code lanes exercise --local.
    "ci/port-sync.py",
    "ci/port-install.sh",
    "ci/port-e2e.sh",
    "ci/port-into-tree.sh",
)
SUPPLY_CHAIN = (
    "Cargo.toml",
    "Cargo.lock",
    "deny.toml",
    "ci/supply-chain.env",
    "ci/supply-chain-pin.sh",
    ".github/workflows/ci-supply-chain.yml",
)
# The two distribution trees and the files only a pipeline consumes. Markdown is ignored too.
CODE_IGNORES = (
    "dist/freebsd/",
    "dist/opnsense/",
    ".github/workflows/ci-port.yml",
    "ci/port-install.sh",
    "ci/port-e2e.sh",
    "ci/port-into-tree.sh",
    ".github/workflows/ci-opnsense.yml",
    ".github/workflows/ci-supply-chain.yml",
    "ci/supply-chain-pin.sh",
    *PACKAGE_PINS,
    "ci/freebsd-port-package.sh",
    "ci/freebsd-plugin-package.sh",
    "ci/freebsd-to-opnsense.sh",
    "ci/opnsense-exercise.sh",
    "ci/pkg-published.sh",
)


def matches(path: str, patterns: tuple[str, ...]) -> bool:
    return any(path.startswith(p) if p.endswith("/") else path == p for p in patterns)


def is_code(path: str) -> bool:
    return not path.endswith(".md") and not matches(path, CODE_IGNORES)


def areas(paths: list[str]) -> dict[str, bool]:
    return {
        "code": any(is_code(p) for p in paths),
        "opnsense": any(matches(p, OPNSENSE) for p in paths),
        "port": any(matches(p, PORT) for p in paths),
        "supply-chain": any(matches(p, SUPPLY_CHAIN) for p in paths),
    }


if __name__ == "__main__":
    changed = [line.strip() for line in sys.stdin if line.strip()]
    for lane, needed in areas(changed).items():
        print(f"{lane}={'true' if needed else 'false'}")
