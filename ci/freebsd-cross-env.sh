#!/usr/bin/env bash
# Prepare one target's sysroot and export its linker/runner to later GitHub steps.
# RUSTFLAGS stay lane-specific: static release assets use the oldest baseline,
# dynamic test lanes use the running kernel's major. Host proc-macros are untouched.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
triple=$(python3 "$here/platforms.py" --freebsd "${FREEBSD_SYSROOT_ARCH:?set FREEBSD_SYSROOT_ARCH}" --field triple)
: "${GITHUB_ENV:?this helper exports to GITHUB_ENV}"
rustup target add "$triple"
"$here/freebsd-sysroot.sh"
prefix="CARGO_TARGET_$(echo "$triple" | tr 'a-z-' 'A-Z_')"
{
    echo "${prefix}_LINKER=$HOME/freebsd-sysroot/bin/freebsd-clang"
    echo "${prefix}_RUNNER=$here/freebsd-ssh-runner.sh"
} >> "$GITHUB_ENV"
