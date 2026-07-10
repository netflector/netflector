#!/usr/bin/env bash
# Set up cross-linking to x86_64-unknown-freebsd on a Linux runner. rustup
# provides the target's std (tier 2), so the only missing pieces are FreeBSD's
# link inputs -- crt*.o and the libc/libm/... archives, extracted from the
# official base.txz -- and a cc driver to order them on the link line; clang
# is inherently a cross-compiler and lld is FreeBSD's own system linker, so a
# two-line wrapper is the entire toolchain. Same recipe rust-lang's CI uses to
# build the official freebsd dist artifacts.
#
# The release + base.txz hash pins live in ci/freebsd.env (Renovate bumps the
# release, ci/freebsd-pin.sh refreshes the hashes).
set -euo pipefail

. "$(dirname "$0")/freebsd.env"
SYSROOT=${FREEBSD_SYSROOT:-$HOME/freebsd-sysroot}

mkdir -p "$SYSROOT"
curl -fsSL "https://download.freebsd.org/releases/amd64/${RELEASE}-RELEASE/base.txz" \
    -o "$SYSROOT/base.txz"
echo "$BASE_SHA256  $SYSROOT/base.txz" | sha256sum -c - || {
    echo "error: base.txz hash mismatch; after a release bump, run ci/freebsd-pin.sh" >&2
    exit 1
}
# Only the link inputs: ./lib holds the runtime .so the /usr/lib linker
# scripts point into, ./usr/lib the crt objects and static archives. No
# ./usr/include -- the crate compiles no C. The warning knob: base.txz
# stores BSD file flags (schg on libc and friends) in SCHILY.fflags pax
# headers, which GNU tar can't apply; a sysroot only needs the contents.
tar --warning=no-unknown-keyword -xJf "$SYSROOT/base.txz" -C "$SYSROOT" ./lib ./usr/lib
rm "$SYSROOT/base.txz"

# cargo invokes the linker without --target (cargo#10863), so bake it into a
# wrapper; the versioned triple sets __FreeBSD__ and picks the right crt set.
# rustc passes -no-pie assuming a PIE-default toolchain; FreeBSD-targeting
# clang is non-PIE already and warns the flag is unused, so silence that.
mkdir -p "$SYSROOT/bin"
cat > "$SYSROOT/bin/freebsd-clang" <<EOF
#!/bin/sh
exec clang --target=x86_64-unknown-freebsd${RELEASE%%.*} --sysroot=$SYSROOT -fuse-ld=lld \\
    -Wno-unused-command-line-argument "\$@"
EOF
chmod +x "$SYSROOT/bin/freebsd-clang"
echo "FreeBSD $RELEASE sysroot at $SYSROOT; linker: $SYSROOT/bin/freebsd-clang"
