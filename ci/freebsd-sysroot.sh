#!/usr/bin/env bash
# Set up cross-linking to <arch>-unknown-freebsd on a Linux runner (arch from
# FREEBSD_SYSROOT_ARCH, required: amd64 or arm64). rustup provides the target's std, so the
# only missing pieces are FreeBSD's link inputs -- crt*.o and the
# libc/libm/... archives, extracted from the official base.txz -- and a cc
# driver to order them on the link line; clang is inherently a
# cross-compiler and lld is FreeBSD's own system linker, so a two-line
# wrapper is the entire toolchain. Same recipe rust-lang's CI uses to build
# the official freebsd dist artifacts.
#
# The release + base.txz hash pins live in ci/freebsd<major>.env (Renovate bumps the
# release, ci/freebsd-pin.sh refreshes the hashes).
set -euo pipefail

# FREEBSD_SYSROOT_VERSION picks the pinned release (major) the sysroot is built from;
# each has a freebsd<major>.env.
VERSION=${FREEBSD_SYSROOT_VERSION:?set FREEBSD_SYSROOT_VERSION to a pinned major, e.g. 14 or 15}
. "$(dirname "$0")/freebsd${VERSION}.env"
ARCH=${FREEBSD_SYSROOT_ARCH:?set FREEBSD_SYSROOT_ARCH to amd64 or arm64}
case "$ARCH" in
amd64)
    BASE_URL=$BASE_URL_AMD64
    BASE_SHA=$BASE_SHA256_AMD64
    TRIPLE=x86_64-unknown-freebsd
    ;;
arm64)
    BASE_URL=$BASE_URL_ARM64
    BASE_SHA=$BASE_SHA256_ARM64
    TRIPLE=aarch64-unknown-freebsd
    ;;
*)
    echo "error: unknown FREEBSD_SYSROOT_ARCH '$ARCH' (amd64|arm64)" >&2
    exit 64
    ;;
esac
SYSROOT=$HOME/freebsd-sysroot

mkdir -p "$SYSROOT"
curl -fsSL "$BASE_URL" -o "$SYSROOT/base.txz"
echo "$BASE_SHA  $SYSROOT/base.txz" | sha256sum -c - || {
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
exec clang --target=${TRIPLE}${RELEASE%%.*} --sysroot=$SYSROOT -fuse-ld=lld \\
    -Wno-unused-command-line-argument "\$@"
EOF
chmod +x "$SYSROOT/bin/freebsd-clang"
echo "FreeBSD $RELEASE $ARCH sysroot at $SYSROOT; linker: $SYSROOT/bin/freebsd-clang"
