#!/usr/bin/env bash
# Run cargo on Linux inside Docker, so cfg(linux)-only code (the epoll backend, the AF_PACKET
# capture path) actually compiles and runs from the macOS dev host. Everything after the script
# name is forwarded to `cargo`; with no args it runs the test suite.
#
#   ./docker_test.sh                                       # cargo test
#   ./docker_test.sh test pair_                            # the root-gated interface-pair tests
#   ./docker_test.sh clippy --all-targets -- -D warnings   # Linux clippy/lints
#
# Named volumes hold the Linux target dir (so the macOS ./target is untouched), the crate
# registry, and the rustup home -- the last so the pinned toolchain's rustfmt/clippy components
# (absent from rust:slim) download once, not every run.
#
# The root-gated tests (interface pairs, captures) need more than a stock `docker run`:
#   NET_ADMIN   create and destroy the veth pair
#   NET_RAW     open AF_PACKET captures, join multicast groups
#   --sysctl    the pair needs accept_local (both ends share one stack, so wire-crossing v4
#               packets carry a local source that fib_validate_source would drop as martian).
#               It is ORCONF (conf/all OR conf/<iface>), so presetting `all` here covers the
#               veths the fixture creates later. Do NOT reach for `systempaths=unconfined` to
#               make /proc/sys writable instead: that also unmasks /proc/sysrq-trigger (a write
#               there panics the HOST) and /proc/kcore (the live kernel memory image).
# rust:slim also ships no `ip`, and without it the veth fixture skips every pair test instead of
# failing, so the image adds iproute2. The layer is cached, so later runs pay nothing for it.
set -euo pipefail
cd "$(dirname "$0")"

[ "$#" -eq 0 ] && set -- test

IMAGE=netflector-devtest
docker build -q -t "$IMAGE" - >/dev/null <<'DOCKERFILE'
FROM rust:slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*
DOCKERFILE

exec docker run --rm \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --sysctl net.ipv4.conf.all.accept_local=1 \
    -v "$PWD":/netflector \
    -v netflector-linux-target:/linux-target \
    -v netflector-cargo-registry:/usr/local/cargo/registry \
    -v netflector-rustup:/usr/local/rustup \
    -e CARGO_TARGET_DIR=/linux-target \
    -w /netflector \
    "$IMAGE" \
    cargo "$@"
