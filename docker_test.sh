#!/usr/bin/env bash
# Run cargo on Linux inside Docker, so cfg(linux)-only code — the epoll poll
# backend now, the AF_PACKET capture path later — actually compiles and runs from
# the macOS dev host. Everything after the script name is forwarded to `cargo`;
# with no args it runs the test suite.
#
#   ./docker_test.sh                                       # cargo test
#   ./docker_test.sh test epoll                            # filter to epoll tests
#   ./docker_test.sh clippy --all-targets -- -D warnings   # Linux clippy/lints
#
# Named volumes hold the Linux target dir (so the macOS ./target is untouched),
# the crate registry, and the rustup home -- the last so the pinned toolchain's
# rustfmt/clippy components (absent from rust:slim) download once, not every run.
# The capture layer will later need raw-socket privileges -- add `--cap-add=NET_RAW`
# here when those tests land.
set -euo pipefail
cd "$(dirname "$0")"

[ "$#" -eq 0 ] && set -- test

exec docker run --rm \
    -v "$PWD":/reflector \
    -v reflector-linux-target:/linux-target \
    -v reflector-cargo-registry:/usr/local/cargo/registry \
    -v reflector-rustup:/usr/local/rustup \
    -e CARGO_TARGET_DIR=/linux-target \
    -w /reflector \
    rust:slim \
    cargo "$@"
