# Developing

Working on netflector itself: the test suites, the platform-gated code, and what CI runs. For
building and running the daemon, see the [README](README.md).

## Platform-gated code

The platform backends are `cfg(target_os)`-gated (rtnetlink/epoll/`AF_PACKET` on Linux,
`getifaddrs`/kqueue/BPF on macOS and FreeBSD), so the other OS's code isn't built on the host. To
exercise the Linux paths from a macOS/FreeBSD dev box, `./docker_test.sh` forwards to `cargo` inside a
`rust:slim` container:

```sh
./docker_test.sh test                                  # cargo test on Linux
./docker_test.sh clippy --all-targets -- -D warnings   # Linux lints
```

## Tests

```sh
cargo test                 # the unit suite
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo doc --no-deps --document-private-items   # the rustdoc intra-doc link gate
```

A subset of tests does privileged work (real packet capture, or binding a socket to an interface) and
needs the same privileges netflector itself does (see
[Runtime privileges](README.md#runtime-privileges)). Each probes for the privilege and self-skips
cleanly when it's missing, so a default `cargo test` run is green on an under-privileged box.

## End-to-end tests

The end-to-end suite drives the real data path: netflector straddles two isolated network segments
and the suite verifies traffic is reflected, multi-protocol. It runs on two backends. The default
`docker` backend uses bridge networks and containers; it's opt-in (it builds/runs containers and
creates temporary Docker networks):

```sh
python3 e2e/run.py                # build the image and run the full suite
python3 e2e/run.py --valgrind     # run the daemon under Valgrind memcheck
python3 e2e/run.py --case reflects_matching_magic_packet   # one case
```

`--valgrind` runs netflector under memcheck (the `runtime-valgrind` image: a glibc release binary
with debug symbols) and fails the run on any leak, leaked fd, or memcheck error. The runner builds
`netflector:e2e` by default, uses `python:3.13-alpine` for UDP-probe containers, can print netflector logs
with `--show-netflector-logs`, and leaves resources behind on failure with `--keep-on-failure`.

The `native` backend runs the same cases without Docker, as root: network namespaces + veth pairs on
Linux, vnet jails + epair(4) on FreeBSD (one namespace/jail per participant either way). Build the
binary first; the harness never runs cargo as root:

```sh
cargo build --release --locked
sudo python3 e2e/run.py --backend native --binary target/release/netflector
```

## CI

CI runs the unit suite on Ubuntu 24.04 (amd64 and arm64, both glibc and the shipped static musl),
macOS 15, FreeBSD 14 and 15 (amd64 and arm64, cross-compiled on the runner and executed in QEMU VMs), and
the cross-compiled `linux/arm/v7` and `linux/arm/v5` builds whose suites run under QEMU, each in both
debug and release. `clippy` and the rustdoc link gate run per target. The e2e suite runs on the
Docker backend for both image arches (plus a Valgrind memcheck job) and natively on linux amd64/arm64
(glibc and musl), armv7/armv5 (daemon under qemu-user), and FreeBSD amd64/arm64.
