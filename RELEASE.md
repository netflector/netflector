# Releasing

## Daemon

The `[package]` version in `Cargo.toml` is the single source of truth: `version.sh` extracts it, and
`release.sh` (the git tag), the published image tag, and the GitHub release name all derive from it. To
cut a release:

- Bump the version in `Cargo.toml`, refresh `Cargo.lock` (`cargo build` updates its `netflector`
  entry; CI builds `--locked`, so a stale lockfile fails the release), and merge it to `origin/main`.
- From a clean `main` in sync with `origin/main`, run `./release.sh`.

`./release.sh` does only the local half: it prints the detected version and asks for confirmation, then
tags `v<version>` and pushes it. Pushing the tag hands off to the `release.yml` workflow, which does
everything else: it runs the full CI pipeline on the tagged commit and checks that the tag matches
`Cargo.toml`, builds the per-arch binaries (Linux amd64/arm64/armv7/armv5, macOS arm64, FreeBSD
amd64/arm64), publishes the multi-arch image to GHCR, and creates the GitHub release
with the binaries and their `SHA256SUMS` attached and generated notes.

For the image, each arch builds on its own runner and the digests are stitched into one manifest.
amd64 and arm64 have native runners, so those layers link with rustc's default linker rather than
cross-linking with `lld`; only armv7 and armv5, which have no native runner, cross-compile.

## OPNsense plugin

The OPNsense plugin releases separately: bump `PLUGIN_VERSION` in
`dist/opnsense/net/netflector/Makefile`, merge, then run `./release-os.sh` from a clean synced `main`.
It does the same local half and tags `os-v<version>`; the tag hands off to `publish-plugin.yml`, which
runs the OPNsense pipeline on the tagged commit, packages the plugin for each supported FreeBSD major
(plus the daemon when the version the port pins is not yet published) and publishes everything to the
[package repository](https://github.com/netflector/pkg).
