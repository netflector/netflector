# Releasing

Three artifacts, in order: the daemon release (tag, binaries, image), the FreeBSD daemon package,
then the OPNsense plugin. The order matters: the package is built from the release, and the plugin
publish validates its rendered config against the daemon package already published.

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

## FreeBSD daemon package

After the release, point the port at it and regenerate the pinned hashes:

```sh
ci/port-sync.py --update <version>
```

Merge that to main. `publish-daemon.yml` fires on any push to main touching
`dist/freebsd/net/netflector/**`, builds the port in per-ABI FreeBSD VMs, verifies the result on
real OPNsense, and publishes the re-signed catalogue trees to the
[package repository](https://github.com/netflector/pkg).

The workflow first compares the port's `DISTVERSION` (plus `PORTREVISION`, if set) against the
published trees and skips silently when that version is already there. So a change to the port's
packaged content that does not come with a version change (an rc script edit, a new file) must bump
`PORTREVISION`, or nothing is published.

## OPNsense plugin

The OPNsense plugin releases separately: bump `PLUGIN_VERSION` in
`dist/opnsense/net/netflector/Makefile`, merge, then run `./release-os.sh` from a clean synced `main`.
It does the same local half and tags `os-v<version>`; the tag hands off to `publish-plugin.yml`, which
runs the OPNsense pipeline on the tagged commit, packages the plugin for each supported FreeBSD major
(plus the daemon when the version the port pins is not yet published) and publishes everything to the
[package repository](https://github.com/netflector/pkg).

A plugin content or metadata change ships only with a `PLUGIN_VERSION` bump: the publish is
tag-driven and the workflow refuses a tag that does not match `PLUGIN_VERSION`, so without a bump
there is no new tag to cut. `PLUGIN_REVISION` is no substitute; `release-os.sh` tags
`os-v<version>` and a revision is not part of that version.
