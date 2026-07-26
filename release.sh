#!/bin/sh
set -eu

# Cut a release. From a clean main in sync with origin/main, this confirms the version, then tags
# v<version> (from Cargo.toml via version.sh) and pushes it. Pushing the tag triggers
# .github/workflows/release.yml, which runs the full CI pipeline on the tagged commit, builds the
# per-arch binaries, publishes the multi-arch image to GHCR, and creates the GitHub release. The
# version in Cargo.toml is the single source of truth; the pushed tag is re-checked against it by the
# release workflow.

cd "$(dirname "$0")"
. ./release-lib.sh

version=$(./version.sh)
tag="v${version}"

ensure_releasable
ensure_tag_absent "$tag" "bump the version in Cargo.toml first"
confirm_and_push_tag "$tag"

echo "Pushed ${tag}. The release workflow takes over from here -- it runs CI on this commit, builds"
echo "the binaries, publishes the image to GHCR, and creates the GitHub release:"
echo "  https://github.com/$(repo_slug)/actions/workflows/release.yml"
