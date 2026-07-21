#!/bin/sh
set -eu

# Cut a release. From a clean main in sync with origin/main, this confirms the version, waits for CI
# (ci.yml) to pass on HEAD, then tags v<version> (from Cargo.toml via version.sh) and pushes it. Gating on
# CI here means a release is never cut on a commit whose CI is red or still running. Pushing the tag
# triggers .github/workflows/release.yml, which re-checks CI, builds the per-arch binaries, publishes the
# multi-arch image to GHCR, and creates the GitHub release. The version in Cargo.toml is the single source
# of truth; the pushed tag is re-checked against it by the release workflow. Requires the gh CLI
# (authenticated) for the CI check.

cd "$(dirname "$0")"
. ./release-lib.sh

version=$(./version.sh)
tag="v${version}"

ensure_releasable
ensure_tag_absent "$tag" "bump the version in Cargo.toml first"
wait_for_ci
confirm_and_push_tag "$tag"

echo "Pushed ${tag}. The release workflow takes over from here -- it re-checks CI, builds the"
echo "binaries, publishes the image to GHCR, and creates the GitHub release:"
echo "  https://github.com/${slug}/actions/workflows/release.yml"
