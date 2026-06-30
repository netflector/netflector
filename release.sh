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

version=$(./version.sh)
tag="v${version}"

if [ -n "$(git status --porcelain)" ]; then
    echo "Working tree is not clean; commit or stash before releasing." >&2
    exit 1
fi

branch=$(git rev-parse --abbrev-ref HEAD)
if [ "$branch" != "main" ]; then
    echo "Releases are cut from main; current branch is \"$branch\"." >&2
    exit 1
fi

git fetch --quiet origin main
if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
    echo "Local main is not in sync with origin/main; push or pull first." >&2
    exit 1
fi

if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null 2>&1 \
        || git ls-remote --exit-code --tags origin "refs/tags/${tag}" >/dev/null 2>&1; then
    echo "Tag ${tag} already exists; bump the version in Cargo.toml first." >&2
    exit 1
fi

# Gate on CI being green for HEAD before the irreversible tag push -- release.yml re-checks this, but only
# after the tag is pushed, so bring the check forward. ci.yml runs on the push to main; we poll its run for
# this commit (~30 min ceiling, matching release.yml's verify-ci).
if ! command -v gh >/dev/null 2>&1; then
    echo "gh CLI is required to verify CI before releasing (install it, or push ${tag} manually)." >&2
    exit 1
fi

slug=$(git config --get remote.origin.url | sed -e 's#^.*github\.com[:/]##' -e 's#\.git$##')
sha=$(git rev-parse HEAD)
echo "Waiting for CI (ci.yml) to pass on ${sha}..."
ci_ok=
i=0
while [ "$i" -lt 90 ]; do
    i=$((i + 1))
    run=$(gh api "repos/${slug}/actions/workflows/ci.yml/runs?head_sha=${sha}&per_page=1" \
        --jq '.workflow_runs[0] | "\(.status)|\(.conclusion // "")"' 2>/dev/null || true)
    case "${run%%|*}" in
        completed)
            if [ "${run##*|}" = success ]; then ci_ok=1; break; fi
            echo "CI concluded '${run##*|}' on ${sha}; not releasing." >&2
            exit 1
            ;;
        "" | null) echo "  no CI run for ${sha} yet; waiting..." ;;
        *) echo "  CI is '${run%%|*}'; waiting..." ;;
    esac
    sleep 20
done
[ -n "$ci_ok" ] || { echo "Timed out waiting for CI on ${sha}; not releasing." >&2; exit 1; }
echo "CI passed on ${sha}."

# Confirm before the irreversible tag push. A non-interactive run (no stdin) reads EOF and aborts.
printf 'Release %s at %s? [y/N] ' "$tag" "$(git rev-parse --short HEAD)"
if ! read -r answer; then answer=""; fi
case "$answer" in
    y | Y | yes | Yes | YES) ;;
    *) echo "Aborted." >&2; exit 1 ;;
esac

echo "Tagging and pushing ${tag}..."
git tag -a "${tag}" -m "Release ${tag}"
git push origin "${tag}"

echo "Pushed ${tag}. The release workflow takes over from here -- it re-checks CI, builds the"
echo "binaries, publishes the image to GHCR, and creates the GitHub release:"
echo "  https://github.com/${slug}/actions/workflows/release.yml"
