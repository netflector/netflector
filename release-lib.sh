# shellcheck shell=sh
# Shared checks for release.sh and os-release.sh. Sourced, not executed; the
# callers run `set -eu` and cd to the repo root first.

# Refuse to release from a dirty tree, off main, or out of sync with origin.
ensure_releasable() {
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
}

# ensure_tag_absent <tag> <bump hint>: fail if the tag exists locally or on origin.
ensure_tag_absent() {
    if git rev-parse -q --verify "refs/tags/$1" >/dev/null 2>&1 \
            || git ls-remote --exit-code --tags origin "refs/tags/$1" >/dev/null 2>&1; then
        echo "Tag $1 already exists; $2." >&2
        exit 1
    fi
}

# Gate on CI being green for HEAD before the irreversible tag push -- the tag-triggered workflows
# re-check this, but only after the tag is pushed, so bring the check forward. ci.yml runs on the
# push to main; we poll its run for this commit (~30 min ceiling, matching verify-ci.yml). Sets
# $slug (owner/repo) for the caller's hand-off message.
wait_for_ci() {
    if ! command -v gh >/dev/null 2>&1; then
        echo "gh CLI is required to verify CI before releasing (install it, or push the tag manually)." >&2
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
}

# confirm_and_push_tag <tag>: ask, then tag and push. A non-interactive run (no stdin) reads EOF
# and aborts.
confirm_and_push_tag() {
    printf 'Release %s at %s? [y/N] ' "$1" "$(git rev-parse --short HEAD)"
    if ! read -r answer; then answer=""; fi
    case "$answer" in
        y | Y | yes | Yes | YES) ;;
        *) echo "Aborted." >&2; exit 1 ;;
    esac

    echo "Tagging and pushing $1..."
    git tag -a "$1" -m "Release $1"
    git push origin "$1"
}
