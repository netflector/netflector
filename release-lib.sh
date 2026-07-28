# shellcheck shell=sh
# Shared checks for release.sh and release-os.sh. Sourced, not executed; the
# callers run `set -eu` and cd to the repo root first.

# The GitHub owner/repo, for the callers' hand-off messages.
repo_slug() {
    git config --get remote.origin.url | sed -e 's#^.*github\.com[:/]##' -e 's#\.git$##'
}

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
# Origin first: once the tag is published the version is spent whatever the local tree
# says, and the bump hint is the right advice.
ensure_tag_absent() {
    if git ls-remote --exit-code --tags origin "refs/tags/$1" >/dev/null 2>&1; then
        echo "Tag $1 is already on origin; $2." >&2
        exit 1
    fi
    if git rev-parse -q --verify "refs/tags/$1" >/dev/null 2>&1; then
        # confirm_and_push_tag cleans up after itself, so this means an interrupted run or a
        # tag made by hand. The version is unspent either way, and bumping it would be wrong.
        echo "Tag $1 exists locally but not on origin; push it or delete it." >&2
        exit 1
    fi
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
    # Leave nothing behind if the push fails -- an ssh agent waiting on approval is the usual
    # cause. The version is unspent, so a bare re-run should just work rather than land on a
    # stale local tag. If origin took the tag but the ack never arrived, deleting here is
    # still right: the next run sees it on origin and says so.
    if ! git push origin "$1"; then
        git tag -d "$1" >/dev/null
        echo "Push failed; removed the local tag $1. Fix the cause and re-run." >&2
        exit 1
    fi
}
