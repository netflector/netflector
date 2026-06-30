#!/bin/sh
set -eu

# Single source of truth for the project version: the [package] version in Cargo.toml. release.sh (the git
# tag) and release.yml (the tag-vs-version guard and the image tag) all read it from here, so the git tag,
# the published image, and the GitHub release can never disagree. Cargo-free (just awk) so it runs anywhere.
root="$(dirname "$0")"
version=$(awk -F'"' '/^\[package\]/{p=1} p && /^version[[:space:]]*=/{print $2; exit}' "$root/Cargo.toml")
if [ -z "$version" ]; then
    echo "Cannot determine version from Cargo.toml [package] section" >&2
    exit 1
fi
printf '%s\n' "$version"
