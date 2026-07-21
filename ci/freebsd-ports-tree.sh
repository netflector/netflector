#!/usr/bin/env bash
# Check out /usr/ports inside the running FreeBSD VM (ci/freebsd-vm.sh env
# applies), pinned to the commit the VM's binary packages were built from:
# every official package records it in the ports_top_git_hash annotation, and
# rust is queried because the port needs it installed anyway. Building against
# that exact tree matches the framework the packages themselves saw.
set -euo pipefail

VM="$(dirname "$0")/freebsd-vm.sh"

"$VM" run 'pkg install -y git rust'
# shellcheck disable=SC2016  # the single quotes are the point: $hash expands in the guest
"$VM" run '
    set -e
    hash=$(pkg info -A rust | sed -n "s/.*ports_top_git_hash:[[:space:]]*//p")
    [ -n "$hash" ] || { echo "rust package records no ports_top_git_hash"; exit 1; }
    echo "ports tree at $hash (the commit our rust package was built from)"
    mkdir -p /usr/ports && cd /usr/ports
    git init -q .
    git remote add origin https://git.FreeBSD.org/ports.git
    git fetch -q --depth 1 origin "$hash"
    git checkout -q FETCH_HEAD
    [ "$(git rev-parse HEAD)" = "$hash" ] || { echo "tree is not at the pinned commit"; exit 1; }
'
