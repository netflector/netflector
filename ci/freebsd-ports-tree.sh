#!/usr/bin/env bash
# Check out /usr/ports inside the running FreeBSD VM (ci/freebsd-vm.sh env
# applies). Default: pinned to the commit the VM's binary packages were built
# from -- every official package records it in the ports_top_git_hash
# annotation, and rust is queried because the port needs it installed anyway.
# Building against that exact tree matches the framework the packages saw.
#
# PORTS_TREE_CURRENT=1 checks out current main instead: the poudriere lane
# fetches build deps from the rolling latest package set, which a pinned
# tree's older ports-mgmt/pkg cannot consume -- poudriere then rebuilds
# everything from source. No rust in the host VM there: testport needs it
# only inside the jail.
set -euo pipefail

VM="$(dirname "$0")/freebsd-vm.sh"

if [ "${PORTS_TREE_CURRENT:-0}" = 1 ]; then
    "$VM" run 'pkg install -y git'
    ref=main
else
    "$VM" run 'pkg install -y git rust'
    ref=$("$VM" run 'pkg info -A rust | sed -n "s/.*ports_top_git_hash:[[:space:]]*//p"' | tr -d ' \r')
    [ -n "$ref" ] || { echo "rust package records no ports_top_git_hash" >&2; exit 1; }
    echo "ports tree pinned to $ref (the commit our rust package was built from)"
fi

"$VM" run "
    set -e
    mkdir -p /usr/ports && cd /usr/ports
    git init -q .
    git remote add origin https://git.FreeBSD.org/ports.git
    git fetch -q --depth 1 origin $ref
    git checkout -q FETCH_HEAD
    echo \"ports tree at \$(git rev-parse HEAD)\"
"

if [ "$ref" != main ]; then
    got=$("$VM" run 'cd /usr/ports && git rev-parse HEAD' | tr -d ' \r')
    [ "$got" = "$ref" ] || { echo "tree is not at the pinned commit" >&2; exit 1; }
fi
