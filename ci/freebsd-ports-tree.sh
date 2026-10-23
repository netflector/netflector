#!/usr/bin/env bash
# Check out /usr/ports inside the running FreeBSD VM (ci/freebsd-vm.sh env
# applies). Default: pinned to the commit the VM's binary packages were built
# from -- every official package records it in the ports_top_git_hash
# annotation, and rust is queried because the port needs it installed anyway.
# Building against that exact tree matches the framework the packages saw.
#
# PORTS_TREE_LATEST=1 pins to the newest commit the rolling latest package set
# was built from instead, for the poudriere lane that fetches its build deps
# from that set. The build at that commit rebuilt whatever had changed, so every
# package in the set matches the tree and none is rebuilt from source; a
# pinned quarterly tree's older ports-mgmt/pkg could not consume the set at all.
# No rust in the host VM there: testport needs it only inside the jail.
set -euo pipefail

VM="$(dirname "$0")/freebsd-vm.sh"

if [ "${PORTS_TREE_LATEST:-0}" = 1 ]; then
    "$VM" run 'pkg install -y git'
    # The repository goes again before the caller installs anything: its packages
    # are for the jail, not the host.
    "$VM" run 'mkdir -p /usr/local/etc/pkg/repos && printf "ci-latest: { url: \"pkg+https://pkg.FreeBSD.org/\${ABI}/latest\", mirror_type: \"srv\", enabled: yes }\n" > /usr/local/etc/pkg/repos/ci-latest.conf'
    "$VM" run 'pkg update -q -r ci-latest'
    ref=$("$VM" run "pkg rquery -a -r ci-latest '%n %At %Av' | grep -E ' (ports_top_git_hash|build_timestamp) '" |
        tr -d '\r' |
        awk '$2 == "ports_top_git_hash" { hash[$1] = $3 }
             $2 == "build_timestamp" { built[$1] = $3 }
             END { for (n in hash) if (built[n] > newest) { newest = built[n]; ref = hash[n] } print ref }')
    "$VM" run 'rm /usr/local/etc/pkg/repos/ci-latest.conf'
    [ -n "$ref" ] || { echo "the latest set records no ports_top_git_hash" >&2; exit 1; }
    echo "ports tree pinned to $ref (the newest commit the latest set was built from)"
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

got=$("$VM" run 'cd /usr/ports && git rev-parse HEAD' | tr -d ' \r')
[ "$got" = "$ref" ] || { echo "tree is not at the pinned commit" >&2; exit 1; }
