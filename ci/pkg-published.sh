#!/usr/bin/env bash
# Is a daemon version already in the published catalogue? Prints true or false on
# stdout, and a found/missing line per tree on stderr.
#
#   ci/pkg-published.sh <pkg-repo-clone> <version>   # e.g. ... pkg-repo 0.13.2_1
#   ci/pkg-published.sh --abis                       # the trees it would probe
#
# true only when EVERY served tree has it. One publish writes them all, so a partial
# result means a publish died midway, and calling that published would freeze the gap:
# both callers skip a version once, and nothing ever revisits it.
#
# The majors are derived, never written down. ci/freebsd<major>-opnsense.env exists for
# exactly the ones we serve, so adding or retiring a series moves this probe with no
# edit here -- which matters because keep-all retention leaves a retired tree in place
# but unwritten, and a probe pinned to it would never match again.
set -euo pipefail

# Every served major is built for both of these; matches build-daemon-pkgs.yml's arch
# matrix. pkg's ABI string spells arm64 as the processor name, aarch64.
ARCHES=(amd64 aarch64)

here=$(dirname "$0")

served_abis() {
    local majors=() pin
    for pin in "$here"/freebsd*-opnsense.env; do
        [ -e "$pin" ] || continue
        pin=${pin##*/}
        pin=${pin#freebsd}
        majors+=("${pin%-opnsense.env}")
    done
    # Stop rather than guess: an invented ABI would answer "not published" and
    # republish over a released package.
    [ ${#majors[@]} -gt 0 ] || {
        echo "no ci/freebsd<major>-opnsense.env: cannot tell which trees to probe" >&2
        return 1
    }
    local major arch
    for major in $(printf '%s\n' "${majors[@]}" | sort -n); do
        for arch in "${ARCHES[@]}"; do
            echo "FreeBSD:${major}:${arch}"
        done
    done
}

if [ "${1:-}" = --abis ]; then
    served_abis
    exit 0
fi

repo=${1:?usage: pkg-published.sh <pkg-repo-clone> <version> | --abis}
version=${2:?usage: pkg-published.sh <pkg-repo-clone> <version> | --abis}

# Assigned before the loop so a failure to resolve the trees exits here, rather than
# feeding an empty list into a loop that would then report everything present.
abis=$(served_abis)

found=0
missing=0
while read -r abi; do
    if [ -e "$repo/opnsense/$abi/latest/netflector-${version}.pkg" ]; then
        printf '  %-24s found\n' "$abi" >&2
        found=$((found + 1))
    else
        printf '  %-24s missing\n' "$abi" >&2
        missing=$((missing + 1))
    fi
done <<< "$abis"

if [ "$missing" -eq 0 ]; then
    echo true
else
    if [ "$found" -gt 0 ]; then
        echo "netflector-${version} is in $found tree(s) and missing from $missing: a publish did not finish" >&2
    fi
    echo false
fi
