#!/bin/sh
# Move every package that a newer version of the same name supersedes out of a tree's latest/
# into its sibling archive/, which `pkg repo` does not index. Runs on FreeBSD: pkg reads the
# names and versions and orders them.
#
#   ci/pkg-archive-superseded.sh <tree>/latest ...
set -eu

for tree in "$@"; do
    archive=${tree%/latest}/archive
    index=
    for f in "$tree"/*.pkg; do
        [ -e "$f" ] || continue
        case ${f##*/} in
        data.pkg | filesite.pkg | packagesite.pkg) continue ;;
        esac
        info=$(pkg query -F "$f" '%n %v')
        index="$index$info $f
"
    done
    old_ifs=$IFS
    IFS='
'
    for name in $(printf '%s\n' "$index" | cut -d' ' -f1 | sort -u); do
        newest=
        newest_version=
        for line in $index; do
            [ "${line%% *}" = "$name" ] || continue
            rest=${line#* }
            version=${rest%% *}
            if [ -z "$newest" ] || [ "$(pkg version -t "$version" "$newest_version")" = '>' ]; then
                newest=${rest#* }
                newest_version=$version
            fi
        done
        for line in $index; do
            [ "${line%% *}" = "$name" ] || continue
            file=${line#* }
            file=${file#* }
            if [ "$file" != "$newest" ]; then
                mkdir -p "$archive"
                mv "$file" "$archive/"
                echo "archived $file (superseded by $newest_version)"
            fi
        done
    done
    IFS=$old_ifs
done
