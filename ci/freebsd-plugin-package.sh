#!/usr/bin/env bash
# Build the plugin package inside the running FreeBSD VM (ci/freebsd-vm.sh env
# applies) on the given opnsense/plugins branch; the .pkg lands in
# /plugins/net/netflector/work/pkg/. The daemon must already be installed
# (plugins.mk resolves PLUGIN_DEPENDS via pkg). PLUGIN_NO_ABI stamps the
# wildcard ABI -- checked here: every arch tree of a major serves this one
# package -- and keeps pkg create from adding a FreeBSD_version annotation,
# so the build VM's base release never enters the artifact.
set -euo pipefail

branch="$1"
HERE="$(dirname "$0")"

"$HERE"/freebsd-vm.sh run 'pkg install -y git'
"$HERE"/freebsd-vm.sh run "git clone -q --depth 1 -b $branch https://github.com/opnsense/plugins /plugins"
# scp -r copies INTO an existing directory, so the day net/netflector lands in
# opnsense/plugins this push starts nesting ours a level down and make below builds
# the branch's plugin instead: green, and testing nothing of the change.
"$HERE"/freebsd-vm.sh run 'rm -rf /plugins/net/netflector'
"$HERE"/freebsd-vm.sh push dist/opnsense/net/netflector /plugins/net/netflector
"$HERE"/freebsd-vm.sh run 'cd /plugins/net/netflector && make package'
"$HERE"/freebsd-vm.sh run 'find /plugins/net/netflector/work -name "*.pkg"'
"$HERE"/freebsd-vm.sh run 'pkg query -F /plugins/net/netflector/work/pkg/*.pkg %q | grep -Fx "FreeBSD:*:*"'
