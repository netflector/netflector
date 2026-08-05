#!/usr/bin/env bash
# Build the daemon package from the port inside the running FreeBSD VM
# (ci/freebsd-vm.sh env applies); the .pkg lands in the port's work/pkg/.
# The VM runs the OPNsense base of its major, older than the newest release:
# the caller must arm IGNORE_OSVERSION first or pkg refuses the toolchain as
# "Newer FreeBSD version", and the pinned ports tree floors OSVERSION at the
# newest release and errors out on the EOL base, hence ALLOW_UNSUPPORTED_SYSTEM.
set -euo pipefail

HERE="$(dirname "$0")"

"$HERE"/freebsd-ports-tree.sh
# scp -r copies INTO an existing directory, so the day net/netflector lands upstream this
# push starts nesting ours at net/netflector/netflector and every make below builds the
# tree's port instead: green, and testing nothing of the change.
"$HERE"/freebsd-vm.sh run 'rm -rf /usr/ports/net/netflector'
"$HERE"/freebsd-vm.sh push dist/freebsd/net/netflector /usr/ports/net/netflector
"$HERE"/freebsd-vm.sh run 'cd /usr/ports/net/netflector && make ALLOW_UNSUPPORTED_SYSTEM=yes package'
# Base-sensitive QA the PR lanes cannot cover: they lint on the release images,
# while this stages on the EOL OPNsense bases the packages are built for.
"$HERE"/freebsd-vm.sh run 'cd /usr/ports/net/netflector && make ALLOW_UNSUPPORTED_SYSTEM=yes stage-qa check-plist'
