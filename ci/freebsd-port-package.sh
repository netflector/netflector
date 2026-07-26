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
"$HERE"/freebsd-vm.sh push dist/freebsd/net/netflector /usr/ports/net/netflector
"$HERE"/freebsd-vm.sh run 'cd /usr/ports/net/netflector && make ALLOW_UNSUPPORTED_SYSTEM=yes package'
