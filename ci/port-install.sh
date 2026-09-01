#!/usr/bin/env bash
# Install the port-built daemon package into the running FreeBSD VM
# (ci/freebsd-vm.sh env applies) and smoke it. pkg add of the .pkg file, not
# make install: the framework installs from the stage directory and never
# opens the tarball again, so only pkg add exercises the artifact that ships,
# manifest and packaged scripts included.
set -euo pipefail

HERE="$(dirname "$0")"

"$HERE"/freebsd-vm.sh run 'pkg add /usr/ports/net/netflector/work/pkg/netflector-*.pkg'
"$HERE"/freebsd-vm.sh run '/usr/local/bin/netflector --version'
# The rc script must refuse a configuration the daemon would reject, rather
# than launching a service that dies a second later.
"$HERE"/freebsd-vm.sh run 'sysrc netflector_enable=YES'
"$HERE"/freebsd-vm.sh run 'printf "[reflectors.bad]\nsource_if = \"em0\"\ntarget_if = \"em0\"\nmdns = true\n" > /usr/local/etc/netflector.toml'
"$HERE"/freebsd-vm.sh run 'service netflector start 2>&1 | grep -q "refusing to start" && echo "rc refused an invalid configuration"'
# report must signal netflector itself, not the daemon(8) supervisor whose pid
# the service advertises: SIGUSR1 kills the supervisor and orphans the daemon.
# The status check would then fail, because the supervisor is what it pgreps.
"$HERE"/freebsd-vm.sh run 'printf "[reflectors.ci]\nsource_if = \"vtnet0\"\ntarget_if = \"lo0\"\nwol = true\n" > /usr/local/etc/netflector.toml'
"$HERE"/freebsd-vm.sh run 'service netflector start'
"$HERE"/freebsd-vm.sh run 'service netflector report && sleep 1 && grep -q "dumping diagnostics" /var/log/messages && echo "report reached the log"'
"$HERE"/freebsd-vm.sh run 'service netflector status'
"$HERE"/freebsd-vm.sh run 'service netflector stop'
"$HERE"/freebsd-vm.sh run 'rm /usr/local/etc/netflector.toml'
