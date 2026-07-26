#!/usr/bin/env bash
# Exercise the installed plugin on the converted OPNsense VM (ci/freebsd-vm.sh
# env applies), the way a user's firewall runs it: the model checked against
# this core, the configuration rendered by real configd, validated by the
# daemon, the service started. No sysrc: the seeded config.xml arms the
# service through the plugin's rc.conf.d template, the same path a user's
# firewall takes (and /etc/rc.conf.d overrides rc.conf anyway).
set -euo pipefail

HERE="$(dirname "$0")"

"$HERE"/freebsd-vm.sh run 'php /usr/local/opnsense/scripts/netflector/modelcheck.php'
"$HERE"/freebsd-vm.sh run 'configctl template reload OPNsense/Netflector'
"$HERE"/freebsd-vm.sh run 'test -s /usr/local/etc/netflector.toml'
"$HERE"/freebsd-vm.sh run 'cat /usr/local/etc/netflector.toml'
"$HERE"/freebsd-vm.sh run 'netflector --check-config /usr/local/etc/netflector.toml'
"$HERE"/freebsd-vm.sh run 'service netflector start && sleep 2 && service netflector status'
