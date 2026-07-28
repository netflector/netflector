#!/usr/bin/env bash
# Exercise the installed plugin on the converted OPNsense VM (ci/freebsd-vm.sh
# env applies), the way a user's firewall runs it: the model checked against
# this core, the configuration rendered by real configd, validated by the
# daemon and through the GUI's own check action, the service started. No sysrc:
# the seeded config.xml arms the
# service through the plugin's rc.conf.d template, the same path a user's
# firewall takes (and /etc/rc.conf.d overrides rc.conf anyway).
set -euo pipefail

HERE="$(dirname "$0")"

"$HERE"/freebsd-vm.sh run 'php /usr/local/opnsense/scripts/netflector/modelcheck.php'
"$HERE"/freebsd-vm.sh run 'configctl template reload OPNsense/Netflector'
"$HERE"/freebsd-vm.sh run 'test -s /usr/local/etc/netflector.toml'
"$HERE"/freebsd-vm.sh run 'cat /usr/local/etc/netflector.toml'
"$HERE"/freebsd-vm.sh run 'netflector --check-config /usr/local/etc/netflector.toml'

# The GUI's validate button, end to end: the configd action wiring plus check.py,
# which nothing else runs. configd reads actions.d at startup and the plugin was
# pkg-added into a running system, so its actions appear only after a restart.
"$HERE"/freebsd-vm.sh run 'service configd restart'
verdict=$("$HERE"/freebsd-vm.sh run 'configctl netflector check')
echo "$verdict"
case "$verdict" in
*'"status": "ok"'*) ;;
*) echo "the configd check action did not report ok" >&2; exit 1 ;;
esac

"$HERE"/freebsd-vm.sh run 'service netflector start && sleep 2 && service netflector status'
