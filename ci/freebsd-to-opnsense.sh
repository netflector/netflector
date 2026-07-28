#!/usr/bin/env bash
# Convert the running FreeBSD VM (ci/freebsd-vm.sh env applies) to the given
# OPNsense series with opnsense-bootstrap, and wait for it to come back up.
# Seeds /conf/config.xml from the gate config first: OPNsense regenerates
# root's authorized_keys from it on every boot, so without the seed the
# conversion reboot locks us out.
set -euo pipefail

series="$1"
HERE="$(dirname "$0")"

b64=$(base64 < "${FREEBSD_VM_DIR:-$HOME/.freebsd-vm}/id_ed25519.pub" | tr -d '\n')
sed "s|__SSH_PUBKEY_B64__|$b64|" \
    dist/opnsense/net/netflector/test/gate-config.xml > config.xml
"$HERE"/freebsd-vm.sh run 'mkdir -p /conf'
"$HERE"/freebsd-vm.sh push config.xml /conf/config.xml

# From the series tag, not master: this script is destructive, its content
# differs per series, and an unpinned fetch means two runs of the same tag can
# convert differently.
"$HERE"/freebsd-vm.sh run "fetch -qo /tmp/bootstrap.sh https://raw.githubusercontent.com/opnsense/update/$series/src/bootstrap/opnsense-bootstrap.sh.in"

# opnsense-bootstrap clears the way with `pkg unlock -ya; pkg delete -fa`,
# guarded only by `pkg -N`, and knows nothing about pkgbase. FreeBSD 15
# VM images install base as ~500 FreeBSD-* packages, and -f overrides
# pkg's vital flag, so on that lane the command deletes the running
# userland: FreeBSD-ssh takes /usr/libexec/sshd-session, so the live
# sshd accepts TCP and then fatals on every session, and FreeBSD-runtime
# takes /bin/rm, so the script dies on its own next line and never
# reaches opnsense-update or reboot. FreeBSD 14 images are
# installworld-built, base is registered nowhere, and the same command
# only reaps the image's couple of ports packages -- which is all this
# conversion has ever done on that lane, and the state bootstrap
# actually supports. Put a pkgbase guest into it: drop the ports
# packages (pkg included, so bootstrap re-bootstraps OPNsense's own),
# then remove the database so `pkg -N` fails and the delete is skipped.
# Base files stay on disk for OPNsense's base.txz to overwrite.
# shellcheck disable=SC2016  # the single quotes are the point: expansion happens in the guest
"$HERE"/freebsd-vm.sh run '
    if pkg -N >/dev/null 2>&1 && pkg query %n | grep -qx FreeBSD-runtime; then
        ports=$(pkg query %n | grep -v "^FreeBSD-") || true
        if [ -n "$ports" ]; then
            pkg delete -fy $ports
        fi
        rm -rf /var/db/pkg
        # Upstream guards the delete on `pkg -N` alone; if that ever
        # changes, fail here rather than losing the base system again.
        if pkg -N >/dev/null 2>&1; then
            echo "pkg -N still succeeds; bootstrap would delete the base system" >&2
            exit 1
        fi
    fi
'

# The conversion ends in a reboot that kills the ssh session, so the exit status says
# nothing and has to be discarded. opnsense-version is no post-condition either:
# bootstrap pkg-installs it before the base swap, so it answers happily on a VM that
# never rebooted. The kernel string is what the swap actually replaces.
kernel_before=$("$HERE"/freebsd-vm.sh run 'uname -v')
"$HERE"/freebsd-vm.sh run "sh /tmp/bootstrap.sh -y -r $series" || true
"$HERE"/freebsd-vm.sh wait
kernel_after=$("$HERE"/freebsd-vm.sh run 'uname -v')
if [ "$kernel_after" = "$kernel_before" ]; then
    echo "opnsense-bootstrap left the kernel at: $kernel_after" >&2
    echo "it died before the base swap and reboot" >&2
    exit 1
fi
"$HERE"/freebsd-vm.sh run 'opnsense-version'
