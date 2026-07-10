#!/usr/bin/env bash
# cargo target runner for x86_64-unknown-freebsd: cargo hands it the host path
# of each cross-built test executable plus libtest args; copy the binary into
# the VM ci/freebsd-vm.sh booted and run it there as root (the privileged
# tests -- interface pairs, BPF captures, joins -- run instead of skipping).
# The remote exit status is the runner's, which cargo treats as the test
# result. cargo runs test binaries serially, so one ssh session at a time.
set -euo pipefail

VM_DIR=${FREEBSD_VM_DIR:-$HOME/.freebsd-vm}
SSH_PORT=${FREEBSD_VM_SSH_PORT:-2222}
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR -i "$VM_DIR/id_ed25519")

bin=$1
shift
remote="/tmp/$(basename "$bin")"
# The runner must be stdout-transparent: cargo judges by exit code, but other
# invocations parse the binary's stdout (--list, --format json, nextest), and
# runner noise is indistinguishable from it. Chatter goes to stderr.
scp -q "${SSH_OPTS[@]}" -P "$SSH_PORT" "$bin" "root@127.0.0.1:$remote" >&2

args=''
for a in "$@"; do
    args="$args $(printf '%q' "$a")"
done
# Root's login shell is csh, so feed a script to sh on stdin. The binary reads
# /dev/null instead of that stdin, or it could eat the lines sh has not
# consumed yet.
printf 'chmod +x %s\n%s%s </dev/null\nrc=$?\nrm -f %s\nexit $rc\n' \
    "$remote" "$remote" "$args" "$remote" |
    ssh "${SSH_OPTS[@]}" -p "$SSH_PORT" root@127.0.0.1 sh
