#!/usr/bin/env bash
# Boot the official FreeBSD VM image under QEMU on a Linux runner and drive it
# over ssh. The FreeBSD lanes cross-compile on the runner; the VM exists only
# to execute the results on a real FreeBSD kernel (kqueue, BPF, PF_ROUTE, vnet
# jails -- qemu-user translates architecture, not OS, so nothing short of a
# FreeBSD kernel serves these). Everything fetched is FreeBSD-project-official
# and hash-pinned; no third-party code runs on the host.
#
#   ci/freebsd-vm.sh launch    fetch + verify the image, build the cloud-init
#                              seed, start QEMU in the background
#   ci/freebsd-vm.sh wait      block until root ssh answers
#   ci/freebsd-vm.sh run CMD   run CMD in the VM as root
#   ci/freebsd-vm.sh push SRC... DEST   copy files/dirs to DEST in the VM
#   ci/freebsd-vm.sh console   dump the serial console (boot diagnostics)
#
# State (disk, seed, per-run ssh key, console log) lives in $FREEBSD_VM_DIR,
# default ~/.freebsd-vm. $FREEBSD_VM_ARCH (required, no default: a guessed
# arch is a silently wrong VM) picks the guest: amd64 (KVM) or arm64 (TCG --
# no GitHub runner has arm64 KVM, so the guest is emulated and gets a far
# larger ssh-wait budget). The release + image hash pins live in
# ci/freebsd<major>.env (Renovate bumps the release, ci/freebsd-pin.sh refreshes
# the hashes).
set -euo pipefail

# FREEBSD_VM_VERSION picks the pinned release (major): each has a freebsd<major>.env.
VERSION=${FREEBSD_VM_VERSION:?set FREEBSD_VM_VERSION to a pinned major, e.g. 14 or 15}
. "$(dirname "$0")/freebsd${VERSION}.env"
ARCH=${FREEBSD_VM_ARCH:?set FREEBSD_VM_ARCH to amd64 or arm64}
case "$ARCH" in
amd64)
    IMAGE_URL=$IMAGE_URL_AMD64
    IMAGE_SHA=$IMAGE_SHA512_AMD64
    WAIT_DEFAULT=300
    ;;
arm64)
    IMAGE_URL=$IMAGE_URL_ARM64
    IMAGE_SHA=$IMAGE_SHA512_ARM64
    WAIT_DEFAULT=1200
    ;;
*)
    echo "error: unknown FREEBSD_VM_ARCH '$ARCH' (amd64|arm64)" >&2
    exit 64
    ;;
esac
IMAGE=$(basename "$IMAGE_URL" .xz)

VM_DIR=${FREEBSD_VM_DIR:-$HOME/.freebsd-vm}
SSH_PORT=${FREEBSD_VM_SSH_PORT:-2222}
SSH_WAIT_SECS=${FREEBSD_VM_SSH_WAIT_SECS:-$WAIT_DEFAULT}

# No port here: ssh wants -p, scp wants -P; each call site adds its own.
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR -i "$VM_DIR/id_ed25519")

# NoCloud seed for nuageinit(7), the in-base cloud-init shim the
# BASIC-CLOUDINIT image enables. The root entry appends our key to the
# existing root user; the sshd_config append permits key-only root login
# before sshd first starts (FreeBSD's sshd defaults root login off, and sshd
# takes the first uncommented value -- the stock file has none). The rc.conf.d
# drop-ins disable the image's first-boot updaters (freebsd-update on 14,
# pkgbase's firstboot_pkg_upgrade on 15), an unpinned fetch
# plus reboot that cost 4 minutes per lane. It must be rc.conf.d, NOT
# rc.conf.local: /etc/rc loads the rc.conf files once at boot start and every
# rc.d script inherits that snapshot (rc.subr _rc_conf_loaded), so a same-boot
# rc.conf.local write is never re-read; the per-service /etc/rc.conf.d/<name>
# file is the one rc knob each script sources fresh.
seed_iso() {
    printf 'instance-id: netflector-ci\nlocal-hostname: netflector-freebsd\n' \
        > "$VM_DIR/meta-data"
    cat > "$VM_DIR/user-data" <<EOF
#cloud-config
users:
  - name: root
    ssh_authorized_keys:
      - $(cat "$VM_DIR/id_ed25519.pub")
write_files:
  - path: /etc/ssh/sshd_config
    append: true
    content: |
      PermitRootLogin prohibit-password
  - path: /etc/rc.conf.d/firstboot_freebsd_update
    content: |
      firstboot_freebsd_update_enable="NO"
  - path: /etc/rc.conf.d/firstboot_pkg_upgrade
    content: |
      firstboot_pkg_upgrade_enable="NO"
EOF
    genisoimage -quiet -output "$VM_DIR/seed.iso" -volid cidata -joliet -rock \
        "$VM_DIR/user-data" "$VM_DIR/meta-data"
}

launch() {
    mkdir -p "$VM_DIR"
    curl -fsSL "$IMAGE_URL" -o "$VM_DIR/$IMAGE.xz"
    echo "$IMAGE_SHA  $VM_DIR/$IMAGE.xz" | sha512sum -c - || {
        echo "error: image hash mismatch; after a release bump, run ci/freebsd-pin.sh" >&2
        exit 1
    }
    xz -dT0 "$VM_DIR/$IMAGE.xz"
    # Headroom over the image's ~1 GB free; the guest growfs's into it at boot.
    qemu-img resize "$VM_DIR/$IMAGE" +4G
    ssh-keygen -q -t ed25519 -N '' -f "$VM_DIR/id_ed25519"
    seed_iso
    # Slirp networking: sshd reachable only through the localhost hostfwd.
    # The empty romfile drops virtio-net's PXE option ROM: the ROM files ship
    # in ipxe-qemu, which qemu-system-arm does not pull in, and these guests
    # only ever boot from disk anyway.
    common=(
        -smp "$(nproc)" -m 6144
        -drive "file=$VM_DIR/$IMAGE,format=qcow2,if=virtio"
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22"
        -device virtio-net-pci,netdev=net0,romfile=
        -display none -serial "file:$VM_DIR/console.log"
        -pidfile "$VM_DIR/qemu.pid" -daemonize
    )
    if [ "$ARCH" = amd64 ]; then
        qemu-system-x86_64 \
            -machine q35 -accel kvm -cpu host \
            -cdrom "$VM_DIR/seed.iso" \
            "${common[@]}"
    else
        # TCG with one thread per vCPU; the virt machine boots via UEFI (a
        # read-only AAVMF code image plus a writable per-VM vars copy) and
        # has no CD controller, so the seed rides a read-only virtio disk --
        # nuageinit finds it by filesystem label, not device type.
        cp /usr/share/AAVMF/AAVMF_VARS.fd "$VM_DIR/AAVMF_VARS.fd"
        qemu-system-aarch64 \
            -machine virt -accel tcg,thread=multi -cpu max \
            -drive "if=pflash,format=raw,readonly=on,file=/usr/share/AAVMF/AAVMF_CODE.fd" \
            -drive "if=pflash,format=raw,file=$VM_DIR/AAVMF_VARS.fd" \
            -drive "file=$VM_DIR/seed.iso,format=raw,if=virtio,readonly=on" \
            "${common[@]}"
    fi
    echo "FreeBSD $RELEASE $ARCH VM started (qemu pid $(cat "$VM_DIR/qemu.pid"))"
}

wait_ssh() {
    local deadline=$((SECONDS + SSH_WAIT_SECS))
    until ssh "${SSH_OPTS[@]}" -p "$SSH_PORT" root@127.0.0.1 true 2>/dev/null; do
        if ((SECONDS >= deadline)); then
            echo "error: no ssh answer after ${SSH_WAIT_SECS}s; console tail:" >&2
            tail -n 50 "$VM_DIR/console.log" >&2
            exit 1
        fi
        sleep 2
    done
    echo "ssh up after ${SECONDS}s"
    run 'uname -a && freebsd-version'
}

# Root's login shell is csh; hand the command to sh on stdin instead of
# fighting two shells' quoting. sshd's non-interactive PATH lacks /usr/local,
# where everything pkg installs lives.
run() {
    printf 'export PATH="$PATH:/usr/local/sbin:/usr/local/bin"\nset -eu\n%s\n' "$*" |
        ssh "${SSH_OPTS[@]}" -p "$SSH_PORT" root@127.0.0.1 sh
}

# Copy files/directories into the VM; the last argument is the remote path.
push() {
    scp -qr "${SSH_OPTS[@]}" -P "$SSH_PORT" "${@:1:$#-1}" "root@127.0.0.1:${!#}"
}

case "${1:-}" in
launch) launch ;;
wait) wait_ssh ;;
run)
    shift
    run "$@"
    ;;
push)
    shift
    push "$@"
    ;;
console) cat "$VM_DIR/console.log" ;;
*)
    echo "usage: $0 launch|wait|run CMD|push SRC... DEST|console" >&2
    exit 64
    ;;
esac
