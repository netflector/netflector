#!/usr/bin/env bash
# Shared Ubuntu-runner setup. Launch first; callers can build while the guest boots.
# FREEBSD_VM_ARCH/VERSION select the guest exactly as in freebsd-vm.sh.
# --cross also installs clang/lld for a following freebsd-cross-env.sh step.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
arch=${FREEBSD_VM_ARCH:?set FREEBSD_VM_ARCH}
packages=$(python3 "$here/platforms.py" --freebsd "$arch" --field packages)
kvm=$(python3 "$here/platforms.py" --freebsd "$arch" --field kvm)
extra=()
case "${1:-}" in
    --cross) extra=(clang lld) ;;
    '') ;;
    *) echo "usage: $0 [--cross]" >&2; exit 64 ;;
esac
# A third-party apt source outage must not hide available Ubuntu packages;
# the actual install still fails loudly if any requested package is unavailable.
sudo apt-get update || true
read -r -a qemu_packages <<< "$packages"
sudo apt-get install -y --no-install-recommends qemu-utils genisoimage "${qemu_packages[@]}" "${extra[@]}"
if [ "$kvm" = true ]; then
    # A group change would not apply to the runner's already-running session.
    echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' | sudo tee /etc/udev/rules.d/99-kvm4all.rules
    sudo udevadm control --reload-rules
    sudo udevadm trigger --name-match=kvm
fi
"$here/freebsd-vm.sh" launch
