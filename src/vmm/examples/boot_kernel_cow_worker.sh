#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Boot a disposable Worker. Only that Worker's /dev/kvm is assigned the test group.
set -euo pipefail
if [[ $# != 3 ]]; then
    echo "Usage: $0 bzImage static-kernel_cow_kvm serial.log" >&2
    exit 2
fi
kernel=$(realpath -e "$1")
harness=$(realpath -e "$2")
log=$(realpath -m "$3")
qemu=${QEMU:-qemu-system-x86_64}
busybox=$(realpath -e "${BUSYBOX:-/usr/bin/busybox}")
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
root="$stage/root"
mkdir -p "$root"/{bin,dev,proc,sys,tmp} "$(dirname "$log")"
install -m 0755 "$busybox" "$root/bin/busybox"
install -m 0755 "$harness" "$root/bin/kernel_cow_kvm"
ln -s busybox "$root/bin/sh"
cat >"$root/init" <<'INIT'
#!/bin/sh
PATH=/bin
busybox mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
if busybox mount -t proc proc /proc &&
   busybox mount -t sysfs sysfs /sys &&
   busybox mount -t tmpfs tmpfs /tmp &&
   busybox chgrp 20103 /dev/kvm &&
   busybox chmod 0660 /dev/kvm; then
    /bin/kernel_cow_kvm --cross-uid
    result=$?
else
    echo 'Disposable Worker setup failed'
    result=1
fi
echo "SMOLVM_COW_WORKER_TAINTED=$(busybox cat /proc/sys/kernel/tainted)"
echo "SMOLVM_COW_WORKER_RESULT=$result"
busybox poweroff -f
INIT
chmod +x "$root/init"
(cd "$root" && find . -print0 | LC_ALL=C sort -z | cpio --quiet --null -o -H newc --owner=0:0) |
    gzip -n >"$stage/initramfs.cpio.gz"
extra=()
if [[ -n ${QEMU_BIOS:-} ]]; then extra+=(-bios "$QEMU_BIOS"); fi
if [[ -n ${QEMU_DATA:-} ]]; then extra+=(-L "$QEMU_DATA"); fi
timeout -k 5 "${BOOT_TIMEOUT:-120}" "$qemu" -no-user-config -machine pc,accel=kvm -cpu host -m 384 -smp 2 \
    -nodefaults -display none -serial stdio -monitor none -no-reboot -nic none "${extra[@]}" \
    -kernel "$kernel" -initrd "$stage/initramfs.cpio.gz" \
    -append 'console=ttyS0,115200 panic=-1 oops=panic panic_on_warn=1' >"$log" 2>&1
tr -d '\r' <"$log" >"$stage/serial.log"
if ! grep -q '^libkrun Worker CoW: ' "$stage/serial.log" ||
   ! grep -q '^libkrun held CoW VMM: ' "$stage/serial.log" ||
   ! grep -qx 'SMOLVM_COW_WORKER_TAINTED=0' "$stage/serial.log" ||
   ! grep -qx 'SMOLVM_COW_WORKER_RESULT=0' "$stage/serial.log"; then
    tail -n 40 "$log" >&2
    exit 1
fi
