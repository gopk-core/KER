#!/bin/bash
# Build a disposable amd64 guest, install the KER deb inside it, and run
# the virtual-media selftest. Never installs the deb or loads BPF on the host.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DIST="$ROOT/dist"
VM="$DIST/vm"
ROOTFS="$DIST/vm-rootfs"
KVER=$(uname -r)
KERNEL="/boot/vmlinuz-$KVER"
# Prefer a locally built initrd that definitely contains virtio + ext4.
INITRD="$DIST/vm-initrd.img"
RESULT_IMG="$VM/result.img"
ROOT_IMG="$VM/root.img"
MEDIA_ROOT="$VM/media-root.img"
MEDIA_ADMIN="$VM/media-admin.img"
MEDIA_SSH="$VM/media-ssh.img"
HOOK_INITRD="$DIST/vm-hook-initrd.img"
LOG="$DIST/qemu-selftest.log"

die() { echo "vm-test: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "need root"
[ -f "$KERNEL" ] || die "missing host kernel $KERNEL"
[ -d "$ROOTFS" ] || die "missing rootfs $ROOTFS (run debootstrap first)"
[ -f "$ROOT/dist/bpf/ker.bpf.o" ] || { make -C "$ROOT" bpf; }
[ -f "$ROOT/dist/ker-probe" ] || make -C "$ROOT" probe

# Build the current amd64 package only (do not dpkg -i on the host).
make -C "$ROOT" bpf probe
bash "$ROOT/packaging/build-deb.sh" amd64
DEB=$(ls -1t "$DIST"/ker_*_amd64.deb | head -1)
[ -n "$DEB" ] || die "amd64 deb not built"
echo "using $DEB"

# Custom initrd with virtio_blk + ext4, because the host initrd may not
# have virtio (this machine is bare metal).
build_initrd() {
  local work conf
  conf=$(mktemp -d)
  work=$(mktemp -d)
  trap 'rm -rf "$conf" "$work"' RETURN
  cat > "$conf/initramfs.conf" << 'CONF'
MODULES=list
BUSYBOX=auto
COMPRESS=gzip
CONF
  mkdir -p "$conf/conf.d"
  printf '%s\n' virtio_blk crc16 crc32c mbcache jbd2 ext4 > "$conf/modules"
  mkdir -p "$conf/conf.d"
  echo RESUME=none > "$conf/conf.d/resume"
  if mkinitramfs -d "$conf" -o "$INITRD" "$KVER"; then
    echo "initrd built with mkinitramfs: $INITRD"
    return 0
  fi
  echo "mkinitramfs failed; assembling a busybox initrd" >&2
  local dest="$work/root"
  mkdir -p "$dest"/{bin,sbin,dev,proc,sys,newroot,lib/modules/"$KVER"}
  cp /bin/busybox "$dest/bin/busybox"
  "$dest/bin/busybox" --install -s "$dest/bin"
  # copy needed modules + deps via modprobe --show-depends
  local m ko
  for m in virtio virtio_ring virtio_pci virtio_blk crc32c mbcache jbd2 ext4; do
    while read -r _ ko; do
      [ -f "${ko:-}" ] || continue
      mkdir -p "$dest/$(dirname "${ko#/}")"
      cp -a "$ko" "$dest$ko"
    done < <(modprobe --set-version "$KVER" --show-depends "$m" 2>/dev/null | awk '/^insmod /{print $1,$2}')
  done
  cp -a "/lib/modules/$KVER/modules.dep" "$dest/lib/modules/$KVER/" 2>/dev/null || true
  cat > "$dest/init" << 'INIT'
#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null || mount -t tmpfs dev /dev
for m in virtio virtio_ring virtio_pci virtio_blk crc32c mbcache jbd2 ext4; do
  modprobe "$m" 2>/dev/null || insmod $(find /lib/modules -name "$m.ko*" | head -1) 2>/dev/null || true
done
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  [ -b /dev/vda ] && break
  sleep 0.25
done
mount -o rw /dev/vda /newroot || { echo "mount root failed"; exec sh; }
exec switch_root /newroot /usr/lib/ker/vm-selftest.sh
INIT
  chmod 755 "$dest/init"
  ( cd "$dest" && find . | cpio -o -H newc ) | gzip -c > "$INITRD"
  echo "initrd assembled: $INITRD"
}

build_initrd
[ -f "$INITRD" ] || die "initrd not built"

# Ensure the chroot has packages (wait if a background apt is still running).
if ! chroot "$ROOTFS" python3 -c 'import cryptography' 2>/dev/null; then
  echo "waiting for chroot packages..."
  for i in $(seq 1 180); do
    grep -q APT_OK "$DIST/chroot-apt.log" 2>/dev/null && break
    sleep 2
  done
  chroot "$ROOTFS" python3 -c 'import cryptography' || die "chroot packages missing"
fi

# Install OpenSSH into the guest rootfs only (never start it on the host).
if ! chroot "$ROOTFS" sh -c "command -v sshd >/dev/null"; then
  echo "installing openssh-server into the guest rootfs"
  printf "%s\n" "#!/bin/sh" "exit 101" > "$ROOTFS/usr/sbin/policy-rc.d"
  chmod 755 "$ROOTFS/usr/sbin/policy-rc.d"
  mount -t proc proc "$ROOTFS/proc"
  mount --bind /dev "$ROOTFS/dev"
  mount -t devpts devpts "$ROOTFS/dev/pts" 2>/dev/null || true
  mkdir -p "$ROOTFS/run"
  DEBIAN_FRONTEND=noninteractive chroot "$ROOTFS" apt-get install -y --no-install-recommends \
    openssh-server openssh-client || die "failed to install openssh into guest rootfs"
  umount -l "$ROOTFS/dev/pts" "$ROOTFS/dev" "$ROOTFS/proc" 2>/dev/null || true
  rm -f "$ROOTFS/usr/sbin/policy-rc.d"
fi

# Drop any leftover chroot mounts before we copy the tree.
for mp in "$ROOTFS/dev/pts" "$ROOTFS/dev" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/run"; do
  mountpoint -q "$mp" && umount -l "$mp" || true
done

# Install the deb into the rootfs (still not the host).
cp -a "$DEB" "$ROOT/scripts/vm-selftest.sh" "$ROOTFS/tmp/"
mount -t proc proc "$ROOTFS/proc"
mount --bind /dev "$ROOTFS/dev"
# Drop a previous half-installed guest package so the new payload is clean.
chroot "$ROOTFS" dpkg --purge --force-all ker >/dev/null 2>&1 || true
rm -rf "$ROOTFS/usr/lib/ker"
# skip running apt/dpkg triggers that need a full systemd
chroot "$ROOTFS" dpkg -i --force-depends /tmp/$(basename "$DEB") || \
  die "dpkg -i of the guest package failed"
install -d -m 755 "$ROOTFS/usr/lib/ker"
install -m 755 "$ROOTFS/tmp/vm-selftest.sh" "$ROOTFS/usr/lib/ker/vm-selftest.sh"
# If the package missed the bpf object or probe, copy from the host build.
if [ ! -f "$ROOTFS/usr/lib/ker/bpf/ker.bpf.o" ]; then
  install -d -m 755 "$ROOTFS/usr/lib/ker/bpf"
  install -m 644 "$ROOT/dist/bpf/ker.bpf.o" "$ROOTFS/usr/lib/ker/bpf/ker.bpf.o"
fi
if [ ! -x "$ROOTFS/usr/lib/ker/ker-probe" ]; then
  install -m 755 "$ROOT/dist/ker-probe" "$ROOTFS/usr/lib/ker/ker-probe"
fi
# hostname + fstab
echo ker-vm > "$ROOTFS/etc/hostname"
cat > "$ROOTFS/etc/fstab" << 'FSTAB'
/dev/vda / ext4 rw,noatime 0 1
FSTAB
# Keep getty off; PID 1 is the selftest.
rm -f "$ROOTFS/tmp/$(basename "$DEB")" "$ROOTFS/tmp/vm-selftest.sh"
umount -l "$ROOTFS/dev" "$ROOTFS/proc" 2>/dev/null || true

mkdir -p "$VM"
# Recreate images each run.
rm -f "$ROOT_IMG" "$MEDIA_ROOT" "$MEDIA_ADMIN" "$MEDIA_SSH" "$RESULT_IMG" "$HOOK_INITRD"
qemu-img create -f raw "$ROOT_IMG" 8G
mkfs.ext4 -F -L KERROOT "$ROOT_IMG"
MNT=$(mktemp -d)
mount -o loop "$ROOT_IMG" "$MNT"
rsync -aHAX --numeric-ids --info=stats1 \
  --exclude=/proc/'*' --exclude=/sys/'*' --exclude=/dev/'*' --exclude=/run/'*' \
  --exclude=/tmp/'*' --exclude=/mnt/'*' \
  "$ROOTFS"/ "$MNT"/
mkdir -p "$MNT"/{proc,sys,dev,run,tmp,mnt,root}
# A little entropy / machine-id
chroot "$MNT" systemd-machine-id-setup 2>/dev/null || \
  echo 00000000000000000000000000000001 > "$MNT/etc/machine-id"
umount "$MNT"
rmdir "$MNT"

# Media are blank until ker init formats them. 512MiB holds several 10MiB keys.
qemu-img create -f raw "$MEDIA_ROOT" 512M
qemu-img create -f raw "$MEDIA_ADMIN" 256M
qemu-img create -f raw "$MEDIA_SSH" 256M
qemu-img create -f raw "$RESULT_IMG" 64M
mkfs.ext4 -F -L KERRESULT "$RESULT_IMG"

# Copy host kernel modules into... already in? We did not copy modules.
# Selftest only needs what's already in the running (host) kernel, which is
# the guest kernel too, so modules come from the initrd or we should copy
# /lib/modules/$KVER into the root image for later modprobe (vfat etc).
# Copy now if missing.
if [ ! -d "$ROOTFS/lib/modules/$KVER" ]; then
  echo "copying host modules $KVER into the root image"
  MNT=$(mktemp -d)
  mount -o loop "$ROOT_IMG" "$MNT"
  mkdir -p "$MNT/lib/modules"
  rsync -a "/lib/modules/$KVER" "$MNT/lib/modules/"
  umount "$MNT"
  rmdir "$MNT"
fi

echo "booting qemu (log: $LOG)"
# Give the guest the same kernel so the BPF object matches this host's BTF.
# -no-reboot: selftest's reboot -f ends the VM.
timeout --signal=KILL 900 qemu-system-x86_64 \
  -enable-kvm -cpu host -m 2048 -smp 2 \
  -nographic -no-reboot \
  -device virtio-rng-pci \
  -kernel "$KERNEL" \
  -initrd "$INITRD" \
  -append "root=/dev/vda rw console=ttyS0,115200n8 init=/usr/lib/ker/vm-selftest.sh random.trust_cpu=on lsm=lockdown,capability,landlock,yama,apparmor,tomoyo,bpf,ipe,ima,evm" \
  -drive file="$ROOT_IMG",if=virtio,format=raw,cache=writeback \
  -drive file="$MEDIA_ROOT",if=virtio,format=raw,cache=writeback \
  -drive file="$MEDIA_ADMIN",if=virtio,format=raw,cache=writeback \
  -drive file="$RESULT_IMG",if=virtio,format=raw,cache=writeback \
  -drive file="$MEDIA_SSH",if=virtio,format=raw,cache=writeback \
  >"$LOG" 2>&1 || {
    echo "qemu exited $?"
  }

collect_results() {
  local mnt
  mnt=$(mktemp -d)
  if mount -o loop "$RESULT_IMG" "$mnt"; then
    mkdir -p "$DIST/vm-results"
    cp -a "$mnt"/. "$DIST/vm-results/" || true
    umount "$mnt"
  else
    echo "could not mount result image" >&2
  fi
  rmdir "$mnt" 2>/dev/null || true
}

collect_results
if [ -f "$DIST/vm-results/phase1.json" ]; then
  echo "phase 1 finished; building hook initrd for early-boot test"
  MNT=$(mktemp -d)
  mount -o loop "$ROOT_IMG" "$MNT"
  if [ ! -f "$MNT/etc/ker/state.json" ]; then
    umount "$MNT"; rmdir "$MNT"
    die "phase1 claimed success but guest has no /etc/ker/state.json"
  fi
  bash "$ROOT/scripts/build-hook-initrd.sh" "$MNT" "$HOOK_INITRD" "$KVER"
  umount "$MNT"
  rmdir "$MNT"
  [ -f "$HOOK_INITRD" ] || die "hook initrd not built"
  echo "booting qemu for hook phase (log appended to $LOG)"
  timeout --signal=KILL 300 qemu-system-x86_64 \
    -enable-kvm -cpu host -m 3072 -smp 2 \
    -nographic -no-reboot \
    -device virtio-rng-pci \
    -kernel "$KERNEL" \
    -initrd "$HOOK_INITRD" \
    -append "root=/dev/vda rw console=ttyS0,115200n8 ker.selftest=phase2 random.trust_cpu=on lsm=lockdown,capability,landlock,yama,apparmor,tomoyo,bpf,ipe,ima,evm" \
    -drive file="$ROOT_IMG",if=virtio,format=raw,cache=writeback \
    -drive file="$MEDIA_ROOT",if=virtio,format=raw,cache=writeback \
    -drive file="$MEDIA_ADMIN",if=virtio,format=raw,cache=writeback \
    -drive file="$RESULT_IMG",if=virtio,format=raw,cache=writeback \
    -drive file="$MEDIA_SSH",if=virtio,format=raw,cache=writeback \
    >>"$LOG" 2>&1 || {
      echo "hook-phase qemu exited $?"
    }
  collect_results
fi

# Collect the result volume (final).
MNT=$(mktemp -d)
if mount -o loop "$RESULT_IMG" "$MNT"; then
  mkdir -p "$DIST/vm-results"
  cp -a "$MNT"/. "$DIST/vm-results/" || true
  umount "$MNT"
else
  echo "could not mount result image" >&2
fi
rmdir "$MNT" 2>/dev/null || true
echo "----- host cleanliness -----"
systemctl is-active ker-guard.service ker-kernel-audit.service || true
if [ -e /etc/ker/state.json ] || [ -e /sys/fs/bpf/ker ]; then
  echo "ERROR: production host picked up KER state or BPF pin" >&2
  exit 1
fi
echo "host remains clean (no /etc/ker/state.json, no /sys/fs/bpf/ker)"

echo "----- result.json -----"
cat "$DIST/vm-results/result.json" 2>/dev/null || echo '(missing)'
echo "----- selftest.log (tail) -----"
tail -n 80 "$DIST/vm-results/selftest.log" 2>/dev/null || tail -n 80 "$LOG"
if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get("ok") else 1)' "$DIST/vm-results/result.json" 2>/dev/null; then
  echo "VM selftest passed"
  exit 0
fi
echo "VM selftest failed"
exit 1
