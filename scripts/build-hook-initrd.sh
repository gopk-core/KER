#!/bin/bash
# Assemble a test initramfs that contains the KER boot hook, Python/crypto,
# trust anchors from a guest root, and virtio+ext4 modules. Used by vm-test.sh
# for an early-boot exercise. Never writes the production host's /boot.
set -euo pipefail
GUEST_ROOT=${1:?guest root mount or rootfs path}
OUT=${2:?output initrd path}
KVER=${3:-$(uname -r)}

die() { echo "build-hook-initrd: $*" >&2; exit 1; }
[ -d "$GUEST_ROOT" ] || die "missing guest root $GUEST_ROOT"
[ -f "$GUEST_ROOT/usr/lib/ker/ker-boot-check" ] || die "KER hook not installed in guest root"
[ -f "$GUEST_ROOT/etc/ker/state.json" ] || die "guest is not initialized (no /etc/ker/state.json)"

WORK=$(mktemp -d)
DEST="$WORK/root"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$DEST"/{bin,sbin,dev,proc,sys,run,tmp,newroot,etc,usr,lib,lib64}

# Busybox for /init. Prefer a statically linked binary so the initrd does not
# depend on host libc (the dynamically linked Debian busybox needs libresolv).
BB=""
for cand in /bin/busybox /usr/bin/busybox "$GUEST_ROOT/bin/busybox" "$GUEST_ROOT/usr/bin/busybox"; do
  if [ -x "$cand" ]; then
    if file "$cand" | grep -q 'statically linked'; then
      BB=$cand
      break
    fi
    [ -n "$BB" ] || BB=$cand
  fi
done
[ -n "$BB" ] || die "busybox not found"
cp "$BB" "$DEST/bin/busybox"
# If we had to use a dynamic busybox, pull its shared libraries too.
if ! file "$DEST/bin/busybox" | grep -q 'statically linked'; then
  ldd "$DEST/bin/busybox" 2>/dev/null | awk '/=>/ {print $3} /^\// {print $1}' | while read -r lib; do
    [ -f "$lib" ] || continue
    mkdir -p "$DEST/$(dirname "$lib")"
    cp -a "$lib" "$DEST$lib"
  done
  for ld in /lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2; do
    if [ -f "$ld" ]; then
      mkdir -p "$DEST/$(dirname "$ld")"
      cp -a "$ld" "$DEST$ld"
    fi
  done
fi
# Do not --install at build time: busybox would emit absolute
# symlinks into the staging path, which are broken inside the guest.
# /init runs: /bin/busybox --install -s /bin

# Kernel modules (host kernel = guest kernel in this VM test)
copy_mod() {
  local m ko
  m=$1
  while read -r _ ko; do
    [ -f "${ko:-}" ] || continue
    mkdir -p "$DEST/$(dirname "${ko#/}")"
    cp -a "$ko" "$DEST$ko"
  done < <(modprobe --set-version "$KVER" --show-depends "$m" 2>/dev/null | awk '/^insmod /{print $1,$2}')
}
for m in virtio virtio_ring virtio_pci virtio_blk crc32c mbcache jbd2 ext4 vfat nls_cp437 nls_iso8859-1 isofs; do
  copy_mod "$m"
done
mkdir -p "$DEST/lib/modules/$KVER"
cp -a "/lib/modules/$KVER/modules.dep" "$DEST/lib/modules/$KVER/" 2>/dev/null || true
cp -a "/lib/modules/$KVER/modules.alias" "$DEST/lib/modules/$KVER/" 2>/dev/null || true
cp -a "/lib/modules/$KVER/modules.builtin" "$DEST/lib/modules/$KVER/" 2>/dev/null || true

# Dynamic loaders from the guest (Debian amd64)
for ld in \
  "$GUEST_ROOT/lib64/ld-linux-x86-64.so.2" \
  "$GUEST_ROOT/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"; do
  if [ -f "$ld" ]; then
    rel=${ld#"$GUEST_ROOT"}
    mkdir -p "$DEST/$(dirname "$rel")"
    cp -a "$ld" "$DEST$rel"
  fi
done

copy_tree() {
  local src=$1 dest=$2
  [ -e "$src" ] || return 0
  mkdir -p "$(dirname "$dest")"
  cp -a "$src" "$dest"
}

# Tools from the guest
for bin in python3 gpgv openssl mount umount poweroff reboot sleep mkdir mountpoint; do
  for dir in /usr/bin /usr/sbin /bin /sbin; do
    if [ -x "$GUEST_ROOT$dir/$bin" ]; then
      copy_tree "$GUEST_ROOT$dir/$bin" "$DEST$dir/$bin"
      break
    fi
  done
done
# python3 may be a symlink to python3.13
if [ -L "$GUEST_ROOT/usr/bin/python3" ]; then
  target=$(readlink "$GUEST_ROOT/usr/bin/python3")
  if [ -x "$GUEST_ROOT/usr/bin/$target" ]; then
    copy_tree "$GUEST_ROOT/usr/bin/$target" "$DEST/usr/bin/$target"
  elif [ -x "$GUEST_ROOT/usr/bin/python3" ]; then
    :
  fi
fi

# Shared libraries: copy every ELF needed by python3, gpgv, openssl, cryptography.
# ldd on binaries that live in the guest, using the guest as a library source.
export_ldd_copy() {
  local bin=$1
  [ -e "$bin" ] || return 0
  ldd "$bin" 2>/dev/null | awk '/=>/ {print $3} /^\// {print $1}' | while read -r lib; do
    [ -f "$lib" ] || continue
    # Prefer guest copy when present
    if [ -f "$GUEST_ROOT$lib" ]; then
      mkdir -p "$DEST/$(dirname "$lib")"
      cp -a "$GUEST_ROOT$lib" "$DEST$lib" 2>/dev/null || cp -a "$lib" "$DEST$lib"
    else
      mkdir -p "$DEST/$(dirname "$lib")"
      cp -a "$lib" "$DEST$lib"
    fi
  done
}

# Copy python and cryptography from the guest, then resolve .so deps.
if [ -d "$GUEST_ROOT/usr/lib/python3.13" ]; then
  mkdir -p "$DEST/usr/lib/python3.13"
  cp -a "$GUEST_ROOT/usr/lib/python3.13/." "$DEST/usr/lib/python3.13/"
fi
for d in /usr/lib/python3/dist-packages /usr/lib/python3/site-packages; do
  if [ -d "$GUEST_ROOT$d" ]; then
    mkdir -p "$DEST$d"
    for pkg in cryptography cffi bcrypt; do
      [ -e "$GUEST_ROOT$d/$pkg" ] && cp -a "$GUEST_ROOT$d/$pkg" "$DEST$d/"
    done
    find "$GUEST_ROOT$d" -maxdepth 1 \( -name '_cffi_backend*.so' -o -name 'cryptography*' \) | while read -r p; do
      cp -a "$p" "$DEST$d/" 2>/dev/null || true
    done
  fi
done

# KER payload + trust
mkdir -p "$DEST/usr/lib/ker" "$DEST/etc/ker"
cp -a "$GUEST_ROOT/usr/lib/ker/." "$DEST/usr/lib/ker/"
cp -a "$GUEST_ROOT/etc/ker/." "$DEST/etc/ker/"
mkdir -p "$DEST/usr/share/initramfs-tools/scripts/local-premount"
if [ -f "$GUEST_ROOT/usr/share/initramfs-tools/scripts/local-premount/ker-boot" ]; then
  cp -a "$GUEST_ROOT/usr/share/initramfs-tools/scripts/local-premount/ker-boot" \
    "$DEST/usr/share/initramfs-tools/scripts/local-premount/ker-boot"
fi

# Record boot-required from guest state
python3 -c 'import json,sys; st=json.load(open(sys.argv[1])); sys.exit(0 if "boot" in (st.get("permissions") or []) else 1)' \
  "$GUEST_ROOT/etc/ker/state.json" \
  && printf 'required\n' > "$DEST/etc/ker/boot-required" \
  || printf 'optional\n' > "$DEST/etc/ker/boot-required"

# Recursively copy shared-library dependencies until the closure is complete.
copy_deps_of() {
  local bin=$1 lib lines
  [ -e "$bin" ] || return 0
  [ -f "$bin" ] || return 0
  file "$bin" 2>/dev/null | grep -q ELF || return 0
  # ldd exits non-zero for static binaries (busybox, ker-probe); never abort the build.
  lines=$(ldd "$bin" 2>/dev/null || true)
  printf '%s\n' "$lines" | awk '/=> \// {print $3} /^\// {print $1}' | while read -r lib; do
    [ -n "$lib" ] && [ -f "$lib" ] || continue
    # Prefer the guest copy
    src=$lib
    [ -f "$GUEST_ROOT$lib" ] && src="$GUEST_ROOT$lib"
    mkdir -p "$DEST/$(dirname "$lib")"
    # Dereference so we do not ship a dangling libfoo.so.1 -> libfoo.so.1.N symlink.
    if [ -L "$src" ]; then
      real=$(readlink -f "$src")
      rel=$(readlink "$src")
      if [ -f "$real" ]; then
        cp -a "$real" "$DEST/$(dirname "$lib")/$(basename "$real")"
        # recreate the soname symlink if needed
        ln -sfn "$(basename "$real")" "$DEST$lib"
      fi
    elif [ ! -e "$DEST$lib" ]; then
      cp -a "$src" "$DEST$lib"
    fi
  done || true
  return 0
}
# Multiple passes over every userspace file so mount/umount/env/python/gpgv
# and every copied .so get a complete library closure (including soname targets).
# Kernel modules are skipped: they are not userspace ELFs and ldd cannot resolve them.
for pass in 1 2 3 4 5 6; do
  find "$DEST" -type f ! -path '*/lib/modules/*' | while read -r f; do
    copy_deps_of "$f"
  done
done
# OpenSSL providers and config (cryptography needs these, or at least a readable openssl.cnf).
mkdir -p "$DEST/usr/lib/x86_64-linux-gnu/ossl-modules" "$DEST/etc/ssl" "$DEST/usr/lib/ssl"
for src_root in "$GUEST_ROOT" ""; do
  if [ -d "${src_root}/usr/lib/x86_64-linux-gnu/ossl-modules" ]; then
    cp -a "${src_root}/usr/lib/x86_64-linux-gnu/ossl-modules/." "$DEST/usr/lib/x86_64-linux-gnu/ossl-modules/"
  fi
  if [ -f "${src_root}/etc/ssl/openssl.cnf" ]; then
    cp -a "${src_root}/etc/ssl/openssl.cnf" "$DEST/etc/ssl/openssl.cnf"
    ln -sfn /etc/ssl/openssl.cnf "$DEST/usr/lib/ssl/openssl.cnf"
  fi
done
# /usr/bin/env is used by hook shebangs.
for envb in /usr/bin/env /bin/env; do
  src=""
  [ -f "$GUEST_ROOT$envb" ] && src="$GUEST_ROOT$envb"
  [ -z "$src" ] && [ -f "$envb" ] && src=$envb
  [ -n "$src" ] || continue
  mkdir -p "$DEST/$(dirname "$envb")"
  cp -a "$src" "$DEST$envb"
  copy_deps_of "$src"
done

# Always include the dynamic linker, including the conventional /lib64 name.
for ld in /lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2; do
  src=""
  [ -e "$GUEST_ROOT$ld" ] && src="$GUEST_ROOT$ld"
  [ -z "$src" ] && [ -e "$ld" ] && src=$ld
  [ -n "$src" ] || continue
  mkdir -p "$DEST/$(dirname "$ld")"
  if [ -L "$src" ]; then
    real=$(readlink -f "$src")
    mkdir -p "$DEST/$(dirname "$real")"
    [ -f "$DEST$real" ] || cp -a "$real" "$DEST$real"
    ln -sfn "$(realpath --relative-to="$(dirname "$ld")" "$real")" "$DEST$ld" 2>/dev/null ||       ln -sfn ../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 "$DEST/lib64/ld-linux-x86-64.so.2"
  elif [ ! -e "$DEST$ld" ]; then
    cp -a "$src" "$DEST$ld"
  fi
done
mkdir -p "$DEST/lib64"
if [ -f "$DEST/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" ] && [ ! -e "$DEST/lib64/ld-linux-x86-64.so.2" ]; then
  ln -sfn ../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 "$DEST/lib64/ld-linux-x86-64.so.2"
fi

cat > "$DEST/init" << 'INIT'
#!/bin/busybox sh
/bin/busybox --install -s /bin 2>/dev/null || true
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PYTHONPATH=/usr/lib/ker
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sys /sys
/bin/busybox mount -t devtmpfs dev /dev 2>/dev/null || /bin/busybox mount -t tmpfs dev /dev
/bin/busybox mount -t tmpfs tmpfs /run
/bin/busybox mount -t tmpfs tmpfs /tmp
for m in virtio virtio_ring virtio_pci virtio_blk crc32c mbcache jbd2 ext4 vfat nls_cp437 nls_iso8859-1; do
  /bin/busybox modprobe "$m" 2>/dev/null || /bin/busybox insmod $(/bin/busybox find /lib/modules -name "$m.ko*" | /bin/busybox head -1) 2>/dev/null || true
done
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  [ -b /dev/vda ] && break
  /bin/busybox sleep 0.25
done

/bin/busybox mkdir -p /run/ker
# Run the shipped hook with busybox sh so a missing /bin/sh cannot fail us.
if [ -f /usr/share/initramfs-tools/scripts/local-premount/ker-boot ]; then
  /bin/busybox sh /usr/share/initramfs-tools/scripts/local-premount/ker-boot
else
  /usr/bin/python3 /usr/lib/ker/ker-boot-check > /run/ker/boot-status.json || {
    echo "KER boot check failed" > /dev/console
    /bin/busybox poweroff -f 2>/dev/null || while :; do /bin/busybox sleep 60; done
  }
fi

# If we are still here, boot was allowed (or not required).
/bin/busybox mkdir -p /newroot
/bin/busybox mount -o rw /dev/vda /newroot || { echo "mount root failed"; exec /bin/busybox sh; }
/bin/busybox mkdir -p /newroot/run/ker /newroot/root
if [ -f /run/ker/boot-status.json ]; then
  /bin/busybox cp -a /run/ker/boot-status.json /newroot/run/ker/boot-status.json
  /bin/busybox cp -a /run/ker/boot-status.json /newroot/root/ker-boot-status.json
  if [ -b /dev/vdd ]; then
    /bin/busybox mkdir -p /newroot/mnt/ker-result-early
    if /bin/busybox mount -o rw /dev/vdd /newroot/mnt/ker-result-early 2>/dev/null; then
      /bin/busybox cp -a /run/ker/boot-status.json /newroot/mnt/ker-result-early/boot-hook.json
      /bin/busybox umount /newroot/mnt/ker-result-early 2>/dev/null || true
    fi
  fi
fi
exec /bin/busybox switch_root /newroot /usr/lib/ker/vm-selftest.sh
INIT
chmod 755 "$DEST/init"

mkdir -p "$(dirname "$OUT")"
( cd "$DEST" && find . | cpio -o -H newc ) | gzip -c > "$OUT"
echo "hook initrd: $OUT ($(wc -c < "$OUT") bytes)"
