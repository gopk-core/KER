#!/bin/bash
# Stage an architecture-specific KER payload into $1 (destination root).
# Usage: stage.sh DEST KER_ARCH
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEST=${1:?destination root}
ARCH=${2:?ker arch name (amd64|arm64|armhf|i386|riscv64)}
VER=$(PYTHONPATH="$ROOT/python" python3 -c 'from ker import __version__; print(__version__)')

umask 022
install -d -m 755 \
  "$DEST/usr/sbin" \
  "$DEST/usr/lib/ker" \
  "$DEST/usr/lib/ker/bpf" \
  "$DEST/usr/lib/ker/hooks/sshd" \
  "$DEST/usr/lib/ker/hooks/pam" \
  "$DEST/usr/lib/systemd/system" \
  "$DEST/usr/lib/udev/rules.d" \
  "$DEST/usr/share/doc/ker/docs" \
  "$DEST/usr/share/initramfs-tools/hooks" \
  "$DEST/usr/share/initramfs-tools/scripts/local-premount" \
  "$DEST/usr/lib/dracut/modules.d/90ker-boot" \
  "$DEST/usr/lib/initcpio/install" \
  "$DEST/usr/lib/initcpio/hooks" \
  "$DEST/usr/share/mkinitfs/hooks" \
  "$DEST/usr/share/mkinitfs/features.d"

install -m 755 "$ROOT/bin/ker" "$DEST/usr/sbin/ker"
# installed layout uses /usr/lib/ker on the first path entry
sed -i 's#Path(__file__).resolve().parents\[1\] / '\''python'\''#Path("/usr/lib/ker")#' "$DEST/usr/sbin/ker" || true

# Copy to usr/lib/ker/ker (destination must not already exist, or cp nests a second ker/).
if [ -e "$DEST/usr/lib/ker/ker" ]; then
  rm -rf "$DEST/usr/lib/ker/ker"
fi
cp -a "$ROOT/python/ker" "$DEST/usr/lib/ker/ker"
chmod -R a+rX "$DEST/usr/lib/ker/ker"
find "$DEST/usr/lib/ker" -depth -type d -name '__pycache__' -exec rm -rf {} +
find "$DEST/usr/lib/ker" -name '*.pyc' -delete

BPF="$ROOT/dist/bpf/$ARCH/ker.bpf.o"
PROBE="$ROOT/dist/probe/$ARCH/ker-probe"
[ -f "$BPF" ] || { echo "missing $BPF (run packaging/build-bpf.sh)" >&2; exit 1; }
[ -x "$PROBE" ] || { echo "missing $PROBE (run packaging/build-probe.sh)" >&2; exit 1; }
install -m 644 "$BPF" "$DEST/usr/lib/ker/bpf/ker.bpf.o"
if [ -f "$ROOT/packaging/release.gpg" ]; then
  install -d -m 755 "$DEST/usr/lib/ker/release-keys"
  install -m 644 "$ROOT/packaging/release.gpg" "$DEST/usr/lib/ker/release-keys/release.gpg"
fi
install -m 755 "$PROBE" "$DEST/usr/lib/ker/ker-probe"
printf '%s\n' "$ARCH" > "$DEST/usr/lib/ker/arch"
chmod 644 "$DEST/usr/lib/ker/arch"

install -m 755 "$ROOT/hooks/ker-boot-check" "$DEST/usr/lib/ker/ker-boot-check"
install -m 755 "$ROOT/hooks/ker-ssh-pam" "$DEST/usr/lib/ker/ker-ssh-pam"
install -m 755 "$ROOT/hooks/ker-ssh-keys" "$DEST/usr/lib/ker/ker-ssh-keys"
install -m 755 "$ROOT/hooks/ker-pam-probe" "$DEST/usr/lib/ker/ker-pam-probe"
install -m 755 "$ROOT/hooks/install-hooks" "$DEST/usr/lib/ker/install-hooks"
# Point packaged Python helpers at the dedicated ker-python interpreter.
# The binary itself is created in postinst (hard link or copy of the
# target system's python3) so the LSM comm is "ker-python", not "python3".
for helper in \
  "$DEST/usr/sbin/ker" \
  "$DEST/usr/lib/ker/ker-boot-check" \
  "$DEST/usr/lib/ker/ker-ssh-pam" \
  "$DEST/usr/lib/ker/ker-ssh-keys" \
  "$DEST/usr/lib/ker/ker-pam-probe"
do
  if [ -f "$helper" ]; then
    sed -i '1s|^#!/usr/bin/env python3|#!/usr/lib/ker/ker-python|' "$helper" || true
    sed -i '1s|^#!/usr/bin/python3|#!/usr/lib/ker/ker-python|' "$helper" || true
  fi
done

install -m 644 "$ROOT/hooks/sshd/99-ker.conf" "$DEST/usr/lib/ker/hooks/sshd/99-ker.conf"
install -m 644 "$ROOT/hooks/pam/ker-sshd" "$DEST/usr/lib/ker/hooks/pam/ker-sshd"

install -m 755 "$ROOT/hooks/initramfs-tools/hooks/ker-boot" \
  "$DEST/usr/share/initramfs-tools/hooks/ker-boot"
install -m 755 "$ROOT/hooks/initramfs-tools/scripts/local-premount/ker-boot" \
  "$DEST/usr/share/initramfs-tools/scripts/local-premount/ker-boot"

install -m 755 "$ROOT/hooks/dracut/module-setup.sh" "$DEST/usr/lib/dracut/modules.d/90ker-boot/module-setup.sh"
install -m 755 "$ROOT/hooks/dracut/ker-boot.sh" "$DEST/usr/lib/dracut/modules.d/90ker-boot/ker-boot.sh"

install -m 755 "$ROOT/hooks/mkinitcpio/ker-boot.install" "$DEST/usr/lib/initcpio/install/ker-boot"
install -m 755 "$ROOT/hooks/mkinitcpio/ker-boot.hook" "$DEST/usr/lib/initcpio/hooks/ker-boot"

install -m 755 "$ROOT/hooks/mkinitfs/ker-boot" "$DEST/usr/share/mkinitfs/hooks/ker-boot"
install -m 644 "$ROOT/hooks/mkinitfs/ker-boot.files" "$DEST/usr/share/mkinitfs/features.d/ker-boot.files"

install -m 644 "$ROOT/systemd/ker-sync.service" \
  "$ROOT/systemd/ker-enforcer.service" \
  "$ROOT/systemd/ker-enforcer.timer" \
  "$ROOT/systemd/ker-enforcer-poke.service" \
  "$DEST/usr/lib/systemd/system/"

install -m 644 "$ROOT/udev/99-ker-enforcer.rules" \
  "$DEST/usr/lib/udev/rules.d/99-ker-enforcer.rules"

PYTHONPATH="$ROOT/python" python3 -c "from pathlib import Path; from ker.compat import write_manifest; write_manifest(Path('$DEST/usr/lib/ker/upgrade-manifest.json'))"

install -m 644 "$ROOT/README.md" "$ROOT/LICENSE" "$DEST/usr/share/doc/ker/"
if [ -f "$ROOT/README_EN.md" ]; then
  install -m 644 "$ROOT/README_EN.md" "$DEST/usr/share/doc/ker/"
fi
for f in upgrade.md packaging.md hooks.md; do
  if [ -f "$ROOT/docs/$f" ]; then
    install -m 644 "$ROOT/docs/$f" "$DEST/usr/share/doc/ker/docs/"
  fi
done
if [ -d "$ROOT/docs/sponsors" ]; then
  install -d -m 755 "$DEST/usr/share/doc/ker/docs/sponsors"
  for img in "$ROOT/docs/sponsors/"*; do
    [ -f "$img" ] || continue
    install -m 644 "$img" "$DEST/usr/share/doc/ker/docs/sponsors/"
  done
fi
echo "$VER"
