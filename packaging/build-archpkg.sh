#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VER=$(PYTHONPATH="$ROOT/python" python3 -c 'from ker import __version__; print(__version__)')
ARCH=${1:-amd64}
python3 - "$ROOT" "$VER" "$ARCH" << 'PY'
import io, json, os, subprocess, sys, tarfile, tempfile, time
from pathlib import Path

root, ver, arch = sys.argv[1:]
meta = json.loads((Path(root) / "packaging/arches.json").read_text())
arch_name = meta[arch]["arch"]
stage = Path(tempfile.mkdtemp(prefix="ker-arch-"))
try:
    subprocess.check_call([str(Path(root) / "packaging/stage.sh"), str(stage), arch], stdout=subprocess.DEVNULL)
    files_size = 0
    for p in stage.rglob("*"):
        if p.is_file() and not p.is_symlink():
            files_size += p.stat().st_size
    pkginfo = f"""pkgname = ker
pkgbase = ker
pkgver = {ver}-1
pkgdesc = Linux media-backed kernel authorization system
url = https://localhost/ker
builddate = {int(time.time())}
packager = KER
size = {files_size}
arch = {arch_name}
license = AGPL-3.0-or-later
"""
    (stage / ".PKGINFO").write_text(pkginfo)
    os.chmod(stage / ".PKGINFO", 0o644)
    install_script = r'''# ker Arch Linux install script
pre_upgrade() {
  if [ -e /etc/ker/state.json ]; then
    TS=$(date -u +%Y%m%dT%H%M%SZ)
    DEST=/var/lib/ker/upgrade/snapshots/preinst-$TS
    mkdir -p "$DEST"
    chmod 700 /var/lib/ker /var/lib/ker/upgrade /var/lib/ker/upgrade/snapshots "$DEST" 2>/dev/null || true
    cp -a /etc/ker/state.json "$DEST/state.json"
    [ -f /etc/ker/config.json ] && cp -a /etc/ker/config.json "$DEST/config.json"
    [ -d /etc/ker/trust ] && cp -a /etc/ker/trust "$DEST/trust"
    [ -d /var/lib/ker/private ] && cp -a /var/lib/ker/private "$DEST/private"
    printf '{"reason":"preinst","created":"%s"}\n' "$TS" > "$DEST/meta.json"
    chmod 700 "$DEST"
  fi
}
post_install() {
  if [ -x /usr/sbin/ker ]; then
    /usr/sbin/ker upgrade --migrate --from-package || true
  fi
  if [ -x /usr/lib/ker/install-hooks ]; then
    /usr/lib/ker/install-hooks --from-package || true
  fi
}
post_upgrade() { post_install; }
pre_remove() { :; }
post_remove() {
  echo "KER package removed; keys and state in /etc/ker and /var/lib/ker were left untouched." >&2
}
'''
    (stage / ".INSTALL").write_text(install_script)
    os.chmod(stage / ".INSTALL", 0o644)

    outdir = Path(root) / "dist"
    outdir.mkdir(exist_ok=True)
    out = outdir / f"ker-{ver}-1-{arch_name}.pkg.tar.zst"
    # Create uncompressed tar then zstd, with root ownership in headers.
    tar_path = Path(tempfile.mkstemp(suffix=".tar")[1])
    with tarfile.open(tar_path, mode="w", format=tarfile.GNU_FORMAT) as tf:
        # .PKGINFO first, then .INSTALL, then payload
        for special in (".PKGINFO", ".INSTALL"):
            path = stage / special
            info = tf.gettarinfo(str(path), arcname=special)
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            with path.open("rb") as f:
                tf.addfile(info, f)
        for dirpath, dirnames, filenames in os.walk(stage):
            dirnames.sort()
            rel_dir = os.path.relpath(dirpath, stage)
            if rel_dir != ".":
                info = tf.gettarinfo(dirpath, arcname=rel_dir.replace("\\", "/"))
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                tf.addfile(info)
            for name in sorted(filenames):
                if name in (".PKGINFO", ".INSTALL"):
                    continue
                path = Path(dirpath) / name
                if not path.is_file():
                    continue
                arc = str(path.relative_to(stage)).replace("\\", "/")
                info = tf.gettarinfo(str(path), arcname=arc)
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                with path.open("rb") as f:
                    tf.addfile(info, f)
    # zstd -19 is unnecessary; default is fine
    if out.exists():
        out.unlink()
    subprocess.check_call(["zstd", "-q", "-f", "-o", str(out), str(tar_path)])
    tar_path.unlink(missing_ok=True)
    print(out)
finally:
    import shutil
    shutil.rmtree(stage, ignore_errors=True)
PY
