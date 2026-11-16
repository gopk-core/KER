#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VER=$(PYTHONPATH="$ROOT/python" python3 -c 'from ker import __version__; print(__version__)')
ARCH=${1:-amd64}
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
umask 022
"$ROOT/packaging/stage.sh" "$STAGE" "$ARCH" >/dev/null
install -d -m 755 "$STAGE/DEBIAN"
python3 - "$ROOT" "$STAGE" "$VER" "$ARCH" << 'PY'
import json, os, sys
root, stage, ver, arch = sys.argv[1:]
meta = json.loads(open(os.path.join(root, "packaging/arches.json")).read())
deb_arch = meta[arch]["deb"]
src = open(os.path.join(root, "packaging/debian/control"), encoding="utf-8").read().splitlines()
out = []
for line in src:
    if line.startswith("Version:"):
        out.append(f"Version: {ver}")
    elif line.startswith("Architecture:"):
        out.append(f"Architecture: {deb_arch}")
    else:
        out.append(line)
open(os.path.join(stage, "DEBIAN/control"), "w").write("\n".join(out) + "\n")
print(deb_arch)
PY
DEB_ARCH=$(python3 -c "import json,os; print(json.load(open('$ROOT/packaging/arches.json'))['$ARCH']['deb'])")
for s in preinst postinst prerm postrm; do
  install -m 755 "$ROOT/packaging/debian/$s" "$STAGE/DEBIAN/$s"
done
( cd "$STAGE" && find usr -type f -exec md5sum {} \; ) > "$STAGE/DEBIAN/md5sums"
mkdir -p "$ROOT/dist"
OUT="$ROOT/dist/ker_${VER}_${DEB_ARCH}.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT"
echo "$OUT"
