#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VER=$(PYTHONPATH="$ROOT/python" python3 -c 'from ker import __version__; print(__version__)')
ARCH=${1:-amd64}
command -v rpmbuild >/dev/null || { echo "rpmbuild is required" >&2; exit 1; }
RPM_ARCH=$(python3 -c "import json; print(json.load(open('$ROOT/packaging/arches.json'))['$ARCH']['rpm'])")
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS,payload}
"$ROOT/packaging/stage.sh" "$WORK/payload" "$ARCH" >/dev/null
# File list (paths relative to payload, leading slash in %files)
( cd "$WORK/payload" && find usr -print | sort ) > "$WORK/filelist.txt"
# rpmbuild wants the payload copied in %install
cat > "$WORK/SPECS/ker.spec" << SPEC
Name:           ker
Version:        ${VER}
Release:        1
Summary:        Linux media-backed kernel authorization system
License:        AGPL-3.0-or-later
Group:          System Environment/Base
URL:            https://github.com/gopk-core/KER
BuildArch:      ${RPM_ARCH}
AutoReqProv:    no
# Built on Debian as a relocatable payload; do not generate Debian-path requires.

%description
KER verifies signed removable media and optionally enforces kernel-level
authorization. First run is terminal-only. Packages are architecture-specific
because they ship a BPF object and ker-probe built for that architecture.
This package does not auto-update.

%prep

%build

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a $WORK/payload/. %{buildroot}/

%pre
if [ -e /etc/ker/state.json ]; then
  TS=\$(date -u +%Y%m%dT%H%M%SZ)
  DEST=/var/lib/ker/upgrade/snapshots/preinst-\$TS
  mkdir -p "\$DEST"
  chmod 700 /var/lib/ker /var/lib/ker/upgrade /var/lib/ker/upgrade/snapshots "\$DEST" 2>/dev/null || true
  cp -a /etc/ker/state.json "\$DEST/state.json"
  [ -f /etc/ker/config.json ] && cp -a /etc/ker/config.json "\$DEST/config.json"
  [ -d /etc/ker/trust ] && cp -a /etc/ker/trust "\$DEST/trust"
  [ -d /var/lib/ker/private ] && cp -a /var/lib/ker/private "\$DEST/private"
  printf '{"reason":"preinst","created":"%s"}\\n' "\$TS" > "\$DEST/meta.json"
  chmod 700 "\$DEST"
fi

%post
if [ -x /usr/sbin/ker ]; then
  /usr/sbin/ker upgrade --migrate --from-package || true
fi
if [ -x /usr/lib/ker/install-hooks ]; then
  /usr/lib/ker/install-hooks --from-package || true
fi

%preun

%postun
if [ "\$1" = "0" ]; then
  echo "KER package removed; keys and state in /etc/ker and /var/lib/ker were left untouched." >&2
fi

SPEC

# Package every staged file so new units, udev rules or docs cannot be left unpackaged.
{
  echo '%files'
  echo '%defattr(-,root,root,-)'
  ( cd "$WORK/payload" && find usr -type f -print | sort | sed 's|^|/|' )
  echo
  echo '%changelog'
  echo "* Mon Nov 16 2026 KER <ker@localhost> - ${VER}-1"
  echo '- Multi-arch package, boot hook, SSH hook, media watcher, boot BPF restore.'
} >> "$WORK/SPECS/ker.spec"


# Allow packaging a prebuilt payload for a foreign RPM architecture.
# rpmbuild otherwise only permits noarch from this x86_64 host.
cat > "$WORK/rpmrc" << RCRC
include: /usr/lib/rpm/rpmrc
buildarch_compat: x86_64: aarch64 armv7hl i686 riscv64 noarch
buildarch_compat: aarch64: noarch
buildarch_compat: armv7hl: noarch
buildarch_compat: i686: noarch
buildarch_compat: riscv64: noarch
RCRC
# Do not strip the eBPF object (host strip does not recognise it).
rpmbuild -bb --noclean \
  --rcfile "$WORK/rpmrc" \
  --define "_topdir $WORK" \
  --define "_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm" \
  --define "__strip /bin/true" \
  --define "_build_id_links none" \
  --target "$RPM_ARCH-linux" \
  "$WORK/SPECS/ker.spec"
mkdir -p "$ROOT/dist"
FOUND=$(find "$WORK/RPMS" -name '*.rpm' | head -1)
[ -n "$FOUND" ] || { echo "rpmbuild produced no rpm" >&2; exit 1; }
OUT="$ROOT/dist/ker-${VER}-1.${RPM_ARCH}.rpm"
cp -a "$FOUND" "$OUT"
echo "$OUT"
