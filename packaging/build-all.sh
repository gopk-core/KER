#!/bin/bash
# Build KER packages for every format and architecture. Never installs them.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
ARCHES=${ARCHES:-amd64 arm64 armhf i386 riscv64}
FORMATS=${FORMATS:-deb rpm apk arch}

"$ROOT/packaging/build-bpf.sh"
"$ROOT/packaging/build-probe.sh"

ok=0
fail=0
for a in $ARCHES; do
  for f in $FORMATS; do
    echo "===== building $f for $a ====="
    case $f in
      deb) cmd="$ROOT/packaging/build-deb.sh" ;;
      rpm) cmd="$ROOT/packaging/build-rpm.sh" ;;
      apk) cmd="$ROOT/packaging/build-apk.sh" ;;
      arch) cmd="$ROOT/packaging/build-archpkg.sh" ;;
      *) echo "unknown format $f" >&2; exit 2 ;;
    esac
    if out=$("$cmd" "$a"); then
      echo "OK $out"
      ok=$((ok+1))
    else
      echo "FAIL $f $a" >&2
      fail=$((fail+1))
    fi
  done
done
echo "Built $ok packages, $fail failures. Artifacts in $ROOT/dist"
[ "$fail" -eq 0 ]
