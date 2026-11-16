#!/bin/bash
# Cross-compile a static ker-probe for each architecture. Does not install it.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
ARCHES=${ARCHES:-amd64 arm64 armhf i386 riscv64}
python3 - "$ROOT" $ARCHES << 'PY'
import json, os, subprocess, sys
root = sys.argv[1]
arches = sys.argv[2:]
meta = json.loads(open(os.path.join(root, "packaging/arches.json")).read())
src = os.path.join(root, "src/c/ker-probe.c")
for a in arches:
    cc = meta[a]["cc"]
    outdir = os.path.join(root, "dist/probe", a)
    os.makedirs(outdir, exist_ok=True)
    out = os.path.join(outdir, "ker-probe")
    cmd = [cc, "-O2", "-s", "-static", "-o", out, src]
    print("+", " ".join(cmd), flush=True)
    subprocess.check_call(cmd)
host = os.uname().machine
alias = {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "armhf", "i686": "i386", "riscv64": "riscv64"}.get(host, "amd64")
srcp = os.path.join(root, "dist/probe", alias, "ker-probe")
if os.path.isfile(srcp):
    dst = os.path.join(root, "dist", "ker-probe")
    data = open(srcp, "rb").read()
    open(dst, "wb").write(data)
    os.chmod(dst, 0o755)
    print("aliased", srcp, "->", dst)
PY
