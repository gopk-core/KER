#!/bin/bash
# Build per-architecture CO-RE BPF objects. Does not load them.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CLANG=${CLANG:-clang-19}
ARCHES=${ARCHES:-amd64 arm64 armhf i386 riscv64}
python3 - "$ROOT" $ARCHES << 'PY'
import json, os, subprocess, sys
root = sys.argv[1]
arches = sys.argv[2:]
meta = json.loads(open(os.path.join(root, "packaging/arches.json")).read())
clang = os.environ.get("CLANG", "clang-19")
src = os.path.join(root, "src/bpf/ker.bpf.c")
for a in arches:
    tgt = meta[a]["bpf_target"]
    outdir = os.path.join(root, "dist/bpf", a)
    os.makedirs(outdir, exist_ok=True)
    out = os.path.join(outdir, "ker.bpf.o")
    cmd = [clang, "-O2", "-g", "-target", "bpf", f"-D__TARGET_ARCH_{tgt}",
           "-c", src, "-o", out, "-I", os.path.join(root, "src/bpf")]
    print("+", " ".join(cmd), flush=True)
    subprocess.check_call(cmd)
# Keep a host-arch alias for local `make test`.
host = os.uname().machine
alias = {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "armhf", "i686": "i386", "riscv64": "riscv64"}.get(host, "amd64")
src_obj = os.path.join(root, "dist/bpf", alias, "ker.bpf.o")
if os.path.isfile(src_obj):
    os.makedirs(os.path.join(root, "dist/bpf"), exist_ok=True)
    dst = os.path.join(root, "dist/bpf", "ker.bpf.o")
    data = open(src_obj, "rb").read()
    open(dst, "wb").write(data)
    print("aliased", src_obj, "->", dst)
PY
