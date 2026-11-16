# Building KER packages

KER 0.1 ships architecture-specific packages in four formats. Python code is
the same on every architecture; each package also contains a BPF object and a
statically linked `ker-probe` built for that architecture.

Do not install a newly built package on the production host that already runs
`ker-guard`. Building the packages does not install them and does not load BPF.

## Formats and architectures

| KER name | Debian `.deb` | RPM `.rpm` | Alpine `.apk` | Arch `.pkg.tar.zst` |
|----------|---------------|------------|---------------|---------------------|
| amd64    | amd64         | x86_64     | x86_64        | x86_64              |
| arm64    | arm64         | aarch64    | aarch64       | aarch64             |
| armhf    | armhf         | armv7hl    | armv7         | armv7h              |
| i386     | i386          | i686       | x86           | i686                |
| riscv64  | riscv64       | riscv64    | riscv64       | riscv64             |

Example artifact names for version 0.1:

- `dist/ker_0.1_amd64.deb`
- `dist/ker-0.1-1.x86_64.rpm`
- `dist/ker-0.1-r0.x86_64.apk`
- `dist/ker-0.1-1-x86_64.pkg.tar.zst`

## Build

From the source tree, without installing KER:

```
# every format and architecture
make packages

# one format, all architectures
make deb
make rpm
make apk
make arch

# one architecture
ARCHES=amd64 make deb
bash packaging/build-rpm.sh arm64
```

`make bpf` and `make probe` only compile artifacts into `dist/`. They never
load a program or install a package. Cross compilers (`gcc-aarch64-linux-gnu`
and the other `*-linux-gnu` toolchains) plus `clang` (BPF) and `rpmbuild`
(for RPMs) are required on the build machine. `packaging/arches.json` lists
the compiler and architecture names.

Unsigned packages still need `--trust-package` when upgrading with `ker
upgrade`, just as in 0.3. Alpine also needs `apk add --allow-untrusted` if
you install the `.apk` directly.

After install, `ker` is in `/usr/sbin`, which is on root's `PATH`. First run
is `ker`.

The packaging scripts only stage files under a temporary directory and write
the finished archive to `dist/`. They never run `dpkg -i`, `rpm -i`, `apk add`,
or `pacman -U` on the build host.

Cross-architecture RPMs are built on this x86_64 host by passing a temporary `rpmrc` that extends `buildarch_compat` so a pre-compiled payload can be wrapped for aarch64, armv7hl, i686 and riscv64. The script never executes those binaries on the build machine.
