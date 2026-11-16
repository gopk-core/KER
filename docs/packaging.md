# Building KER packages

KER 0.1.0 ships architecture-specific packages in four formats. Python code is
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

Example artifact names for version 0.1.0:

- `dist/ker_0.1.0_amd64.deb`
- `dist/ker-0.1.0-1.x86_64.rpm`
- `dist/ker-0.1.0-r0.x86_64.apk`
- `dist/ker-0.1.0-1-x86_64.pkg.tar.zst`

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

## Release signatures

`packaging/release.gpg` is a public OpenPGP key. `packaging/stage.sh` installs it to `/usr/lib/ker/release-keys/release.gpg`. The private key is not in git, and this repository does not contain a passphrase or a secret keyring.

The public key currently in the tree (fingerprint `AB264D24E538B7DC0E449FC16EE0524231372B31`) was generated so the file format and the install path are real. Its private half was not retained. Before you publish signed packages, replace `packaging/release.gpg` with the public key that matches the offline private key you will actually sign with, and tell operators that fingerprint out of band. Until then, `gpgv` against the shipped key will not verify signatures from any other key.

Create the key on a machine you keep offline:

```
export KER_RELEASE_GNUPGHOME=/path/outside/this/repo
mkdir -m 700 "$KER_RELEASE_GNUPGHOME"
gpg --batch --pinentry-mode loopback --passphrase '' \
  --homedir "$KER_RELEASE_GNUPGHOME" \
  --quick-gen-key 'KER Release <ker-release@localhost>' rsa3072 sign 0
gpg --homedir "$KER_RELEASE_GNUPGHOME" --export --output packaging/release.gpg
```

Keep `$KER_RELEASE_GNUPGHOME` offline. Commit only the exported public key. When that directory is set and contains a secret key, `packaging/sign-dist.sh` (also run at the end of `packaging/build-all.sh`) writes `<artifact>.sig` next to each package. The script refuses a keyring path inside the source tree. If the variable is unset, the build still succeeds and the packages are unsigned.

`ker upgrade` verifies `<file>.sig` with the installed public key. No `.sig` means the package is unsigned and `--trust-package` is required. A bad signature is rejected even if `--trust-package` is set. Alpine still needs `apk add --allow-untrusted` when you install an unsigned `.apk` directly; a signature KER understands is the detached `.sig` next to the package, not an Alpine package signature.

After install, `ker` is in `/usr/sbin`, which is on root's `PATH`. First run
is `ker`.

The packaging scripts only stage files under a temporary directory and write
the finished archive to `dist/`. They never run `dpkg -i`, `rpm -i`, `apk add`,
or `pacman -U` on the build host.

Cross-architecture RPMs are built on this x86_64 host by passing a temporary `rpmrc` that extends `buildarch_compat` so a pre-compiled payload can be wrapped for aarch64, armv7hl, i686 and riscv64. The script never executes those binaries on the build machine.
