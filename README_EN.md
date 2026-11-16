# KER

<p align="center">
  <img src="docs/logo.png" alt="KER" width="160" height="160">
</p>

A Linux kernel-level authorization system. Signed keys live on removable media; installation and administration happen in the terminal. There is no graphical interface.

[简体中文](README.md)

Current version: **0.1.0** (first public release; the already published `0.1` compares equal to `0.1.0` and upgrades in place). License: [GNU Affero General Public License v3.0](LICENSE).

## Safety notes (read these first)

- **Do not** install a KER package on a production host that already runs another kernel-level guard (for example `ker-guard`). Do not load the new BPF on that host, and do not rebuild its initramfs.
- Kernel enforcement is off by default and is **never** turned on by installing or upgrading a package. An administrator enables it only after media verifies, with an explicit `ker enforce --set enforce --yes`. Bare-metal hosts refuse to load BPF unless `KER_ALLOW_HOST_BPF=1` is set on purpose.
- Without Secure Boot or kernel lockdown, KER still cannot stop a root user from replacing the kernel or the bootloader. It provides signed-media authorization and optional LSM enforcement, not a firmware root of trust.
- The `boot.pem` early-boot hook is fail-closed in enforcement mode: missing media or a failed verify refuses to continue to the real root filesystem. Do not weaken this policy.

## Disclaimer

KER is provided as is, and its source code is publicly available. The authors and contributors are not liable for any loss arising from use of this software, including but not limited to failure to boot or log in, system deadlock or lockout, inaccessible data, or service interruption.

Once enforcement, the boot hook, or runtime interception is enabled, the machine may refuse to boot, refuse login, or immediately deny user commands (including those of root) if required media is missing, damaged, lost, or unreadable, if verification fails, or if hardware, configuration, or operator error occurs. You assume those risks. Assess them before use, and keep your own recovery plan.

## What KER is

KER carries signed permission keys on external media (USB drives, removable disks, DVDs, WORM, and similar devices) and uses them at boot, login, and runtime to decide whether a machine is authorized for a given action.

Typical uses:

- The machine must present signed boot media before it is allowed to switch to the real root filesystem;
- At runtime, optional BPF LSM enforcement can block read, write, execute, or network operations when required media is absent;
- Machines can form a master/child cluster. The master signs and syncs policy; children fail closed if the master disappears.

The first run of `ker` starts a terminal wizard (English / Simplified Chinese / Traditional Chinese) and must be run as root.

## How media and keys work

- KER lists every recognizable block device (not only USB sticks). After confirmation it formats the device and writes a sealed file set.
- Rewritable removable media uses FAT32, hard disks use ext4, DVD-R gets an ISO9660 image, and WORM media is written only when empty — it is never reformatted. The optical disc is a data image; see [docs/dvd-image.md](docs/dvd-image.md).
- Each key is 10MB. The signed object on the medium is `bundle.json`, a hash list of the key files. It carries a detached GPG signature (`bundle.json.sig`) and an OpenSSL RSA signature (`bundle.json.ksig`). Individual pem files are not signed on their own; their integrity is the hash in that list. `root.pem` is not encrypted. Every other key is encrypted with the fixed section of `root.pem` and then listed. This is not a per-pem signature. A holder of `root.pem` can unwrap the other keys; KER does not claim confidentiality against that holder. Without the root key, no permission can be established.
- Unwrapped material is placed in the kernel keyring where possible, not written in cleartext under ordinary directories.
- The default is a single medium. Keys can also be split across several disks, each signed on its own. The admin key `admin.pem` is required for `ker console`.
- After writing media, KER enters test mode: it reports verification results in the terminal and does not enable kernel interception. An optional unplug/replug check is available.

## Installing from packages

Packages are architecture-specific (no longer `Architecture: all`) because they ship a BPF object and `ker-probe` built for that architecture. Releases include `.deb`, `.rpm`, `.apk`, and `.pkg.tar.zst` for amd64, arm64, armhf, i386, and riscv64.

Copy the package that matches the machine, then:

```bash
sudo dpkg -i ker_0.1.0_amd64.deb
# or
sudo rpm -Uvh ker-0.1.0-1.x86_64.rpm
sudo apk add --allow-untrusted ker-0.1.0-r0.x86_64.apk
sudo pacman -U ker-0.1.0-1-x86_64.pkg.tar.zst
```

After installation, `/usr/sbin/ker` is on root's `PATH`. Run `ker` to start the first-run wizard.

Packages install the public release key (`/usr/lib/ker/release-keys/release.gpg`). The packager writes a detached signature only when `KER_RELEASE_GNUPGHOME` points at an offline private key. A CI build without that key still produces unsigned packages. `ker upgrade` checks `<package>.sig` with the public key. An unsigned file needs an explicit `--trust-package`. A signature that does not match the public key is rejected. Never commit a private key, a passphrase, or a secret keyring. Typical dependencies include Python 3, python3-cryptography, GnuPG, openssl, dosfstools, e2fsprogs, xorriso, util-linux, keyutils, and bpftool. See [docs/packaging.md](docs/packaging.md) for the full matrix.

## Upgrades (manual only; no automatic updates)

KER never checks for or installs a new version by itself. Copy the new package onto the machine and use the package manager commands above, or:

```bash
sudo ker upgrade ./ker_0.1.0_amd64.deb
# unsigned local file only:
# sudo ker upgrade --trust-package ./ker_0.1.0_amd64.deb
```

The new package takes over the previous install: keys, media, policy, and mode are kept, and any required state migrations run automatically. An upgrade **does not** turn kernel enforcement on or off, and it does not rewrite sealed media. New features come with the new package; features that need new keys must be issued later and are never written onto old media during an upgrade.

Inspect the plan with `ker upgrade --check`. Apply pending migrations after the new program is already in place with `ker upgrade --migrate`. Restore the most recent upgrade snapshot with `ker upgrade --rollback`.

The full contract is in [docs/upgrade.md](docs/upgrade.md).

0.1.0 is the version of the first public release (numerically equal to the already published 0.1). If `state.json` already has kernel enforcement enabled, a reboot restores and reattaches BPF automatically (via `ker-enforcer.service`). A host that never opted in still will not get enforcement.

## Boot hook (`boot.pem`, fail-closed)

`boot.pem` is enforced by early-boot hooks for initramfs-tools, dracut, mkinitcpio, and mkinitfs. In enforcement mode, missing media or a failed verify refuses to continue to the real root filesystem and reports the reason on the console. In test mode the same condition is logged and boot is allowed to proceed.

SSH hooks (a PAM account module and `AuthorizedKeysCommand`) follow the same rule: in enforcement mode, a missing `ssh.pem` rejects both password and public-key logins; test mode only logs. Details are in [docs/hooks.md](docs/hooks.md).

## Runtime enforcement and live media presence

Test mode is the default. After media verifies and an administrator confirms, KER can load a BPF LSM in a virtual machine (or on a host that has been explicitly allowed).

Once enforcement is on:

- `ker enforce --watch` runs as a persistent systemd service and is enabled so that BPF maps are restored at boot;
- udev triggers an immediate presence check when block devices appear or disappear, with a timer as a backup;
- **One medium, one set of bits**: removing or failing to verify the medium that holds `ssh.pem` denies SSH only. Read, write, execute, network, and root login follow their own key media. A missing `root.pem` medium denies every selected runtime permission, because no permission can be established without it. `boot.pem` is enforced by the early-boot hook, and `admin.pem` is enforced by `ker console`.
- **Custom rules stay scoped.** A rule that names paths, users, ports, or units authorizes only those subjects. If a constraint cannot be checked exactly, that rule authorizes nothing and is not widened into a machine-wide execute, read, write, or network bit.
- **Deny first, then verify**: removing a runtime-required medium clears the bits that medium authorizes immediately, without waiting for a mount or a signature check. Reinserting it and a successful verify restores those bits.
- Enforcement is never enabled by a package install or upgrade. Turn it off with `ker enforce --set test`.

## Cluster, console, and uninstall

- Master/child cluster: `ker addnet`, `ker token`, and `ker serve`. A join installs a new trust anchor only after an out-of-band fingerprint (`ker addnet --fingerprint`) or after a root/admin medium already on the machine verifies that anchor. The node does not install the token's trust and then verify the token with the trust it just wrote. Children fail closed if the master is lost.
- Console and key rotation: `ker console` (admin media required). Rotation clears kernel enforcement before rewriting media. It does not set `media_ok` until the new media verify. A failed replug leaves enforcement fail-closed: the flag may be restored, but the selected bits stay in the deny mask. BPF maps and the `ker-enforcer` units follow that result.
- Lost media: `ker revoke-medium --drop` or `--replace /dev/...` (the same action as `ker console revoke-medium`). Proof is a remaining root medium, or the admin medium when the root medium itself is lost. A present root medium is enough; the operator is not asked for an admin disk as well. If both the root medium and the admin medium are missing, the command fails closed and will not revoke without proof. The new signing keys are what make the lost disk stop verifying. There is no separate CRL.
- Uninstall: `ker uninstall` requires root and verification of the root medium plus every permission medium. A master can dispatch a signed uninstall to online children; offline children must be uninstalled locally.

## Build and test

Build from the source tree. You do not need to install KER on the build machine:

```bash
make test
make packages          # deb + rpm + apk + pkg.tar.zst, all five architectures
make deb               # .deb only
ARCHES=amd64 make deb  # amd64 .deb only, useful for a local VM test
```

Artifacts land in `dist/`. The VM self-test is `sudo bash scripts/vm-test.sh` (it does not install the package on the host and does not load BPF on the host).


## Sponsors

If KER is useful to you, you are welcome to sponsor ongoing maintenance.

### WeChat 微信支付

![WeChat Pay](docs/sponsors/weixin.png)

### Alipay 支付宝

![Alipay](docs/sponsors/alipay.jpg)
