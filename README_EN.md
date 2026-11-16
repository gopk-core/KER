# KER

A Linux kernel-level authorization system. Signed keys live on removable media; installation and administration happen in the terminal. There is no graphical interface.

[简体中文](README.md)

Current version: **0.1** (first public release). License: [GNU Affero General Public License v3.0](LICENSE).

## Safety notes (read these first)

- **Do not** install a KER package on a production host that already runs another kernel-level guard (for example `ker-guard`). Do not load the new BPF on that host, and do not rebuild its initramfs.
- Kernel enforcement is off by default and is **never** turned on by installing or upgrading a package. An administrator enables it only after media verifies, with an explicit `ker enforce --set enforce --yes`. Bare-metal hosts refuse to load BPF unless `KER_ALLOW_HOST_BPF=1` is set on purpose.
- Without Secure Boot or kernel lockdown, KER still cannot stop a root user from replacing the kernel or the bootloader. It provides signed-media authorization and optional LSM enforcement, not a firmware root of trust.
- The `boot.pem` early-boot hook is fail-closed in enforcement mode: missing media or a failed verify refuses to continue to the real root filesystem. Do not weaken this policy.

## What KER is

KER carries signed permission keys on external media (USB drives, removable disks, DVDs, WORM, and similar devices) and uses them at boot, login, and runtime to decide whether a machine is authorized for a given action.

Typical uses:

- The machine must present signed boot media before it is allowed to switch to the real root filesystem;
- At runtime, optional BPF LSM enforcement can block read, write, execute, or network operations when required media is absent;
- Machines can form a master/child cluster. The master signs and syncs policy; children fail closed if the master disappears.

The first run of `ker` starts a terminal wizard (English / Simplified Chinese / Traditional Chinese) and must be run as root.

## How media and keys work

- KER lists every recognizable block device (not only USB sticks). After confirmation it formats the device and writes a sealed file set.
- Rewritable removable media uses FAT32, hard disks use ext4, DVD-R gets an ISO9660 image, and WORM media is written only when empty — it is never reformatted.
- Each key is 10MB. `root.pem` is signed but not encrypted; other keys are encrypted and then signed. Unwrapping material comes from a fixed section of `root.pem`. Without the root key, no permission can be established.
- Unwrapped material is placed in the kernel keyring where possible, not written in cleartext under ordinary directories.
- The default is a single medium. Keys can also be split across several disks, each signed on its own. The admin key `admin.pem` is required for `ker console`.
- After writing media, KER enters test mode: it reports verification results in the terminal and does not enable kernel interception. An optional unplug/replug check is available.

## Installing from packages

Packages are architecture-specific (no longer `Architecture: all`) because they ship a BPF object and `ker-probe` built for that architecture. Releases include `.deb`, `.rpm`, `.apk`, and `.pkg.tar.zst` for amd64, arm64, armhf, i386, and riscv64.

Copy the package that matches the machine, then:

```bash
sudo dpkg -i ker_0.1_amd64.deb
# or
sudo rpm -Uvh ker-0.1-1.x86_64.rpm
sudo apk add --allow-untrusted ker-0.1-r0.x86_64.apk
sudo pacman -U ker-0.1-1-x86_64.pkg.tar.zst
```

After installation, `/usr/sbin/ker` is on root's `PATH`. Run `ker` to start the first-run wizard.

Unsigned local packages still require `--trust-package` when installed through `ker upgrade --trust-package`. Typical dependencies include Python 3, python3-cryptography, GnuPG, openssl, dosfstools, e2fsprogs, xorriso, util-linux, keyutils, and bpftool. See [docs/packaging.md](docs/packaging.md) for the full matrix.

## Upgrades (manual only; no automatic updates)

KER never checks for or installs a new version by itself. Copy the new package onto the machine and use the package manager commands above, or:

```bash
sudo ker upgrade --trust-package ./ker_0.1_amd64.deb
```

The new package takes over the previous install: keys, media, policy, and mode are kept, and any required state migrations run automatically. An upgrade **does not** turn kernel enforcement on or off, and it does not rewrite sealed media. New features come with the new package; features that need new keys must be issued later and are never written onto old media during an upgrade.

Inspect the plan with `ker upgrade --check`. Apply pending migrations after the new program is already in place with `ker upgrade --migrate`. Restore the most recent upgrade snapshot with `ker upgrade --rollback`.

The full contract is in [docs/upgrade.md](docs/upgrade.md).

0.1 is the first public release. If `state.json` already has kernel enforcement enabled, a reboot now restores and reattaches BPF automatically (via `ker-enforcer.service`). A host that never opted in still will not get enforcement.

## Boot hook (`boot.pem`, fail-closed)

`boot.pem` is enforced by early-boot hooks for initramfs-tools, dracut, mkinitcpio, and mkinitfs. In enforcement mode, missing media or a failed verify refuses to continue to the real root filesystem and reports the reason on the console. In test mode the same condition is logged and boot is allowed to proceed.

SSH hooks (a PAM account module and `AuthorizedKeysCommand`) follow the same rule: in enforcement mode, a missing `ssh.pem` rejects both password and public-key logins; test mode only logs. Details are in [docs/hooks.md](docs/hooks.md).

## Runtime enforcement and live media presence

Test mode is the default. After media verifies and an administrator confirms, KER can load a BPF LSM in a virtual machine (or on a host that has been explicitly allowed).

Once enforcement is on:

- `ker enforce --watch` runs as a persistent systemd service and is enabled so that BPF maps are restored at boot;
- udev triggers an immediate presence check when block devices appear or disappear, with a timer as a backup;
- **Deny first, then verify**: removing a required medium sets `media_ok` to 0 immediately, without waiting for a mount or signature check; reinserting and a successful verify allows access again;
- Enforcement is never enabled by a package install or upgrade. Turn it off with `ker enforce --set test`.

## Cluster, console, and uninstall

- Master/child cluster: `ker addnet`, `ker token`, and `ker serve` use signed join tokens and policy sync. Children fail closed if the master is lost.
- Console and key rotation: `ker console` (admin media required). Rotation switches atomically and notifies child nodes.
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
