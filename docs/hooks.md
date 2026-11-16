# Boot and SSH hooks (0.1.0)

Both hooks use the same policy as the rest of KER:

- If KER is not initialized, or the `boot` / `ssh` permission was not selected
  at init time, the hook is inactive and must not block.
- Test mode (the default): log the verification result to the console / syslog,
  and do not block.
- Enforcement (`ker enforce --set enforce`, after media verifies): allow only
  when the sealed permission key (`boot.pem` or `ssh.pem`) verifies together
  with `root.pem`. Otherwise deny, fail closed.

The hooks never load BPF themselves. Enabling kernel enforcement still follows
the existing VM / `KER_ALLOW_HOST_BPF` rules.

## Boot hook (`boot.pem`)

The package ships equivalent early-boot hooks for:

- Debian / Ubuntu: initramfs-tools, under
  `/usr/share/initramfs-tools/hooks/ker-boot` and
  `/usr/share/initramfs-tools/scripts/local-premount/ker-boot`
- Fedora / RHEL and other dracut systems:
  `/usr/lib/dracut/modules.d/90ker-boot/`
- Arch: mkinitcpio install + hook scripts under `/usr/lib/initcpio/`
- Alpine: mkinitfs hook and `features.d` list under `/usr/share/mkinitfs/`

The hook copies the checker, Python/cryptography, `gpgv`, `openssl`, and the
current `/etc/ker` trust anchors into the initramfs when that image is built.
Early boot mounts candidate media read-only, verifies the signed bundle, unwraps
`boot.pem` with the fixed segment in `root.pem`, and then either continues to
the real root or (in enforcement, on failure) prints a console message and
powers off. There is no GUI.

### Enabling the boot hook

1. Install the KER package on the *target* system (not the production host
   that already runs `ker-guard`).
2. Run `ker` / `ker init` and include the `boot` permission so `boot.pem` is
   issued onto authorized media.
3. Rebuild the initramfs so it embeds the current trust anchors:
   - Debian: `update-initramfs -u`
   - dracut: `dracut -f`
   - Arch: add `ker-boot` to the `HOOKS` array in `/etc/mkinitcpio.conf`, then
     `mkinitcpio -P`
   - Alpine: add `ker-boot` to the mkinitfs features, then `mkinitfs`
4. After `ker console rotate`, rebuild the initramfs again so the new trust
   anchors are embedded. Rotation will attempt this automatically on a VM;
   on bare metal it is skipped unless `KER_ALLOW_HOST_INITRAMFS=1`.

`install-hooks` (run from the package post-install) will try to refresh the
initramfs only when `KER_IN_VM=1` or `KER_ALLOW_HOST_INITRAMFS=1`. It refuses
to touch a machine where `ker-guard.service` is active. Do not rebuild the
production host's initramfs.

## SSH hook

The package ships:

- `/usr/lib/ker/ker-ssh-pam` — `pam_exec` helper for the sshd *account*
  stack (covers password and key logins when `UsePAM yes`)
- `/usr/lib/ker/ker-ssh-keys` — `AuthorizedKeysCommand` for public-key logins
- drop-in config templates under `/usr/lib/ker/hooks/`

On the target system, `install-hooks` copies the sshd drop-in to
`/etc/ssh/sshd_config.d/99-ker.conf` (or appends to `sshd_config`) and appends a
marked PAM block to `/etc/pam.d/sshd`. Reload sshd after that, for example
`systemctl reload ssh` or a new `sshd` start in a test guest. The helper
prints the user's `authorized_keys` when SSH is allowed, so key login keeps
working when the hook is inactive or in test mode.

In enforcement, a missing or invalid `ssh.pem` medium denies both key and
password SSH. In test mode the same condition is logged and the login is
allowed.

The installer refuses to modify sshd or PAM on a host where
`ker-guard.service` is active, so this production machine's real sshd is not
weakened by a package build.
