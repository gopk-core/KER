"""Boot and SSH authorization decisions from sealed KER media.

Hook policy is consistent with the rest of KER:
- If KER is not initialized, or the permission was not selected, the hook
  is inactive and must not block.
- Test mode (the default): log the verification result, never block.
- Enforcement: allow only when the required permission key verifies;
  otherwise deny (fail closed).
These helpers never load BPF and never change kernel enforcement.
"""
from __future__ import annotations

import json
import os
import subprocess
import syslog
import tempfile
import time
from pathlib import Path

from ker.bundle import verify_directory
from ker.paths import MOUNT_ROOT, PRIVATE_DIR, TRUST_DIR
from ker.sign import SignError
from ker.state import state as load_state

PERM_FILES = {
    'boot': 'boot.pem',
    'ssh': 'ssh.pem',
}


class HookError(RuntimeError):
    pass


def enforcement_enabled(st: dict | None = None) -> bool:
    st = st or load_state()
    if st.get('kernel_enforcement'):
        return True
    return st.get('mode') == 'enforce'


def permission_selected(st: dict, permission: str) -> bool:
    return permission in (st.get('permissions') or [])


def _keys_from_state(st: dict) -> dict:
    return {
        'gpg_fingerprint': st.get('gpg_fingerprint'),
        'gpg_home': str(PRIVATE_DIR / 'gnupg'),
        'rsa_key': str(PRIVATE_DIR / 'kernel-signing.key'),
        'rsa_pub': str(TRUST_DIR / 'kernel-cert.pem'),
    }


# Captured mount/umount failures (also appended to /run/ker/mount.err).
_MOUNT_ERRORS: list[str] = []
_MOUNT_ERR_PATHS = (Path('/run/ker/mount.err'),)


def _record_mount_error(msg: str) -> None:
    text = msg.rstrip()
    if not text:
        return
    _MOUNT_ERRORS.append(text)
    for path in _MOUNT_ERR_PATHS:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('a', encoding='utf-8') as fh:
                fh.write(text + '\n')
        except OSError:
            pass


def _helper_commands(verb: str) -> list[list[str]]:
    """Prefer a working busybox applet over a broken util-linux binary."""
    seen: set[tuple[str, ...]] = set()
    out: list[list[str]] = []

    def add(cmd: list[str]) -> None:
        key = tuple(cmd)
        if key in seen:
            return
        seen.add(key)
        out.append(cmd)

    bb = Path('/bin/busybox')
    if bb.is_file() and os.access(bb, os.X_OK):
        add(['/bin/busybox', verb])
    add([verb])
    for path in (f'/bin/{verb}', f'/sbin/{verb}', f'/usr/bin/{verb}', f'/usr/sbin/{verb}'):
        add([path])
    return out


def _run_helper(verb: str, *args: str) -> subprocess.CompletedProcess:
    last = None
    for cmd in _helper_commands(verb):
        try:
            last = subprocess.run(
                [*cmd, *args], capture_output=True, text=True,
            )
        except FileNotFoundError as e:
            last = subprocess.CompletedProcess(cmd, 127, '', str(e))
        if last.returncode == 0:
            return last
        detail = (last.stderr or last.stdout or '').strip() or f'exit {last.returncode}'
        _record_mount_error(f"{' '.join(cmd)} {' '.join(args)}: {detail}")
    return last or subprocess.CompletedProcess([verb], 127, '', 'no mount helper')


def _umount(dest: Path) -> None:
    # busybox/util-linux may need a retry when the fs is busy
    for _ in range(6):
        r = _run_helper('umount', str(dest))
        if r.returncode == 0:
            return
        if not _is_mounted(dest):
            return
        time.sleep(0.1)


def _is_mounted(path: Path) -> bool:
    try:
        return path.is_mount()
    except AttributeError:
        pass
    try:
        mounts = Path('/proc/mounts').read_text().splitlines()
    except OSError:
        return False
    target = str(path)
    return any(line.split()[1] == target for line in mounts)


def _mount_ro(dev: str, dest: Path) -> bool:
    dest.mkdir(parents=True, exist_ok=True)
    if _is_mounted(dest):
        _umount(dest)
    r = _run_helper('mount', '-o', 'ro,nosuid,nodev,noexec', dev, str(dest))
    return r.returncode == 0


def _root_block_devices() -> set[str]:
    """Block devices currently backing the mounted real root, if any."""
    out: set[str] = set()
    try:
        for line in Path('/proc/mounts').read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] == '/':
                src = parts[0]
                if src.startswith('/dev/'):
                    out.add(src)
                    # also the parent disk of a partition
                    name = Path(src).name
                    for suffix in (name.rstrip('0123456789'),):
                        p = Path('/dev') / suffix
                        if p.exists():
                            out.add(str(p))
    except OSError:
        pass
    return out


def candidate_devices(st: dict, extra: list[str] | None = None, scan: bool = False) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []

    def add(dev: str) -> None:
        if not dev or dev in seen:
            return
        seen.add(dev)
        ordered.append(dev)

    for m in st.get('media') or []:
        if isinstance(m, dict) and m.get('path'):
            add(m['path'])
    for dev in extra or []:
        add(dev)
    if scan:
        skip = _root_block_devices()
        base = Path('/sys/class/block')
        if base.is_dir():
            for blk in sorted(base.iterdir()):
                name = blk.name
                if name.startswith(('loop', 'ram', 'fd', 'dm-')) and not any(
                    (m.get('path') or '').endswith(name) for m in (st.get('media') or []) if isinstance(m, dict)
                ):
                    # still allow loop devices listed later; skip generic loop/ram
                    # unless they were already added from state
                    continue
                dev = f'/dev/{name}'
                if dev in skip:
                    continue
                if Path(dev).exists():
                    add(dev)
    return ordered


def _verify_mounted(st: dict, mounts: list[Path], permission: str) -> tuple[bool, str]:
    key_name = PERM_FILES[permission]
    keys = _keys_from_state(st)
    if not keys.get('gpg_fingerprint'):
        return False, 'NO_TRUST_FINGERPRINT'
    if not (TRUST_DIR / 'media.gpg').is_file() or not (TRUST_DIR / 'kernel-cert.pem').is_file():
        return False, 'TRUST_ANCHOR_MISSING'
    root_pem = None
    infos = []
    try:
        for dest in mounts:
            if not (dest / 'bundle.json').is_file():
                continue
            if (dest / 'root.pem').is_file():
                root_pem = (dest / 'root.pem').read_bytes()
        if root_pem is None:
            return False, 'ROOT_MEDIA_MISSING'
        found_perm = False
        for dest in mounts:
            if not (dest / 'bundle.json').is_file():
                continue
            info = verify_directory(dest, keys, root_pem=root_pem)
            infos.append(info)
            bundle_keys = (info.get('bundle') or {}).get('keys') or {}
            if key_name in bundle_keys:
                found_perm = True
        if not found_perm:
            return False, f'PERMISSION_KEY_MISSING:{key_name}'
        return True, 'OK'
    except SignError as e:
        return False, str(e) or 'SIGNATURE_REJECTED'
    except Exception as e:
        return False, f'VERIFY_ERROR:{type(e).__name__}'


def verify_permission(permission: str, st: dict | None = None,
                      devices: list[str] | None = None, scan: bool = False) -> dict:
    """Mount candidate media and verify the named permission key."""
    if permission not in PERM_FILES:
        raise HookError(f'unknown hook permission: {permission}')
    st = st or load_state()
    devs = devices if devices is not None else candidate_devices(st, scan=scan)
    _MOUNT_ERRORS.clear()
    mounts: list[Path] = []
    try:
        for i, dev in enumerate(devs):
            if not dev or not Path(dev).exists():
                continue
            dest = MOUNT_ROOT / 'hook' / permission / f'm{i}'
            if _mount_ro(dev, dest):
                mounts.append(dest)
        if not mounts:
            out = {'ok': False, 'reason': 'NO_MEDIA_MOUNTED', 'devices': devs}
            if _MOUNT_ERRORS:
                out['mount_errors'] = list(_MOUNT_ERRORS)
            return out
        ok, reason = _verify_mounted(st, mounts, permission)
        return {'ok': ok, 'reason': reason, 'devices': devs, 'mounted': [str(m) for m in mounts]}
    finally:
        for dest in mounts:
            _umount(dest)


def authorize(permission: str, st: dict | None = None, devices: list[str] | None = None,
              scan: bool = False) -> dict:
    """Return an allow/block decision for a hook permission."""
    st = st or load_state()
    base = {
        'permission': permission,
        'allow': True,
        'block': False,
        'mode': 'test',
        'required': False,
        'verified': False,
        'reason': 'INACTIVE',
        'initialized': bool(st.get('initialized')),
    }
    if not st.get('initialized'):
        base['reason'] = 'NOT_INITIALIZED'
        return base
    if not permission_selected(st, permission):
        base['reason'] = 'PERMISSION_NOT_SELECTED'
        return base
    enforce = enforcement_enabled(st)
    base['mode'] = 'enforce' if enforce else 'test'
    base['required'] = True
    result = verify_permission(permission, st=st, devices=devices, scan=scan)
    base['verified'] = bool(result.get('ok'))
    base['reason'] = result.get('reason') or ('OK' if result.get('ok') else 'VERIFY_FAILED')
    base['verify'] = result
    if enforce:
        base['allow'] = bool(result.get('ok'))
        base['block'] = not base['allow']
    else:
        base['allow'] = True
        base['block'] = False
    return base


def log_decision(decision: dict, *, tag: str = 'ker-hook') -> None:
    msg = (
        f"{tag}: permission={decision.get('permission')} mode={decision.get('mode')} "
        f"allow={decision.get('allow')} block={decision.get('block')} "
        f"verified={decision.get('verified')} reason={decision.get('reason')}"
    )
    try:
        syslog.openlog(tag, syslog.LOG_PID, syslog.LOG_AUTH)
        facility = syslog.LOG_WARNING if decision.get('block') or not decision.get('verified') else syslog.LOG_NOTICE
        syslog.syslog(facility, msg)
    except Exception:
        pass
    try:
        print(msg, file=__import__("sys").stderr, flush=True)
    except Exception:
        pass


def legacy_guard_active() -> bool:
    """True when the pre-KER ker-guard stack is running on this machine."""
    if not Path("/run/systemd/system").is_dir():
        return False
    try:
        r = subprocess.run(
            ['systemctl', 'is-active', '--quiet', 'ker-guard.service'],
            capture_output=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def may_modify_host_boot() -> bool:
    """Refuse to rebuild a bare-metal host initramfs unless explicitly allowed."""
    if os.environ.get('KER_ALLOW_HOST_INITRAMFS') == '1':
        return True
    if os.environ.get('KER_IN_VM') == '1':
        return True
    if legacy_guard_active():
        return False
    try:
        r = subprocess.run(['systemd-detect-virt', '-q'], capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def refresh_boot_initramfs() -> dict:
    """Rebuild initramfs so it embeds current trust anchors. Never runs on this production host's stack."""
    if legacy_guard_active() and os.environ.get('KER_ALLOW_HOST_INITRAMFS') != '1':
        return {'ok': True, 'skipped': 'legacy-ker-guard'}
    if not may_modify_host_boot():
        return {'ok': True, 'skipped': 'bare-metal-guard'}
    if not Path('/etc/ker/state.json').is_file() and not os.environ.get('KER_PREFIX'):
        return {'ok': True, 'skipped': 'not-initialized'}
    cmds = []
    if Path('/usr/sbin/update-initramfs').is_file():
        cmds.append(['update-initramfs', '-u'])
    if Path('/usr/bin/dracut').is_file():
        cmds.append(['dracut', '-f'])
    if Path('/usr/bin/mkinitcpio').is_file():
        cmds.append(['mkinitcpio', '-P'])
    if Path('/sbin/mkinitfs').is_file():
        cmds.append(['mkinitfs'])
    if not cmds:
        return {'ok': True, 'skipped': 'no-initramfs-tool'}
    ran = []
    errors = []
    for cmd in cmds:
        r = subprocess.run(cmd, capture_output=True, text=True)
        ran.append(' '.join(cmd))
        if r.returncode != 0:
            errors.append((r.stderr or r.stdout or 'failed')[-1000:])
    return {'ok': not errors, 'ran': ran, 'errors': errors}


def user_authorized_keys(username: str) -> str:
    """Return the authorized_keys text that sshd should accept when SSH is allowed."""
    import pwd

    chunks: list[str] = []
    try:
        home = Path(pwd.getpwnam(username).pw_dir)
    except KeyError:
        return ''
    for path in (
        home / '.ssh' / 'authorized_keys',
        home / '.ssh' / 'authorized_keys2',
        Path('/etc/ssh/authorized_keys.d') / username,
    ):
        try:
            if path.is_file():
                chunks.append(path.read_text(encoding='utf-8', errors='replace'))
        except OSError:
            continue
    return ''.join(chunks)


def decision_json(decision: dict) -> str:
    return json.dumps(decision, ensure_ascii=False, indent=2) + '\n'
