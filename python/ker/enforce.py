"""Kernel enforcement switch. Never auto-enabled by a package install.

BPF LSM is a host-wide kernel attachment. This module refuses to load
programs on a bare-metal machine unless KER_ALLOW_HOST_BPF=1, so a test
prefix or a package install cannot alter the production host's LSM.
"""
from __future__ import annotations

import fcntl
import json
import os
import struct
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

from ker.catalog import BUILTIN_IDS
from ker.devices import required_media_presence
from ker.paths import PREFIX
from ker.state import save_state, state as load_state
from ker.testmode import verify_all, verify_each


class EnforceError(RuntimeError):
    pass


PIN_DIR = Path('/sys/fs/bpf/ker')
BIT = {
    'run': 1 << 0,
    'read': 1 << 1,
    'write': 1 << 2,
    'rootsu': 1 << 3,
    'network': 1 << 4,
    'rootuser': 1 << 5,
    'ssh': 1 << 6,
}

# Concrete executables spared while the bits they are not denied for are off.
# BPF allow_inos is filled from this list (inode + kernel dev_t). A basename
# match is never enough: /tmp/systemd is not systemd. The whole /usr/lib/ker/
# directory is not allowed — only the helpers KER actually installs.
# ker-python is a copy of the system interpreter (not a hard link) so its
# inode does not also authorize /usr/bin/python3. The shebang
# #!/usr/lib/ker/ker-python still runs as comm ker-python.
# 64 slots match allow_inos in src/bpf/ker.bpf.c.
ALLOWED_EXEC_PATHS = (
    '/usr/lib/systemd/systemd',
    '/lib/systemd/systemd',
    '/usr/lib/systemd/systemd-journald',
    '/lib/systemd/systemd-journald',
    '/usr/lib/systemd/systemd-udevd',
    '/lib/systemd/systemd-udevd',
    '/usr/lib/systemd/systemd-executor',
    '/lib/systemd/systemd-executor',
    '/usr/lib/systemd/systemd-shutdown',
    '/lib/systemd/systemd-shutdown',
    '/sbin/init',
    '/usr/sbin/init',
    '/usr/lib/udev/ata_id',
    '/lib/udev/ata_id',
    '/usr/lib/udev/scsi_id',
    '/lib/udev/scsi_id',
    '/usr/lib/udev/cdrom_id',
    '/lib/udev/cdrom_id',
    '/usr/sbin/blkid',
    '/sbin/blkid',
    '/usr/bin/blkid',
    '/usr/bin/udevadm',
    '/bin/udevadm',
    '/sbin/udevadm',
    '/usr/sbin/udevadm',
    '/usr/bin/dbus-daemon',
    '/bin/dbus-daemon',
    '/usr/bin/dbus-broker',
    '/usr/bin/dbus-broker-launch',
    '/usr/sbin/ker',
    '/usr/bin/ker',
    '/usr/lib/ker/ker-python',
    '/usr/lib/ker/ker-boot-check',
    '/usr/lib/ker/ker-ssh-pam',
    '/usr/lib/ker/ker-ssh-keys',
    '/usr/lib/ker/ker-pam-probe',
    '/usr/lib/ker/install-hooks',
    '/usr/lib/ker/ker-probe',
    '/usr/bin/gpgv',
    '/bin/gpgv',
    '/usr/bin/openssl',
    '/usr/bin/bpftool',
    '/usr/sbin/bpftool',
    '/bin/mount',
    '/usr/bin/mount',
    '/bin/umount',
    '/usr/bin/umount',
    '/bin/systemctl',
    '/usr/bin/systemctl',
    '/usr/bin/timeout',
    '/bin/timeout',
    '/sbin/reboot',
    '/usr/sbin/reboot',
    '/sbin/poweroff',
    '/usr/sbin/poweroff',
    '/sbin/halt',
    '/usr/sbin/halt',
    '/sbin/shutdown',
    '/usr/sbin/shutdown',
)

ALLOW_SLOTS = 64

# Names that must never be treated as an allow by themselves.
FORBIDDEN_COMMS = (
    'bash', 'sh', 'dash', 'zsh', 'fish',
    'cat', 'ls', 'python3', 'python', 'sudo', 'su',
    'login', 'agetty', 'sshd', 'nginx', 'httpd',
    'systemd',
)


def task_comm(name: str) -> str:
    """Return the 15-character TASK_COMM_LEN form used by the kernel."""
    return (name or '')[:15]


def is_allowed_comm(name: str) -> bool:
    """Comm is not an authorization. Always false.

    A process whose comm is systemd, ker-python, or ker-enforcer is allowed
    only when its executable inode was recorded from ALLOWED_EXEC_PATHS.
    """
    return False


def path_is_allowed_exec(path: str) -> bool:
    """True only for a concrete allowed path, not a basename or a directory prefix."""
    raw = path or ''
    if not raw.startswith('/') or raw.endswith('/'):
        return False
    if raw in ALLOWED_EXEC_PATHS:
        return True
    try:
        real = os.path.realpath(raw)
    except OSError:
        return False
    return real in ALLOWED_EXEC_PATHS


def kernel_dev(st_dev: int) -> int:
    """Convert a userspace stat st_dev to the kernel dev_t stored in super_block.s_dev."""
    major = os.major(st_dev)
    minor = os.minor(st_dev)
    return ((major & 0xFFFFFFFF) << 20) | (minor & 0xFFFFF)


def executable_identity(path: str, allowed: tuple[str, ...] | None = None) -> tuple[int, int] | None:
    """Inode and kernel dev for an allowlisted path, or None.

    A symlink is recorded only when its realpath is itself allowlisted
    (so /sbin/init -> systemd counts, and ker-python -> bash does not).
    """
    allowed_set = allowed if allowed is not None else ALLOWED_EXEC_PATHS
    raw = path or ''
    if raw not in allowed_set:
        return None
    try:
        st = os.stat(raw, follow_symlinks=True)
        real = os.path.realpath(raw)
    except OSError:
        return None
    if real not in allowed_set:
        return None
    return int(st.st_ino), kernel_dev(st.st_dev)


def would_deny(*, enforcement: bool, media_ok: bool, deny_mask_value: int,
               bit: int, allowed: bool) -> bool:
    """Userspace mirror of the BPF decide() policy (excluding prior LSM denials)."""
    if allowed:
        return False
    if not enforcement:
        return False
    if media_ok:
        return False
    return bool(deny_mask_value & bit)


def deny_mask(permissions: list[str] | None) -> int:
    mask = 0
    for p in permissions or []:
        mask |= BIT.get(p, 0)
    return mask


# file_permission MAY_* mirrors. Keep in lockstep with src/bpf/ker.bpf.c.
MAY_EXEC = 0x01
MAY_WRITE = 0x02
MAY_READ = 0x04
MAY_APPEND = 0x08

# Keys whose documented scope is not a runtime LSM bit.
# boot.pem: early-boot hook, fail-closed there.
# admin.pem: ker console.
# root.pem: foundation of every permission; handled on the medium, not as its own bit.
_NO_BPF_KEYS = frozenset({'root.pem', 'boot.pem', 'admin.pem'})

_CUSTOM_BITS = {
    'file_read': BIT['read'],
    'file_write': BIT['write'],
    'file_exec': BIT['run'],
    'command': BIT['run'],
    'login': BIT['rootuser'],
    'network': BIT['network'],
    'service': BIT['run'],
    'device': BIT['read'] | BIT['write'],
}


def classify_file_mask(mask: int) -> int:
    """Map a Linux file_permission mask onto KER bits.

    MAY_EXEC (0x01) is execute, the same class as bprm_check_security / BIT_RUN.
    Combined masks keep every class that is present. An empty mask classifies
    as no KER bit (the hook does not invent a read denial).
    """
    bits = 0
    if mask & MAY_EXEC:
        bits |= BIT['run']
    if mask & MAY_WRITE:
        bits |= BIT['write']
    if mask & MAY_READ:
        bits |= BIT['read']
    if mask & MAY_APPEND:
        bits |= BIT['write']
    return bits


def custom_bits(item: dict | None) -> int:
    if not item:
        return 0
    return _CUSTOM_BITS.get(item.get('type') or '', 0)


def policy_bits(st: dict | None) -> int:
    """Runtime bits selected by policy (built-ins plus custom rules)."""
    st = st or {}
    mask = deny_mask(st.get('permissions') or [])
    for item in st.get('custom') or []:
        mask |= custom_bits(item)
    return mask


def key_bits(name: str, st: dict | None = None) -> int:
    """Bits one key file authorizes. root/boot/admin have no LSM bit of their own."""
    st = st or {}
    if not name or name in _NO_BPF_KEYS:
        return 0
    stem = name[:-4] if name.endswith('.pem') else name
    if stem in BIT:
        return BIT[stem]
    for item in st.get('custom') or []:
        if item.get('key') == name:
            return custom_bits(item)
    return 0


def medium_is_root(medium: dict | None) -> bool:
    if not isinstance(medium, dict):
        return False
    role = (medium.get('role') or '').replace('+', ' ')
    if 'root' in role.split():
        return True
    return 'root.pem' in (medium.get('keys') or [])


def bits_for_medium(medium: dict, st: dict | None = None) -> int:
    """Bits cleared when this medium is absent or fails verify.

    Root media fail closed for every selected runtime bit: without root.pem
    no permission can be established. Boot-only and admin-only media do not
    (their fail-closed scope is the boot hook and the admin console).
    A medium with no recorded keys is treated as unknown and fails closed.
    """
    st = st or {}
    if not isinstance(medium, dict):
        return policy_bits(st)
    if medium_is_root(medium):
        return policy_bits(st)
    keys = list(medium.get('keys') or [])
    if not keys and not medium.get('role'):
        return policy_bits(st)
    mask = 0
    for name in keys:
        mask |= key_bits(name, st)
    return mask


def denied_bits(st: dict, missing: list | None = None, failed: list | None = None) -> int:
    mask = 0
    for medium in list(missing or []) + list(failed or []):
        mask |= bits_for_medium(medium, st)
    return mask


def presence_sets(st: dict | None = None) -> tuple[list[dict], list[dict]]:
    """Split recorded media into (present, missing) without mounting."""
    from ker.devices import resolve_media_path
    st = st or load_state()
    present: list[dict] = []
    missing: list[dict] = []
    for medium in st.get('media') or []:
        if not isinstance(medium, dict):
            missing.append({'path': str(medium)})
            continue
        if resolve_media_path(medium):
            present.append(medium)
        else:
            missing.append(medium)
    return present, missing


def runtime_required(medium: dict, st: dict | None = None) -> bool:
    """Root and any medium that authorizes a runtime bit.

    Admin-only and boot-only disks stay out of the BPF presence gate; the
    console and the boot hook enforce those scopes themselves.
    """
    if medium_is_root(medium):
        return True
    return bits_for_medium(medium, st) != 0


def runtime_presence(st: dict | None = None) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    """Return (runtime_present, runtime_missing, all_present, all_missing)."""
    st = st or load_state()
    present, missing = presence_sets(st)
    req_present = [m for m in present if runtime_required(m, st)]
    req_missing = [m for m in missing if runtime_required(m, st)]
    return req_present, req_missing, present, missing


def _previous_denied(current: dict | None, policy: int) -> int:
    """Bits the pinned map is currently denying.

    A zeroed map (media_ok=0 and deny_mask=0) while policy bits exist has
    not been verified yet, so it fails closed for the whole policy.
    """
    if not current:
        return policy
    if current.get('media_ok'):
        return 0
    mask = int(current.get('deny_mask') or 0)
    if mask == 0 and policy:
        return policy
    return mask


def in_virtual_machine() -> bool:
    if os.environ.get('KER_IN_VM') == '1':
        return True
    virt = Path('/proc/device-tree/hypervisor/compatible')
    try:
        r = subprocess.run(['systemd-detect-virt', '-q'], capture_output=True)
        if r.returncode == 0:
            return True
    except FileNotFoundError:
        pass
    try:
        cpu = Path('/proc/cpuinfo').read_text()
        if 'hypervisor' in cpu:
            return True
    except OSError:
        pass
    return virt.exists()


def may_load_bpf() -> bool:
    if os.environ.get('KER_ALLOW_HOST_BPF') == '1':
        return True
    return in_virtual_machine()


def bpf_object() -> Path:
    candidates = [
        Path('/usr/lib/ker/bpf/ker.bpf.o'),
        Path(__file__).resolve().parents[2] / 'src' / 'bpf' / 'ker.bpf.o',
        Path(__file__).resolve().parents[2] / 'dist' / 'bpf' / 'ker.bpf.o',
        Path(__file__).resolve().parents[2] / 'dist' / 'bpf' / 'amd64' / 'ker.bpf.o',
    ]
    if PREFIX:
        candidates.insert(0, PREFIX / 'usr' / 'lib' / 'ker' / 'bpf' / 'ker.bpf.o')
    for p in candidates:
        if p.is_file():
            return p
    raise EnforceError('BPF object not found; build it with make bpf')


def _pin_exists(p: Path) -> bool:
    """bpffs/LSM may raise EPERM on a missing candidate pin name; that is not found."""
    try:
        return p.exists()
    except OSError:
        return False


def load_bpf() -> None:
    if not may_load_bpf():
        raise EnforceError(
            'refusing to load BPF LSM on a bare-metal host '
            '(set KER_ALLOW_HOST_BPF=1 only if you intend this)'
        )
    obj = bpf_object()
    PIN_DIR.mkdir(parents=True, exist_ok=True)
    # Load and auto-attach LSM programs; pin maps for later updates.
    r = subprocess.run(
        ['bpftool', 'prog', 'loadall', str(obj), str(PIN_DIR),
         'type', 'lsm', 'autoattach', 'pinmaps', str(PIN_DIR)],
        capture_output=True, text=True,
    )
    err = ((r.stderr or '') + (r.stdout or '')).lower()
    already = r.returncode == 0 or 'file exists' in err or 'already' in err
    if not already:
        r2 = subprocess.run(
            ['bpftool', 'prog', 'loadall', str(obj), str(PIN_DIR), 'pinmaps', str(PIN_DIR)],
            capture_output=True, text=True,
        )
        err2 = ((r2.stderr or '') + (r2.stdout or '')).lower()
        already = r2.returncode == 0 or 'file exists' in err2 or 'already' in err2
        err = (r.stderr or '') + chr(10) + (r2.stderr or r2.stdout or '')
    else:
        err = r.stderr or r.stdout or ''
    # PIN_DIR itself is created before load; success is a pinned cfg map.
    if not _cfg_pin():
        raise EnforceError((err or 'bpftool load failed')[-2000:])
    try:
        refresh_allow_maps()
    except EnforceError:
        pass


def unload_bpf() -> None:
    if not may_load_bpf():
        return
    subprocess.run(['rm', '-rf', str(PIN_DIR)], capture_output=True)


def _cfg_pin() -> Path | None:
    # libbpf may pin as cfg_map
    for name in ('cfg_map', 'cfg', 'ker.cfg_map'):
        p = PIN_DIR / name
        if _pin_exists(p):
            return p
    try:
        if PIN_DIR.exists():
            for p in PIN_DIR.iterdir():
                if 'cfg' in p.name and _pin_exists(p):
                    return p
    except OSError:
        pass
    return None


def _map_path() -> Path:
    p = _cfg_pin()
    if p is not None:
        return p
    raise EnforceError('cfg_map pin not found')


def _hex_bytes(data: bytes) -> list[str]:
    """Format raw bytes as individual hex tokens for bpftool (one argv per byte)."""
    return [f'{b:02x}' for b in data]


def bpftool_map_update_argv(pin: Path | str, key: bytes, value: bytes) -> list[str]:
    return [
        'bpftool', 'map', 'update', 'pinned', str(pin),
        'key', 'hex', *_hex_bytes(key),
        'value', 'hex', *_hex_bytes(value),
    ]


def _map_update(pin: Path, key: bytes, value: bytes) -> None:
    cmd = bpftool_map_update_argv(pin, key, value)
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        raise EnforceError((r.stderr or r.stdout or 'bpftool map update failed').strip())


def _path_slot_count() -> int:
    if len(ALLOWED_EXEC_PATHS) > ALLOW_SLOTS:
        raise EnforceError('allowlisted executable paths exceed BPF allow_inos slots')
    return ALLOW_SLOTS


def refresh_allow_maps() -> None:
    """Rewrite allow_inos from ALLOWED_EXEC_PATHS. No-op when the map is not pinned.

    Does not load BPF. A symlink is recorded only when its realpath is itself
    on the allowlist, so a helper path pointing at bash does not authorize bash.
    """
    if not may_load_bpf():
        return
    pin = PIN_DIR / 'allow_inos'
    if not _pin_exists(pin):
        return
    slots = _path_slot_count()
    paths = list(ALLOWED_EXEC_PATHS)
    for i in range(slots):
        path = paths[i] if i < len(paths) else ''
        ident = executable_identity(path) if path else None
        if ident is None:
            value = struct.pack('QII', 0, 0, 0)
        else:
            ino, dev = ident
            value = struct.pack('QII', ino, dev & 0xFFFFFFFF, 1)
        _map_update(pin, struct.pack('I', i), value)


def update_maps(*, enforcement: bool, media_ok: bool, permissions: list[str] | None,
                deny_mask_value: int | None = None) -> None:
    if not may_load_bpf():
        raise EnforceError('BPF map update refused on bare-metal host')
    key = struct.pack('I', 0)
    mask = deny_mask(permissions) if deny_mask_value is None else int(deny_mask_value)
    value = struct.pack('IIII', 1 if enforcement else 0, 1 if media_ok else 0, mask, 0)
    mp = _map_path()
    _map_update(mp, key, value)
    # Best-effort: an older pinned object may not have allow_inos yet.
    try:
        refresh_allow_maps()
    except EnforceError:
        if _pin_exists(PIN_DIR / 'allow_inos'):
            raise



REFRESH_LOCK = Path('/run/ker/enforce.refresh.lock')
MAP_LOCK = Path('/run/ker/enforce.map.lock')
WATCH_PID = Path('/run/ker/enforcer.pid')
SSH_RECOVER_STAMP = Path('/run/ker/ssh.recovered')


@contextmanager
def _flock(path: Path, timeout: float | None = 0):
    """Advisory exclusive lock. timeout=0 means non-blocking (raises TimeoutError)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    deadline = None if timeout is None else (time.monotonic() + max(0.0, timeout))
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as e:
                if deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError(f'lock busy: {path}') from e
                time.sleep(0.05)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def media_present(st: dict | None = None) -> tuple[bool, list[str]]:
    """Cheap presence of every medium recorded in state. No mounts."""
    st = st or load_state()
    if not st.get('initialized'):
        return False, ['(not-initialized)']
    return required_media_presence(st.get('media') or [])


def media_ok(st: dict | None = None) -> bool:
    """Full signature verify of all recorded media. May take seconds; must not be
    used as the only unplug detector. Prefer media_present() to fail closed."""
    st = st or load_state()
    if not st.get('initialized'):
        return False
    present, missing = media_present(st)
    if not present:
        return False
    try:
        return bool(verify_all(st).get('ok'))
    except Exception:
        return False


def read_maps() -> dict | None:
    """Read the pinned cfg_map. Returns None if BPF is not loaded."""
    try:
        mp = _map_path()
    except EnforceError:
        return None
    try:
        r = subprocess.run(
            ['bpftool', '-j', 'map', 'lookup', 'pinned', str(mp),
             'key', 'hex', '00', '00', '00', '00'],
            capture_output=True, text=True, timeout=3,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if r.returncode:
        return None
    try:
        data = json.loads(r.stdout or 'null')
    except json.JSONDecodeError:
        return None
    if not data:
        return None
    formatted = data.get('formatted') if isinstance(data, dict) else None
    if isinstance(formatted, dict):
        fv = formatted.get('value')
        if isinstance(fv, dict) and 'media_ok' in fv:
            return {
                'enforcement': bool(fv.get('enforcement')),
                'media_ok': bool(fv.get('media_ok')),
                'deny_mask': int(fv.get('deny_mask') or 0),
            }
    raw = data.get('value') if isinstance(data, dict) else None
    if isinstance(raw, dict):
        if 'media_ok' in raw:
            return {
                'enforcement': bool(raw.get('enforcement')),
                'media_ok': bool(raw.get('media_ok')),
                'deny_mask': int(raw.get('deny_mask') or 0),
            }
        raw = raw.get('value')
    if isinstance(raw, str):
        parts = raw.replace(',', ' ').split()
        try:
            buf = bytes(int(x, 16) for x in parts)
        except ValueError:
            return None
    elif isinstance(raw, list) and raw:
        try:
            buf = bytes(int(x, 16) if isinstance(x, str) else int(x) for x in raw)
        except (TypeError, ValueError):
            return None
    else:
        return None
    if len(buf) < 12:
        return None
    enf, mok, mask = struct.unpack_from('III', buf, 0)
    return {'enforcement': bool(enf), 'media_ok': bool(mok), 'deny_mask': mask}


def _ensure_bpf_if_enforcing(st: dict) -> bool:
    """Load BPF in a VM when state already has kernel enforcement on."""
    if not st.get('kernel_enforcement'):
        return False
    if not may_load_bpf():
        return False
    try:
        _map_path()
        return True
    except EnforceError:
        pass
    load_bpf()
    _map_path()
    return True


def _recover_sshd() -> None:
    """sshd is not allowlisted, so a deny window can stall kex. After media_ok
    flips back to allowed, restart ssh so a new session can connect.

    Cooldown avoids a poke+watcher double restart that drops a just-opened
    kex (seen at boot as Stopped/Started ssh.service twice in a second).
    """
    try:
        SSH_RECOVER_STAMP.parent.mkdir(parents=True, exist_ok=True)
        if SSH_RECOVER_STAMP.exists():
            if time.time() - SSH_RECOVER_STAMP.stat().st_mtime < 8:
                return
        SSH_RECOVER_STAMP.write_text('%.3f' % time.time(), encoding='utf-8')
    except OSError:
        pass
    for unit in ('ssh.service', 'sshd.service'):
        try:
            subprocess.run(
                ['systemctl', 'try-restart', unit],
                timeout=8,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass


def _push_maps(st: dict, denied: int, *, recover_ssh: bool = False) -> None:
    """Push the bits that are denied right now.

    media_ok is 1 only when nothing is denied. The mask then still records the
    armed policy bits; decide() ignores the mask while media_ok is set.
    When some bits are denied, the mask is exactly those bits — not every
    permission the policy selected.
    """
    policy = policy_bits(st)
    denied = int(denied) & 0xFFFFFFFF
    media_ok_flag = denied == 0
    mask = policy if media_ok_flag else denied
    update_maps(
        enforcement=True,
        media_ok=media_ok_flag,
        permissions=st.get('permissions') or [],
        deny_mask_value=mask,
    )
    if not media_ok_flag:
        try:
            SSH_RECOVER_STAMP.unlink(missing_ok=True)
        except OSError:
            pass
    elif recover_ssh:
        _recover_sshd()


def _paths(media: list[dict]) -> list[str]:
    return [(m.get('path') if isinstance(m, dict) else str(m)) or '(no-path)' for m in media]


def apply_presence(*, verify_if_present: bool = False) -> dict:
    """Fail-closed, per-medium presence check.

    When a runtime-required medium disappears, clear only the bits that medium
    authorizes and return immediately — never mount, never verify. Root media
    clear every selected runtime bit. Admin-only and boot-only media do not
    (those scopes are the console and the early-boot hook).

    When every runtime-required medium is present and verify_if_present is
    true (or the map is not already fully allowed), verify and restore only
    the bits whose media verified.
    """
    st = load_state()
    req_present, req_missing, _present, missing = runtime_presence(st)
    missing_paths = _paths(missing)
    runtime_paths = _paths(req_missing)
    if not st.get('kernel_enforcement'):
        return {
            'ok': True, 'skipped': True, 'media_ok': None,
            'present': not req_missing, 'missing': missing_paths,
            'runtime_missing': runtime_paths,
        }
    if not may_load_bpf():
        return {'ok': False, 'error': 'host bpf not allowed'}
    try:
        _ensure_bpf_if_enforcing(st)
    except EnforceError as e:
        return {'ok': False, 'error': str(e)}
    current = read_maps() or {}
    policy = policy_bits(st)
    if req_missing:
        # Deny FIRST. Do not wait on a hung verify lock or a mount.
        fresh = denied_bits(st, req_missing)
        if current.get('media_ok'):
            denied = fresh
        else:
            prev = _previous_denied(current, policy)
            present_bits = 0
            for medium in req_present:
                present_bits |= bits_for_medium(medium, st)
            denied = fresh | (prev & present_bits)
        _push_maps(st, denied)
        return {
            'ok': True, 'media_ok': denied == 0, 'present': False,
            'missing': missing_paths, 'runtime_missing': runtime_paths,
            'denied_bits': denied, 'maps': read_maps(), 'verified': False,
        }
    need_verify = verify_if_present or (not current.get('media_ok')) or _previous_denied(current, policy) != 0
    if not need_verify:
        return {
            'ok': True, 'media_ok': True, 'present': True,
            'missing': missing_paths, 'runtime_missing': [],
            'maps': current, 'verified': False, 'unchanged': True,
        }
    try:
        with _flock(REFRESH_LOCK, timeout=0):
            req_present, req_missing, _present, missing = runtime_presence(st)
            missing_paths = _paths(missing)
            runtime_paths = _paths(req_missing)
            if req_missing:
                fresh = denied_bits(st, req_missing)
                _push_maps(st, fresh)
                return {
                    'ok': True, 'media_ok': fresh == 0, 'present': False,
                    'missing': missing_paths, 'runtime_missing': runtime_paths,
                    'denied_bits': fresh, 'maps': read_maps(), 'verified': False,
                }
            verify_error = None
            report: dict = {'ok': False, 'missing': [], 'failed': [], 'results': []}
            for attempt in range(3):
                try:
                    report = verify_each(st, devices=req_present)
                    verify_error = None
                except Exception as e:
                    report = {'ok': False, 'missing': [], 'failed': list(req_present), 'results': []}
                    verify_error = f'{type(e).__name__}: {e}'
                req_present, req_missing, _present, missing = runtime_presence(st)
                if req_missing:
                    break
                if report.get('ok'):
                    break
                if attempt < 2:
                    time.sleep(0.4)
            if req_missing:
                denied = denied_bits(st, req_missing)
                verified = False
            else:
                denied = denied_bits(st, report.get('missing') or [], report.get('failed') or [])
                verified = True
            was_denied = not current.get('media_ok')
            _push_maps(st, denied, recover_ssh=bool(denied == 0 and was_denied))
            out = {
                'ok': True, 'media_ok': denied == 0, 'present': not req_missing and denied == 0,
                'devices_present': not req_missing,
                'missing': _paths(missing) if req_missing else missing_paths,
                'runtime_missing': _paths(req_missing),
                'denied_bits': denied,
                'maps': read_maps(), 'verified': verified,
                'ssh_recovered': bool(denied == 0 and was_denied),
            }
            if verify_error:
                out['verify_error'] = verify_error
            return out
    except TimeoutError:
        # Another verify is in progress. Runtime media are present, so do not block.
        return {
            'ok': True, 'media_ok': current.get('media_ok'),
            'present': True, 'missing': missing_paths, 'busy': True, 'maps': current,
        }


def refresh_media_flag() -> dict:
    """Keep media_ok in the map in sync with current media.

    Missing media: fail closed immediately (no mounts).
    All media present: full verify, then allow only if it succeeds.
    """
    return apply_presence(verify_if_present=True)


def presence_refresh() -> dict:
    """Udev/watch entry: deny immediately if anything is gone; verify only when
    flipping from denied back to allowed."""
    return apply_presence(verify_if_present=False)


def watch_loop(poll: float = 0.5) -> None:
    """Persistent watcher: netlink uevents plus a short poll.

    On remove, media_ok is set to 0 before any verify. On add, a full verify
    runs only when every required medium is present again. A hung verify is
    serialized behind a flock and cannot delay a later deny.
    """
    WATCH_PID.parent.mkdir(parents=True, exist_ok=True)
    WATCH_PID.write_text(str(os.getpid()), encoding='utf-8')
    last_sig = None

    def snapshot_sig(st: dict) -> tuple:
        _req_present, req_missing, _present, _missing = runtime_presence(st)
        return (not req_missing, tuple(_paths(req_missing)))

    def tick(reason: str) -> dict:
        st = load_state()
        if not st.get('kernel_enforcement'):
            return {'ok': True, 'skipped': True, 'reason': reason}
        sig = snapshot_sig(st)
        current = read_maps() or {}
        # Missing -> always push deny, even if we already did (cheap, keeps maps honest).
        if not sig[0]:
            return apply_presence(verify_if_present=False) | {'reason': reason}
        # All present: verify when the set of devices changed or maps are not allowed.
        if sig != last_sig or not current.get('media_ok'):
            return apply_presence(verify_if_present=True) | {'reason': reason}
        return {'ok': True, 'unchanged': True, 'media_ok': True, 'reason': reason}

    def on_signal(signum, _frame):
        try:
            tick('signal-%s' % signum)
        except Exception:
            pass

    try:
        import signal
        signal.signal(signal.SIGUSR1, on_signal)
        signal.signal(signal.SIGHUP, on_signal)
    except Exception:
        pass

    sock = None
    try:
        import socket
        # NETLINK_KOBJECT_UEVENT = 15; group 1 receives kernel uevents.
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, 15)
        sock.bind((os.getpid(), 1))
        sock.setblocking(False)
    except OSError:
        sock = None

    try:
        st = load_state()
        last_sig = snapshot_sig(st)
        try:
            r = tick('start')
        except Exception as e:
            r = {'ok': False, 'error': str(e), 'reason': 'start'}
        # Best-effort log to stderr for journald.
        try:
            print('ker-enforcer: watch start', json.dumps(r, default=str), flush=True)
        except Exception:
            pass
        while True:
            ready = True
            if sock is not None:
                import select
                try:
                    readable, _, _ = select.select([sock], [], [], poll)
                except (InterruptedError, OSError):
                    readable = []
                event = False
                saw_remove = False
                def _ingest(payload: str) -> None:
                    nonlocal event, saw_remove
                    if not payload:
                        return
                    if 'SUBSYSTEM=block' in payload or 'SUBSYSTEM=usb' in payload or 'ACTION=remove' in payload or 'ACTION=add' in payload:
                        event = True
                    if 'ACTION=remove' in payload and ('SUBSYSTEM=block' in payload or 'SUBSYSTEM=usb' in payload or 'DEVTYPE=disk' in payload):
                        saw_remove = True
                for s in readable:
                    try:
                        data = s.recv(65536)
                    except BlockingIOError:
                        data = b''
                    _ingest(data.decode('utf-8', 'replace') if data else '')
                if event:
                    # Coalesce the udev burst so we tick once. Short enough
                    # that deny stays well under one second; long enough for
                    # add events to expose a live node before presence runs.
                    drain_until = time.time() + (0.05 if saw_remove else 0.25)
                    while time.time() < drain_until:
                        remain = max(0.0, drain_until - time.time())
                        try:
                            more, _, _ = select.select([sock], [], [], remain)
                        except (InterruptedError, OSError):
                            more = []
                        if not more:
                            break
                        for s in more:
                            try:
                                data = s.recv(65536)
                            except BlockingIOError:
                                data = b''
                            _ingest(data.decode('utf-8', 'replace') if data else '')
                    st = load_state()
                    r = tick('uevent-remove' if saw_remove else 'uevent')
                    last_sig = snapshot_sig(st)
                    try:
                        if not r.get('unchanged'):
                            print('ker-enforcer:', json.dumps(r, default=str), flush=True)
                    except Exception:
                        pass
                    continue
            else:
                time.sleep(poll)
            st = load_state()
            sig = snapshot_sig(st)
            if sig != last_sig:
                r = tick('poll')
                last_sig = sig
                try:
                    if not r.get('unchanged'):
                        print('ker-enforcer:', json.dumps(r, default=str), flush=True)
                except Exception:
                    pass
            else:
                # If maps drifted (e.g. bpf reloaded) and media are present, re-verify.
                current = read_maps()
                if current is None and st.get('kernel_enforcement'):
                    tick('poll-reload')
                    last_sig = snapshot_sig(st)
                elif sig[0] and current and not current.get('media_ok'):
                    # All present but still denied — a previous verify may have
                    # failed or been skipped while busy; retry.
                    r = tick('poll-retry-allow')
                    last_sig = snapshot_sig(st)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        try:
            if WATCH_PID.is_file() and WATCH_PID.read_text().strip() == str(os.getpid()):
                WATCH_PID.unlink()
        except OSError:
            pass



ENFORCER_UNITS = ('ker-enforcer.service', 'ker-enforcer.timer')


def _legacy_guard_active() -> bool:
    """Do not touch systemd units on a host that already runs ker-guard."""
    try:
        r = subprocess.run(
            ['systemctl', 'is-active', '--quiet', 'ker-guard.service'],
            timeout=3,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return r.returncode == 0
    except Exception:
        return False


def _systemd_available() -> bool:
    if PREFIX or os.environ.get('KER_SKIP_SYSTEMD') == '1':
        return False
    if _legacy_guard_active():
        return False
    return True


def sync_enforcer_units(enabled: bool) -> dict:
    """Enable the persistent watcher and backup timer when enforcement is on.

    This is what restores BPF after reboot when state.json already has
    kernel_enforcement enabled. The package install path never enables these
    units by itself. Best-effort: missing systemd, a prefixed test tree, or a
    live ker-guard host is not an error and does not load BPF.
    """
    if not _systemd_available():
        return {'ok': True, 'skipped': True}
    action = ['enable', '--now'] if enabled else ['disable', '--now']
    ran = []
    for unit in ENFORCER_UNITS:
        try:
            subprocess.run(
                ['systemctl', *action, unit],
                timeout=8,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            ran.append(unit)
        except Exception:
            pass
    return {'ok': True, 'enabled': bool(enabled), 'units': ran}


def set_enforcement(enabled: bool, *, confirm: bool = True, already_confirmed: bool = False) -> dict:
    """Turn kernel enforcement on or off. Test mode is the default."""
    from ker.cluster import assert_not_fail_closed
    st = load_state()
    if not st.get('initialized'):
        raise EnforceError('not initialized')
    assert_not_fail_closed(st)
    if enabled and not already_confirmed and confirm:
        raise EnforceError('enabling kernel enforcement requires an explicit confirmation')
    if enabled and not media_present(st)[0]:
        raise EnforceError('all required media must be present before enabling enforcement')
    if enabled and not media_ok(st):
        raise EnforceError('all required media must verify before enabling enforcement')
    applied = False
    if enabled:
        if not may_load_bpf():
            raise EnforceError(
                'this machine is not a VM and host BPF is not allowed; '
                'enforcement was not enabled'
            )
        load_bpf()
        update_maps(enforcement=True, media_ok=True, permissions=st.get('permissions') or [])
        applied = True
    else:
        if may_load_bpf() and PIN_DIR.exists():
            try:
                update_maps(enforcement=False, media_ok=True, permissions=st.get('permissions') or [])
            except EnforceError:
                pass
        applied = True
    st['kernel_enforcement'] = bool(enabled)
    st['mode'] = 'enforce' if enabled else 'test'
    save_state(st)
    units = sync_enforcer_units(bool(enabled))
    return {
        'ok': True,
        'kernel_enforcement': bool(enabled),
        'bpf_applied': applied,
        'units': units,
    }


def run_enforcer_once() -> dict:
    return refresh_media_flag()
