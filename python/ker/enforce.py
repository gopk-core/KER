"""Kernel enforcement switch. Never auto-enabled by a package install.

BPF LSM is a host-wide kernel attachment. This module refuses to load
programs on a bare-metal machine unless KER_ALLOW_HOST_BPF=1, so a test
prefix or a package install cannot alter the production host's LSM.
"""
from __future__ import annotations

import fcntl
import json
import os
import stat
import struct
import subprocess
import tempfile
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
# allow_inos is a hash of inode+device, not a 64-slot array. ALLOW_SLOTS is
# that hash's max_entries and stays well above the concrete path list.
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
    '/usr/lib/udev/usb_id',
    '/lib/udev/usb_id',
    '/usr/lib/systemd/systemd-udev-worker',
    '/lib/systemd/systemd-udev-worker',
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

ALLOW_SLOTS = 1024
SCOPE_INO_SLOTS = 1024
SCOPE_UID_SLOTS = 256
SCOPE_PORT_SLOTS = 256
SCOPE_NET4_SLOTS = 256
SCOPE_NET6_SLOTS = 256

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


def init_blockers() -> list[str]:
    """Why enforcement would brick this host, or [] when it is safe to arm.

    The LSM hook denies BIT_RUN for any executable whose inode is not in
    allow_inos, and there is deliberately no comm or basename fallback. PID 1
    must therefore be an allowlisted concrete file. A busybox init, openrc,
    runit or s6 host has an init whose realpath is not on the list, and
    arming enforcement there would refuse to exec init itself.

    This is a pre-flight check, not a bypass: it never widens the allowlist.
    A host it rejects must stay in test mode or get its init allowlisted in a
    later package.
    """
    reasons: list[str] = []
    inits = (
        '/sbin/init', '/usr/sbin/init', '/etc/init',
        '/bin/init', '/usr/bin/init',
    )
    found = [p for p in inits if Path(p).exists()]
    if not found:
        reasons.append('no init binary found at /sbin/init or /usr/sbin/init')
    elif not any(executable_identity(p) is not None for p in found):
        targets = ', '.join(
            '%s -> %s' % (p, os.path.realpath(p)) for p in found
        )
        reasons.append(
            'init is not an allowlisted executable (%s); arming enforcement '
            'would deny exec of PID 1' % targets
        )
    return reasons


def assert_armable() -> None:
    """Raise when arming kernel enforcement would lock the host out."""
    reasons = init_blockers()
    if reasons:
        raise EnforceError(
            'refusing to enable kernel enforcement: ' + '; '.join(reasons)
            + '. Stay in test mode, or use a package that allows this init.'
        )


def decide_subject(*, enforcement: bool, media_ok: bool, deny_mask_value: int,
                   bit: int, allowed: bool, narrow_mask: int = 0,
                   scope_allow: int = 0, scope_deny: int = 0,
                   in_scope: bool = False) -> bool:
    """True when BPF decide_subject would deny this subject.

    A scoped allow clears only its own bits. It does not clear a deny for a
    different path, user, or port, because that subject is not in_scope.

    narrow_mask is applied even when media_ok is set. media_ok == 1 does not
    open a class that narrow_mask still names: a replace rule is policy, not
    a medium-presence flag. deny_mask is applied only when media_ok is 0.
    """
    if allowed or not enforcement:
        return False
    blocked = int(narrow_mask) & int(bit)
    if not media_ok:
        blocked |= int(deny_mask_value) & int(bit)
    if in_scope:
        blocked |= int(scope_deny) & int(bit)
        blocked &= (~int(scope_allow)) & 0xFFFFFFFF
    return bool(blocked)


def would_deny(*, enforcement: bool, media_ok: bool, deny_mask_value: int,
               bit: int, allowed: bool) -> bool:
    """Userspace mirror of the global BPF decide() policy (no subject scope).

    narrow_mask defaults to 0 here. A replace rule's narrow_mask still denies
    when media_ok is 1; pass it through decide_subject to see that.
    """
    return decide_subject(
        enforcement=enforcement, media_ok=media_ok, deny_mask_value=deny_mask_value,
        bit=bit, allowed=allowed,
    )


def bprm_denies(*, enforcement: bool, media_ok: bool, deny_mask_value: int,
                uid: int, allowed: bool = False, narrow_mask: int = 0,
                file_allow: int = 0, file_deny: int = 0, have_file: bool = False,
                uid_allow: int = 0, uid_deny: int = 0, have_uid: bool = False) -> bool:
    """Userspace mirror of lsm/bprm_check_security.

    The run class uses the file scope. Login scope is consulted only when
    euid is 0, and only for BIT_ROOTUSER. A grant for uid 1000, even if its
    allow bits are passed in, does not clear BIT_ROOTUSER or BIT_ROOTSU on
    that uid's ordinary exec.
    """
    if decide_subject(
        enforcement=enforcement, media_ok=media_ok, deny_mask_value=deny_mask_value,
        bit=BIT['run'], allowed=allowed, narrow_mask=narrow_mask,
        scope_allow=file_allow, scope_deny=file_deny, in_scope=have_file,
    ):
        return True
    if int(uid) != 0:
        return False
    return decide_subject(
        enforcement=enforcement, media_ok=media_ok, deny_mask_value=deny_mask_value,
        bit=BIT['rootuser'], allowed=allowed, narrow_mask=narrow_mask,
        scope_allow=uid_allow if have_uid else 0,
        scope_deny=uid_deny if have_uid else 0,
        in_scope=bool(have_uid),
    )


def setuid_denies(*, enforcement: bool, media_ok: bool, deny_mask_value: int,
                  new_uid: int, allowed: bool = False, narrow_mask: int = 0,
                  uid_allow: int = 0, uid_deny: int = 0, have_uid: bool = False) -> bool:
    """Userspace mirror of lsm/task_fix_setuid.

    Only a transition to euid 0 is a root login / setuid-to-root decision.
    BIT_ROOTSU is checked without the login scope, so a login grant cannot
    clear it. A uid-0 login grant or lock is then applied to BIT_ROOTUSER.
    A scope for any other uid is ignored.
    """
    if int(new_uid) != 0:
        return False
    if decide_subject(
        enforcement=enforcement, media_ok=media_ok, deny_mask_value=deny_mask_value,
        bit=BIT['rootsu'], allowed=allowed, narrow_mask=narrow_mask,
    ):
        return True
    if not have_uid or not ((int(uid_allow) | int(uid_deny)) & BIT['rootuser']):
        return False
    return decide_subject(
        enforcement=enforcement, media_ok=media_ok, deny_mask_value=deny_mask_value,
        bit=BIT['rootuser'], allowed=allowed, narrow_mask=narrow_mask,
        scope_allow=uid_allow, scope_deny=uid_deny, in_scope=True,
    )


def connect_scope_bits(plan: dict | None, addr: str | None, port: int) -> tuple[int, int]:
    """Allow and deny bits the socket_connect hook would see for this tuple.

    An exact address+port entry wins over a port-only entry, so a grant for
    10.0.0.5:443 does not become an allow for every address on 443. A
    ports-only entry matches any destination address. Returns (allow, deny)
    with deny already cleared of bits the matching allow names.
    """
    from ker.custom import parse_exact_ip
    plan = plan or {}
    try:
        port_n = int(port)
    except (TypeError, ValueError):
        return 0, 0
    parsed = parse_exact_ip(addr) if addr is not None else None
    if parsed is not None:
        family, raw = parsed
        key = (raw, port_n)
        if family == '4':
            allow_map = plan.get('net4_allow') or {}
            deny_map = plan.get('net4_deny') or {}
        else:
            allow_map = plan.get('net6_allow') or {}
            deny_map = plan.get('net6_deny') or {}
        if key in allow_map or key in deny_map:
            allow = int(allow_map.get(key, 0))
            deny = int(deny_map.get(key, 0)) & ~allow
            return allow, deny
    allow = int((plan.get('port_allow') or {}).get(port_n, 0))
    deny = int((plan.get('port_deny') or {}).get(port_n, 0)) & ~allow
    return allow, deny


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
    # Root-account login only. Not rootsu, and not an allow on a non-root
    # uid's ordinary exec. scope_plan records it for uid 0 alone; other
    # login rules are enforced by the SSH PAM helper.
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
    """Global LSM bits contributed by one custom rule.

    Always zero. A constrained rule must not become a machine-wide bit, and
    a rule whose constraint cannot be enforced exactly must not either.
    The class bit is applied only to the subject inside scope maps.
    """
    return 0


def scope_class_bits(item: dict | None) -> int:
    """Class bits a custom rule may set on its own subject, never globally."""
    if not item:
        return 0
    return _CUSTOM_BITS.get(item.get('type') or '', 0)


def policy_bits(st: dict | None) -> int:
    """Runtime bits selected by built-in permissions.

    Custom rules are not included. Folding one into this mask would allow
    every path, user, or port in that class.
    """
    st = st or {}
    mask = deny_mask(st.get('permissions') or [])
    for item in st.get('custom') or []:
        mask |= custom_bits(item)
    return mask


def key_bits(name: str, st: dict | None = None) -> int:
    """Global bits one key file authorizes.

    root/boot/admin have no LSM bit of their own. A custom key also has no
    global bit; its constraint is enforced on the named subject only.
    """
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


def _medium_has_custom(medium: dict, st: dict | None) -> bool:
    keys = set((medium or {}).get('keys') or [])
    if not keys:
        return False
    for item in (st or {}).get('custom') or []:
        if isinstance(item, dict) and item.get('key') in keys:
            return True
    return False


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
    if bits_for_medium(medium, st) != 0:
        return True
    # A custom key has no global bit, but losing it must still refresh scope.
    return _medium_has_custom(medium, st)


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
    # Arming denies exec of any non-allowlisted inode, PID 1 included.
    assert_armable()
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
        raise EnforceError('allowlisted executable paths exceed BPF allow_inos capacity')
    return ALLOW_SLOTS


def allow_key_bytes(ino: int, dev: int) -> bytes:
    """16-byte hash key: inode, kernel dev_t, pad. Matches struct allow_key."""
    return struct.pack('QII', int(ino), int(dev) & 0xFFFFFFFF, 0)


def allow_value_bytes() -> bytes:
    return struct.pack('I', 1)


def scope_value_bytes(allow_bits: int, deny_bits: int) -> bytes:
    return struct.pack('II', int(allow_bits) & 0xFFFFFFFF, int(deny_bits) & 0xFFFFFFFF)


def scalar_key_bytes(value: int) -> bytes:
    return struct.pack('I', int(value) & 0xFFFFFFFF)


def net4_key_bytes(addr: bytes, port: int) -> bytes:
    """8-byte key: 4 wire-order address bytes, host-order port, pad.

    Matches struct net4_key in src/bpf/ker.bpf.c.
    """
    if len(addr) != 4:
        raise EnforceError('network v4 key must be 4 bytes')
    return struct.pack('<4sHH', addr, int(port) & 0xFFFF, 0)


def net6_key_bytes(addr: bytes, port: int) -> bytes:
    """20-byte key: 16 wire-order address bytes, host-order port, pad.

    Matches struct net6_key in src/bpf/ker.bpf.c (no trailing compiler pad;
    the struct's alignment is 2).
    """
    if len(addr) != 16:
        raise EnforceError('network v6 key must be 16 bytes')
    return struct.pack('<16sHH', addr, int(port) & 0xFFFF, 0)


def _coerce_bpf_bytes(raw) -> bytes | None:
    if isinstance(raw, str):
        parts = raw.replace(',', ' ').split()
        if not parts:
            return b''
        try:
            return bytes(int(x, 16) for x in parts)
        except ValueError:
            return None
    if isinstance(raw, list):
        try:
            return bytes(int(x, 16) if isinstance(x, str) else int(x) for x in raw)
        except (TypeError, ValueError):
            return None
    if isinstance(raw, dict):
        if 'hex' in raw:
            return _coerce_bpf_bytes(raw.get('hex'))
        if 'value' in raw:
            return _coerce_bpf_bytes(raw.get('value'))
    return None


def parse_map_dump(stdout: str) -> dict[bytes, bytes]:
    """Parse `bpftool -j map dump` into key bytes -> value bytes."""
    text = (stdout or '').strip()
    if not text or text == 'null':
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}
    if isinstance(data, dict):
        data = data.get('elements') or data.get('entries') or [data]
    out: dict[bytes, bytes] = {}
    for item in data or []:
        if not isinstance(item, dict):
            continue
        key_raw = item.get('key')
        val_raw = item.get('value')
        formatted = item.get('formatted')
        if isinstance(formatted, dict):
            key_raw = formatted.get('key', key_raw)
            val_raw = formatted.get('value', val_raw)
        key = _coerce_bpf_bytes(key_raw)
        value = _coerce_bpf_bytes(val_raw)
        if key is None or value is None:
            continue
        out[key] = value
    return out


def diff_hash_map(current: dict[bytes, bytes], desired: dict[bytes, bytes]) -> tuple[list[bytes], dict[bytes, bytes]]:
    """Keys to delete and keys whose value must be written. Unchanged keys are omitted."""
    deletes = [key for key in current if key not in desired]
    updates = {key: value for key, value in desired.items() if current.get(key) != value}
    return deletes, updates


def bpftool_batch_lines(pin: Path | str, deletes: list[bytes], updates: dict[bytes, bytes]) -> list[str]:
    lines = []
    for key in deletes:
        lines.append('map delete pinned %s key hex %s' % (pin, ' '.join(_hex_bytes(key))))
    for key, value in updates.items():
        lines.append(
            'map update pinned %s key hex %s value hex %s'
            % (pin, ' '.join(_hex_bytes(key)), ' '.join(_hex_bytes(value)))
        )
    return lines


def desired_allow_entries(paths: tuple[str, ...] | list[str] | None = None) -> dict[bytes, bytes]:
    """One hash entry per existing allowlisted inode+device. Missing paths are omitted."""
    chosen = list(ALLOWED_EXEC_PATHS if paths is None else paths)
    if len(chosen) > ALLOW_SLOTS:
        raise EnforceError('allowlisted executable paths exceed BPF allow_inos capacity')
    entries: dict[bytes, bytes] = {}
    for path in chosen:
        ident = executable_identity(path)
        if ident is None:
            continue
        ino, dev = ident
        entries[allow_key_bytes(ino, dev)] = allow_value_bytes()
    return entries


def _scope_inode(path: str) -> tuple[int, int] | None:
    """Exact inode for a scope path. Symlinks are not followed (fail closed)."""
    if not path or not str(path).startswith('/') or os.path.islink(path):
        return None
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return None
    mode = st.st_mode
    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode)):
        return None
    return int(st.st_ino), kernel_dev(st.st_dev) & 0xFFFFFFFF


def _or_bits(store: dict, key, bits: int) -> None:
    store[key] = int(store.get(key, 0)) | int(bits)


def scope_plan(st: dict | None, *, verified: bool = False,
               inactive_keys: set[str] | None = None) -> dict:
    """Subject allow/deny bits for expressible custom rules.

    Grants are installed only when the rule's key is active. Lock and replace
    rules deny their own subject while the key is inactive. Nothing here is a
    global bit. A subject that cannot be named (missing path, symlink, shell
    ExecStart, address-only / interface-only / direction-only network rule,
    or a port rule that also names a constraint connect() cannot check) is
    not granted. A ports-only network rule is a grant for that port on any
    destination address. A rule that also names exact addresses is stored
    as address+port, never as the port alone.

    Login allow/deny bits are recorded only for uid 0. A login grant for
    any other uid is not an LSM allow: it must not clear BIT_ROOTUSER on
    that uid's ordinary exec. The SSH PAM helper enforces those rules.
    """
    from ker.custom import (
        iter_custom, login_uids, network_scope, rule_expressible, scope_paths, service_exec_path,
    )
    inactive = set(inactive_keys or ())
    ino_allow: dict[tuple[int, int], int] = {}
    ino_deny: dict[tuple[int, int], int] = {}
    uid_allow: dict[int, int] = {}
    uid_deny: dict[int, int] = {}
    port_allow: dict[int, int] = {}
    port_deny: dict[int, int] = {}
    net4_allow: dict[tuple[bytes, int], int] = {}
    net4_deny: dict[tuple[bytes, int], int] = {}
    net6_allow: dict[tuple[bytes, int], int] = {}
    net6_deny: dict[tuple[bytes, int], int] = {}
    narrow = 0
    for item in iter_custom(st):
        if not rule_expressible(item):
            continue
        mode = item.get('mode') or 'grant'
        key_name = item.get('key')
        active = bool(verified) and bool(key_name) and key_name not in inactive
        bits = scope_class_bits(item)
        if not bits:
            continue
        grant = active and mode in ('grant', 'lock', 'replace')
        deny = (not active) and mode in ('lock', 'replace')
        if not grant and not deny:
            continue
        # A replace rule narrows its class only when at least one subject
        # was recorded. Otherwise it would deny the whole class with no
        # exception, which is a wider effect than the constraint names.
        recorded = False

        def _mark(store, key, class_bits=bits):
            nonlocal recorded
            _or_bits(store, key, class_bits)
            recorded = True

        typ = item.get('type')
        if typ in ('file_read', 'file_write', 'file_exec', 'command', 'device'):
            store = ino_allow if grant else ino_deny
            for path in scope_paths(item):
                ident = _scope_inode(path)
                if ident is None:
                    continue
                _mark(store, ident)
        elif typ == 'service':
            store = ino_allow if grant else ino_deny
            units = (item.get('constraints') or {}).get('units') or []
            if isinstance(units, str):
                units = [units]
            for unit in units:
                binary = service_exec_path(str(unit))
                if not binary:
                    continue
                ident = _scope_inode(binary)
                if ident is None:
                    continue
                _mark(store, ident)
        elif typ == 'login':
            # uid 0 only. Non-root login rules stay on the PAM path.
            store = uid_allow if grant else uid_deny
            for uid in login_uids(item):
                if int(uid) != 0:
                    continue
                _mark(store, 0)
        elif typ == 'network':
            scope = network_scope(item.get('constraints') or {})
            if not scope:
                continue
            if scope['addrs']:
                for family, raw_addr in scope['addrs']:
                    if family == '4':
                        store = net4_allow if grant else net4_deny
                    else:
                        store = net6_allow if grant else net6_deny
                    for port in scope['ports']:
                        _mark(store, (raw_addr, int(port)))
            else:
                # Ports only (or ports plus outbound, which connect() is).
                # Any destination address on that port. Do not do this when
                # the rule also named an address.
                store = port_allow if grant else port_deny
                for port in scope['ports']:
                    _mark(store, int(port))
        if mode == 'replace' and active and recorded:
            narrow |= bits
    return {
        'ino_allow': ino_allow,
        'ino_deny': ino_deny,
        'uid_allow': uid_allow,
        'uid_deny': uid_deny,
        'port_allow': port_allow,
        'port_deny': port_deny,
        'net4_allow': net4_allow,
        'net4_deny': net4_deny,
        'net6_allow': net6_allow,
        'net6_deny': net6_deny,
        'narrow_mask': narrow,
    }


def _combine_scope(allow_map: dict, deny_map: dict, key_bytes) -> dict[bytes, bytes]:
    out: dict[bytes, bytes] = {}
    for key in set(allow_map) | set(deny_map):
        allow = int(allow_map.get(key, 0))
        deny = int(deny_map.get(key, 0)) & ~allow
        out[key_bytes(key)] = scope_value_bytes(allow, deny)
    return out


def desired_scope_entries(st: dict | None, *, verified: bool = False,
                          inactive_keys: set[str] | None = None) -> dict[str, dict[bytes, bytes]]:
    plan = scope_plan(st, verified=verified, inactive_keys=inactive_keys)
    inos = _combine_scope(
        plan['ino_allow'], plan['ino_deny'],
        lambda ident: allow_key_bytes(ident[0], ident[1]),
    )
    uids = _combine_scope(plan['uid_allow'], plan['uid_deny'], scalar_key_bytes)
    ports = _combine_scope(plan['port_allow'], plan['port_deny'], scalar_key_bytes)
    net4 = _combine_scope(
        plan.get('net4_allow') or {}, plan.get('net4_deny') or {},
        lambda item: net4_key_bytes(item[0], item[1]),
    )
    net6 = _combine_scope(
        plan.get('net6_allow') or {}, plan.get('net6_deny') or {},
        lambda item: net6_key_bytes(item[0], item[1]),
    )
    if (
        len(inos) > SCOPE_INO_SLOTS or len(uids) > SCOPE_UID_SLOTS
        or len(ports) > SCOPE_PORT_SLOTS or len(net4) > SCOPE_NET4_SLOTS
        or len(net6) > SCOPE_NET6_SLOTS
    ):
        raise EnforceError('custom scope exceeds BPF map capacity')
    return {
        'inos': inos,
        'uids': uids,
        'ports': ports,
        'net4': net4,
        'net6': net6,
        'narrow_mask': plan['narrow_mask'],
    }


def _pinned_map_type(pin: Path) -> str | None:
    if not _pin_exists(pin):
        return None
    try:
        r = subprocess.run(
            ['bpftool', '-j', 'map', 'show', 'pinned', str(pin)],
            capture_output=True, text=True, timeout=3,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    text = ((r.stdout or '') + '\n' + (r.stderr or '')).lower()
    if r.returncode == 0 and (r.stdout or '').strip():
        try:
            data = json.loads(r.stdout)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, list) and data:
            data = data[0]
        if isinstance(data, dict):
            kind = str(data.get('type') or '').lower()
            if kind:
                return kind
    if 'hash' in text:
        return 'hash'
    if 'array' in text:
        return 'array'
    return None


def _dump_hash(pin: Path) -> dict[bytes, bytes]:
    try:
        r = subprocess.run(
            ['bpftool', '-j', 'map', 'dump', 'pinned', str(pin)],
            capture_output=True, text=True, timeout=3,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        raise EnforceError('bpftool map dump failed') from e
    if r.returncode:
        err = ((r.stderr or '') + (r.stdout or '')).lower()
        if not (r.stdout or '').strip() or 'empty' in err or 'no such' in err:
            return {}
        raise EnforceError((r.stderr or r.stdout or 'bpftool map dump failed').strip())
    if not (r.stdout or '').strip():
        return {}
    return parse_map_dump(r.stdout)


def _bpftool_batch(lines: list[str]) -> None:
    if not lines:
        return
    fd, name = tempfile.mkstemp(prefix='ker-bpf-')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            fh.write('\n'.join(lines) + '\n')
        r = subprocess.run(['bpftool', 'batch', 'file', name], capture_output=True, text=True)
        if r.returncode == 0:
            return
        errors = []
        for line in lines:
            one = subprocess.run(['bpftool', *line.split()], capture_output=True, text=True)
            if one.returncode:
                errors.append((one.stderr or one.stdout or line).strip())
        if errors:
            raise EnforceError(errors[-1])
    finally:
        try:
            os.unlink(name)
        except OSError:
            pass


def _apply_hash_diff(pin: Path, desired: dict[bytes, bytes]) -> int:
    """Write only the keys that changed. Returns how many keys were updated or deleted."""
    current = _dump_hash(pin)
    deletes, updates = diff_hash_map(current, desired)
    lines = bpftool_batch_lines(pin, deletes, updates)
    if not lines:
        return 0
    _bpftool_batch(lines)
    return len(lines)


_MIGRATING = False


def _migrate_legacy_allow_map() -> None:
    """Replace a pinned ARRAY allow_inos with the current object.

    The enforcement flag already in cfg is written back after the reload.
    A missing cfg is left at zero, so this never turns enforcement on by itself.
    """
    global _MIGRATING
    if _MIGRATING:
        return
    _MIGRATING = True
    try:
        previous = read_maps() or {}
        unload_bpf()
        if _pin_exists(PIN_DIR):
            raise EnforceError('old BPF pin could not be removed')
        load_bpf()
        kind = _pinned_map_type(PIN_DIR / 'allow_inos')
        if kind == 'array':
            raise EnforceError('reloaded BPF still has the legacy allow map')
        if not previous:
            return
        update_maps(
            enforcement=bool(previous.get('enforcement')),
            media_ok=bool(previous.get('media_ok')),
            permissions=[],
            deny_mask_value=int(previous.get('deny_mask') or 0),
            narrow_mask=int(previous.get('narrow_mask') or 0),
            scopes_verified=bool(previous.get('media_ok')),
            skip_migrate=True,
        )
    finally:
        _MIGRATING = False


def refresh_allow_maps() -> None:
    """Insert allow_inos entries for concrete allowlisted paths.

    No-op when the map is not pinned. Does not load BPF on its own. An old
    64-slot array is recreated as a hash without changing the enforcement
    flag. Unchanged keys are not rewritten, so a udev event does not spawn
    one bpftool process per slot.
    """
    if not may_load_bpf():
        return
    pin = PIN_DIR / 'allow_inos'
    if not _pin_exists(pin):
        return
    kind = _pinned_map_type(pin)
    if kind == 'array':
        if _MIGRATING:
            return
        _migrate_legacy_allow_map()
        return
    if kind not in ('hash', 'percpu_hash'):
        return
    _apply_hash_diff(pin, desired_allow_entries())


def refresh_scope_maps(*, scopes_verified: bool = False,
                       inactive_keys: set[str] | None = None) -> None:
    """Sync custom subject maps. Missing pins are left alone (older objects)."""
    if not may_load_bpf():
        return
    try:
        st = load_state()
    except Exception:
        st = {}
    desired = desired_scope_entries(st, verified=scopes_verified, inactive_keys=inactive_keys)
    for name, entries in (
        ('scope_inos', desired['inos']),
        ('scope_uids', desired['uids']),
        ('scope_ports', desired['ports']),
        ('scope_net4', desired.get('net4') or {}),
        ('scope_net6', desired.get('net6') or {}),
    ):
        pin = PIN_DIR / name
        if not _pin_exists(pin):
            continue
        if _pinned_map_type(pin) not in ('hash', 'percpu_hash'):
            continue
        _apply_hash_diff(pin, entries)


def update_maps(*, enforcement: bool, media_ok: bool, permissions: list[str] | None,
                deny_mask_value: int | None = None, narrow_mask: int | None = None,
                scopes_verified: bool = False, inactive_keys: set[str] | None = None,
                skip_migrate: bool = False) -> None:
    if not may_load_bpf():
        raise EnforceError('BPF map update refused on bare-metal host')
    if not skip_migrate:
        allow_pin = PIN_DIR / 'allow_inos'
        if _pin_exists(allow_pin) and _pinned_map_type(allow_pin) == 'array':
            _migrate_legacy_allow_map()
    if narrow_mask is None:
        try:
            st_now = load_state()
        except Exception:
            st_now = {}
        narrow_mask = scope_plan(
            st_now, verified=bool(scopes_verified), inactive_keys=inactive_keys,
        )['narrow_mask']
    key = struct.pack('I', 0)
    mask = deny_mask(permissions) if deny_mask_value is None else int(deny_mask_value)
    value = struct.pack(
        'IIII',
        1 if enforcement else 0,
        1 if media_ok else 0,
        mask & 0xFFFFFFFF,
        int(narrow_mask) & 0xFFFFFFFF,
    )
    mp = _map_path()
    _map_update(mp, key, value)
    # Best-effort: an older pinned object may not have allow_inos yet.
    try:
        refresh_allow_maps()
    except EnforceError:
        if _pin_exists(PIN_DIR / 'allow_inos'):
            raise
    try:
        refresh_scope_maps(scopes_verified=scopes_verified, inactive_keys=inactive_keys)
    except EnforceError:
        if _pin_exists(PIN_DIR / 'scope_inos'):
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
                'narrow_mask': int(fv.get('narrow_mask') or fv.get('reserved') or 0),
            }
    raw = data.get('value') if isinstance(data, dict) else None
    if isinstance(raw, dict):
        if 'media_ok' in raw:
            return {
                'enforcement': bool(raw.get('enforcement')),
                'media_ok': bool(raw.get('media_ok')),
                'deny_mask': int(raw.get('deny_mask') or 0),
                'narrow_mask': int(raw.get('narrow_mask') or raw.get('reserved') or 0),
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
    narrow = struct.unpack_from('I', buf, 12)[0] if len(buf) >= 16 else 0
    return {
        'enforcement': bool(enf), 'media_ok': bool(mok),
        'deny_mask': mask, 'narrow_mask': narrow,
    }


def _ensure_bpf_if_enforcing(st: dict) -> bool:
    """Load BPF in a VM when state already has kernel enforcement on."""
    if not st.get('kernel_enforcement'):
        return False
    if not may_load_bpf():
        return False
    if init_blockers():
        # A host that was armed under an older package but whose init is not
        # allowlisted must not be re-armed on boot. Stay off, keep the flag.
        return False
    try:
        _map_path()
        allow = PIN_DIR / 'allow_inos'
        # An in-place upgrade from the 0.1.0 array map recreates the hash
        # here. The previous enforcement flag is written back; a zero cfg
        # stays off.
        if _pin_exists(allow) and _pinned_map_type(allow) == 'array':
            _migrate_legacy_allow_map()
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


def _inactive_keys(*groups) -> set[str]:
    keys: set[str] = set()
    for group in groups:
        for medium in group or []:
            if isinstance(medium, dict):
                keys.update(medium.get('keys') or [])
    return keys


def _invalidate_login_key_cache() -> None:
    """Drop the PAM verified-key cache. Deny-first: never leave a stale allow.

    Called when a medium is absent or a verify failed. A later hook call
    must not reuse the previous verified set. Best-effort: a missing
    runtime directory is not an enforcement error.
    """
    try:
        from ker.hooks import invalidate_verified_custom_keys
        invalidate_verified_custom_keys()
    except Exception:
        return


def _push_maps(st: dict, denied: int, *, recover_ssh: bool = False,
               scopes_verified: bool = False, inactive_keys: set[str] | None = None) -> None:
    """Push the bits that are denied right now.

    media_ok is 1 only when no selected runtime bit is denied for a missing
    or unverified medium. The mask then still records the armed policy bits.
    decide() does not apply deny_mask while media_ok is set. It does still
    apply narrow_mask: media_ok == 1 does not open a class that an active
    replace rule has narrowed. narrow_mask is policy, not a presence flag.
    When some bits are denied, deny_mask is exactly those bits — not every
    permission the policy selected.

    Custom scope grants are written only when scopes_verified is true. Until
    then a constrained rule does not open its subject.
    """
    policy = policy_bits(st)
    denied = int(denied) & 0xFFFFFFFF
    media_ok_flag = denied == 0
    mask = policy if media_ok_flag else denied
    plan = scope_plan(st, verified=bool(scopes_verified), inactive_keys=inactive_keys)
    update_maps(
        enforcement=True,
        media_ok=media_ok_flag,
        permissions=st.get('permissions') or [],
        deny_mask_value=mask,
        narrow_mask=int(plan['narrow_mask']),
        scopes_verified=bool(scopes_verified),
        inactive_keys=inactive_keys,
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
        _invalidate_login_key_cache()
        _push_maps(
            st, denied,
            scopes_verified=bool(current.get('media_ok')),
            inactive_keys=_inactive_keys(req_missing),
        )
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
                _invalidate_login_key_cache()
                _push_maps(
                    st, fresh, scopes_verified=False,
                    inactive_keys=_inactive_keys(req_missing),
                )
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
            if req_missing or not report.get('ok') or report.get('failed') or report.get('missing'):
                _invalidate_login_key_cache()
            _push_maps(
                st, denied,
                recover_ssh=bool(denied == 0 and was_denied),
                scopes_verified=bool(verified) and not req_missing,
                inactive_keys=_inactive_keys(
                    req_missing, report.get('missing'), report.get('failed'),
                ),
            )
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
        # Fail before touching maps so state.json is not left claiming enforce.
        assert_armable()
        load_bpf()
        # media_ok() already verified signatures above. The armed mask stays
        # the selected policy bits; it is not cleared.
        update_maps(
            enforcement=True, media_ok=True,
            permissions=st.get('permissions') or [],
            deny_mask_value=policy_bits(st),
            scopes_verified=True,
        )
        applied = True
    else:
        if may_load_bpf() and PIN_DIR.exists():
            try:
                # Leave a deny mask in place so a later enforcement=1 cannot
                # observe media_ok=1 with an empty mask.
                update_maps(
                    enforcement=False, media_ok=False,
                    permissions=st.get('permissions') or [],
                    deny_mask_value=policy_bits(st),
                    scopes_verified=False,
                )
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
