"""List and classify block devices similarly to lsblk."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


def _lsblk() -> list[dict]:
    out = subprocess.check_output(
        ['lsblk', '-J', '-b', '-o',
         'NAME,PATH,SIZE,TYPE,FSTYPE,TRAN,RM,RO,MODEL,SERIAL,LABEL,UUID,MOUNTPOINTS,HOTPLUG,PKNAME'],
        text=True,
    )
    return json.loads(out).get('blockdevices') or []


def flatten(devs=None, parent=None, acc=None) -> list[dict]:
    acc = acc if acc is not None else []
    for dev in devs or _lsblk():
        item = dict(dev)
        item['parent'] = parent
        children = item.pop('children', None) or []
        acc.append(item)
        flatten(children, parent=item.get('path') or item.get('name'), acc=acc)
    return acc


def system_paths() -> set[str]:
    keep = set()
    try:
        out = subprocess.check_output(['findmnt', '-J', '-o', 'SOURCE,TARGET'], text=True)
        for rec in json.loads(out).get('filesystems', []):
            def walk(node):
                tgt = node.get('target')
                src = node.get('source') or ''
                if tgt in ('/', '/boot', '/boot/efi', '[SWAP]') or (tgt and tgt.startswith('/boot')):
                    keep.add(src)
                    # also resolve mapper
                    if src.startswith('/dev/'):
                        keep.add(os.path.realpath(src))
                for child in node.get('children') or []:
                    walk(child)
            walk(rec)
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError):
        pass
    # host root via /
    try:
        src = subprocess.check_output(['findmnt', '-n', '-o', 'SOURCE', '/'], text=True).strip()
        if src:
            keep.add(src)
            keep.add(os.path.realpath(src))
    except Exception:
        pass
    return keep


def _sys_text(*parts) -> str:
    p = Path('/sys/class/block')
    try:
        return (p.joinpath(*parts)).read_text(encoding='utf-8', errors='ignore').strip()
    except FileNotFoundError:
        return ''


def classify(dev: dict) -> str:
    typ = (dev.get('type') or '').lower()
    tran = (dev.get('tran') or '').lower()
    model = (dev.get('model') or '').upper()
    path = dev.get('path') or ''
    name = Path(path).name if path else (dev.get('name') or '')
    # optical
    if typ in ('rom', '5') or 'DVD' in model or 'CD-ROM' in model or 'BD-R' in model or 'CDRW' in model:
        return 'dvd-r' if any(x in model for x in ('DVD-R', 'DVD+R', 'BD-R')) or typ == 'rom' else 'optical'
    # WORM hints
    if 'WORM' in model or _sys_text(name, 'device', 'type') == '4':
        return 'worm'
    if typ == 'disk' and (dev.get('rm') or tran == 'usb' or dev.get('hotplug')):
        return 'removable'
    if typ in ('disk', 'part'):
        return 'disk'
    return typ or 'unknown'


def candidates(include_system: bool = False) -> list[dict]:
    sys_paths = system_paths()
    result = []
    for dev in flatten():
        typ = dev.get('type')
        path = dev.get('path')
        if not path or typ not in ('disk', 'rom', 'part'):
            continue
        real = os.path.realpath(path)
        # skip partitions of system disks only when listing top-level media; keep disks
        mounted = [m for m in (dev.get('mountpoints') or []) if m]
        if not include_system:
            if path in sys_paths or real in sys_paths:
                continue
            if any(m in ('/', '/boot', '/boot/efi') for m in mounted):
                continue
        kind = classify(dev)
        # Prefer whole disks / optical, not every noisy partition of the system disk
        if typ == 'part' and kind == 'disk':
            # allow unmounted data partitions as ext4 targets only if user wants; hide by default if parent is system
            parent = dev.get('parent')
            if parent and (parent in sys_paths or os.path.realpath(parent) in sys_paths):
                continue
        item = dict(dev)
        item['kind'] = kind
        item['size_h'] = _human(dev.get('size') or 0)
        result.append(item)
    return result


def _human(n) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return '?'
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if n < 1024 or unit == 'TiB':
            return f'{n:.1f} {unit}' if unit != 'B' else f'{n} B'
        n /= 1024
    return f'{n} B'


def is_empty_filesystem(mountpoint: Path) -> bool:
    try:
        return not any(mountpoint.iterdir())
    except FileNotFoundError:
        return False


def block_device_live(path: str | None) -> bool:
    """Cheap, non-blocking check that a block device node is still usable.

    Used to fail-closed on unplug without mounting. A stale by-id symlink or a
    sysfs entry that is already going away counts as not present.
    """
    if not path:
        return False
    p = Path(path)
    try:
        if not p.exists():
            return False
    except OSError:
        return False
    try:
        st = p.stat()
    except OSError:
        return False
    import stat as statmod
    if not statmod.S_ISBLK(st.st_mode):
        return False
    try:
        real = os.path.realpath(path, strict=True)
    except (OSError, ValueError, TypeError):
        try:
            real = os.path.realpath(path)
        except OSError:
            return False
    name = Path(real).name
    if not name or name.startswith(('loop', 'ram', 'fd')):
        # still allow if the recorded path itself is a loop used as media
        if not (path.endswith(name) or Path(path).name == name):
            pass
    sysfs = Path('/sys/class/block') / name
    if not sysfs.is_dir():
        return False
    try:
        size = (sysfs / 'size').read_text(encoding='utf-8', errors='ignore').strip()
    except OSError:
        return False
    if size == '0':
        return False
    return True


def serial_from_media(entry: dict | str | None) -> str:
    """Best-effort serial for a state media entry (path or explicit serial)."""
    if isinstance(entry, str):
        path, serial = entry, ''
    elif isinstance(entry, dict):
        path = entry.get('path') or ''
        serial = (entry.get('serial') or '').strip()
    else:
        return ''
    if serial:
        return serial
    name = Path(path).name
    # usb-QEMU_QEMU_HARDDISK_KER-PERM-0:0 -> KER-PERM
    import re
    m = re.search(r'(KER-[A-Z0-9]+)', name)
    return m.group(1) if m else ''


def resolve_media_path(entry: dict | str | None) -> str | None:
    """Return a live block device for this recorded medium, or None.

    Prefers the recorded by-id path. After a live unplug/replug, udev may
    assign a new by-id suffix, or helpers may lag; fall back to a device
    whose kernel/udev serial or by-id name matches KER-*.
    """
    if isinstance(entry, str):
        path = entry
        serial = serial_from_media(entry)
    elif isinstance(entry, dict):
        path = entry.get('path') or ''
        serial = serial_from_media(entry)
    else:
        return None
    if path and block_device_live(path):
        return path
    if not serial:
        return None
    try:
        byid = Path('/dev/disk/by-id')
        if byid.is_dir():
            for p in byid.iterdir():
                if serial not in p.name or '-part' in p.name:
                    continue
                if block_device_live(str(p)):
                    return str(p)
    except OSError:
        pass
    try:
        base = Path('/sys/class/block')
        if base.is_dir():
            for blk in base.iterdir():
                n = blk.name
                if n.startswith(('loop', 'ram', 'fd', 'sr', 'dm-')):
                    continue
                # skip partitions (sda1) — whole disk only
                if n[-1].isdigit() and not n.startswith('nvme'):
                    continue
                serials = serials_up_from_block(blk)
                if serial in serials and block_device_live(f'/dev/{n}'):
                    return f'/dev/{n}'
    except OSError:
        pass
    return None


def serials_up_from_block(sys_blk: Path) -> list[str]:
    """Serial values walking from a /sys/class/block/<name> node toward the root.

    QEMU usb-storage does not expose serial at device/serial. The USB device
    a few parents up has it (e.g. .../usb2/2-2/serial = KER-PERM). Hub and
    controller nodes also have serials; callers must match a known token.
    """
    vals: list[str] = []
    try:
        start = sys_blk / 'device' if (sys_blk / 'device').exists() else sys_blk
        cur = start
    except OSError:
        return vals
    seen: set[Path] = set()
    for _ in range(16):
        try:
            cur = cur.resolve()
        except OSError:
            break
        if cur in seen or cur == cur.parent:
            break
        seen.add(cur)
        sp = cur / 'serial'
        try:
            if sp.is_file():
                v = sp.read_text(encoding='utf-8', errors='ignore').strip()
                if v:
                    vals.append(v)
        except OSError:
            pass
        cur = cur.parent
        if str(cur) in ('/', '/sys', '/sys/devices'):
            break
    return vals


def required_media_presence(media: list | None) -> tuple[bool, list[str]]:
    """Return (all_present, missing_paths) for state.json media entries."""
    missing: list[str] = []
    for m in media or []:
        path = (m.get('path') if isinstance(m, dict) else None) or ''
        if not resolve_media_path(m if isinstance(m, dict) else {'path': path}):
            missing.append(path or '(no-path)')
    return (not missing, missing)

