"""Format and write a sealed KER authorization medium."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

from ker.devices import is_empty_filesystem


class MediaError(RuntimeError):
    pass


ALLOWED_NAMES = None  # set by writer from payload


def _run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode:
        raise MediaError((r.stderr or r.stdout or 'command failed')[-2000:])
    return r


def _wipe(dev: str) -> None:
    _run(['wipefs', '-a', dev])
    # clear first 8MiB to drop old metadata
    _run(['dd', 'if=/dev/zero', f'of={dev}', 'bs=1M', 'count=8', 'conv=fsync'], timeout=60)


def format_media(dev: str, kind: str, label: str = 'KER_AUTH') -> None:
    if kind in ('dvd-r', 'optical'):
        return
    if kind == 'worm':
        return
    _wipe(dev)
    if kind == 'removable':
        _run(['mkfs.vfat', '-F', '32', '-n', label[:11], dev])
    elif kind == 'disk':
        _run(['mkfs.ext4', '-F', '-L', label, dev])
    else:
        raise MediaError(f'unsupported media kind: {kind}')


def _mount(dev: str, dest: Path, kind: str) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    opts = 'rw,nosuid,nodev,noexec'
    if kind == 'removable' or kind == 'worm':
        opts += ',uid=0,gid=0,umask=077'
    _run(['mount', '-o', opts, dev, str(dest)])


def _umount(dest: Path) -> None:
    subprocess.run(['sync'], check=False)
    for _ in range(10):
        r = subprocess.run(['umount', str(dest)], capture_output=True, text=True)
        if r.returncode == 0:
            return
        time.sleep(0.3)
    raise MediaError(f'umount failed: {dest}')


def worm_must_be_empty(dev: str) -> None:
    with tempfile.TemporaryDirectory(prefix='ker-worm-') as tmp:
        mp = Path(tmp) / 'm'
        mp.mkdir()
        r = subprocess.run(['mount', '-o', 'ro,nosuid,nodev,noexec', dev, str(mp)], capture_output=True, text=True)
        if r.returncode:
            # no filesystem or cannot mount: treat non-empty raw as not empty if it has a signature
            raise MediaError('WORM media could not be mounted to check emptiness')
        try:
            if not is_empty_filesystem(mp):
                raise MediaError('WORM_NOT_EMPTY')
        finally:
            subprocess.run(['umount', str(mp)], capture_output=True)


def write_payload(dest_dir: Path, files: dict[str, bytes]) -> None:
    """Write an exact file set. No other names allowed later."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        if '/' in name or name in ('.', '..'):
            raise MediaError(f'illegal name: {name}')
        path = dest_dir / name
        path.write_bytes(data)
        os.chmod(path, 0o444)
    # drop lost+found if ext4 created it? keep it? Scheme: no extra files.
    lf = dest_dir / 'lost+found'
    if lf.is_dir():
        try:
            lf.rmdir()
        except OSError:
            pass


def list_payload(dest_dir: Path) -> dict[str, int]:
    out = {}
    for p in sorted(dest_dir.iterdir()):
        if p.name == 'lost+found':
            continue
        if p.is_symlink() or not p.is_file():
            raise MediaError(f'unexpected entry on media: {p.name}')
        out[p.name] = p.stat().st_size
    return out


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def build_iso(files: dict[str, bytes], iso_path: Path, label: str = 'KER_AUTH') -> None:
    with tempfile.TemporaryDirectory(prefix='ker-iso-') as tmp:
        stage = Path(tmp) / 's'
        write_payload(stage, files)
        iso_path.parent.mkdir(parents=True, exist_ok=True)
        _run([
            'xorriso', '-as', 'mkisofs', '-iso-level', '3', '-R', '-J',
            '-V', label[:32], '-o', str(iso_path), str(stage),
        ], timeout=600)


def write_device(dev: str, kind: str, files: dict[str, bytes], iso_out: Path | None = None) -> None:
    if kind in ('dvd-r', 'optical'):
        if iso_out is None:
            iso_out = Path('/var/lib/ker') / 'keydata-dvd.iso'
        build_iso(files, iso_out)
        # If a real burner node is selected, try a disc image burn; otherwise leave the ISO.
        if dev.startswith('/dev/sr') or dev.startswith('/dev/cd'):
            _run(['xorriso', '-as', 'cdrecord', '-v', f'dev={dev}', '-eject', str(iso_out)], timeout=3600)
        return
    if kind == 'worm':
        worm_must_be_empty(dev)
        with tempfile.TemporaryDirectory(prefix='ker-wrm-') as tmp:
            mp = Path(tmp) / 'm'
            _mount(dev, mp, kind)
            try:
                if not is_empty_filesystem(mp):
                    raise MediaError('WORM_NOT_EMPTY')
                write_payload(mp, files)
            finally:
                _umount(mp)
        return
    format_media(dev, kind)
    with tempfile.TemporaryDirectory(prefix='ker-mnt-') as tmp:
        mp = Path(tmp) / 'm'
        _mount(dev, mp, kind)
        try:
            write_payload(mp, files)
        finally:
            _umount(mp)
