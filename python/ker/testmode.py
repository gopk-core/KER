"""Test mode: verify after unplug/replug, report in the terminal, no kernel blocks."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from ker.bundle import verify_directory
from ker.i18n import t
from ker.paths import MOUNT_ROOT, PRIVATE_DIR, TRUST_DIR
from ker.sign import SignError
from ker.state import state as load_state


def _keys_from_state(st: dict) -> dict:
    return {
        'gpg_fingerprint': st['gpg_fingerprint'],
        'gpg_home': str(PRIVATE_DIR / 'gnupg'),
        'rsa_key': str(PRIVATE_DIR / 'kernel-signing.key'),
        'rsa_pub': str(TRUST_DIR / 'kernel-cert.pem'),
    }


def _serial(dev: str) -> str:
    name = Path(dev).name
    p = Path('/sys/class/block') / name / 'device' / 'serial'
    try:
        return p.read_text().strip()
    except FileNotFoundError:
        return ''


def wait_replug(dev: str, timeout: int = 600) -> str:
    """Wait until dev disappears, then a disk with the same serial (or new same path) returns."""
    serial = _serial(dev)
    start = time.time()
    gone = False
    while time.time() - start < timeout:
        exists = Path(dev).exists()
        if not exists:
            gone = True
        elif gone:
            return dev
        if gone and serial:
            # search new path with same serial
            base = Path('/sys/class/block')
            if base.exists():
                for blk in base.iterdir():
                    sp = blk / 'device' / 'serial'
                    try:
                        if sp.read_text().strip() == serial:
                            return f'/dev/{blk.name}'
                    except OSError:
                        pass
        time.sleep(1)
    raise TimeoutError(dev)


def _mount_ro(dev: str, dest: Path) -> None:
    """Mount read-only with a hard timeout. Never start a mount if the device is gone."""
    import shlex
    import subprocess
    from ker.devices import block_device_live
    if not block_device_live(dev):
        raise RuntimeError(f'mount failed: {dev}')
    dest.mkdir(parents=True, exist_ok=True)
    # timeout --kill-after sends SIGKILL if SIGTERM cannot unstick the helper.
    # A kernel D-state I/O may still outlive this; callers must skip dead devices
    # first so we never issue mount against a disappearing path.
    # argv only: a shell would be /bin/sh, which is not allowlisted while media_ok=0.
    r = subprocess.run(
        ['timeout', '--kill-after=2', '5', 'mount',
         '-o', 'ro,nosuid,nodev,noexec', dev, str(dest)],
        capture_output=True, text=True, timeout=8,
    )
    if r.returncode != 0:
        raise RuntimeError(f'mount failed: {dev}')


def _umount(dest: Path) -> None:
    import subprocess
    subprocess.run(['timeout', '--kill-after=1', '3', 'umount', str(dest)],
                   capture_output=True, timeout=5)


def verify_each(st: dict, devices: list[dict] | None = None, *, proof_only: bool = False) -> dict:
    """Verify each present medium on its own.

    Missing devices are reported and not mounted. A failed signature or hash
    fails that medium only. proof_only accepts a signed bundle that cannot be
    decrypted yet (admin proof while root.pem is absent). Otherwise a medium
    that still needs root.pem is a failure: the permission is not established.
    """
    from ker.devices import resolve_media_path
    keys = _keys_from_state(st)
    media = list(devices if devices is not None else (st.get('media') or []))
    missing: list[dict] = []
    present: list[tuple[dict, str]] = []
    for medium in media:
        if not isinstance(medium, dict):
            missing.append({'path': str(medium)})
            continue
        live = resolve_media_path(medium)
        if not live:
            missing.append(medium)
        else:
            present.append((medium, live))
    mounts: list[Path] = []
    root_pem = None
    failed: list[dict] = []
    results: list[dict] = []
    try:
        mounted: list[tuple[dict, Path]] = []
        for i, (medium, live) in enumerate(present):
            dest = MOUNT_ROOT / f'e{i}'
            _umount(dest)
            if not resolve_media_path(medium):
                missing.append(medium)
                continue
            try:
                _mount_ro(live, dest)
            except Exception as e:
                failed.append(medium)
                results.append({'path': medium.get('path'), 'ok': False, 'error': str(e)})
                continue
            mounts.append(dest)
            mounted.append((medium, dest))
            if (dest / 'root.pem').is_file():
                root_pem = (dest / 'root.pem').read_bytes()
        for medium, dest in mounted:
            try:
                info = verify_directory(dest, keys, root_pem=root_pem)
            except Exception as e:
                failed.append(medium)
                results.append({
                    'path': medium.get('path'), 'ok': False,
                    'error': f'{type(e).__name__}: {e}',
                })
                continue
            if info.get('need_root') and not proof_only:
                failed.append(medium)
                results.append({'path': medium.get('path'), 'ok': False, 'error': 'ROOT_MEDIA_MISSING'})
                continue
            results.append({
                'path': medium.get('path'), 'ok': True,
                'media_id': (info.get('bundle') or {}).get('media_id'),
                'proof_only': bool(info.get('need_root')),
            })
        return {'ok': not missing and not failed, 'missing': missing, 'failed': failed, 'results': results}
    finally:
        for dest in mounts:
            _umount(dest)


def verify_all(st: dict, devices: list[dict] | None = None) -> dict:
    """Mount and verify every recorded medium. Missing devices fail immediately.

    This is for flipping media_ok back to allow. Callers that only need to
    deny must not call this: check presence first and update BPF maps.
    """
    from ker.devices import required_media_presence
    keys = _keys_from_state(st)
    media = devices or st.get('media') or []
    all_present, missing = required_media_presence(media)
    if not all_present:
        raise SignError('MEDIA_MISSING:' + ','.join(missing))
    mounts = []
    root_pem = None
    try:
        for i, m in enumerate(media):
            dest = MOUNT_ROOT / f'm{i}'
            _umount(dest)
            # Re-check immediately before each mount; a stick can vanish mid-loop.
            if not all_present:
                raise SignError('MEDIA_MISSING:' + m.get('path', ''))
            from ker.devices import resolve_media_path
            live = resolve_media_path(m)
            if not live:
                raise SignError('MEDIA_MISSING:' + (m.get('path') or ''))
            _mount_ro(live, dest)
            mounts.append(dest)
            if (dest / 'root.pem').is_file():
                root_pem = (dest / 'root.pem').read_bytes()
        if root_pem is None:
            raise SignError('ROOT_MEDIA_MISSING')
        results = []
        for dest, m in zip(mounts, media):
            info = verify_directory(dest, keys, root_pem=root_pem)
            results.append({'path': m['path'], 'ok': True, 'media_id': info['bundle'].get('media_id')})
        return {'ok': True, 'results': results}
    finally:
        for dest in mounts:
            _umount(dest)


def run_replug_tests(lang: str, st: dict, assume: bool = False) -> None:
    media = list(st.get('media') or [])
    if not media:
        raise SystemExit('no media in state')
    if assume:
        report = verify_all(st)
        if not report['ok']:
            print(t(lang, 'fail'), report)
            raise SystemExit(2)
        print(t(lang, 'ok'), 'media verification (assumed already inserted)')
        return
    for m in media:
        print(t(lang, 'replug_prompt', name=f"{m['path']} ({', '.join(m['keys'])})"))
        new_path = wait_replug(m['path'])
        m['path'] = new_path
        # save updated path
        from ker.state import save_state
        save_state(st)
    report = verify_all(st)
    if not report['ok']:
        print(t(lang, 'fail'))
        raise SystemExit(2)
    print(t(lang, 'ok'))
