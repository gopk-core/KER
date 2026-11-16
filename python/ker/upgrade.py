"""Manual upgrade: snapshot, migrate, take over an older package, rollback.

KER never checks for or installs updates on its own. A newer package is
installed by the administrator (dpkg/rpm/apk or `ker upgrade <file>`). The
new package must take over existing keys, media, policy, and mode without
rewriting sealed media or enabling kernel enforcement.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from ker.compat import (
    CRYPTO_EPOCH,
    MEDIA_SCHEMA,
    PACKAGE_VERSION,
    STATE_SCHEMA,
    manifest,
    takeover_errors,
    inspect_state,
    write_manifest,
)
from ker.features import added_features, apply_replacements, pending_replacements, stamp_known
from ker.migrations import REGISTRY, pending as pending_migrations
from ker.paths import CONFIG_PATH, PRIVATE_DIR, SNAPSHOT_DIR, STATE_PATH, TRUST_DIR, UPGRADE_DIR, VAR
from ker.state import ensure_dirs, save_state, state as load_state


class UpgradeError(RuntimeError):
    pass


KEEP_SNAPSHOTS = 5


def stamp_new_install(st: dict) -> dict:
    """Attach current contract fields to a freshly initialized state."""
    st = dict(st)
    st['package_version'] = PACKAGE_VERSION
    st['state_schema'] = STATE_SCHEMA
    st['media_schema'] = st.get('media_schema') or MEDIA_SCHEMA
    st['crypto_epoch'] = st.get('crypto_epoch') or CRYPTO_EPOCH
    st.setdefault('feature_replacements', {})
    st['migrations_applied'] = [m.ID for m in REGISTRY if m.TARGET_SCHEMA <= STATE_SCHEMA]
    st = stamp_known(st)
    st['upgrade'] = {
        'last_from': None,
        'last_to': PACKAGE_VERSION,
        'last_at': _now(),
        'last_result': 'installed',
    }
    return st


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_reason(reason: str) -> str:
    out = ''.join(c if c.isalnum() or c in '-_.' else '-' for c in (reason or 'upgrade'))
    return out[:40] or 'upgrade'



def _ignore_ephemeral(directory: str, names: list[str]) -> list[str]:
    """Skip gpg-agent sockets and other non-regular nodes when snapshotting."""
    skip = []
    for name in names:
        path = Path(directory) / name
        try:
            mode = path.lstat().st_mode
        except OSError:
            skip.append(name)
            continue
        if stat.S_ISSOCK(mode) or stat.S_ISFIFO(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
            skip.append(name)
    return skip


def _copytree(src: Path, dst: Path) -> None:
    shutil.copytree(
        src, dst, dirs_exist_ok=True,
        ignore=_ignore_ephemeral, ignore_dangling_symlinks=True,
    )


def snapshot(reason: str = 'upgrade') -> Path:
    """Copy host trust/state/private material. Never copies removable media."""
    ensure_dirs()
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(UPGRADE_DIR, 0o700)
    os.chmod(SNAPSHOT_DIR, 0o700)
    name = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '-' + _safe_reason(reason)
    dest = SNAPSHOT_DIR / name
    tmp = SNAPSHOT_DIR / ('.tmp-' + name)
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(mode=0o700)
    if STATE_PATH.exists():
        shutil.copy2(STATE_PATH, tmp / 'state.json')
    if CONFIG_PATH.exists():
        shutil.copy2(CONFIG_PATH, tmp / 'config.json')
    if TRUST_DIR.exists():
        _copytree(TRUST_DIR, tmp / 'trust')
    if PRIVATE_DIR.exists():
        _copytree(PRIVATE_DIR, tmp / 'private')
    meta = {'reason': reason, 'created': _now(), 'package_version': PACKAGE_VERSION}
    (tmp / 'meta.json').write_text(json.dumps(meta, indent=2) + '\n', encoding='utf-8')
    os.chmod(tmp, 0o700)
    tmp.rename(dest)
    _prune_snapshots()
    return dest


def _prune_snapshots() -> None:
    snaps = sorted((p for p in SNAPSHOT_DIR.iterdir() if p.is_dir() and not p.name.startswith('.')), key=lambda p: p.name)
    for old in snaps[:-KEEP_SNAPSHOTS]:
        shutil.rmtree(old, ignore_errors=True)


def latest_snapshot() -> Path | None:
    if not SNAPSHOT_DIR.exists():
        return None
    snaps = sorted((p for p in SNAPSHOT_DIR.iterdir() if p.is_dir() and not p.name.startswith('.')), key=lambda p: p.name)
    return snaps[-1] if snaps else None


def restore(path: Path | None = None) -> Path:
    path = Path(path) if path else latest_snapshot()
    if path is None or not path.is_dir():
        raise UpgradeError('no upgrade snapshot to restore')
    if (path / 'state.json').exists():
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path / 'state.json', STATE_PATH)
    if (path / 'config.json').exists():
        shutil.copy2(path / 'config.json', CONFIG_PATH)
    if (path / 'trust').is_dir():
        if TRUST_DIR.exists():
            shutil.rmtree(TRUST_DIR)
        _copytree(path / 'trust', TRUST_DIR)
    if (path / 'private').is_dir():
        if PRIVATE_DIR.exists():
            shutil.rmtree(PRIVATE_DIR)
        _copytree(path / 'private', PRIVATE_DIR)
    return path


def plan(st: dict | None = None, target: dict | None = None) -> dict:
    st = load_state() if st is None else st
    target = target or manifest()
    info = inspect_state(st)
    migrations = []
    if info['initialized']:
        migrations = [
            {'id': m.ID, 'target_schema': m.TARGET_SCHEMA}
            for m in pending_migrations(st, up_to=int(target['state_schema']))
        ]
    replacements = pending_replacements(st) if info['initialized'] else []
    added = added_features(st) if info['initialized'] else []
    pkg_from = info['package_version']
    pkg_to = target['package_version']
    needed = bool(migrations or replacements or (info['initialized'] and pkg_from != pkg_to))
    return {
        'initialized': info['initialized'],
        'needed': needed,
        'from_package': pkg_from,
        'to_package': pkg_to,
        'from_schema': info['state_schema'],
        'to_schema': target['state_schema'],
        'migrations': migrations,
        'replacements': replacements,
        'added_features': added,
        'mode': info['mode'],
        'kernel_enforcement': info['kernel_enforcement'],
        'enforcement_will_change': False,
        'no_auto_update': True,
    }


def preflight(st: dict | None = None, target: dict | None = None) -> dict:
    st = load_state() if st is None else st
    target = target or manifest()
    errors = takeover_errors(st, target)
    warnings: list[str] = []
    if st.get('initialized') and st.get('kernel_enforcement'):
        warnings.append('kernel enforcement is on; it will stay on, and sealed media will not be rewritten')
    if st.get('role') == 'master' and st.get('children'):
        warnings.append('after a schema or feature change, child nodes must sync before they accept new policy')
    try:
        usage = shutil.disk_usage(str(VAR if VAR.exists() else VAR.parent))
        if usage.free < 2 * 1024 * 1024:
            errors.append('not enough free space for an upgrade snapshot')
    except OSError:
        warnings.append('could not check free space for snapshots')
    return {
        'ok': not errors,
        'errors': errors,
        'warnings': warnings,
        'plan': plan(st, target),
        'manifest': {k: target[k] for k in target if k != 'features'},
    }



def _sync_enforcer_units(st: dict) -> None:
    """Enable or disable boot-restore units to match kernel_enforcement.

    Does not turn enforcement on or off, and does not load BPF itself.
    """
    try:
        from ker.enforce import sync_enforcer_units
        sync_enforcer_units(bool(st.get('kernel_enforcement')))
    except Exception:
        pass


def migrate(*, reason: str = 'manual', from_package: bool = False) -> dict:
    ensure_dirs()
    st = load_state()
    if not st.get('initialized'):
        return {'ok': True, 'skipped': True, 'reason': 'not_initialized'}
    pf = preflight(st)
    if not pf['ok']:
        raise UpgradeError('; '.join(pf['errors']))
    pl = pf['plan']
    # Reconcile watcher units with the persisted flag even when no migration
    # is needed (0.1+ boot restore after a package takeover).
    _sync_enforcer_units(st)
    if not pl['needed']:
        return {'ok': True, 'skipped': True, 'reason': 'already_current', 'plan': pl}
    old_ver = pl['from_package']
    snap = snapshot(reason if reason != 'manual' else ('package' if from_package else 'migrate'))
    ctx = {
        'package_version': PACKAGE_VERSION,
        'media_schema': MEDIA_SCHEMA,
        'crypto_epoch': CRYPTO_EPOCH,
        'snapshot': str(snap),
        'reason': reason,
    }
    try:
        for m in pending_migrations(st):
            st = m.apply(st, ctx)
            applied = list(st.get('migrations_applied') or [])
            if m.ID not in applied:
                applied.append(m.ID)
            st['migrations_applied'] = applied
            st['state_schema'] = max(int(st.get('state_schema') or 0), m.TARGET_SCHEMA)
            if hasattr(m, 'verify'):
                m.verify(st, ctx)
        st, changes = apply_replacements(st)
        new_feats = added_features(st)
        st = stamp_known(st)
        st['package_version'] = PACKAGE_VERSION
        st['media_schema'] = st.get('media_schema') or MEDIA_SCHEMA
        st['crypto_epoch'] = st.get('crypto_epoch') or CRYPTO_EPOCH
        if st.get('role') == 'master' and st.get('children') and (pl['migrations'] or changes or new_feats):
            compat = dict(st.get('compat') or {})
            compat['needs_child_sync'] = True
            st['compat'] = compat
        st['upgrade'] = {
            'last_from': old_ver,
            'last_to': PACKAGE_VERSION,
            'last_at': _now(),
            'last_result': 'ok',
            'snapshot': snap.name,
            'migrations': [m['id'] for m in pl['migrations']],
            'replacements': changes,
            'added_features': new_feats,
            'from_package_install': from_package,
        }
        # mode and kernel_enforcement are intentionally left untouched
        save_state(st)
        _sync_enforcer_units(st)
    except Exception as e:
        restore(snap)
        raise UpgradeError(f'upgrade failed and was rolled back: {e}') from e
    return {
        'ok': True,
        'skipped': False,
        'from': old_ver,
        'to': PACKAGE_VERSION,
        'snapshot': str(snap),
        'migrations': [m['id'] for m in pl['migrations']],
        'replacements': st['upgrade']['replacements'],
        'added_features': st['upgrade']['added_features'],
        'mode': st.get('mode'),
        'kernel_enforcement': st.get('kernel_enforcement'),
        'plan': plan(st),
    }


def rollback() -> dict:
    path = latest_snapshot()
    if path is None:
        raise UpgradeError('no upgrade snapshot to restore')
    restore(path)
    return {'ok': True, 'snapshot': str(path)}


def verify_package_file(path: Path, trust_package: bool = False) -> list[str]:
    """Optional detached signature: <file>.sig verified with trust/release.gpg."""
    from ker.paths import TRUST_DIR
    warnings: list[str] = []
    path = Path(path)
    sig = Path(str(path) + '.sig')
    keyring = TRUST_DIR / 'release.gpg'
    shipped = Path('/usr/lib/ker/release-keys/release.gpg')
    key = keyring if keyring.exists() else (shipped if shipped.exists() else None)
    if sig.exists() and key is not None:
        r = subprocess.run(
            ['gpgv', '--keyring', str(key), str(sig), str(path)],
            capture_output=True, text=True,
        )
        if r.returncode:
            raise UpgradeError('PACKAGE_SIGNATURE_REJECTED')
        return warnings
    if sig.exists() and key is None:
        raise UpgradeError('package signature present but no release.gpg trust anchor')
    msg = 'package is unsigned; pass --trust-package for a locally built or otherwise verified file'
    if not trust_package:
        raise UpgradeError(msg)
    warnings.append(msg)
    return warnings


def install_package(path: Path, trust_package: bool = False) -> dict:
    path = Path(path).resolve()
    if not path.is_file():
        raise UpgradeError(f'package not found: {path}')
    warnings = verify_package_file(path, trust_package=trust_package)
    pf = preflight()
    if not pf['ok']:
        raise UpgradeError('; '.join(pf['errors']))
    st = load_state()
    snap = None
    if st.get('initialized'):
        snap = snapshot('pre-package')
    env = os.environ.copy()
    env['KER_UPGRADE_IN_PROGRESS'] = '1'
    name = path.name.lower()
    if name.endswith('.deb'):
        cmd = ['dpkg', '-i', str(path)]
    elif name.endswith('.rpm'):
        cmd = ['rpm', '-Uvh', str(path)]
    elif name.endswith('.apk'):
        cmd = ['apk', 'add', '--allow-untrusted', str(path)] if trust_package else ['apk', 'add', str(path)]
    elif name.endswith('.pkg.tar.zst') or name.endswith('.pkg.tar.xz'):
        cmd = ['pacman', '-U', '--noconfirm', str(path)]
    else:
        raise UpgradeError(f'unsupported package format: {path.name}')
    r = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if r.returncode:
        if snap is not None:
            try:
                restore(snap)
            except Exception:
                pass
        raise UpgradeError((r.stderr or r.stdout or 'package install failed')[-4000:])
    # postinst should have migrated; run again in case the package had no script
    result = migrate(reason='package', from_package=True)
    result['package'] = str(path)
    result['warnings'] = warnings + pf['warnings']
    result['installer'] = cmd[0]
    return result


def format_plan(pl: dict, lang: str = 'zh-CN') -> str:
    from ker.i18n import t
    if not pl['initialized']:
        return t(lang, 'upgrade_not_init')
    if not pl['needed']:
        return t(lang, 'upgrade_already', version=pl['to_package'], schema=pl['to_schema'])
    lines = [
        t(lang, 'upgrade_need_migrate',
          src=pl['from_package'] or '?',
          dst=pl['to_package'],
          from_schema=pl['from_schema'] if pl['from_schema'] is not None else 0,
          to_schema=pl['to_schema']),
        t(lang, 'upgrade_enforcement_kept',
          mode=pl.get('mode') or 'test',
          enforcement='on' if pl.get('kernel_enforcement') else 'off'),
    ]
    if pl['migrations']:
        ids = ', '.join(m['id'] for m in pl['migrations'])
        lines.append(t(lang, 'upgrade_migrations', ids=ids))
    if pl['added_features']:
        lines.append(t(lang, 'upgrade_added', ids=', '.join(pl['added_features'])))
    if pl['replacements']:
        bits = [f"{r['old']}->{r['new']}" for r in pl['replacements']]
        lines.append(t(lang, 'upgrade_replacements', ids=', '.join(bits)))
    lines.append(t(lang, 'upgrade_no_auto'))
    return '\n'.join(lines)
