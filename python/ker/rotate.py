"""Key rotation and revocation of a missing medium."""
from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

from ker.bundle import cert_sha256, make_bundle, pack_media_files
from ker.catalog import BUILTIN_IDS
from ker.cluster import _trust_blob, assert_not_fail_closed, queue_command
from ker.crypto import build_permission_pem, build_root_pem, encrypt_key
from ker.custom import validate_custom
from ker.enforce import medium_is_root, runtime_presence
from ker.media import write_device
from ker.paths import PRIVATE_DIR, TRUST_DIR, VAR
from ker.sign import generate_signing_keys
from ker.state import save_state, state as load_state
from ker.testmode import run_replug_tests, verify_all, verify_each
from ker.upgrade import snapshot
from ker.vault import VaultError, store_unwrap


class RotateError(RuntimeError):
    pass


def _hash(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _custom_for_rotate(items: list | None) -> list:
    """Re-validate entries that have not been normalized yet.

    Stored custom rules already carry a key name; they are kept as recorded.
    The previous condition was `not c.get('key') or True`, which is always
    true and hid the intended check.
    """
    out = []
    for item in items or []:
        if not item.get('key'):
            out.append(validate_custom(item))
        else:
            out.append(item)
    return out


def _replacement_for(medium: dict, replacements: dict | None) -> dict | None:
    replacements = replacements or {}
    for key in (medium.get('media_id'), medium.get('path')):
        if key and key in replacements:
            spec = replacements[key] or {}
            if not spec.get('path'):
                raise RotateError('replacement for %s needs a device path' % key)
            return spec
    return None


def _plan_media(st: dict, present: list[dict], missing: list[dict],
                replacements: dict | None, drop_missing: bool) -> tuple[list[dict], list, list]:
    """Build the media set to rewrite, dropping or replacing what is gone."""
    selected = list(st.get('permissions') or [])
    custom = _custom_for_rotate(st.get('custom') or [])
    planned = [dict(m) for m in present]
    for medium in missing:
        repl = _replacement_for(medium, replacements)
        if repl:
            nxt = dict(medium)
            nxt['path'] = repl['path']
            nxt['kind'] = repl.get('kind') or medium.get('kind') or 'disk'
            planned.append(nxt)
            continue
        if medium_is_root(medium):
            raise RotateError('lost root medium requires a replacement device')
        if not drop_missing:
            label = medium.get('path') or medium.get('media_id') or '(unknown)'
            raise RotateError(
                'lost medium %s: pass a replacement device or drop it explicitly' % label
            )
        kept_keys: set[str] = set()
        for other in planned:
            kept_keys.update(other.get('keys') or [])
        for name in medium.get('keys') or []:
            if name in kept_keys or name in ('root.pem', 'admin.pem'):
                continue
            stem = name[:-4] if str(name).endswith('.pem') else str(name)
            if stem in selected:
                selected = [p for p in selected if p != stem]
            custom = [c for c in custom if c.get('key') != name]
    if not any(medium_is_root(m) for m in planned):
        raise RotateError('rotation requires a root medium')
    for perm in selected:
        if perm not in BUILTIN_IDS:
            raise RotateError('unknown permission on rotate: %s' % perm)
    return planned, selected, custom


def _require_proof(st: dict, present: list[dict], missing: list[dict]) -> None:
    """Lost-media rotation needs a remaining root medium, or admin if root is the one lost."""
    root_present = [m for m in present if medium_is_root(m)]
    admin_present = [
        m for m in present
        if 'admin.pem' in (m.get('keys') or []) or (m.get('role') == 'admin')
    ]
    root_missing = [m for m in missing if medium_is_root(m)]
    if root_missing:
        if not admin_present:
            raise RotateError('lost root medium requires a verified admin medium as proof')
        proof = admin_present
    else:
        if not root_present:
            raise RotateError('rotation requires the root medium, or the admin medium when root is lost')
        proof = root_present
    report = verify_each(st, devices=proof, proof_only=True)
    if not report.get('ok'):
        raise RotateError('remaining root or admin medium failed verification')


def _apply_kernel_mode(st: dict, enabled: bool) -> None:
    """Make loaded BPF maps and enforcer units match enabled.

    Does not load BPF. If a pin is already present, its enforcement flag is
    updated so a watcher that has stopped cannot leave enforcement=1 behind.
    """
    try:
        from ker.enforce import EnforceError, PIN_DIR, may_load_bpf, sync_enforcer_units, update_maps
    except Exception:
        return
    try:
        sync_enforcer_units(bool(enabled))
    except Exception:
        pass
    try:
        if not may_load_bpf() or not PIN_DIR.exists():
            return
        update_maps(
            enforcement=bool(enabled),
            media_ok=True,
            permissions=st.get('permissions') or [],
        )
    except EnforceError:
        pass


def rotate(*, assume_replug: bool = False, lang: str = 'zh-CN',
           allow_missing: bool = False, replacements: dict | None = None,
           drop_missing: bool = False) -> dict:
    st = load_state()
    if not st.get('initialized') or st.get('role') != 'master':
        raise RotateError('rotation is only allowed on an initialized master')
    assert_not_fail_closed(st)

    _req_present, _req_missing, present, missing = runtime_presence(st)
    if missing and not allow_missing:
        try:
            report = verify_all(st)
        except Exception as e:
            raise RotateError(f'media must all verify before rotation: {e}') from e
        if not report.get('ok'):
            raise RotateError('media must all verify before rotation')
        raise RotateError('media must all verify before rotation')
    if not missing:
        try:
            report = verify_all(st)
        except Exception as e:
            raise RotateError(f'media must all verify before rotation: {e}') from e
        if not report.get('ok'):
            raise RotateError('media must all verify before rotation')
        planned, selected, custom = _plan_media(st, list(st.get('media') or []), [], None, False)
    else:
        _require_proof(st, present, missing)
        planned, selected, custom = _plan_media(st, present, missing, replacements, drop_missing)

    previous_enforce = bool(st.get('kernel_enforcement'))
    # Drop enforcement for real before rewriting media, including a map that
    # was left at enforcement=1 after an earlier state-only update.
    _apply_kernel_mode(st, False)

    try:
        return _rotate_body(
            st, planned, selected, custom,
            previous_enforce=previous_enforce,
            assume_replug=assume_replug, lang=lang,
        )
    except Exception:
        st['kernel_enforcement'] = previous_enforce
        st['mode'] = 'enforce' if previous_enforce else (st.get('mode') or 'test')
        try:
            _apply_kernel_mode(st, previous_enforce)
        except Exception:
            pass
        raise


def _rotate_body(st: dict, planned: list[dict], selected: list, custom: list, *,
                 previous_enforce: bool, assume_replug: bool, lang: str) -> dict:
    snap = snapshot('rotate')
    old_gen = int(st.get('key_generation') or 1)
    staging_gpg = PRIVATE_DIR / 'gnupg.next'
    staging_trust = TRUST_DIR.parent / 'trust.next'
    staging_rsa = PRIVATE_DIR / 'kernel-signing.key.next'
    staging_pub = staging_trust / 'kernel-cert.pem'
    if staging_trust.exists():
        shutil.rmtree(staging_trust)
    staging_trust.mkdir(parents=True, exist_ok=True)

    new_sign = generate_signing_keys(
        homedir=staging_gpg,
        rsa_key=staging_rsa,
        rsa_pub=staging_pub,
        pubring=staging_trust / 'media.gpg',
    )
    new_sign['kernel_cert_sha256'] = cert_sha256(Path(new_sign['rsa_pub']))

    root_plain = build_root_pem()
    try:
        store_unwrap(root_plain)
        vault = 'keyring'
    except VaultError:
        vault = st.get('vault') or 'memory-only'

    plains: dict[str, bytes] = {'root.pem': root_plain}
    for name in selected:
        plains[f'{name}.pem'] = build_permission_pem()
    for item in custom:
        plains[item['key']] = build_permission_pem()
    plains['admin.pem'] = build_permission_pem()
    # Keep boot.pem if any planned medium still carries it, even when boot
    # is not a runtime LSM bit.
    needed = {'root.pem', 'admin.pem'}
    for medium in planned:
        needed.update(medium.get('keys') or [])
    for name in list(plains):
        if name not in needed and name not in ('root.pem', 'admin.pem'):
            plains.pop(name, None)
    for name in needed:
        if name not in plains and name not in ('root.pem', 'admin.pem'):
            plains[name] = build_permission_pem()
    encrypted = {n: (raw if n == 'root.pem' else encrypt_key(raw, root_plain)) for n, raw in plains.items()}

    cluster_id = st['cluster_id']
    root_media_id = None
    for medium in planned:
        if medium_is_root(medium):
            root_media_id = medium.get('media_id')
            break
    required = [
        {'media_id': m.get('media_id'), 'keys': list(m.get('keys') or []), 'role': m.get('role')}
        for m in planned
    ]
    results = []
    iso_paths = []
    for medium in planned:
        payload = {}
        key_meta = {}
        for name in medium.get('keys') or []:
            if name not in encrypted:
                raise RotateError('no key material for %s' % name)
            blob = encrypted[name]
            payload[name] = blob
            key_meta[name] = {'sha256': _hash(blob), 'size': len(blob), 'encrypted': name != 'root.pem'}
        bundle = make_bundle({
            'bundle_id': str(uuid.uuid4()),
            'cluster_id': cluster_id,
            'media_id': medium.get('media_id') or str(uuid.uuid4()),
            'role': medium.get('role') or 'keys',
            'gpg_fingerprint': new_sign['gpg_fingerprint'],
            'kernel_cert_sha256': new_sign['kernel_cert_sha256'],
            'keys': key_meta,
            'permissions': selected,
            'custom': custom,
            'required_media': required,
            'root_media_id': root_media_id,
            'independent_child_media': bool(st.get('independent_child_media', False)),
        })
        files = pack_media_files(bundle, payload, new_sign)
        iso_out = None
        if medium.get('kind') in ('dvd-r', 'optical'):
            iso_out = VAR / f"{medium.get('media_id') or 'media'}.iso"
            iso_paths.append(str(iso_out))
        write_device(medium['path'], medium['kind'], files, iso_out=iso_out)
        results.append({
            'path': medium['path'], 'kind': medium['kind'],
            'media_id': medium.get('media_id'), 'keys': list(medium.get('keys') or []),
            'role': medium.get('role'),
        })

    retired = PRIVATE_DIR / 'retired' / f'gen{old_gen}'
    retired.mkdir(parents=True, exist_ok=True)
    for src, name in (
        (PRIVATE_DIR / 'gnupg', 'gnupg'),
        (PRIVATE_DIR / 'kernel-signing.key', 'kernel-signing.key'),
        (TRUST_DIR / 'media.gpg', 'media.gpg'),
        (TRUST_DIR / 'kernel-cert.pem', 'kernel-cert.pem'),
    ):
        if src.exists():
            dest = retired / name
            if dest.exists():
                shutil.rmtree(dest) if dest.is_dir() else dest.unlink()
            shutil.move(str(src), str(dest))
    if TRUST_DIR.exists():
        shutil.rmtree(TRUST_DIR)
    shutil.move(str(staging_trust), str(TRUST_DIR))
    shutil.move(str(staging_gpg), str(PRIVATE_DIR / 'gnupg'))
    shutil.move(str(staging_rsa), str(PRIVATE_DIR / 'kernel-signing.key'))
    os.chmod(PRIVATE_DIR / 'kernel-signing.key', 0o400)

    new_gen = old_gen + 1
    st['gpg_fingerprint'] = new_sign['gpg_fingerprint']
    st['kernel_cert_sha256'] = new_sign['kernel_cert_sha256']
    st['media'] = results
    st['permissions'] = selected
    st['custom'] = custom
    st['root_media_id'] = root_media_id
    st['iso'] = iso_paths
    st['vault'] = vault
    st['key_generation'] = new_gen
    # Restore the mode that was in effect. The rewrite window above really
    # did clear enforcement; this puts maps and units back in step with state.
    st['kernel_enforcement'] = previous_enforce
    st['mode'] = 'enforce' if previous_enforce else 'test'
    save_state(st)
    _apply_kernel_mode(st, previous_enforce)

    queue_command(None, {
        'type': 'cutover',
        'key_generation': new_gen,
        'policy': {
            'permissions': selected,
            'custom': custom,
            'independent_child_media': bool(st.get('independent_child_media', False)),
            'mode': st['mode'],
            'kernel_enforcement': previous_enforce,
            'gpg_fingerprint': new_sign['gpg_fingerprint'],
            'kernel_cert_sha256': new_sign['kernel_cert_sha256'],
            'key_generation': new_gen,
            'cluster_id': cluster_id,
        },
        'trust': _trust_blob(),
    })
    kids = list(st.get('children') or [])
    for child in kids:
        if not child.get('online'):
            child['fail_closed_pending'] = True
    st['children'] = kids
    st.setdefault('compat', {})['needs_child_sync'] = bool(kids)
    save_state(st)

    run_replug_tests(lang, st, assume=assume_replug)
    try:
        from ker.hooks import refresh_boot_initramfs
        refresh_boot_initramfs()
    except Exception:
        pass
    return {
        'ok': True,
        'key_generation': new_gen,
        'snapshot': str(snap),
        'media': results,
        'children': len(kids),
        'kernel_enforcement': previous_enforce,
        'revoked': True,
    }
