"""Key rotation: rewrite media, atomically cut over, fully sync children."""
from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

from ker.bundle import cert_sha256, make_bundle, pack_media_files
from ker.cluster import _keys, _trust_blob, assert_not_fail_closed, queue_command
from ker.crypto import build_permission_pem, build_root_pem, encrypt_key
from ker.custom import validate_custom
from ker.media import write_device
from ker.paths import PRIVATE_DIR, TRUST_DIR, VAR
from ker.sign import generate_signing_keys
from ker.state import save_state, state as load_state
from ker.testmode import run_replug_tests, verify_all
from ker.upgrade import snapshot
from ker.vault import VaultError, store_unwrap


class RotateError(RuntimeError):
    pass


def _hash(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def rotate(*, assume_replug: bool = False, lang: str = 'zh-CN') -> dict:
    st = load_state()
    if not st.get('initialized') or st.get('role') != 'master':
        raise RotateError('rotation is only allowed on an initialized master')
    assert_not_fail_closed(st)
    try:
        report = verify_all(st)
    except Exception as e:
        raise RotateError(f'media must all verify before rotation: {e}') from e
    if not report.get('ok'):
        raise RotateError('media must all verify before rotation')

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

    selected = list(st.get('permissions') or [])
    custom = [validate_custom(c) if not c.get('key') or True else c for c in (st.get('custom') or [])]
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
    encrypted = {n: (raw if n == 'root.pem' else encrypt_key(raw, root_plain)) for n, raw in plains.items()}

    media = list(st.get('media') or [])
    cluster_id = st['cluster_id']
    root_media_id = st.get('root_media_id')
    required = [{'media_id': m['media_id'], 'keys': list(m['keys']), 'role': m.get('role')} for m in media]
    results = []
    iso_paths = []
    for m in media:
        payload = {}
        key_meta = {}
        for name in m['keys']:
            blob = encrypted[name]
            payload[name] = blob
            key_meta[name] = {'sha256': _hash(blob), 'size': len(blob), 'encrypted': name != 'root.pem'}
        bundle = make_bundle({
            'bundle_id': str(uuid.uuid4()),
            'cluster_id': cluster_id,
            'media_id': m['media_id'],
            'role': m.get('role') or 'keys',
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
        if m.get('kind') in ('dvd-r', 'optical'):
            iso_out = VAR / f"{m['media_id']}.iso"
            iso_paths.append(str(iso_out))
        write_device(m['path'], m['kind'], files, iso_out=iso_out)
        results.append({'path': m['path'], 'kind': m['kind'], 'media_id': m['media_id'], 'keys': m['keys']})

    # Atomic swap of trust + private signing material
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
    st['iso'] = iso_paths
    st['vault'] = vault
    st['key_generation'] = new_gen
    st['mode'] = 'test'  # rotation always returns to test mode; enforcement must be reconfirmed
    st['kernel_enforcement'] = False
    save_state(st)

    # Children must fully sync; offline ones fail closed until they do.
    queue_command(None, {
        'type': 'cutover',
        'key_generation': new_gen,
        'policy': {
            'permissions': selected,
            'custom': custom,
            'independent_child_media': bool(st.get('independent_child_media', False)),
            'mode': 'test',
            'kernel_enforcement': False,
            'gpg_fingerprint': new_sign['gpg_fingerprint'],
            'kernel_cert_sha256': new_sign['kernel_cert_sha256'],
            'key_generation': new_gen,
            'cluster_id': cluster_id,
        },
        'trust': _trust_blob(),
    })
    kids = list(st.get('children') or [])
    for c in kids:
        if not c.get('online'):
            c['fail_closed_pending'] = True
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
    }
