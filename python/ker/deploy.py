"""Create keys, sign, and write media. Used by the first-run wizard and rotation."""
from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path

from ker import KEY_SIZE
from ker.bundle import cert_sha256, make_bundle, pack_media_files
from ker.catalog import BUILTIN_IDS
from ker.crypto import build_permission_pem, build_root_pem, encrypt_key
from ker.custom import validate_custom
from ker.media import sha256_file, write_device
from ker.paths import CONFIG_PATH, PRIVATE_DIR, TRUST_DIR, VAR
from ker.sign import generate_signing_keys
from ker.state import ensure_dirs, save_json, save_state
from ker.upgrade import stamp_new_install
from ker.vault import VaultError, store_unwrap


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def deploy(spec: dict) -> dict:
    """
    spec: lang, permissions, custom, media (list of {path, kind, keys, role}),
          optional admin media, generate_keys True
    """
    ensure_dirs()
    keys = generate_signing_keys()
    keys['kernel_cert_sha256'] = cert_sha256(Path(keys['rsa_pub']))
    cluster_id = str(uuid.uuid4())
    root_plain = build_root_pem()
    PRIVATE_DIR.mkdir(parents=True, exist_ok=True)
    # Do not leave plaintext permission keys on disk. root.pem plaintext is needed
    # only until it is written and hashed; keep a restricted copy for rotation backups?
    # Scheme: plaintext unwrap goes to kernel keyring, not a directory root can edit.
    try:
        store_unwrap(root_plain)
        vault = 'keyring'
    except VaultError:
        vault = 'memory-only'

    selected = list(spec.get('permissions') or [])
    for p in selected:
        if p not in BUILTIN_IDS:
            raise ValueError(f'unknown permission: {p}')
    custom = [validate_custom(c) for c in (spec.get('custom') or [])]

    plains: dict[str, bytes] = {'root.pem': root_plain}
    for name in selected:
        plains[f'{name}.pem'] = build_permission_pem()
    for item in custom:
        plains[item['key']] = build_permission_pem()
    admin_name = 'admin.pem'
    plains[admin_name] = build_permission_pem()

    encrypted = {n: (raw if n == 'root.pem' else encrypt_key(raw, root_plain)) for n, raw in plains.items()}
    media_specs = list(spec['media'])
    # ids
    for m in media_specs:
        m['media_id'] = m.get('media_id') or str(uuid.uuid4())
    root_media_id = None
    for m in media_specs:
        if 'root.pem' in m['keys']:
            root_media_id = m['media_id']
            m['role'] = 'root' if m.get('role') != 'admin' else 'root+admin'
    if root_media_id is None:
        raise ValueError('root.pem must be assigned to one medium')

    required = [{'media_id': m['media_id'], 'keys': list(m['keys']), 'role': m.get('role')} for m in media_specs]
    results = []
    iso_paths = []
    for m in media_specs:
        payload = {}
        key_meta = {}
        for name in m['keys']:
            blob = encrypted[name]
            payload[name] = blob
            key_meta[name] = {
                'sha256': _hash_bytes(blob),
                'size': len(blob),
                'encrypted': name != 'root.pem',
            }
        bundle = make_bundle({
            'bundle_id': str(uuid.uuid4()),
            'cluster_id': cluster_id,
            'media_id': m['media_id'],
            'role': m.get('role') or ('admin' if m['keys'] == [admin_name] else 'keys'),
            'gpg_fingerprint': keys['gpg_fingerprint'],
            'kernel_cert_sha256': keys['kernel_cert_sha256'],
            'keys': key_meta,
            'permissions': selected,
            'custom': custom,
            'required_media': required,
            'root_media_id': root_media_id,
            'independent_child_media': False,
        })
        files = pack_media_files(bundle, payload, keys)
        iso_out = None
        if m.get('kind') in ('dvd-r', 'optical'):
            iso_out = VAR / f"{m['media_id']}.iso"
            iso_paths.append(str(iso_out))
        write_device(m['path'], m['kind'], files, iso_out=iso_out)
        results.append({'path': m['path'], 'kind': m['kind'], 'media_id': m['media_id'], 'keys': m['keys']})

    # drop any accidental plaintext copies
    for n, raw in plains.items():
        # overwrite memory as best-effort
        plains[n] = b''
    del plains, encrypted, root_plain

    st = {
        'initialized': True,
        'role': 'master',
        'cluster_id': cluster_id,
        'gpg_fingerprint': keys['gpg_fingerprint'],
        'kernel_cert_sha256': keys['kernel_cert_sha256'],
        'permissions': selected,
        'custom': custom,
        'media': results,
        'root_media_id': root_media_id,
        'vault': vault,
        'mode': 'test',
        'kernel_enforcement': False,
        'independent_child_media': False,
        'children': [],
        'iso': iso_paths,
    }
    st = stamp_new_install(st)
    save_state(st)
    save_json(CONFIG_PATH, {
        'gpg_keyring': str(TRUST_DIR / 'media.gpg'),
        'gpg_fingerprint': keys['gpg_fingerprint'],
        'kernel_cert': str(TRUST_DIR / 'kernel-cert.pem'),
        'kernel_cert_sha256': keys['kernel_cert_sha256'],
        'expected_expiry_policy': 'never',
        'mode': 'test',
    })
    return st
