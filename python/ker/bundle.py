"""Build and verify a signed KER media bundle."""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ker import KEY_SIZE
from ker.crypto import CryptoError, decrypt_key, inspect_root
from ker.media import list_payload, sha256_file
from ker.sign import SignError, sign_bytes, verify_bytes


def canonical(data: dict) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def cert_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_bundle(meta: dict) -> dict:
    body = {
        'schema': 2,
        'expiry_policy': 'never',
        'expires': None,
        'bundle_id': meta['bundle_id'],
        'cluster_id': meta['cluster_id'],
        'media_id': meta['media_id'],
        'role': meta['role'],
        'created': datetime.now(timezone.utc).isoformat(),
        'gpg_fingerprint': meta['gpg_fingerprint'],
        'kernel_cert_sha256': meta['kernel_cert_sha256'],
        'keys': meta['keys'],
        'permissions': meta.get('permissions') or [],
        'custom': meta.get('custom') or [],
        'required_media': meta.get('required_media') or [],
        'root_media_id': meta.get('root_media_id'),
        'independent_child_media': bool(meta.get('independent_child_media', False)),
    }
    return body


def pack_media_files(bundle: dict, payload: dict[str, bytes], keys: dict) -> dict[str, bytes]:
    raw = canonical(bundle)
    gsig, ksig = sign_bytes(raw, keys)
    files = {
        'bundle.json': raw,
        'bundle.json.sig': gsig,
        'bundle.json.ksig': ksig,
    }
    files.update(payload)
    return files


def expected_names(bundle: dict) -> set[str]:
    names = {'bundle.json', 'bundle.json.sig', 'bundle.json.ksig'}
    names.update(bundle.get('keys') or {})
    return names


def verify_directory(media_dir: Path, keys: dict, root_pem: bytes | None = None) -> dict:
    """Verify a mounted medium. Fail if the file set is not exact."""
    bundle_path = media_dir / 'bundle.json'
    data = bundle_path.read_bytes()
    verify_bytes(data, (media_dir / 'bundle.json.sig').read_bytes(),
                 (media_dir / 'bundle.json.ksig').read_bytes(), keys)
    bundle = json.loads(data.decode('utf-8'))
    if bundle.get('schema') != 2 or bundle.get('expiry_policy') != 'never' or bundle.get('expires') is not None:
        raise SignError('DESCRIPTOR_PERMANENT_POLICY')
    if bundle.get('gpg_fingerprint') != keys['gpg_fingerprint']:
        raise SignError('SIGNED_DESCRIPTOR_PINS')
    listed = list_payload(media_dir)
    want = expected_names(bundle)
    if set(listed) != want:
        raise SignError('MEDIA_FILE_SET:' + ','.join(sorted(set(listed) ^ want)))
    # hash keys
    present = {}
    for name, info in (bundle.get('keys') or {}).items():
        path = media_dir / name
        digest = sha256_file(path)
        if not hmac.compare_digest(digest, info['sha256']) or path.stat().st_size != info['size']:
            raise SignError('KEY_HASH:' + name)
        present[name] = path
    # root.pem must be plain and parseable
    if 'root.pem' in present:
        root_pem = present['root.pem'].read_bytes()
        if len(root_pem) != KEY_SIZE:
            raise SignError('ROOT_SIZE')
        inspect_root(root_pem)
    if root_pem is None and 'root.pem' not in present:
        return {'ok': True, 'bundle': bundle, 'need_root': True, 'media_dir': str(media_dir)}
    if root_pem is None:
        root_pem = present['root.pem'].read_bytes()
    # decrypt encrypted keys when root is available
    for name, info in (bundle.get('keys') or {}).items():
        if name == 'root.pem' or not info.get('encrypted'):
            continue
        try:
            plain = decrypt_key(present[name].read_bytes(), root_pem)
        except CryptoError as e:
            raise SignError('DECRYPT:' + name + ':' + str(e)) from e
        if len(plain) != KEY_SIZE:
            raise SignError('DECRYPT_SIZE:' + name)
    return {'ok': True, 'bundle': bundle, 'need_root': False, 'media_dir': str(media_dir), 'root_present': True}


def new_ids():
    return str(uuid.uuid4()), str(uuid.uuid4())
