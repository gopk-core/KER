"""10MiB key files, AEAD encryption, unwrap material from root.pem."""
from __future__ import annotations

import os
import struct

# Early boot (initramfs) may lack OpenSSL's legacy provider. KER does not
# need legacy algorithms; allow cryptography to load without it.
os.environ.setdefault("CRYPTOGRAPHY_OPENSSL_NO_LEGACY", "1")

from cryptography.exceptions import InvalidTag

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from ker import KEY_SIZE

ROOT_MAGIC = b'KERROOT\x01'
ENC_MAGIC = b'KERENC\x01'
UNWRAP_OFF = 64
UNWRAP_LEN = 32
SALT_OFF = 20
SALT_LEN = 16
AAD = b'KER-key-v1'


class CryptoError(ValueError):
    pass


def _hkdf(unwrap: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b'ker-unwrap-v1').derive(unwrap)


def build_root_pem(size: int = KEY_SIZE) -> bytes:
    if size < 4096:
        raise CryptoError('root key too small')
    blob = bytearray(os.urandom(size))
    blob[0:8] = ROOT_MAGIC
    struct.pack_into('<I', blob, 8, 1)
    struct.pack_into('<I', blob, 12, UNWRAP_OFF)
    struct.pack_into('<I', blob, 16, UNWRAP_LEN)
    # random salt already in blob; keep it
    return bytes(blob)


def inspect_root(root_pem: bytes) -> dict:
    if len(root_pem) != KEY_SIZE or not root_pem.startswith(ROOT_MAGIC):
        raise CryptoError('invalid root.pem')
    version, off, length = struct.unpack_from('<III', root_pem, 8)
    if version != 1 or off != UNWRAP_OFF or length != UNWRAP_LEN:
        raise CryptoError('unsupported root.pem')
    if off + length > len(root_pem):
        raise CryptoError('root unwrap segment truncated')
    return {
        'version': version,
        'unwrap': bytes(root_pem[off:off + length]),
        'salt': bytes(root_pem[SALT_OFF:SALT_OFF + SALT_LEN]),
    }


def aead_key(root_pem: bytes) -> bytes:
    info = inspect_root(root_pem)
    return _hkdf(info['unwrap'], info['salt'])


def build_permission_pem(size: int = KEY_SIZE) -> bytes:
    if size != KEY_SIZE:
        raise CryptoError('permission key must be 10MiB')
    return os.urandom(size)


def encrypt_key(plain: bytes, root_pem: bytes) -> bytes:
    if len(plain) != KEY_SIZE:
        raise CryptoError('plaintext key must be 10MiB')
    nonce = os.urandom(12)
    ct = AESGCM(aead_key(root_pem)).encrypt(nonce, plain, AAD)
    return ENC_MAGIC + nonce + ct


def decrypt_key(blob: bytes, root_pem: bytes) -> bytes:
    hdr = len(ENC_MAGIC)
    min_len = hdr + 12 + 16 + KEY_SIZE
    if not blob.startswith(ENC_MAGIC) or len(blob) < min_len:
        raise CryptoError('invalid encrypted key')
    nonce = blob[hdr:hdr + 12]
    ct = blob[hdr + 12:]
    try:
        plain = AESGCM(aead_key(root_pem)).decrypt(nonce, ct, AAD)
    except InvalidTag as e:
        raise CryptoError('decrypt failed') from e
    if len(plain) != KEY_SIZE:
        raise CryptoError('decrypted key has wrong size')
    return plain
