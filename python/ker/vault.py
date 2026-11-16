"""Hold the root unwrap key in the kernel keyring, not a userspace file."""
from __future__ import annotations

import subprocess

from ker.crypto import aead_key


class VaultError(RuntimeError):
    pass


KEY_DESC = 'ker-root-unwrap'


def store_unwrap(root_pem: bytes) -> None:
    material = aead_key(root_pem)
    # session + user keyrings; still not root-proof without lockdown
    try:
        # padd reads raw bytes from stdin; argv cannot contain NUL
        r = subprocess.run(
            ['keyctl', 'padd', 'user', KEY_DESC, '@s'],
            input=material,
            capture_output=True,
        )
    except FileNotFoundError as e:
        raise VaultError('keyctl unavailable') from e
    if r.returncode:
        err = (r.stderr or r.stdout or b'keyctl unavailable').decode('utf-8', 'replace').strip()
        raise VaultError(err or 'keyctl unavailable')
    key_id = r.stdout.decode().strip()
    subprocess.run(['keyctl', 'setperm', key_id, '0x3f000000'], capture_output=True)
    subprocess.run(['keyctl', 'link', key_id, '@u'], capture_output=True)


def available() -> bool:
    return subprocess.run(['keyctl', 'search', '@s', 'user', KEY_DESC], capture_output=True).returncode == 0
