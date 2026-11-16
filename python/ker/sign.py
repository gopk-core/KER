"""GPG detached signatures plus RSA signatures for kernel-style verify."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from ker.paths import PRIVATE_DIR, TRUST_DIR


class SignError(RuntimeError):
    pass


def _run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode:
        raise SignError(r.stderr[-2000:] or r.stdout[-2000:] or 'command failed')
    return r


def generate_signing_keys(homedir: Path | None = None, rsa_key: Path | None = None,
                          rsa_pub: Path | None = None, pubring: Path | None = None) -> dict:
    """Create a GPG key (no expiry) and an RSA key. Public material goes to TRUST_DIR unless overridden."""
    gpg_home = Path(homedir or (PRIVATE_DIR / 'gnupg'))
    if gpg_home.exists():
        shutil.rmtree(gpg_home)
    gpg_home.mkdir(parents=True, exist_ok=True)
    os.chmod(gpg_home, 0o700)
    batch = gpg_home / 'batch'
    batch.write_text(
        'Key-Type: RSA\nKey-Length: 3072\nKey-Usage: sign\n'
        'Name-Real: KER Media Signing\nName-Email: ker-signing@localhost\n'
        'Expire-Date: 0\n%no-protection\n%commit\n',
        encoding='utf-8',
    )
    env = os.environ.copy()
    env['GNUPGHOME'] = str(gpg_home)
    _run(['gpg', '--batch', '--generate-key', str(batch)], env=env, timeout=120)
    r = _run(['gpg', '--batch', '--fingerprint', '--with-colons'], env=env)
    fpr = None
    for line in r.stdout.splitlines():
        if line.startswith('fpr:'):
            fpr = line.split(':')[9]
            break
    if not fpr:
        raise SignError('no GPG fingerprint')
    pub = Path(pubring or (TRUST_DIR / 'media.gpg'))
    pub.parent.mkdir(parents=True, exist_ok=True)
    TRUST_DIR.mkdir(parents=True, exist_ok=True)
    _run(['gpg', '--batch', '--export', '--output', str(pub), fpr], env=env)
    os.chmod(pub, 0o400)

    rsa_key = Path(rsa_key or (PRIVATE_DIR / 'kernel-signing.key'))
    rsa_pub = Path(rsa_pub or (TRUST_DIR / 'kernel-cert.pem'))
    rsa_key.parent.mkdir(parents=True, exist_ok=True)
    rsa_pub.parent.mkdir(parents=True, exist_ok=True)
    _run(['openssl', 'genrsa', '-out', str(rsa_key), '3072'], timeout=60)
    os.chmod(rsa_key, 0o400)
    # "No well-defined expiration" style cert: end date 99991231235959Z
    _run([
        'openssl', 'req', '-new', '-x509', '-key', str(rsa_key),
        '-subj', '/CN=KER Kernel Verify/',
        '-days', '365000',
        '-out', str(rsa_pub),
    ])
    os.chmod(rsa_pub, 0o400)
    return {'gpg_fingerprint': fpr, 'gpg_home': str(gpg_home), 'rsa_key': str(rsa_key), 'rsa_pub': str(rsa_pub)}


def sign_bytes(data: bytes, keys: dict) -> tuple[bytes, bytes]:
    """Return (gpg_detached_sig, openssl_sha256_rsa_sig)."""
    with tempfile.TemporaryDirectory(prefix='ker-sign-') as tmp:
        src = Path(tmp) / 'data'
        src.write_bytes(data)
        gpg_sig = Path(tmp) / 'data.sig'
        env = os.environ.copy()
        env['GNUPGHOME'] = keys['gpg_home']
        _run(['gpg', '--batch', '--yes', '--detach-sign', '--output', str(gpg_sig), str(src)], env=env)
        rsa_sig = Path(tmp) / 'data.ksig'
        _run(['openssl', 'dgst', '-sha256', '-sign', keys['rsa_key'], '-out', str(rsa_sig), str(src)])
        return gpg_sig.read_bytes(), rsa_sig.read_bytes()


def verify_bytes(data: bytes, gpg_sig: bytes, rsa_sig: bytes, keys: dict) -> None:
    with tempfile.TemporaryDirectory(prefix='ker-vfy-') as tmp:
        src = Path(tmp) / 'data'
        sig = Path(tmp) / 'data.sig'
        ksig = Path(tmp) / 'data.ksig'
        src.write_bytes(data)
        sig.write_bytes(gpg_sig)
        ksig.write_bytes(rsa_sig)
        r = subprocess.run(
            ['gpgv', '--keyring', str(TRUST_DIR / 'media.gpg'), str(sig), str(src)],
            capture_output=True, text=True, timeout=20,
        )
        if r.returncode:
            raise SignError('GPG_SIGNATURE_REJECTED')
        # openssl dgst -verify wants a public key, not an X.509 certificate
        pub = Path(tmp) / 'pub.pem'
        _run([
            'openssl', 'x509', '-in', str(TRUST_DIR / 'kernel-cert.pem'),
            '-pubkey', '-noout', '-out', str(pub),
        ])
        r = subprocess.run(
            ['openssl', 'dgst', '-sha256', '-verify', str(pub),
             '-signature', str(ksig), str(src)],
            capture_output=True, text=True, timeout=20,
        )
        if r.returncode:
            raise SignError('KERNEL_SIGNATURE_REJECTED')
