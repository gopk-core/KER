import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'python'))

from ker import KEY_SIZE
from ker.crypto import build_permission_pem, build_root_pem, decrypt_key, encrypt_key, inspect_root, CryptoError


class CryptoTests(unittest.TestCase):
    def test_root_and_roundtrip(self):
        root = build_root_pem()
        self.assertEqual(len(root), KEY_SIZE)
        info = inspect_root(root)
        self.assertEqual(len(info['unwrap']), 32)
        plain = build_permission_pem()
        enc = encrypt_key(plain, root)
        self.assertTrue(enc.startswith(b'KERENC\x01'))
        self.assertEqual(decrypt_key(enc, root), plain)

    def test_wrong_root_fails(self):
        a, b = build_root_pem(), build_root_pem()
        enc = encrypt_key(build_permission_pem(), a)
        with self.assertRaises(CryptoError):
            decrypt_key(enc, b)

    def test_without_root_cannot_decrypt(self):
        # no root material at all
        enc = encrypt_key(build_permission_pem(), build_root_pem())
        with self.assertRaises(Exception):
            decrypt_key(enc, b'\x00' * KEY_SIZE)


if __name__ == '__main__':
    unittest.main()
