"""Rotation, lost-media revocation, and enforcement sync."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'python'))


class RotatePolicyTests(unittest.TestCase):
    def test_custom_with_key_is_not_revalidated(self):
        from ker.rotate import _custom_for_rotate
        item = {
            'name': 'backup', 'type': 'file_write', 'mode': 'grant',
            'constraints': {'paths': ['/var/backup']}, 'key': 'backup.pem',
        }
        with patch('ker.rotate.validate_custom') as validate:
            out = _custom_for_rotate([item])
        validate.assert_not_called()
        self.assertEqual(out, [item])
        bare = {
            'name': 'backup', 'type': 'file_write', 'mode': 'grant',
            'constraints': {'paths': ['/var/backup']},
        }
        out = _custom_for_rotate([bare])
        self.assertEqual(out[0]['key'], 'backup.pem')

    def test_plan_replaces_or_drops_lost_medium(self):
        from ker.rotate import RotateError, _plan_media
        st = {'permissions': ['write', 'ssh'], 'custom': []}
        present = [{
            'path': '/dev/root', 'media_id': 'r', 'kind': 'disk', 'role': 'root',
            'keys': ['root.pem', 'write.pem'],
        }]
        missing = [{
            'path': '/dev/ssh', 'media_id': 's', 'kind': 'disk', 'role': 'keys',
            'keys': ['ssh.pem'],
        }]
        with self.assertRaises(RotateError):
            _plan_media(st, present, missing, None, False)
        planned, selected, _custom = _plan_media(st, present, missing, None, True)
        self.assertEqual(selected, ['write'])
        self.assertEqual([m['path'] for m in planned], ['/dev/root'])
        planned, selected, _custom = _plan_media(
            st, present, missing, {'s': {'path': '/dev/new', 'kind': 'disk'}}, False,
        )
        self.assertIn('ssh', selected)
        self.assertEqual(planned[-1]['path'], '/dev/new')
        self.assertEqual(planned[-1]['keys'], ['ssh.pem'])
        with self.assertRaises(RotateError):
            _plan_media(st, [], [present[0]], None, True)

    def test_apply_kernel_mode_updates_units_and_maps(self):
        from ker.rotate import _apply_kernel_mode
        pin = type('P', (), {'exists': lambda self: True})()
        with patch('ker.enforce.may_load_bpf', return_value=True), \
             patch('ker.enforce.PIN_DIR', pin), \
             patch('ker.enforce.sync_enforcer_units') as sync, \
             patch('ker.enforce.update_maps') as maps:
            _apply_kernel_mode({'permissions': ['write']}, False)
        sync.assert_called_once_with(False)
        self.assertFalse(maps.call_args.kwargs['enforcement'])
        self.assertFalse(maps.call_args.kwargs['media_ok'])
        self.assertTrue(maps.call_args.kwargs['deny_mask_value'] & 0b100)
        with patch('ker.enforce.may_load_bpf', return_value=True), \
             patch('ker.enforce.PIN_DIR', pin), \
             patch('ker.enforce.sync_enforcer_units') as sync, \
             patch('ker.enforce.update_maps') as maps:
            _apply_kernel_mode({'permissions': ['write']}, True)
        sync.assert_called_once_with(True)
        self.assertTrue(maps.call_args.kwargs['enforcement'])
        # Enforcement may come back before the new media verify, but not open.
        self.assertFalse(maps.call_args.kwargs['media_ok'])
        self.assertFalse(maps.call_args.kwargs['scopes_verified'])
        self.assertTrue(maps.call_args.kwargs['deny_mask_value'] & 0b100)
        with patch('ker.enforce.may_load_bpf', return_value=True), \
             patch('ker.enforce.PIN_DIR', pin), \
             patch('ker.enforce.sync_enforcer_units'), \
             patch('ker.enforce.update_maps') as maps:
            _apply_kernel_mode({'permissions': ['write']}, True, verified=True)
        self.assertTrue(maps.call_args.kwargs['media_ok'])
        self.assertTrue(maps.call_args.kwargs['scopes_verified'])
        self.assertTrue(maps.call_args.kwargs['deny_mask_value'] & 0b100)

    def test_rotate_restores_previous_enforcement(self):
        tmp = tempfile.TemporaryDirectory(prefix='ker-rot-')
        self.addCleanup(tmp.cleanup)
        os.environ['KER_PREFIX'] = tmp.name
        os.environ['KER_SKIP_SYSTEMD'] = '1'
        from importlib import reload
        import ker.paths as paths
        import ker.state as state_mod
        reload(paths)
        reload(state_mod)
        import ker.rotate as rotate_mod
        reload(rotate_mod)

        def _restore_modules():
            os.environ.pop('KER_PREFIX', None)
            os.environ.pop('KER_SKIP_SYSTEMD', None)
            reload(paths)
            reload(state_mod)
            reload(rotate_mod)
        self.addCleanup(_restore_modules)
        from ker.rotate import RotateError, rotate
        from ker.state import save_state, state
        root = {
            'path': '/dev/root', 'media_id': 'r', 'kind': 'disk', 'role': 'root',
            'keys': ['root.pem', 'write.pem'],
        }
        ssh = {
            'path': '/dev/ssh', 'media_id': 's', 'kind': 'disk', 'role': 'keys',
            'keys': ['ssh.pem'],
        }
        save_state({
            'initialized': True, 'role': 'master', 'cluster_id': 'c',
            'permissions': ['write', 'ssh'], 'custom': [],
            'media': [root, ssh], 'root_media_id': 'r',
            'mode': 'enforce', 'kernel_enforcement': True,
            'children': [], 'key_generation': 1,
            'gpg_fingerprint': 'A' * 40, 'kernel_cert_sha256': 'b' * 64,
        })
        calls = []

        def _track(st, enabled, verified=False):
            calls.append((bool(enabled), bool(verified)))

        with patch('ker.rotate.runtime_presence', return_value=([root], [ssh], [root], [ssh])), \
             patch('ker.rotate.verify_all', side_effect=RuntimeError('gone')):
            with self.assertRaises(RotateError) as caught:
                rotate(assume_replug=True)
        self.assertIn('verify', str(caught.exception).lower())
        self.assertEqual(calls, [])

        def _fake_keys(**kwargs):
            pub = Path(kwargs['rsa_pub'])
            pub.parent.mkdir(parents=True, exist_ok=True)
            pub.write_text('cert')
            key = Path(kwargs['rsa_key'])
            key.parent.mkdir(parents=True, exist_ok=True)
            key.write_text('key')
            Path(kwargs['homedir']).mkdir(parents=True, exist_ok=True)
            Path(kwargs['pubring']).write_bytes(b'gpg')
            return {'gpg_fingerprint': 'C' * 40, 'rsa_pub': str(pub), 'gpg_home': kwargs['homedir'], 'rsa_key': kwargs['rsa_key']}

        with patch('ker.rotate.runtime_presence', return_value=([root], [ssh], [root], [ssh])), \
             patch('ker.rotate.verify_each', return_value={'ok': True, 'missing': [], 'failed': [], 'results': [{'ok': True}]}), \
             patch('ker.rotate._apply_kernel_mode', side_effect=_track), \
             patch('ker.rotate.generate_signing_keys', side_effect=_fake_keys), \
             patch('ker.rotate.cert_sha256', return_value='d' * 64), \
             patch('ker.rotate.build_root_pem', return_value=b'r' * 16), \
             patch('ker.rotate.build_permission_pem', return_value=b'p' * 16), \
             patch('ker.rotate.encrypt_key', side_effect=lambda raw, root: b'e' + raw), \
             patch('ker.rotate.store_unwrap'), \
             patch('ker.rotate.write_device'), \
             patch('ker.rotate.pack_media_files', return_value={'bundle.json': b'{}'}), \
             patch('ker.rotate.snapshot', return_value=Path(tmp.name) / 'snap'), \
             patch('ker.rotate._trust_blob', return_value={'media_gpg': 'YQ', 'kernel_cert': 'YQ'}), \
             patch('ker.rotate.queue_command'), \
             patch('ker.rotate.run_replug_tests', side_effect=lambda *a, **k: calls.append('replug')), \
             patch('ker.hooks.refresh_boot_initramfs', return_value={'ok': True}):
            result = rotate(assume_replug=True, allow_missing=True, drop_missing=True)
        self.assertEqual(calls, [(False, False), (True, False), 'replug', (True, True)])
        self.assertTrue(result['kernel_enforcement'])
        saved = state()
        self.assertTrue(saved['kernel_enforcement'])
        self.assertEqual(saved['mode'], 'enforce')
        self.assertNotIn('ssh', saved['permissions'])
        self.assertEqual([m['path'] for m in saved['media']], ['/dev/root'])

    def test_failed_replug_does_not_leave_maps_open(self):
        tmp = tempfile.TemporaryDirectory(prefix='ker-rot-fail-')
        self.addCleanup(tmp.cleanup)
        os.environ['KER_PREFIX'] = tmp.name
        os.environ['KER_SKIP_SYSTEMD'] = '1'
        from importlib import reload
        import ker.paths as paths
        import ker.state as state_mod
        reload(paths)
        reload(state_mod)
        import ker.rotate as rotate_mod
        reload(rotate_mod)

        def _restore_modules():
            os.environ.pop('KER_PREFIX', None)
            os.environ.pop('KER_SKIP_SYSTEMD', None)
            reload(paths)
            reload(state_mod)
            reload(rotate_mod)
        self.addCleanup(_restore_modules)
        from ker.enforce import BIT
        from ker.rotate import rotate
        from ker.state import save_state
        root = {
            'path': '/dev/root', 'media_id': 'r', 'kind': 'disk', 'role': 'root',
            'keys': ['root.pem', 'write.pem'],
        }
        ssh = {
            'path': '/dev/ssh', 'media_id': 's', 'kind': 'disk', 'role': 'keys',
            'keys': ['ssh.pem'],
        }
        save_state({
            'initialized': True, 'role': 'master', 'cluster_id': 'c',
            'permissions': ['write', 'ssh'], 'custom': [],
            'media': [root, ssh], 'root_media_id': 'r',
            'mode': 'enforce', 'kernel_enforcement': True,
            'children': [], 'key_generation': 1,
            'gpg_fingerprint': 'A' * 40, 'kernel_cert_sha256': 'b' * 64,
        })

        def _fake_keys(**kwargs):
            pub = Path(kwargs['rsa_pub'])
            pub.parent.mkdir(parents=True, exist_ok=True)
            pub.write_text('cert')
            key = Path(kwargs['rsa_key'])
            key.parent.mkdir(parents=True, exist_ok=True)
            key.write_text('key')
            Path(kwargs['homedir']).mkdir(parents=True, exist_ok=True)
            Path(kwargs['pubring']).write_bytes(b'gpg')
            return {'gpg_fingerprint': 'C' * 40, 'rsa_pub': str(pub), 'gpg_home': kwargs['homedir'], 'rsa_key': kwargs['rsa_key']}

        pin = type('P', (), {'exists': lambda self: True})()
        seen = []

        def _maps(**kwargs):
            seen.append(kwargs)

        with patch('ker.rotate.runtime_presence', return_value=([root], [ssh], [root], [ssh])), \
             patch('ker.rotate.verify_each', return_value={'ok': True, 'missing': [], 'failed': [], 'results': [{'ok': True}]}), \
             patch('ker.enforce.may_load_bpf', return_value=True), \
             patch('ker.enforce.PIN_DIR', pin), \
             patch('ker.enforce.sync_enforcer_units'), \
             patch('ker.enforce.update_maps', side_effect=_maps), \
             patch('ker.rotate.generate_signing_keys', side_effect=_fake_keys), \
             patch('ker.rotate.cert_sha256', return_value='d' * 64), \
             patch('ker.rotate.build_root_pem', return_value=b'r' * 16), \
             patch('ker.rotate.build_permission_pem', return_value=b'p' * 16), \
             patch('ker.rotate.encrypt_key', side_effect=lambda raw, root: b'e' + raw), \
             patch('ker.rotate.store_unwrap'), \
             patch('ker.rotate.write_device'), \
             patch('ker.rotate.pack_media_files', return_value={'bundle.json': b'{}'}), \
             patch('ker.rotate.snapshot', return_value=Path(tmp.name) / 'snap'), \
             patch('ker.rotate._trust_blob', return_value={'media_gpg': 'YQ', 'kernel_cert': 'YQ'}), \
             patch('ker.rotate.queue_command'), \
             patch('ker.rotate.run_replug_tests', side_effect=SystemExit(2)):
            with self.assertRaises(SystemExit):
                rotate(assume_replug=True, allow_missing=True, drop_missing=True)
        self.assertTrue(seen)
        self.assertFalse(any(call.get('media_ok') for call in seen))
        last = seen[-1]
        self.assertFalse(last['media_ok'])
        self.assertFalse(last.get('scopes_verified'))
        self.assertTrue(last['deny_mask_value'] & BIT['write'])
        self.assertTrue(last['enforcement'])

    def test_revoke_proof_accepts_root_without_admin(self):
        from ker.rotate import RotateError, _require_proof
        root = {'path': '/dev/root', 'keys': ['root.pem', 'write.pem'], 'role': 'root'}
        ssh = {'path': '/dev/ssh', 'keys': ['ssh.pem'], 'role': 'keys'}
        st = {'media': [root, ssh], 'permissions': ['write', 'ssh']}
        with patch('ker.rotate.verify_each', return_value={'ok': True, 'missing': [], 'failed': [], 'results': []}):
            _require_proof(st, [root], [ssh])
        with patch('ker.rotate.verify_each') as verify:
            with self.assertRaises(RotateError) as caught:
                _require_proof(st, [], [root, {'path': '/dev/admin', 'keys': ['admin.pem'], 'role': 'admin'}])
        verify.assert_not_called()
        text = str(caught.exception).lower()
        self.assertIn('admin', text)
        self.assertIn('refusing', text)

    def test_top_level_revoke_medium_accepts_root_without_admin(self):
        tmp = tempfile.TemporaryDirectory(prefix='ker-revoke-cli-')
        self.addCleanup(tmp.cleanup)
        os.environ['KER_PREFIX'] = tmp.name
        os.environ['KER_SKIP_SYSTEMD'] = '1'
        from importlib import reload
        import ker.paths as paths
        import ker.state as state_mod
        import ker.console as console_mod
        import ker.cli as cli_mod
        reload(paths)
        reload(state_mod)
        reload(console_mod)
        reload(cli_mod)

        def _restore_modules():
            os.environ.pop('KER_PREFIX', None)
            os.environ.pop('KER_SKIP_SYSTEMD', None)
            reload(paths)
            reload(state_mod)
            reload(console_mod)
            reload(cli_mod)
        self.addCleanup(_restore_modules)
        from ker.state import save_state
        root = {
            'path': '/dev/root', 'media_id': 'r', 'kind': 'disk', 'role': 'root',
            'keys': ['root.pem', 'write.pem'],
        }
        ssh = {
            'path': '/dev/ssh', 'media_id': 's', 'kind': 'disk', 'role': 'keys',
            'keys': ['ssh.pem'],
        }
        save_state({
            'initialized': True, 'role': 'master', 'cluster_id': 'c',
            'permissions': ['write', 'ssh'], 'custom': [],
            'media': [root, ssh], 'mode': 'test', 'kernel_enforcement': False,
        })
        with patch('ker.console._require_admin') as admin, \
             patch('ker.console.rotate', return_value={'ok': True, 'kernel_enforcement': False, 'media': []}) as rot:
            rc = cli_mod.main(['revoke-medium', '--drop', '--assume-replug'])
        admin.assert_not_called()
        self.assertEqual(rc, 0, )
        self.assertTrue(rot.call_args.kwargs['allow_missing'])
        self.assertTrue(rot.call_args.kwargs['drop_missing'])
        with patch('ker.console._require_admin') as admin, \
             patch('ker.console.rotate', return_value={'ok': True, 'kernel_enforcement': False, 'media': []}) as rot:
            rc = console_mod.run('en', ['revoke-medium', '--replace', '/dev/new', '--media-id', 's'])
        admin.assert_not_called()
        self.assertEqual(rc, 0)
        self.assertEqual(rot.call_args.kwargs['replacements']['s']['path'], '/dev/new')


class PackageSignatureTests(unittest.TestCase):
    def test_signed_package_verifies_and_unsigned_does_not(self):
        import subprocess
        from ker.upgrade import UpgradeError, verify_package_file
        home = tempfile.mkdtemp(prefix='ker-sign-test-')
        self.addCleanup(lambda: __import__('shutil').rmtree(home, ignore_errors=True))
        os.chmod(home, 0o700)
        env = os.environ.copy()
        env['GNUPGHOME'] = home
        subprocess.check_call([
            'gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '',
            '--quick-gen-key', 'KER Test Release <ker-test@localhost>', 'rsa2048', 'sign', '0',
        ], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pub = Path(home) / 'pub.gpg'
        subprocess.check_call(['gpg', '--batch', '--export', '--output', str(pub)], env=env)
        blob = Path(home) / 'ker_test.deb'
        blob.write_bytes(b'not-a-real-deb')
        os.environ['KER_RELEASE_KEYRING'] = str(pub)
        self.addCleanup(lambda: os.environ.pop('KER_RELEASE_KEYRING', None))
        with self.assertRaises(UpgradeError):
            verify_package_file(blob, trust_package=False)
        warnings = verify_package_file(blob, trust_package=True)
        self.assertTrue(warnings)
        subprocess.check_call([
            'gpg', '--batch', '--yes', '--detach-sign', '--output', str(blob) + '.sig', str(blob),
        ], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.assertEqual(verify_package_file(blob, trust_package=False), [])
        blob.write_bytes(b'tampered')
        with self.assertRaises(UpgradeError):
            verify_package_file(blob, trust_package=True)

    def test_repo_release_key_is_public(self):
        key = ROOT / 'packaging' / 'release.gpg'
        self.assertTrue(key.is_file())
        packets = subprocess_packets(key)
        self.assertNotIn('secret key packet', packets.lower())
        self.assertNotIn(b'PRIVATE KEY', key.read_bytes())
        stage = (ROOT / 'packaging' / 'stage.sh').read_text()
        self.assertIn('release.gpg', stage)
        signer = (ROOT / 'packaging' / 'sign-dist.sh').read_text()
        self.assertIn('KER_RELEASE_GNUPGHOME', signer)
        self.assertIn('refusing to use a keyring inside the source tree', signer)
        post = (ROOT / 'packaging' / 'debian' / 'postinst').read_text()
        self.assertIn('cp -a', post)
        self.assertNotIn('ln -f', post)


def subprocess_packets(path: Path) -> str:
    import subprocess
    r = subprocess.run(['gpg', '--list-packets', str(path)], capture_output=True, text=True)
    return (r.stdout or '') + (r.stderr or '')


if __name__ == '__main__':
    unittest.main()
