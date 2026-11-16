import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'python'))

MODULES = [
    'ker.paths',
    'ker.state',
    'ker.compat',
    'ker.features',
    'ker.migrations.m0001_baseline',
    'ker.migrations',
    'ker.upgrade',
]


def _reload():
    for name in MODULES:
        if name in sys.modules:
            importlib.reload(sys.modules[name])
        else:
            importlib.import_module(name)


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ker-up-')
        os.environ['KER_PREFIX'] = self.tmp.name
        _reload()
        from ker.features import reset_features
        reset_features()

    def tearDown(self):
        from ker.features import reset_features
        reset_features()
        self.tmp.cleanup()
        os.environ.pop('KER_PREFIX', None)
        _reload()

    def _legacy_state(self, **extra):
        st = {
            'initialized': True,
            'role': 'master',
            'permissions': ['write', 'ssh'],
            'custom': [],
            'mode': 'test',
            'kernel_enforcement': False,
            'children': [],
        }
        st.update(extra)
        from ker.state import save_state
        save_state(st)
        return st

    def test_uninitialized_is_skipped(self):
        from ker.upgrade import migrate
        r = migrate()
        self.assertTrue(r['ok'] and r['skipped'])
        self.assertEqual(r['reason'], 'not_initialized')

    def test_legacy_state_migrates_to_schema_1(self):
        self._legacy_state()
        from ker.compat import PACKAGE_VERSION, STATE_SCHEMA
        from ker.upgrade import migrate, plan, preflight
        pf = preflight()
        self.assertTrue(pf['ok'])
        self.assertTrue(pf['plan']['needed'])
        self.assertEqual(pf['plan']['migrations'][0]['id'], '0001_baseline')
        r = migrate()
        self.assertTrue(r['ok'] and not r['skipped'])
        self.assertEqual(r['to'], PACKAGE_VERSION)
        from ker.state import state
        st = state()
        self.assertEqual(st['state_schema'], STATE_SCHEMA)
        self.assertEqual(st['package_version'], PACKAGE_VERSION)
        self.assertIn('0001_baseline', st['migrations_applied'])
        self.assertEqual(st['mode'], 'test')
        self.assertIs(st['kernel_enforcement'], False)
        self.assertEqual(st['permissions'], ['write', 'ssh'])
        # second run is a no-op
        r2 = migrate()
        self.assertTrue(r2['skipped'])
        self.assertFalse(plan()['needed'])

    def test_enforcement_mode_preserved(self):
        self._legacy_state(mode='enforce', kernel_enforcement=True)
        from ker.upgrade import migrate
        r = migrate()
        self.assertTrue(r['ok'])
        from ker.state import state
        st = state()
        self.assertEqual(st['mode'], 'enforce')
        self.assertIs(st['kernel_enforcement'], True)

    def test_refuse_future_schema(self):
        self._legacy_state(state_schema=99, package_version='9.9.9', migrations_applied=['0001_baseline'])
        from ker.upgrade import UpgradeError, migrate, preflight
        pf = preflight()
        self.assertFalse(pf['ok'])
        self.assertTrue(any('newer' in e or 'downgrade' in e for e in pf['errors']))
        with self.assertRaises(UpgradeError):
            migrate()

    def test_refuse_downgrade(self):
        from ker.compat import takeover_errors
        st = {
            'initialized': True,
            'package_version': '1.0.0',
            'state_schema': 1,
            'media_schema': 2,
            'crypto_epoch': 1,
        }
        target = {
            'package_version': '0.1.0',
            'state_schema': 1,
            'min_state_schema': 0,
            'min_upgrade_from_package': '0.1.0',
            'supported_media_schemas': [2],
            'supported_crypto_epochs': [1],
        }
        errs = takeover_errors(st, target)
        self.assertTrue(any('downgrade' in e for e in errs))

    def test_first_public_release_takes_over_unreleased(self):
        from ker.compat import takeover_errors
        st = {
            'initialized': True,
            'package_version': '0.4.2',
            'state_schema': 1,
            'media_schema': 2,
            'crypto_epoch': 1,
        }
        target = {
            'package_version': '0.1',
            'state_schema': 1,
            'min_state_schema': 0,
            'min_upgrade_from_package': '0.1.0',
            'supported_media_schemas': [2],
            'supported_crypto_epochs': [1],
        }
        self.assertEqual(takeover_errors(st, target), [])

    def test_snapshot_and_rollback(self):
        self._legacy_state()
        from ker.state import save_state, state
        from ker.upgrade import rollback, snapshot
        snap = snapshot('test')
        self.assertTrue((snap / 'state.json').exists())
        st = state()
        st['permissions'] = ['network']
        save_state(st)
        self.assertEqual(state()['permissions'], ['network'])
        rollback()
        self.assertEqual(state()['permissions'], ['write', 'ssh'])

    def test_failed_migration_rolls_back(self):
        self._legacy_state()
        import ker.migrations as migrations
        from ker.upgrade import UpgradeError, migrate
        from ker.state import state

        class Boom:
            ID = '0099_boom'
            TARGET_SCHEMA = 1

            def apply(self, st, ctx):
                st = dict(st)
                st['marker'] = 'partial'
                return st

            def verify(self, st, ctx):
                raise RuntimeError('boom')

        migrations.REGISTRY.append(Boom())
        try:
            with self.assertRaises(UpgradeError):
                migrate()
            st = state()
            self.assertNotIn('marker', st)
            self.assertNotIn('package_version', st)
            self.assertEqual(st['permissions'], ['write', 'ssh'])
        finally:
            migrations.REGISTRY[:] = [m for m in migrations.REGISTRY if getattr(m, 'ID', '') != '0099_boom']

    def test_lossless_feature_replacement(self):
        self._legacy_state(permissions=['legacy_demo', 'ssh'])
        from ker.features import Feature, register_feature
        register_feature(Feature(
            'legacy_demo', 'permission', 1,
            status='replaced', replaced_by='read', lossless=True,
            provision_needed=True,
        ))
        from ker.upgrade import migrate, plan
        pl = plan()
        self.assertTrue(any(r['old'] == 'legacy_demo' and r['new'] == 'read' for r in pl['replacements']))
        r = migrate()
        self.assertTrue(any(c.get('old') == 'legacy_demo' and c.get('applied') for c in r['replacements']))
        from ker.state import state
        st = state()
        self.assertEqual(st['permissions'], ['read', 'ssh'])
        self.assertEqual(st['feature_replacements']['legacy_demo'], 'read')

    def test_new_feature_listed_on_package_takeover(self):
        self._legacy_state()
        from ker.features import Feature, register_feature
        register_feature(Feature('netplus', 'capability', 1, status='active'))
        from ker.upgrade import migrate
        r = migrate()
        self.assertIn('netplus', r['added_features'])
        from ker.state import state
        self.assertIn('netplus', state()['features_known'])
        # no media rewrite, no auto provisioning
        self.assertNotIn('netplus', state().get('permissions') or [])

    def test_master_flags_child_sync(self):
        self._legacy_state(children=[{'id': 'child-1'}])
        from ker.upgrade import migrate
        migrate()
        from ker.state import state
        self.assertTrue(state()['compat']['needs_child_sync'])

    def test_cli_check_and_migrate(self):
        self._legacy_state()
        import subprocess
        env = os.environ.copy()
        env['KER_PREFIX'] = self.tmp.name
        env['PYTHONPATH'] = str(ROOT / 'python')
        r = subprocess.run(
            [sys.executable, '-m', 'ker', '--language', 'zh-CN', 'upgrade', '--check'],
            env=env, capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('可以升级', r.stdout)
        r2 = subprocess.run(
            [sys.executable, '-m', 'ker', '--language', 'zh-CN', 'upgrade', '--migrate'],
            env=env, capture_output=True, text=True,
        )
        self.assertEqual(r2.returncode, 0, r2.stdout + r2.stderr)
        self.assertIn('升级完成', r2.stdout)
        st = json.loads((Path(self.tmp.name) / 'etc' / 'ker' / 'state.json').read_text())
        self.assertEqual(st['state_schema'], 1)
        self.assertEqual(st['package_version'], __import__('ker').__version__)

    def test_snapshot_skips_sockets(self):
        import socket
        from ker.paths import PRIVATE_DIR
        from ker.upgrade import snapshot
        PRIVATE_DIR.mkdir(parents=True, exist_ok=True)
        (PRIVATE_DIR / 'keepme').write_text('ok')
        sock_path = PRIVATE_DIR / 'S.gpg-agent'
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.bind(str(sock_path))
            path = snapshot('socket-test')
            self.assertTrue((path / 'private' / 'keepme').is_file())
            self.assertFalse((path / 'private' / 'S.gpg-agent').exists())
        finally:
            s.close()


    def test_0_4_features_listed_on_takeover(self):
        from ker.features import SCHEMA1_FEATURE_IDS
        from ker.state import state
        from ker.upgrade import migrate
        self._legacy_state(package_version='0.3.0', features_known=sorted(SCHEMA1_FEATURE_IDS))
        r = migrate(reason='test')
        for fid in ('boot_hook', 'ssh_hook', 'multiarch_packages'):
            self.assertIn(fid, r['added_features'])
        st = state()
        self.assertEqual(st['package_version'], __import__('ker').__version__)
        self.assertIn('boot_hook', st['features_known'])
        self.assertEqual(st['mode'], 'test')
        self.assertFalse(st['kernel_enforcement'])

if __name__ == '__main__':
    unittest.main()
