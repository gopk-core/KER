import importlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'python'))

MODULES = [
    'ker.paths', 'ker.state', 'ker.compat', 'ker.features',
    'ker.migrations.m0001_baseline', 'ker.migrations', 'ker.upgrade',
    'ker.sign', 'ker.protocol', 'ker.cluster', 'ker.enforce', 'ker.console',
]


def _reload():
    for name in MODULES:
        if name in sys.modules:
            importlib.reload(sys.modules[name])
        else:
            importlib.import_module(name)


def _free_port() -> int:
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ClusterTests(unittest.TestCase):
    def setUp(self):
        self.master = tempfile.TemporaryDirectory(prefix='ker-master-')
        self.child = tempfile.TemporaryDirectory(prefix='ker-child-')
        os.environ['KER_PREFIX'] = self.master.name
        os.environ['KER_SYNC_TIMEOUT'] = '2'
        _reload()
        self.port = _free_port()
        self.stopper = None

    def tearDown(self):
        if self.stopper is not None:
            self.stopper.set()
            time.sleep(0.2)
        self.master.cleanup()
        self.child.cleanup()
        os.environ.pop('KER_PREFIX', None)
        os.environ.pop('KER_SYNC_TIMEOUT', None)
        _reload()

    def _init_master(self):
        from ker.sign import generate_signing_keys
        from ker.state import ensure_dirs, save_state
        from ker.upgrade import stamp_new_install
        from ker.bundle import cert_sha256
        from pathlib import Path as P
        ensure_dirs()
        keys = generate_signing_keys()
        st = stamp_new_install({
            'initialized': True,
            'role': 'master',
            'cluster_id': 'cluster-test',
            'gpg_fingerprint': keys['gpg_fingerprint'],
            'kernel_cert_sha256': cert_sha256(P(keys['rsa_pub'])),
            'permissions': ['write'],
            'custom': [],
            'media': [],
            'mode': 'test',
            'kernel_enforcement': False,
            'children': [],
            'independent_child_media': False,
        })
        save_state(st)
        return st

    def test_join_sync_and_fail_closed(self):
        self._init_master()
        from ker.cluster import create_join_token, queue_policy_sync, start_server
        from ker.state import save_state, state
        self.stopper = start_server('127.0.0.1', self.port)
        token = create_join_token('127.0.0.1', self.port, name='child1')
        env = os.environ.copy()
        env['KER_PREFIX'] = self.child.name
        env['PYTHONPATH'] = str(ROOT / 'python')
        env['KER_SYNC_TIMEOUT'] = '2'
        r = subprocess.run(
            [sys.executable, '-c',
             'from ker.cluster import join_master, child_poll\n'
             f'join_master("127.0.0.1", {self.port}, {token!r}, name="child1")\n'],
            env=env, capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        child_state = json.loads((Path(self.child.name) / 'etc/ker/state.json').read_text())
        self.assertEqual(child_state['role'], 'child')
        self.assertTrue(child_state['joined'])
        self.assertFalse(child_state['kernel_enforcement'])
        self.assertEqual(child_state['permissions'], ['write'])
        self.assertFalse((Path(self.child.name) / 'var/lib/ker/private/kernel-signing.key').exists())

        st = state()
        st['permissions'] = ['write', 'ssh']
        save_state(st)
        queue_policy_sync()
        r = subprocess.run(
            [sys.executable, '-c',
             'from ker.cluster import child_poll\n'
             'import json; print(json.dumps(child_poll()))\n'],
            env=env, capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        child_state = json.loads((Path(self.child.name) / 'etc/ker/state.json').read_text())
        self.assertEqual(child_state['permissions'], ['write', 'ssh'])
        self.assertFalse(child_state.get('fail_closed'))

        self.stopper.set()
        time.sleep(2.3)
        r = subprocess.run(
            [sys.executable, '-c',
             'from ker.cluster import child_poll, check_fail_closed\n'
             'from ker.state import state\n'
             'try:\n'
             '    child_poll()\n'
             'except Exception as e:\n'
             '    print("ERR", e)\n'
             'print("FC", check_fail_closed())\n'],
            env=env, capture_output=True, text=True,
        )
        self.assertIn('FC True', r.stdout, r.stdout + r.stderr)

    def test_signed_uninstall(self):
        self._init_master()
        from ker.cluster import create_join_token, dispatch_uninstall, start_server
        self.stopper = start_server('127.0.0.1', self.port)
        token = create_join_token('127.0.0.1', self.port, name='child1')
        env = os.environ.copy()
        env['KER_PREFIX'] = self.child.name
        env['PYTHONPATH'] = str(ROOT / 'python')
        r = subprocess.run(
            [sys.executable, '-c',
             f'from ker.cluster import join_master; join_master("127.0.0.1", {self.port}, {token!r})'],
            env=env, capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        dispatch_uninstall()
        r = subprocess.run(
            [sys.executable, '-c',
             'from ker.cluster import child_poll\n'
             'print(child_poll())\n'],
            env=env, capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('uninstalled', r.stdout)
        self.assertFalse((Path(self.child.name) / 'etc/ker/state.json').exists())

    def test_deny_mask_and_host_bpf_refused(self):
        from ker.enforce import deny_mask, may_load_bpf, set_enforcement, EnforceError
        self.assertEqual(deny_mask(['write', 'run']), (1 << 2) | (1 << 0))
        # prefix tests run on the production host: must not load BPF
        os.environ.pop('KER_ALLOW_HOST_BPF', None)
        os.environ.pop('KER_IN_VM', None)
        if not may_load_bpf():
            self._init_master()
            with self.assertRaises(EnforceError):
                set_enforcement(True, already_confirmed=True)

    def test_console_status_assume_admin(self):
        self._init_master()
        env = os.environ.copy()
        env['KER_PREFIX'] = self.master.name
        env['PYTHONPATH'] = str(ROOT / 'python')
        r = subprocess.run(
            [sys.executable, '-m', 'ker', 'console', '--assume-admin', 'status'],
            env=env, capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(data['role'], 'master')
        self.assertEqual(data['permissions'], ['write'])

    def test_console_admin_dev_includes_root(self):
        from unittest.mock import patch
        from ker.console import _has_admin
        st = {
            'media': [
                {'path': '/dev/vdb', 'keys': ['root.pem', 'write.pem'], 'kind': 'disk'},
                {'path': '/dev/vdc', 'keys': ['admin.pem'], 'kind': 'disk'},
            ]
        }
        seen = {}
        def fake_verify(state, devices=None):
            seen['devices'] = list(devices or [])
            return {'ok': True, 'results': [{'path': d['path'], 'ok': True} for d in devices or []]}
        with patch('ker.console.verify_all', side_effect=fake_verify):
            self.assertTrue(_has_admin(st, '/dev/vdc'))
        paths = [d['path'] for d in seen['devices']]
        self.assertEqual(paths, ['/dev/vdb', '/dev/vdc'])
        with patch('ker.console.verify_all', side_effect=Exception('missing')):
            self.assertFalse(_has_admin(st, '/dev/vdc'))

    def test_bpftool_map_update_argv(self):
        import struct
        from ker.enforce import bpftool_map_update_argv, deny_mask
        key = struct.pack('I', 0)
        value = struct.pack('IIII', 1, 1, deny_mask(['write', 'read', 'run']), 0)
        cmd = bpftool_map_update_argv('/sys/fs/bpf/ker/cfg_map', key, value)
        # each byte is its own argument; this is what bpftool parses
        self.assertEqual(cmd[cmd.index('key')+1], 'hex')
        key_bytes = cmd[cmd.index('key')+2:cmd.index('value')]
        self.assertEqual(key_bytes, ['00', '00', '00', '00'])
        val_bytes = cmd[cmd.index('value')+2:]
        self.assertEqual(val_bytes, ['01', '00', '00', '00', '01', '00', '00', '00', '07', '00', '00', '00', '00', '00', '00', '00'])


    def test_allowlist_and_deny_mask_policy(self):
        from ker.enforce import (
            ALLOWED_COMMS, BIT, FORBIDDEN_COMMS, deny_mask,
            is_allowed_comm, task_comm, would_deny,
        )
        src = (ROOT / 'src' / 'bpf' / 'ker.bpf.c').read_text()
        # The BPF program is the source of truth for names actually enforced.
        for name in ALLOWED_COMMS:
            self.assertIn(f'"{name}"', src, name)
            self.assertTrue(is_allowed_comm(name), name)
            self.assertLessEqual(len(name), 15, name)
        for name in FORBIDDEN_COMMS:
            self.assertFalse(is_allowed_comm(name), name)
            # A quoted exact comm in is_allowed_name would allow it.
            self.assertNotIn(f'comm_eq(c, "{name}")', src, name)
        self.assertEqual(task_comm('systemd-journald'), 'systemd-journal')
        self.assertEqual(task_comm('systemd-executor'), 'systemd-executo')
        self.assertEqual(task_comm('systemd-shutdown'), 'systemd-shutdow')
        self.assertTrue(is_allowed_comm('systemd-journald'))
        self.assertTrue(is_allowed_comm('systemd-executor'))
        self.assertTrue(is_allowed_comm('systemd-udevd'))
        self.assertTrue(is_allowed_comm('ker-enforcer'))
        self.assertTrue(is_allowed_comm('ker-python'))
        self.assertTrue(is_allowed_comm('udev-worker'))
        self.assertTrue(is_allowed_comm('systemd-udev-worker'))
        self.assertEqual(task_comm('systemd-udev-worker'), 'systemd-udev-wo')
        self.assertFalse(is_allowed_comm('bash'))
        self.assertFalse(is_allowed_comm('cat'))
        self.assertFalse(is_allowed_comm('python3'))
        # Exec is judged by the target, not the parent: bash launching cat is denied.
        mask = deny_mask(['read', 'write', 'run'])
        self.assertTrue(would_deny(enforcement=True, media_ok=False,
                                   deny_mask_value=mask, bit=BIT['run'], allowed=False))
        self.assertTrue(would_deny(enforcement=True, media_ok=False,
                                   deny_mask_value=mask, bit=BIT['read'], allowed=False))
        # journald / udevd / ker-enforcer stay usable while media is missing.
        for comm in ('systemd-journald', 'systemd-udevd', 'ker-enforcer', 'ker-python', 'bpftool'):
            self.assertFalse(
                would_deny(enforcement=True, media_ok=False, deny_mask_value=mask,
                           bit=BIT['read'] | BIT['write'] | BIT['run'],
                           allowed=is_allowed_comm(comm)),
                comm,
            )
        # Reinserting media lifts the denial without changing the allowlist.
        self.assertFalse(would_deny(enforcement=True, media_ok=True,
                                    deny_mask_value=mask, bit=BIT['run'], allowed=False))
        # Test mode never denies.
        self.assertFalse(would_deny(enforcement=False, media_ok=False,
                                    deny_mask_value=mask, bit=BIT['run'], allowed=False))
        # exec decision must look at the target program, not current comm.
        self.assertIn('allowed_exec(bprm)', src)
        self.assertIn('bpf_probe_read_kernel_str', src)
        self.assertIn('bpf_probe_read_user_str', src)
        self.assertIn('bprm, filename', src)
        self.assertIn('/usr/lib/systemd/', src)
        self.assertIn('/usr/lib/ker/', src)
        from ker.enforce import ALLOWED_EXEC_PREFIXES, DENIED_EXEC_BASENAMES, path_is_allowed_exec
        for pfx in ALLOWED_EXEC_PREFIXES:
            self.assertIn(f'"{pfx}"', src, pfx)
        self.assertIn('ker-probe', DENIED_EXEC_BASENAMES)
        self.assertIn('ker-probe', src)
        self.assertIn('path[13 + i]', src)
        self.assertFalse(path_is_allowed_exec('/usr/lib/ker/ker-probe'))
        self.assertTrue(path_is_allowed_exec('/usr/lib/ker/ker-python'))
        self.assertTrue(path_is_allowed_exec('/usr/sbin/ker'))

if __name__ == '__main__':
    unittest.main()
