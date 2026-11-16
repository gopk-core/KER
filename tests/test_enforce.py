"""Presence-first kernel enforcement: deny immediately, verify only to allow."""
from __future__ import annotations

import sys
import struct
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "python"))

import tempfile
import unittest
from unittest.mock import MagicMock, patch

from ker.devices import block_device_live, required_media_presence
from ker.enforce import (
    apply_presence, is_allowed_comm, media_present, would_deny,
)


class PresenceTests(unittest.TestCase):
    def test_missing_path_is_not_live(self):
        self.assertFalse(block_device_live(''))
        self.assertFalse(block_device_live('/dev/disk/by-id/usb-DOES-NOT-EXIST'))
        self.assertFalse(block_device_live('/etc/hostname'))  # not a block device

    def test_required_media_presence_lists_missing(self):
        ok, missing = required_media_presence([
            {'path': '/dev/disk/by-id/usb-KER-ROOT-missing'},
            {'path': '/dev/disk/by-id/usb-KER-PERM-missing'},
        ])
        self.assertFalse(ok)
        self.assertEqual(len(missing), 2)

    def test_empty_media_list_is_present(self):
        ok, missing = required_media_presence([])
        self.assertTrue(ok)
        self.assertEqual(missing, [])



    def test_serial_from_by_id_path(self):
        from ker.devices import serial_from_media
        self.assertEqual(
            serial_from_media({'path': '/dev/disk/by-id/usb-QEMU_QEMU_HARDDISK_KER-PERM-0:0'}),
            'KER-PERM',
        )
        self.assertEqual(serial_from_media({'serial': 'KER-BOOT', 'path': '/dev/foo'}), 'KER-BOOT')

    def test_serials_up_from_block_finds_usb_parent(self):
        import tempfile
        from ker.devices import serials_up_from_block
        root = _Path(tempfile.mkdtemp())
        usb = root / 'devices' / 'usb2' / '2-2'
        scsi = usb / 'iface' / 'host1' / 'target' / '1:0:0:0'
        scsi.mkdir(parents=True)
        blk = root / 'class' / 'block' / 'sdb'
        blk.mkdir(parents=True)
        (blk / 'device').symlink_to(scsi)
        (usb / 'serial').write_text('KER-PERM\n')
        (root / 'devices' / 'usb2' / 'serial').write_text('0000:00:03.0\n')
        found = serials_up_from_block(blk)
        self.assertIn('KER-PERM', found)
        self.assertIn('0000:00:03.0', found)


class RefreshDenyFirstTests(unittest.TestCase):
    def _state(self):
        return {
            'initialized': True,
            'kernel_enforcement': True,
            'permissions': ['read', 'write', 'run', 'network'],
            'media': [{'path': '/dev/disk/by-id/usb-KER-PERM'}],
        }

    def test_missing_media_denies_without_verify(self):
        st = self._state()
        medium = st['media'][0]
        with patch('ker.enforce.load_state', return_value=st), \
             patch('ker.enforce.may_load_bpf', return_value=True), \
             patch('ker.enforce._ensure_bpf_if_enforcing', return_value=True), \
             patch('ker.enforce.runtime_presence', return_value=([], [medium], [], [medium])), \
             patch('ker.enforce.update_maps') as maps, \
             patch('ker.enforce.read_maps', return_value={'enforcement': True, 'media_ok': False, 'deny_mask': 0}), \
             patch('ker.enforce.verify_each') as verify:
            r = apply_presence(verify_if_present=True)
        verify.assert_not_called()
        maps.assert_called_once()
        self.assertFalse(maps.call_args.kwargs['media_ok'])
        self.assertTrue(maps.call_args.kwargs['enforcement'])
        self.assertFalse(r['media_ok'])
        self.assertEqual(r['missing'], ['/dev/disk/by-id/usb-KER-PERM'])

    def test_presence_only_skips_verify_when_already_allowed(self):
        st = self._state()
        medium = st['media'][0]
        with patch('ker.enforce.load_state', return_value=st), \
             patch('ker.enforce.may_load_bpf', return_value=True), \
             patch('ker.enforce._ensure_bpf_if_enforcing', return_value=True), \
             patch('ker.enforce.runtime_presence', return_value=([medium], [], [medium], [])), \
             patch('ker.enforce.update_maps') as maps, \
             patch('ker.enforce.read_maps', return_value={'enforcement': True, 'media_ok': True, 'deny_mask': 0}), \
             patch('ker.enforce.verify_each') as verify:
            r = apply_presence(verify_if_present=False)
        verify.assert_not_called()
        maps.assert_not_called()
        self.assertTrue(r.get('unchanged'))
        self.assertTrue(r['media_ok'])

    def test_all_present_and_denied_runs_verify_to_allow(self):
        st = self._state()
        medium = st['media'][0]
        with patch('ker.enforce.load_state', return_value=st), \
             patch('ker.enforce.may_load_bpf', return_value=True), \
             patch('ker.enforce._ensure_bpf_if_enforcing', return_value=True), \
             patch('ker.enforce.runtime_presence', return_value=([medium], [], [medium], [])), \
             patch('ker.enforce.update_maps') as maps, \
             patch('ker.enforce.read_maps', return_value={'enforcement': True, 'media_ok': False, 'deny_mask': 0}), \
             patch('ker.enforce.verify_each', return_value={'ok': True, 'missing': [], 'failed': [], 'results': []}), \
             patch('ker.enforce._flock') as flock:
            flock.return_value.__enter__ = lambda s: None
            flock.return_value.__exit__ = lambda s, *a: False
            r = apply_presence(verify_if_present=False)
        maps.assert_called()
        self.assertTrue(maps.call_args.kwargs['media_ok'])
        self.assertTrue(r['verified'])
        self.assertTrue(r['media_ok'])

    def test_uninitialized_or_not_enforcing_skips(self):
        st = {'initialized': True, 'kernel_enforcement': False, 'media': []}
        with patch('ker.enforce.load_state', return_value=st), \
             patch('ker.enforce.update_maps') as maps:
            r = apply_presence(verify_if_present=True)
        maps.assert_not_called()
        self.assertTrue(r.get('skipped'))

    def test_root_commands_still_denied_when_media_missing(self):
        from ker.enforce import path_is_allowed_exec
        mask = (1 << 0) | (1 << 1) | (1 << 2)  # run|read|write
        self.assertTrue(would_deny(enforcement=True, media_ok=False,
                                   deny_mask_value=mask, bit=1 << 1, allowed=False))
        self.assertFalse(is_allowed_comm('bash'))
        self.assertFalse(is_allowed_comm('cat'))
        self.assertFalse(is_allowed_comm('systemd'))
        self.assertFalse(path_is_allowed_exec('/tmp/systemd'))
        self.assertTrue(path_is_allowed_exec('/usr/lib/systemd/systemd-udevd'))

    def test_one_permission_medium_denies_only_its_bits(self):
        from ker.enforce import BIT, bits_for_medium, denied_bits
        st = {
            'initialized': True,
            'kernel_enforcement': True,
            'permissions': ['read', 'write', 'run', 'network', 'ssh', 'rootuser'],
            'media': [
                {'path': '/dev/root', 'keys': ['root.pem', 'read.pem', 'write.pem', 'run.pem', 'network.pem', 'rootuser.pem'], 'role': 'root'},
                {'path': '/dev/ssh', 'keys': ['ssh.pem'], 'role': 'keys'},
                {'path': '/dev/admin', 'keys': ['admin.pem'], 'role': 'admin'},
            ],
        }
        root, ssh, admin = st['media']
        self.assertEqual(bits_for_medium(ssh, st), BIT['ssh'])
        self.assertEqual(bits_for_medium(admin, st), 0)
        self.assertEqual(bits_for_medium(root, st),
                         BIT['read'] | BIT['write'] | BIT['run'] | BIT['network'] | BIT['ssh'] | BIT['rootuser'])
        ssh_only = denied_bits(st, [ssh])
        self.assertEqual(ssh_only, BIT['ssh'])
        self.assertFalse(ssh_only & BIT['read'])
        self.assertFalse(ssh_only & BIT['write'])
        self.assertFalse(ssh_only & BIT['run'])
        self.assertFalse(ssh_only & BIT['network'])
        self.assertEqual(denied_bits(st, [admin]), 0)
        self.assertEqual(denied_bits(st, [root]), bits_for_medium(root, st))

        with patch('ker.enforce.load_state', return_value=st), \
             patch('ker.enforce.may_load_bpf', return_value=True), \
             patch('ker.enforce._ensure_bpf_if_enforcing', return_value=True), \
             patch('ker.enforce.runtime_presence', return_value=([root], [ssh], [root, admin], [ssh])), \
             patch('ker.enforce.update_maps') as maps, \
             patch('ker.enforce.read_maps', return_value={'enforcement': True, 'media_ok': True, 'deny_mask': 0}), \
             patch('ker.enforce.verify_each') as verify:
            r = apply_presence(verify_if_present=True)
        verify.assert_not_called()
        self.assertEqual(maps.call_args.kwargs['deny_mask_value'], BIT['ssh'])
        self.assertFalse(maps.call_args.kwargs['media_ok'])
        self.assertEqual(r['denied_bits'], BIT['ssh'])

    def test_may_mask_matches_kernel_constants(self):
        from ker.enforce import BIT, classify_file_mask
        src = (_Path(__file__).resolve().parents[1] / 'src' / 'bpf' / 'ker.bpf.c').read_text()
        fn = src.split('SEC("lsm/file_permission")', 1)[1].split('SEC(', 1)[0]
        self.assertIn('MAY_EXEC', fn)
        self.assertIn('BIT_RUN', fn)
        self.assertNotIn('bits |= BIT_READ', fn.split('MAY_READ')[0])
        self.assertEqual(classify_file_mask(0x01), BIT['run'])
        self.assertEqual(classify_file_mask(0x02), BIT['write'])
        self.assertEqual(classify_file_mask(0x04), BIT['read'])
        self.assertEqual(classify_file_mask(0x01 | 0x04), BIT['run'] | BIT['read'])
        self.assertEqual(classify_file_mask(0x02 | 0x04), BIT['write'] | BIT['read'])
        self.assertEqual(classify_file_mask(0x08), BIT['write'])
        self.assertEqual(classify_file_mask(0), 0)
        self.assertEqual(classify_file_mask(0x01 | 0x02 | 0x04), BIT['run'] | BIT['write'] | BIT['read'])


class BootRestoreTests(unittest.TestCase):
    def test_ensure_bpf_skips_when_enforcement_off(self):
        from ker.enforce import _ensure_bpf_if_enforcing
        with patch('ker.enforce.load_bpf') as load:
            self.assertFalse(_ensure_bpf_if_enforcing({'kernel_enforcement': False}))
            load.assert_not_called()

    def test_ensure_bpf_loads_when_maps_missing(self):
        from pathlib import Path as P
        from ker.enforce import EnforceError, _ensure_bpf_if_enforcing
        with patch('ker.enforce.may_load_bpf', return_value=True), \
             patch('ker.enforce._map_path', side_effect=[EnforceError('missing'), P('/tmp/fake')]), \
             patch('ker.enforce.load_bpf') as load:
            self.assertTrue(_ensure_bpf_if_enforcing({'kernel_enforcement': True}))
            load.assert_called_once()

    def test_ensure_bpf_does_not_load_when_maps_present(self):
        from pathlib import Path as P
        from ker.enforce import _ensure_bpf_if_enforcing
        with patch('ker.enforce.may_load_bpf', return_value=True), \
             patch('ker.enforce._map_path', return_value=P('/tmp/fake')), \
             patch('ker.enforce.load_bpf') as load:
            self.assertTrue(_ensure_bpf_if_enforcing({'kernel_enforcement': True}))
            load.assert_not_called()

    def test_apply_presence_restores_when_maps_missing(self):
        from contextlib import nullcontext
        st = {'initialized': True, 'kernel_enforcement': True, 'media': [], 'permissions': []}
        with patch('ker.enforce.load_state', return_value=st), \
             patch('ker.enforce.may_load_bpf', return_value=True), \
             patch('ker.enforce._ensure_bpf_if_enforcing', return_value=True) as ens, \
             patch('ker.enforce.runtime_presence', return_value=([], [], [], [])), \
             patch('ker.enforce.read_maps', side_effect=[None, {'media_ok': True}]), \
             patch('ker.enforce.verify_each', return_value={'ok': True, 'missing': [], 'failed': [], 'results': []}), \
             patch('ker.enforce._flock', return_value=nullcontext()), \
             patch('ker.enforce._push_maps') as push:
            r = apply_presence(verify_if_present=False)
        ens.assert_called_once()
        push.assert_called()
        self.assertTrue(r.get('verified'))

    def test_set_enforcement_enables_units(self):
        from ker.enforce import set_enforcement
        st = {'initialized': True, 'kernel_enforcement': False, 'permissions': []}
        with patch('ker.enforce.load_state', return_value=st), \
             patch('ker.cluster.assert_not_fail_closed'), \
             patch('ker.enforce.media_present', return_value=(True, [])), \
             patch('ker.enforce.media_ok', return_value=True), \
             patch('ker.enforce.may_load_bpf', return_value=True), \
             patch('ker.enforce.load_bpf'), \
             patch('ker.enforce.update_maps'), \
             patch('ker.enforce.save_state'), \
             patch('ker.enforce.sync_enforcer_units', return_value={'ok': True, 'enabled': True}) as sync:
            r = set_enforcement(True, already_confirmed=True)
        sync.assert_called_once_with(True)
        self.assertTrue(r['kernel_enforcement'])

    def test_set_enforcement_disables_units(self):
        from ker.enforce import set_enforcement
        st = {'initialized': True, 'kernel_enforcement': True, 'permissions': []}
        pin = MagicMock()
        pin.exists.return_value = False
        with patch('ker.enforce.load_state', return_value=st), \
             patch('ker.cluster.assert_not_fail_closed'), \
             patch('ker.enforce.may_load_bpf', return_value=True), \
             patch('ker.enforce.PIN_DIR', pin), \
             patch('ker.enforce.update_maps'), \
             patch('ker.enforce.save_state'), \
             patch('ker.enforce.sync_enforcer_units', return_value={'ok': True, 'enabled': False}) as sync:
            r = set_enforcement(False, already_confirmed=True)
        sync.assert_called_once_with(False)
        self.assertFalse(r['kernel_enforcement'])

    def test_sync_units_skipped_when_systemd_unavailable(self):
        from ker.enforce import sync_enforcer_units
        with patch('ker.enforce._systemd_available', return_value=False), \
             patch('ker.enforce.subprocess.run') as run:
            r = sync_enforcer_units(True)
        run.assert_not_called()
        self.assertTrue(r.get('skipped'))


if __name__ == '__main__':
    unittest.main()
