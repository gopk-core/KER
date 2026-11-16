"""Policy tests for the boot and SSH hooks."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'python'))


def _losetup(img: Path) -> str:
    return subprocess.check_output(['losetup', '--show', '--find', str(img)], text=True).strip()


class HookPolicyTests(unittest.TestCase):
    def test_inactive_when_not_initialized(self):
        with tempfile.TemporaryDirectory(prefix='ker-hook-') as tmp:
            env = os.environ.copy()
            env['KER_PREFIX'] = tmp
            env['PYTHONPATH'] = str(ROOT / 'python')
            r = subprocess.run(
                [sys.executable, '-c',
                 'from ker.hooks import authorize; import json; print(json.dumps(authorize("boot")))'],
                env=env, capture_output=True, text=True,
            )
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            d = json.loads(r.stdout)
            self.assertTrue(d['allow'])
            self.assertFalse(d['block'])
            self.assertEqual(d['reason'], 'NOT_INITIALIZED')

    def test_boot_and_ssh_allow_deny(self):
        if os.geteuid() != 0:
            self.skipTest('root required for loop devices')
        with tempfile.TemporaryDirectory(prefix='ker-hook-') as tmp:
            tmp = Path(tmp)
            media_root = tmp / 'root.img'
            media_admin = tmp / 'admin.img'
            media_ssh = tmp / 'ssh.img'
            for p in (media_root, media_admin, media_ssh):
                subprocess.check_call(['truncate', '-s', '256M', str(p)])
            loop_devs = []
            env = os.environ.copy()
            env['KER_PREFIX'] = str(tmp)
            env['PYTHONPATH'] = str(ROOT / 'python')
            try:
                for img in (media_root, media_admin, media_ssh):
                    loop_devs.append(_losetup(img))
                d_root, d_admin, d_ssh = loop_devs
                media = [
                    {'path': d_root, 'kind': 'disk',
                     'keys': ['root.pem', 'boot.pem', 'write.pem'], 'role': 'root'},
                    {'path': d_admin, 'kind': 'disk', 'keys': ['admin.pem'], 'role': 'admin'},
                    {'path': d_ssh, 'kind': 'disk', 'keys': ['ssh.pem'], 'role': 'keys'},
                ]
                r = subprocess.run(
                    [sys.executable, '-m', 'ker', '--language', 'en', 'init', '--yes',
                     '--permissions', 'boot,ssh,write', '--assume-replug',
                     '--media-json', json.dumps(media)],
                    env=env, capture_output=True, text=True,
                )
                self.assertEqual(r.returncode, 0, r.stdout + '\n' + r.stderr)

                def decide(perm, extra=''):
                    code = (
                        'from ker.hooks import authorize; import json,sys; '
                        f'd=authorize({perm!r}, scan=False); print(json.dumps(d))'
                    )
                    rr = subprocess.run(
                        [sys.executable, '-c', extra + code],
                        env=env, capture_output=True, text=True,
                    )
                    self.assertEqual(rr.returncode, 0, rr.stdout + rr.stderr)
                    return json.loads(rr.stdout)

                # test mode, media present
                for perm in ('boot', 'ssh'):
                    d = decide(perm)
                    self.assertTrue(d['allow'], d)
                    self.assertFalse(d['block'], d)
                    self.assertTrue(d['verified'], d)
                    self.assertEqual(d['mode'], 'test')
                    self.assertEqual(d['reason'], 'OK')

                # test mode, ssh media missing: still allow
                hide = (
                    'from ker.state import state, save_state; '
                    'st=state(); '
                    'st["_media_backup"]=list(st["media"]); '
                    'st["media"]=[m for m in st["media"] if "ssh.pem" not in m.get("keys",[])]; '
                    'save_state(st); '
                )
                d = decide('ssh', hide)
                self.assertTrue(d['allow'], d)
                self.assertFalse(d['block'], d)
                self.assertFalse(d['verified'], d)
                self.assertEqual(d['mode'], 'test')

                # restore media list, switch to enforce without loading BPF
                restore = (
                    "from ker.state import state, save_state\n"
                    "st=state()\n"
                    "if st.get('_media_backup'):\n"
                    "    st['media']=st.pop('_media_backup')\n"
                    "st['mode']='enforce'\n"
                    "st['kernel_enforcement']=True\n"
                    "save_state(st)\n"
                )
                subprocess.run([sys.executable, '-c', restore], env=env, check=True)

                d = decide('boot')
                self.assertTrue(d['allow'] and d['verified'] and not d['block'], d)
                self.assertEqual(d['mode'], 'enforce')
                d = decide('ssh')
                self.assertTrue(d['allow'] and d['verified'] and not d['block'], d)

                # enforce + missing ssh media -> deny
                d = decide('ssh', hide)
                self.assertFalse(d['allow'], d)
                self.assertTrue(d['block'], d)
                self.assertFalse(d['verified'], d)

                # enforce + boot media present still ok
                d = decide('boot')
                self.assertTrue(d['allow'] and d['verified'], d)

                # permission not selected -> inactive allow even in enforce
                other = (
                    'from ker.hooks import authorize; import json; '
                    'from ker.state import state, save_state; '
                    'st=state(); st["permissions"]=["write"]; save_state(st); '
                    'print(json.dumps(authorize("boot", scan=False)))'
                )
                rr = subprocess.run([sys.executable, '-c', other], env=env, capture_output=True, text=True)
                self.assertEqual(rr.returncode, 0, rr.stderr)
                d = json.loads(rr.stdout)
                self.assertTrue(d['allow'] and not d['block'])
                self.assertEqual(d['reason'], 'PERMISSION_NOT_SELECTED')
            finally:
                for d in loop_devs:
                    subprocess.run(['losetup', '-d', d], capture_output=True)

    def test_mount_failure_is_recorded(self):
        from ker import hooks
        hooks._MOUNT_ERRORS.clear()
        with tempfile.TemporaryDirectory(prefix='ker-mntfail-') as tmp:
            dest = Path(tmp) / 'mnt'
            ok = hooks._mount_ro('/dev/ker-no-such-device', dest)
            self.assertFalse(ok)
            self.assertTrue(hooks._MOUNT_ERRORS, 'mount failures must be recorded')
            blob = '\n'.join(hooks._MOUNT_ERRORS)
            self.assertIn('ker-no-such-device', blob)


class HookPackagingContractTests(unittest.TestCase):
    def test_hook_initrd_builder_copies_all_elf_deps(self):
        text = (ROOT / 'scripts' / 'build-hook-initrd.sh').read_text()
        self.assertIn('copy_deps_of', text)
        self.assertIn("find \"$DEST\" -type f ! -path '*/lib/modules/*'", text)
        self.assertIn('export PATH=/bin:/sbin:/usr/bin:/usr/sbin', text)
        self.assertIn('/bin/busybox --install -s /bin', text)

    def test_packaged_boot_hook_prefers_bin_path(self):
        boot = (ROOT / 'hooks/initramfs-tools/scripts/local-premount/ker-boot').read_text()
        self.assertIn('PATH="/bin:/sbin:/usr/bin:/usr/sbin"', boot)
        self.assertIn('mount.err', boot)
        # Result volume must be selected by KERRESULT label only — never a
        # bare /dev/sdd or /dev/vdd fallback, which can be authorization media.
        self.assertIn('RESULT_LABEL=KERRESULT', boot)
        self.assertIn('find_result_dev', boot)
        self.assertIn('fs_label', boot)
        self.assertNotIn('/dev/disk/by-label/KERRESULT /dev/vdd /dev/sdd', boot)


    def test_lab_initrd_runs_boot_hook(self):
        init_path = ROOT / 'lab' / 'initrd-init.sh'
        prep_path = ROOT / 'scripts' / 'lab-prepare-image.sh'
        if not init_path.is_file() or not prep_path.is_file():
            self.skipTest('lab tree is local-only')
        init = init_path.read_text()
        prep = prep_path.read_text()
        self.assertIn('lab/initrd-init.sh', prep)
        self.assertIn('usb-storage', prep)
        self.assertIn('xhci-pci', prep)
        self.assertIn('vfat', prep)
        self.assertIn('nls_ascii', prep)
        self.assertIn('--initrd-only', prep)
        # Build-time busybox --install writes absolute host paths.
        self.assertNotIn('--install -s "$dest/bin"', prep.replace('  ', ' '))
        self.assertIn('Do not --install at build time', prep)
        self.assertIn('/bin/busybox', init)
        # Fail closed: missing/unverified boot.pem must not switch_root.
        self.assertIn('refusing to continue to the real root', init)
        self.assertIn('local-premount/ker-boot', init)
        self.assertIn('ker-boot-check', init)
        self.assertIn('poweroff -f', init)
        self.assertIn('switch_root', init)
        # The hook must see USB boot media (modules packed by the builder,
        # loaded with a multi-pass insmod of every bundled .ko).
        self.assertIn('usb-storage', prep)
        self.assertIn('xhci-pci', prep)
        self.assertIn('vfat', prep)
        self.assertIn('insmod', init)
        self.assertIn("name '*.ko'", init)
        # Live state from the disk, not a stale baked-in copy.
        self.assertIn('/newroot/etc/ker/state.json', init)
        # Writable tmp for python tempfile during the ro-root chroot verify.
        self.assertIn('mount -t tmpfs tmpfs /newroot/tmp', init)
        self.assertIn('export TMPDIR=/tmp', init)
        # Wait until USB disks settle; do not break on the first sdX.
        self.assertIn('usb_disks', init)
        self.assertIn('"$n" -ge 5', init)
        self.assertNotIn('ls /dev/sd[a-z] >/dev/null 2>&1 || $BB ls /dev/disk/by-id/usb-*', init)
        # Refuse path unmounts and never reaches switch_root (function returns via loop).
        self.assertIn('refuse_boot', init)
        refuse = init.split('refuse_boot()', 1)[1].split('}', 1)[0]
        self.assertNotIn('switch_root', refuse)


class VerifiedKeyCacheTests(unittest.TestCase):
    def test_second_hook_skips_verify_and_unplug_drops_the_key(self):
        from unittest.mock import patch
        from ker.hooks import invalidate_verified_custom_keys, merge_login_constraint, verified_custom_keys
        alice = {'path': '/dev/ker-alice', 'media_id': 'a', 'role': 'keys', 'keys': ['alice.pem']}
        bob = {'path': '/dev/ker-bob', 'media_id': 'b', 'role': 'keys', 'keys': ['bob.pem']}
        st = {
            'initialized': True, 'key_generation': 3,
            'gpg_fingerprint': 'A' * 40, 'kernel_cert_sha256': 'b' * 64,
            'kernel_enforcement': True, 'mode': 'enforce',
            'custom': [{
                'name': 'alice', 'type': 'login', 'mode': 'lock', 'key': 'alice.pem',
                'constraints': {'users': ['alice']},
            }],
            'media': [alice, bob],
        }
        box = {'present': [alice, bob], 'missing': []}
        calls = {'n': 0}

        def presence(_st=None):
            return list(box['present']), list(box['missing'])

        def verify(_st, devices=None, **kwargs):
            calls['n'] += 1
            return {
                'ok': True, 'missing': [], 'failed': [],
                'results': [{'ok': True, 'path': m.get('path')} for m in (devices or [])],
            }

        with tempfile.TemporaryDirectory(prefix='ker-keycache-') as tmp, \
             patch('ker.paths.RUN_DIR', Path(tmp)), \
             patch('ker.enforce.presence_sets', side_effect=presence), \
             patch('ker.testmode.verify_each', side_effect=verify):
            invalidate_verified_custom_keys()
            first = verified_custom_keys(st)
            second = verified_custom_keys(st)
            self.assertEqual(first, {'alice.pem', 'bob.pem'})
            self.assertEqual(second, first)
            self.assertEqual(calls['n'], 1)
            base = {'allow': True, 'block': False, 'mode': 'enforce'}
            pam = merge_login_constraint(base, 'alice', st)
            self.assertFalse(pam['block'])
            self.assertEqual(calls['n'], 1)

            box['present'] = [alice]
            box['missing'] = [bob]
            dropped = verified_custom_keys(st)
            self.assertIn('alice.pem', dropped)
            self.assertNotIn('bob.pem', dropped)
            # The removed key is gone without a TTL. A fresh verify of what
            # remains is fine; the old verified set is not reused.
            self.assertGreaterEqual(calls['n'], 2)

            box['present'] = [alice, bob]
            box['missing'] = []
            invalidate_verified_custom_keys()

            def fail_bob(_st, devices=None, **kwargs):
                calls['n'] += 1
                return {
                    'ok': False, 'missing': [], 'failed': [bob],
                    'results': [
                        {'ok': True, 'path': alice['path']},
                        {'ok': False, 'path': bob['path']},
                    ],
                }

            with patch('ker.testmode.verify_each', side_effect=fail_bob):
                failed = verified_custom_keys(st)
                mark = calls['n']
                again = verified_custom_keys(st)
            self.assertIn('alice.pem', failed)
            self.assertNotIn('bob.pem', failed)
            self.assertEqual(again, failed)
            self.assertEqual(calls['n'], mark)

            # A generation change must not keep the previous verified set.
            st['key_generation'] = 4
            with patch('ker.testmode.verify_each', side_effect=verify):
                before = calls['n']
                regenerated = verified_custom_keys(st)
                self.assertEqual(calls['n'], before + 1)
            self.assertEqual(regenerated, {'alice.pem', 'bob.pem'})


class VmScriptGuardTests(unittest.TestCase):
    def test_guest_scripts_do_not_touch_the_host(self):
        vm = (ROOT / 'scripts' / 'vm-test.sh').read_text()
        guest = (ROOT / 'scripts' / 'vm-selftest.sh').read_text()
        self.assertIn('chroot "$ROOTFS" dpkg -i', vm)
        self.assertIn('Never dpkg -i on the host', vm)
        self.assertIn('env -u KER_ALLOW_HOST_BPF', vm)
        self.assertNotIn('bpftool', vm)
        self.assertIn('[ "$$" -ne 1 ]', guest)
        self.assertIn('init=/usr/lib/ker/vm-selftest.sh', guest)
        self.assertIn('ker.selftest=phase2', guest)

