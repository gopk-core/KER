"""Packaging metadata and (when present) built artifact checks."""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'python'))

ARCHES = ['amd64', 'arm64', 'armhf', 'i386', 'riscv64']


class PackagingTests(unittest.TestCase):
    def test_version_is_0_1(self):
        import ker
        self.assertEqual(ker.__version__, '0.1.0')

    def test_arch_map_covers_matrix(self):
        meta = json.loads((ROOT / 'packaging' / 'arches.json').read_text())
        self.assertEqual(set(meta), set(ARCHES))
        for name, row in meta.items():
            for key in ('deb', 'rpm', 'apk', 'arch', 'bpf_target', 'cc'):
                self.assertIn(key, row, msg=f'{name}.{key}')
        self.assertEqual(meta['amd64']['rpm'], 'x86_64')
        self.assertEqual(meta['armhf']['arch'], 'armv7h')
        self.assertEqual(meta['i386']['apk'], 'x86')

    def test_new_features_in_catalog(self):
        from ker.features import FEATURES, SCHEMA1_FEATURE_IDS
        for fid in ('boot_hook', 'ssh_hook', 'multiarch_packages'):
            self.assertIn(fid, FEATURES)
            self.assertNotIn(fid, SCHEMA1_FEATURE_IDS)
            self.assertFalse(FEATURES[fid].provision_needed)

    def test_built_packages_if_present(self):
        import ker
        ver = ker.__version__
        meta = json.loads((ROOT / 'packaging' / 'arches.json').read_text())
        dist = ROOT / 'dist'
        expected = []
        for a, row in meta.items():
            expected.append(dist / f'ker_{ver}_{row["deb"]}.deb')
            expected.append(dist / f'ker-{ver}-1.{row["rpm"]}.rpm')
            expected.append(dist / f'ker-{ver}-r0.{row["apk"]}.apk')
            expected.append(dist / f'ker-{ver}-1-{row["arch"]}.pkg.tar.zst')
        present = [p for p in expected if p.is_file()]
        if not present:
            self.skipTest('packages not built yet')
        self.assertEqual(len(present), len(expected),
                         'missing: ' + ', '.join(str(p) for p in expected if not p.is_file()))

        # Probe ELF architecture in a couple of debs / all debs.
        file_of = {
            'amd64': 'x86-64',
            'arm64': 'aarch64',
            'armhf': 'ARM',
            'i386': 'Intel i386',
            'riscv64': 'RISC-V',
        }
        for a, row in meta.items():
            deb = dist / f'ker_{ver}_{row["deb"]}.deb'
            listing = subprocess.check_output(['dpkg-deb', '-c', str(deb)], text=True)
            for needle in (
                './usr/sbin/ker',
                './usr/lib/ker/ker/__init__.py',
                './usr/lib/ker/ker/hooks.py',
                './usr/lib/ker/bpf/ker.bpf.o',
                './usr/lib/ker/ker-probe',
                './usr/lib/ker/ker-boot-check',
                './usr/lib/ker/ker-ssh-pam',
                './usr/lib/ker/ker-ssh-keys',
                './usr/share/initramfs-tools/scripts/local-premount/ker-boot',
                './usr/lib/dracut/modules.d/90ker-boot/module-setup.sh',
                './usr/lib/initcpio/hooks/ker-boot',
                './usr/share/mkinitfs/hooks/ker-boot',
                './usr/lib/ker/upgrade-manifest.json',
            ):
                self.assertIn(needle, listing, msg=f'{deb} missing {needle}')
            ctrl = subprocess.check_output(['dpkg-deb', '-f', str(deb), 'Architecture', 'Version'], text=True)
            self.assertIn(row['deb'], ctrl)
            self.assertIn(ver, ctrl)
            # extract probe and check ELF
            work = Path('/tmp') / f'ker-pkgtest-{a}'
            if work.exists():
                subprocess.run(['rm', '-rf', str(work)], check=False)
            work.mkdir()
            subprocess.check_call(['dpkg-deb', '-x', str(deb), str(work)])
            archfile = (work / 'usr/lib/ker/arch').read_text().strip()
            self.assertEqual(archfile, a)
            probe = work / 'usr/lib/ker/ker-probe'
            desc = subprocess.check_output(['file', str(probe)], text=True)
            self.assertIn(file_of[a], desc, msg=desc)
            subprocess.run(['rm', '-rf', str(work)], check=False)

            # rpm / apk / arch at least exist and are non-empty archives
            for p in (
                dist / f'ker-{ver}-1.{row["rpm"]}.rpm',
                dist / f'ker-{ver}-r0.{row["apk"]}.apk',
                dist / f'ker-{ver}-1-{row["arch"]}.pkg.tar.zst',
            ):
                self.assertGreater(p.stat().st_size, 1000, msg=str(p))

    def test_postinst_creates_ker_python_before_ker(self):
        deb = (ROOT / 'packaging' / 'debian' / 'postinst').read_text()
        other = (ROOT / 'packaging' / 'scripts' / 'postinst.sh').read_text()
        for text, name in ((deb, 'debian/postinst'), (other, 'scripts/postinst.sh')):
            self.assertIn('ker-python', text, name)
            self.assertLess(text.find('ker-python'), text.find('/usr/sbin/ker upgrade'), name)


    def test_enforcer_watch_is_packaged(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        svc = (root / 'systemd/ker-enforcer.service').read_text()
        self.assertIn('ker enforce --watch', svc)
        self.assertIn('Restart=always', svc)
        poke = (root / 'systemd/ker-enforcer-poke.service').read_text()
        self.assertIn('ker enforce --presence', poke)
        rules = (root / 'udev/99-ker-enforcer.rules').read_text()
        self.assertIn('ker-enforcer-poke.service', rules)
        self.assertNotIn('enforce --refresh', rules)
        stage = (root / 'packaging/stage.sh').read_text()
        self.assertIn('99-ker-enforcer.rules', stage)
        self.assertIn('ker-enforcer-poke.service', stage)
        timer = (root / 'systemd/ker-enforcer.timer').read_text()
        self.assertIn('Unit=ker-enforcer-poke.service', timer)


    def test_rpm_files_are_generated_from_payload(self):
        src = (ROOT / 'packaging' / 'build-rpm.sh').read_text()
        self.assertIn('find usr -type f', src)
        self.assertIn('%files', src)
        self.assertIn('github.com/gopk-core/KER', src)
