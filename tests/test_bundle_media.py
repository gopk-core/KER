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


class BundleMediaTests(unittest.TestCase):
    def test_deploy_and_verify_two_virtual_disks(self):
        if os.geteuid() != 0:
            self.skipTest('root required for loop devices')
        with tempfile.TemporaryDirectory(prefix='ker-ut-') as tmp:
            tmp = Path(tmp)
            os.environ['KER_PREFIX'] = str(tmp)
            # reimport paths after prefix? modules may already be imported later
            # Import inside the prefix context as a subprocess for isolation.
            media1 = tmp / 'm1.img'
            media2 = tmp / 'm2.img'
            for p in (media1, media2):
                subprocess.check_call(['truncate', '-s', '256M', str(p)])
            d1 = _losetup(media1)
            d2 = _losetup(media2)
            try:
                env = os.environ.copy()
                env['KER_PREFIX'] = str(tmp)
                env['PYTHONPATH'] = str(ROOT / 'python')
                media = [
                    {'path': d1, 'kind': 'disk', 'keys': ['root.pem', 'write.pem'], 'role': 'root'},
                    {'path': d2, 'kind': 'disk', 'keys': ['admin.pem'], 'role': 'admin'},
                ]
                r = subprocess.run(
                    [sys.executable, '-m', 'ker', '--language', 'zh-CN', 'init', '--yes',
                     '--permissions', 'write', '--assume-replug',
                     '--media-json', json.dumps(media)],
                    env=env, capture_output=True, text=True,
                )
                if r.returncode != 0:
                    self.fail(r.stdout + '\n' + r.stderr)
                r2 = subprocess.run(
                    [sys.executable, '-m', 'ker', 'test-media', '--assume-replug'],
                    env=env, capture_output=True, text=True,
                )
                self.assertEqual(r2.returncode, 0, r2.stdout + r2.stderr)
                data = json.loads(r2.stdout)
                self.assertTrue(data['ok'])
                self.assertEqual(len(data['results']), 2)
            finally:
                subprocess.run(['losetup', '-d', d1], capture_output=True)
                subprocess.run(['losetup', '-d', d2], capture_output=True)


if __name__ == '__main__':
    unittest.main()
