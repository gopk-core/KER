import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'python'))
from ker.custom import CustomError, validate_custom

class CustomTests(unittest.TestCase):
    def test_ok(self):
        item = validate_custom({'name': 'backup', 'type': 'file_write', 'mode': 'grant',
                                'constraints': {'paths': ['/var/backups']}})
        self.assertEqual(item['key'], 'backup.pem')

    def test_reject_all_files(self):
        with self.assertRaises(CustomError):
            validate_custom({'name': 'all', 'type': 'file_write', 'constraints': {'paths': ['/']}})

    def test_reject_relative(self):
        with self.assertRaises(CustomError):
            validate_custom({'name': 'x', 'type': 'file_read', 'constraints': {'paths': ['tmp/x']}})

if __name__ == '__main__':
    unittest.main()
