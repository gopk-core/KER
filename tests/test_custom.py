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

    def test_scoped_rules_do_not_grant_global_bits_or_other_subjects(self):
        from ker.custom import custom_authorizes, governed_subject, rule_expressible
        from ker.enforce import BIT, custom_bits, decide_subject, policy_bits, scope_plan
        command = validate_custom({
            'name': 'tool', 'type': 'command', 'mode': 'grant',
            'constraints': {'paths': ['/opt/x']},
        })
        login = validate_custom({
            'name': 'alice', 'type': 'login', 'mode': 'grant',
            'constraints': {'users': ['alice']},
        })
        network = validate_custom({
            'name': 'web', 'type': 'network', 'mode': 'grant',
            'constraints': {'ports': [443]},
        })
        vague = validate_custom({
            'name': 'lan', 'type': 'network', 'mode': 'grant',
            'constraints': {'addrs': ['10.0.0.0/8']},
        })
        st = {
            'permissions': [],
            'custom': [command, login, network, vague],
            'media': [{'path': '/dev/custom', 'keys': ['tool.pem', 'alice.pem', 'web.pem', 'lan.pem']}],
        }
        self.assertEqual(policy_bits(st), 0)
        for item in st['custom']:
            self.assertEqual(custom_bits(item), 0)
        active = {'tool.pem', 'alice.pem', 'web.pem', 'lan.pem'}
        self.assertTrue(custom_authorizes(st, kind='command', path='/opt/x', active_keys=active))
        self.assertFalse(custom_authorizes(st, kind='command', path='/opt/other', active_keys=active))
        self.assertFalse(custom_authorizes(st, kind='command', path='/opt/x2', active_keys=active))
        self.assertFalse(custom_authorizes(st, kind='command', path='/usr/bin/id', active_keys=active))
        self.assertFalse(custom_authorizes(st, kind='command', path='/opt/x', active_keys=set()))
        self.assertTrue(custom_authorizes(st, kind='login', user='alice', active_keys=active))
        self.assertFalse(custom_authorizes(st, kind='login', user='bob', active_keys=active))
        self.assertFalse(custom_authorizes(st, kind='login', user='alice2', active_keys=active))
        self.assertTrue(custom_authorizes(st, kind='network', port=443, active_keys=active))
        self.assertFalse(custom_authorizes(st, kind='network', port=22, active_keys=active))
        self.assertFalse(custom_authorizes(st, kind='network', port=80, active_keys=active))
        self.assertFalse(rule_expressible(vague))
        self.assertFalse(custom_authorizes(st, kind='network', port=443, active_keys={'lan.pem'}))
        self.assertTrue(governed_subject(st, kind='login', user='alice'))
        self.assertFalse(governed_subject(st, kind='login', user='bob'))
        self.assertTrue(decide_subject(
            enforcement=True, media_ok=False, deny_mask_value=BIT['run'],
            bit=BIT['run'], allowed=False, in_scope=False,
        ))
        self.assertFalse(decide_subject(
            enforcement=True, media_ok=False, deny_mask_value=BIT['run'],
            bit=BIT['run'], allowed=False, in_scope=True, scope_allow=BIT['run'],
        ))
        self.assertTrue(decide_subject(
            enforcement=True, media_ok=False, deny_mask_value=BIT['run'],
            bit=BIT['run'], allowed=False, in_scope=True, scope_allow=BIT['read'],
        ))
        plan = scope_plan(st, verified=True, inactive_keys=set())
        self.assertEqual(plan['narrow_mask'], 0)
        self.assertEqual(plan['port_allow'].get(443), BIT['network'])
        self.assertNotIn(22, plan['port_allow'])
        self.assertNotIn(80, plan['port_allow'])

    def test_replace_narrows_only_while_active_and_login_hook_is_per_user(self):
        import tempfile
        from ker.enforce import BIT, scope_plan
        from ker.hooks import merge_login_constraint
        with tempfile.TemporaryDirectory() as tmp:
            tool = Path(tmp) / 'tool'
            tool.write_text('x')
            item = validate_custom({
                'name': 'onlytool', 'type': 'command', 'mode': 'replace',
                'constraints': {'paths': [str(tool)]},
            })
            st_tool = {'permissions': ['run'], 'custom': [item]}
            self.assertEqual(scope_plan(st_tool, verified=True, inactive_keys=set())['narrow_mask'], BIT['run'])
            self.assertEqual(
                scope_plan(st_tool, verified=False, inactive_keys={'onlytool.pem'})['narrow_mask'],
                0,
            )
            missing = validate_custom({
                'name': 'gone', 'type': 'command', 'mode': 'replace',
                'constraints': {'paths': ['/opt/does-not-exist-ker']},
            })
            self.assertEqual(
                scope_plan({'custom': [missing]}, verified=True, inactive_keys=set())['narrow_mask'],
                0,
            )
        login = validate_custom({
            'name': 'alice', 'type': 'login', 'mode': 'lock',
            'constraints': {'users': ['alice'], 'uids': [1000]},
        })
        st = {'permissions': ['run'], 'custom': [login], 'kernel_enforcement': True, 'mode': 'enforce'}
        base = {'allow': True, 'block': False, 'mode': 'enforce'}
        alice = merge_login_constraint(base, 'alice', st, active_keys={'alice.pem'})
        self.assertFalse(alice['block'])
        bob = merge_login_constraint(dict(base), 'bob', st, active_keys={'alice.pem'})
        self.assertFalse(bob['block'])
        self.assertEqual(bob['custom_login'], 'not_governed')
        denied = merge_login_constraint(dict(base), 'alice', st, active_keys=set())
        self.assertTrue(denied['block'])
        self.assertEqual(denied['reason'], 'CUSTOM_LOGIN_DENIED')

    def test_service_shell_is_not_a_global_exec_grant(self):
        import tempfile
        from ker.custom import service_exec_path
        from ker.enforce import BIT, policy_bits, scope_plan
        with tempfile.TemporaryDirectory() as tmp:
            unit_dir = Path(tmp)
            (unit_dir / 'backup.service').write_text('[Service]\nExecStart=/bin/bash -c /opt/backup\n')
            (unit_dir / 'tool.service').write_text('[Service]\nExecStart=/opt/x\n')
            self.assertIsNone(service_exec_path('backup.service', search=(unit_dir,)))
            self.assertEqual(service_exec_path('tool.service', search=(unit_dir,)), '/opt/x')
            self.assertIsNone(service_exec_path('../evil.service', search=(unit_dir,)))
        item = validate_custom({
            'name': 'backup', 'type': 'service', 'mode': 'grant',
            'constraints': {'units': ['backup.service']},
        })
        st = {'permissions': [], 'custom': [item]}
        self.assertEqual(policy_bits(st) & BIT['run'], 0)
        self.assertEqual(scope_plan(st, verified=True, inactive_keys=set())['ino_allow'], {})


if __name__ == '__main__':
    unittest.main()
