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

    def test_network_address_is_not_widened_to_the_port(self):
        import ipaddress
        from ker.custom import custom_authorizes, rule_expressible
        from ker.enforce import BIT, connect_scope_bits, scope_plan
        exact = validate_custom({
            'name': 'one', 'type': 'network', 'mode': 'grant',
            'constraints': {'ports': [443], 'addrs': ['10.0.0.5']},
        })
        st = {'custom': [exact]}
        active = {'one.pem'}
        self.assertTrue(rule_expressible(exact))
        self.assertTrue(custom_authorizes(
            st, kind='network', port=443, addr='10.0.0.5', active_keys=active,
        ))
        self.assertFalse(custom_authorizes(
            st, kind='network', port=443, addr='1.2.3.4', active_keys=active,
        ))
        self.assertFalse(custom_authorizes(
            st, kind='network', port=80, addr='10.0.0.5', active_keys=active,
        ))
        # Port alone is not enough when the rule named an address.
        self.assertFalse(custom_authorizes(st, kind='network', port=443, active_keys=active))
        plan = scope_plan(st, verified=True, inactive_keys=set())
        self.assertNotIn(443, plan['port_allow'])
        key = (ipaddress.IPv4Address('10.0.0.5').packed, 443)
        self.assertEqual(plan['net4_allow'].get(key), BIT['network'])
        self.assertNotIn((ipaddress.IPv4Address('10.0.0.5').packed, 80), plan['net4_allow'])
        self.assertEqual(connect_scope_bits(plan, '1.2.3.4', 443)[0] & BIT['network'], 0)
        self.assertEqual(connect_scope_bits(plan, '10.0.0.5', 80)[0] & BIT['network'], 0)
        self.assertEqual(connect_scope_bits(plan, '10.0.0.5', 443)[0] & BIT['network'], BIT['network'])

        closed = [
            {'addrs': ['10.0.0.5']},
            {'interfaces': ['eth0']},
            {'direction': 'outbound'},
            {'direction': 'inbound'},
            {'ports': [443], 'interfaces': ['eth0']},
            {'ports': [443], 'addrs': ['10.0.0.0/8']},
            {'ports': [443], 'direction': 'inbound'},
            {'ports': [443], 'addrs': ['example.com']},
        ]
        for constraints in closed:
            rule = validate_custom({
                'name': 'closed', 'type': 'network', 'mode': 'grant',
                'constraints': constraints,
            })
            scoped = scope_plan({'custom': [rule]}, verified=True, inactive_keys=set())
            self.assertFalse(rule_expressible(rule), constraints)
            self.assertEqual(scoped['port_allow'], {}, constraints)
            self.assertEqual(scoped['net4_allow'], {}, constraints)
            self.assertEqual(scoped['net6_allow'], {}, constraints)
            self.assertFalse(custom_authorizes(
                {'custom': [rule]}, kind='network', port=443, addr='10.0.0.5',
                direction='outbound', active_keys={'closed.pem'},
            ), constraints)

        ports_only = validate_custom({
            'name': 'web', 'type': 'network', 'mode': 'grant',
            'constraints': {'ports': [443]},
        })
        plan = scope_plan({'custom': [ports_only]}, verified=True, inactive_keys=set())
        self.assertEqual(plan['port_allow'].get(443), BIT['network'])
        self.assertEqual(plan['net4_allow'], {})
        self.assertTrue(custom_authorizes(
            {'custom': [ports_only]}, kind='network', port=443, active_keys={'web.pem'},
        ))
        self.assertFalse(custom_authorizes(
            {'custom': [ports_only]}, kind='network', port=80, active_keys={'web.pem'},
        ))
        self.assertEqual(connect_scope_bits(plan, '1.2.3.4', 443)[0] & BIT['network'], BIT['network'])
        self.assertEqual(connect_scope_bits(plan, '8.8.8.8', 443)[0] & BIT['network'], BIT['network'])
        self.assertEqual(connect_scope_bits(plan, '1.2.3.4', 22)[0] & BIT['network'], 0)
        outbound = validate_custom({
            'name': 'out', 'type': 'network', 'mode': 'grant',
            'constraints': {'ports': [443], 'direction': 'outbound'},
        })
        self.assertTrue(rule_expressible(outbound))
        self.assertTrue(custom_authorizes(
            {'custom': [outbound]}, kind='network', port=443, direction='outbound',
            active_keys={'out.pem'},
        ))
        self.assertFalse(custom_authorizes(
            {'custom': [outbound]}, kind='network', port=443, active_keys={'out.pem'},
        ))
        plan = scope_plan({'custom': [outbound]}, verified=True, inactive_keys=set())
        self.assertEqual(plan['port_allow'].get(443), BIT['network'])
        v6 = validate_custom({
            'name': 'v6', 'type': 'network', 'mode': 'grant',
            'constraints': {'ports': [443], 'addrs': ['2001:db8::5']},
        })
        plan = scope_plan({'custom': [v6]}, verified=True, inactive_keys=set())
        self.assertEqual(plan['port_allow'], {})
        v6_key = (ipaddress.IPv6Address('2001:db8::5').packed, 443)
        self.assertEqual(plan['net6_allow'].get(v6_key), BIT['network'])
        self.assertEqual(connect_scope_bits(plan, '2001:db8::6', 443)[0], 0)
        self.assertEqual(connect_scope_bits(plan, '2001:db8::5', 443)[0] & BIT['network'], BIT['network'])
        src = (Path(__file__).resolve().parents[1] / 'python' / 'ker' / 'custom.py').read_text()
        self.assertIn('any address', src)
        bpf = (Path(__file__).resolve().parents[1] / 'src' / 'bpf' / 'ker.bpf.c').read_text()
        self.assertIn('scope_net4', bpf)
        self.assertIn('AF_UNIX', bpf)
        self.assertIn('AF_NETLINK', bpf)

    def test_login_grant_does_not_change_nonroot_exec(self):
        from ker.enforce import BIT, bprm_denies, scope_plan, setuid_denies
        from ker.hooks import merge_login_constraint
        login = validate_custom({
            'name': 'alice', 'type': 'login', 'mode': 'grant',
            'constraints': {'users': ['alice'], 'uids': [1000]},
        })
        st = {'permissions': ['rootuser', 'rootsu', 'run'], 'custom': [login]}
        plan = scope_plan(st, verified=True, inactive_keys=set())
        self.assertNotIn(1000, plan['uid_allow'])
        self.assertNotIn(1000, plan['uid_deny'])
        self.assertEqual(plan['ino_allow'], {})
        self.assertEqual(plan['uid_allow'].get(1000, 0) & (BIT['rootuser'] | BIT['rootsu']), 0)
        mask = BIT['rootuser'] | BIT['rootsu'] | BIT['run']
        common = dict(enforcement=True, media_ok=False, deny_mask_value=mask, allowed=False)
        plain = bprm_denies(**common, uid=1000)
        stuffed = bprm_denies(
            **common, uid=1000, have_uid=True,
            uid_allow=BIT['rootuser'] | BIT['rootsu'],
            uid_deny=BIT['rootuser'] | BIT['rootsu'],
        )
        self.assertEqual(plain, stuffed)
        self.assertTrue(plain)
        # The root-login bit is not consulted for a non-root exec, so a
        # login lock does not turn that exec into a denial by itself.
        self.assertFalse(bprm_denies(
            enforcement=True, media_ok=True, deny_mask_value=0, uid=1000,
            allowed=False, have_uid=True, uid_deny=BIT['rootuser'] | BIT['rootsu'],
        ))
        self.assertFalse(setuid_denies(
            enforcement=True, media_ok=False,
            deny_mask_value=BIT['rootuser'] | BIT['rootsu'],
            new_uid=1000, have_uid=True,
            uid_allow=BIT['rootuser'] | BIT['rootsu'],
        ))

        root = validate_custom({
            'name': 'rootlogin', 'type': 'login', 'mode': 'grant',
            'constraints': {'uids': [0]},
        })
        plan0 = scope_plan(
            {'permissions': ['rootuser', 'rootsu'], 'custom': [root]},
            verified=True, inactive_keys=set(),
        )
        self.assertEqual(plan0['uid_allow'].get(0), BIT['rootuser'])
        self.assertEqual(plan0['uid_allow'][0] & BIT['rootsu'], 0)
        self.assertFalse(bprm_denies(
            enforcement=True, media_ok=False, deny_mask_value=BIT['rootuser'],
            uid=0, allowed=False, have_uid=True, uid_allow=BIT['rootuser'],
        ))
        self.assertTrue(bprm_denies(
            enforcement=True, media_ok=False, deny_mask_value=BIT['rootuser'],
            uid=0, allowed=False,
        ))
        # setuid-to-root still honors the login grant for BIT_ROOTUSER, and
        # still denies when the privilege class itself is denied.
        self.assertFalse(setuid_denies(
            enforcement=True, media_ok=False, deny_mask_value=BIT['rootuser'],
            new_uid=0, have_uid=True, uid_allow=BIT['rootuser'],
        ))
        self.assertTrue(setuid_denies(
            enforcement=True, media_ok=False, deny_mask_value=BIT['rootsu'],
            new_uid=0, have_uid=True, uid_allow=BIT['rootuser'],
        ))
        self.assertTrue(setuid_denies(
            enforcement=True, media_ok=True, deny_mask_value=0,
            new_uid=0, have_uid=True, uid_deny=BIT['rootuser'],
        ))
        self.assertTrue(bprm_denies(
            enforcement=True, media_ok=True, deny_mask_value=0,
            uid=0, allowed=False, have_uid=True, uid_deny=BIT['rootuser'],
        ))

        base = {'allow': True, 'block': False, 'mode': 'enforce'}
        pam = {'custom': [login], 'kernel_enforcement': True, 'mode': 'enforce'}
        alice = merge_login_constraint(base, 'alice', pam, active_keys={'alice.pem'})
        self.assertFalse(alice['block'])
        self.assertEqual(alice['custom_login'], 'allow')
        denied = merge_login_constraint(dict(base), 'alice', pam, active_keys=set())
        self.assertTrue(denied['block'])
        bob = merge_login_constraint(dict(base), 'bob', pam, active_keys={'alice.pem'})
        self.assertEqual(bob['custom_login'], 'not_governed')
        self.assertFalse(bob['block'])

    def test_replace_rule_still_narrows_when_media_ok(self):
        import tempfile
        from ker.enforce import BIT, decide_subject, scope_plan
        with tempfile.TemporaryDirectory() as tmp:
            tool = Path(tmp) / 'tool'
            tool.write_text('x')
            item = validate_custom({
                'name': 'onlytool', 'type': 'command', 'mode': 'replace',
                'constraints': {'paths': [str(tool)]},
            })
            plan = scope_plan(
                {'permissions': ['run'], 'custom': [item]},
                verified=True, inactive_keys=set(),
            )
        self.assertEqual(plan['narrow_mask'], BIT['run'])
        self.assertTrue(decide_subject(
            enforcement=True, media_ok=True, deny_mask_value=0,
            bit=BIT['run'], allowed=False, narrow_mask=plan['narrow_mask'],
        ))
        self.assertTrue(decide_subject(
            enforcement=True, media_ok=True, deny_mask_value=BIT['run'],
            bit=BIT['run'], allowed=False, narrow_mask=BIT['run'],
        ))
        # Without the replace rule, media_ok leaves the deny mask unused.
        self.assertFalse(decide_subject(
            enforcement=True, media_ok=True, deny_mask_value=BIT['run'],
            bit=BIT['run'], allowed=False, narrow_mask=0,
        ))
        src = (Path(__file__).resolve().parents[1] / 'src' / 'bpf' / 'ker.bpf.c').read_text()
        self.assertIn('media_ok == 1 does not open a class that narrow_mask', src)
        userspace = (Path(__file__).resolve().parents[1] / 'python' / 'ker' / 'enforce.py').read_text()
        self.assertIn('media_ok == 1 does not', userspace)


if __name__ == '__main__':
    unittest.main()
