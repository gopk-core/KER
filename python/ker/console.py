"""Master admin console. Requires the admin-key medium, except under a test prefix with --assume-admin."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from ker.cluster import (
    DEFAULT_PORT, check_fail_closed, create_join_token, policy_export,
    queue_policy_sync,
)
from ker.custom import validate_custom
from ker.enforce import set_enforcement
from ker.i18n import t
from ker.paths import LOG_DIR, PREFIX
from ker.rotate import RotateError, rotate
from ker.state import save_state, state as load_state
from ker.testmode import verify_all
from ker.trustcheck import secure_boot_status
from ker.ui import ask, die


class ConsoleError(RuntimeError):
    pass


def _media_with_key(media: list, key: str) -> list[dict]:
    return [m for m in media if key in (m.get('keys') or [])]


def _has_admin(st: dict, admin_dev: str | None = None) -> bool:
    """Admin console needs a verified admin medium *and* root.pem (the foundation)."""
    media = list(st.get('media') or [])
    admin = []
    if admin_dev:
        admin = [m for m in media if m.get('path') == admin_dev]
        if not admin:
            admin = [{'path': admin_dev, 'keys': ['admin.pem'], 'kind': 'disk'}]
    else:
        admin = _media_with_key(media, 'admin.pem')
    if not admin:
        return False
    roots = _media_with_key(media, 'root.pem')
    check, seen = [], set()
    for m in roots + admin:
        path = m.get('path')
        if not path or path in seen:
            continue
        seen.add(path)
        check.append(m)
    try:
        report = verify_all(st, devices=check)
    except Exception:
        return False
    if not (report and report.get('ok')):
        return False
    return True


def _require_admin(st: dict, args) -> None:
    if getattr(args, 'assume_admin', False):
        if not PREFIX and not os.environ.get('KER_PREFIX'):
            raise ConsoleError('--assume-admin is only allowed under KER_PREFIX')
        return
    admin_dev = getattr(args, 'admin_dev', None)
    if not _has_admin(st, admin_dev):
        raise ConsoleError('admin medium required')


def _save_and_sync(st: dict) -> None:
    save_state(st)
    if st.get('role') == 'master' and st.get('children'):
        queue_policy_sync()


def cmd_status(st, args) -> dict:
    out = {
        'role': st.get('role'),
        'mode': st.get('mode'),
        'kernel_enforcement': st.get('kernel_enforcement'),
        'cluster_id': st.get('cluster_id'),
        'key_generation': st.get('key_generation') or 1,
        'permissions': st.get('permissions'),
        'custom': st.get('custom'),
        'independent_child_media': bool(st.get('independent_child_media', False)),
        'children': [
            {k: v for k, v in c.items() if k != 'secret'}
            for c in (st.get('children') or [])
        ],
        'fail_closed': check_fail_closed(st),
        'package_version': st.get('package_version'),
        'state_schema': st.get('state_schema'),
        'secure_boot': secure_boot_status(),
        'policy': policy_export(st),
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return out


def cmd_children(st, args) -> dict:
    kids = [
        {k: v for k, v in c.items() if k != 'secret'}
        for c in (st.get('children') or [])
    ]
    print('no children' if not kids else json.dumps(kids, ensure_ascii=False, indent=2))
    return {'children': kids}


def cmd_permissions(st, args) -> dict:
    print(json.dumps({'permissions': st.get('permissions') or [], 'custom': st.get('custom') or []},
                     ensure_ascii=False, indent=2))
    return {'permissions': st.get('permissions'), 'custom': st.get('custom')}


def cmd_independent(st, args) -> dict:
    if getattr(args, 'value', None) is None:
        print('independent_child_media =', bool(st.get('independent_child_media', False)))
        print('off: children follow the master media; on: each child needs its own media')
        return {'independent_child_media': bool(st.get('independent_child_media', False))}
    val = args.value in ('on', '1', 'true', 'yes')
    st['independent_child_media'] = val
    _save_and_sync(st)
    print('independent_child_media =', val)
    return {'independent_child_media': val}


def cmd_set_mode(st, args) -> dict:
    want = args.value
    if want not in ('test', 'enforce'):
        raise ConsoleError('mode must be test or enforce')
    result = set_enforcement(want == 'enforce', confirm=True, already_confirmed=bool(getattr(args, 'yes', False)))
    if st.get('children'):
        queue_policy_sync()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return result


def cmd_secureboot(st, args) -> dict:
    sb = secure_boot_status()
    print(json.dumps(sb, ensure_ascii=False, indent=2))
    return sb


def cmd_logs(st, args) -> dict:
    path = LOG_DIR / 'ker.log'
    if not path.exists():
        print('(no log file yet)')
        return {'lines': []}
    lines = path.read_text(encoding='utf-8', errors='replace').splitlines()[-80:]
    print('\n'.join(lines))
    return {'lines': lines}


def cmd_sync(st, args) -> dict:
    queue_policy_sync()
    print('policy sync queued for online children')
    return {'ok': True, 'queued': True}


def cmd_token(st, args) -> dict:
    host = args.host or '127.0.0.1'
    port = int(getattr(args, 'port', None) or DEFAULT_PORT)
    token = create_join_token(host, port, name=getattr(args, 'name', None))
    print(token)
    return {'token': token, 'master': host, 'port': port}


def cmd_rotate(st, args) -> dict:
    result = rotate(assume_replug=bool(getattr(args, 'assume_replug', False)), lang=getattr(args, 'lang', 'zh-CN') or 'zh-CN')
    print(json.dumps({k: v for k, v in result.items() if k != 'media'}, ensure_ascii=False, indent=2))
    return result


def cmd_revoke_medium(st, args) -> dict:
    """Replace or drop a missing medium. Requires the remaining root medium,
    or the admin medium when the lost disk is root. This is the revocation
    path: rotation retires the signing keys, so the lost disk no longer verifies.
    """
    replacements = {}
    if getattr(args, 'replace', None):
        key = getattr(args, 'media_id', None) or getattr(args, 'path', None)
        if not key:
            raise ConsoleError('revoke-medium --replace needs --media-id or --path')
        replacements[key] = {'path': args.replace, 'kind': getattr(args, 'kind', None) or 'disk'}
    if not replacements and not getattr(args, 'drop', False):
        raise ConsoleError('revoke-medium needs --replace or --drop')
    try:
        result = rotate(
            assume_replug=bool(getattr(args, 'assume_replug', False)),
            lang=getattr(args, 'lang', 'zh-CN') or 'zh-CN',
            allow_missing=True,
            replacements=replacements,
            drop_missing=bool(getattr(args, 'drop', False)),
        )
    except RotateError as e:
        raise ConsoleError(str(e)) from e
    print(json.dumps({k: v for k, v in result.items() if k != 'media'}, ensure_ascii=False, indent=2))
    return result


def cmd_add_permission(st, args) -> dict:
    from ker.catalog import BUILTIN_IDS
    pid = args.permission
    if pid not in BUILTIN_IDS:
        raise ConsoleError(f'unknown permission: {pid}')
    perms = list(st.get('permissions') or [])
    if pid not in perms:
        perms.append(pid)
    st['permissions'] = perms
    _save_and_sync(st)
    print('permissions:', perms)
    print('note: a new key is not written until the next rotation')
    return {'permissions': perms, 'pending_provision': pid}


def cmd_add_custom(st, args) -> dict:
    item = json.loads(args.json)
    item = validate_custom(item)
    custom = list(st.get('custom') or [])
    custom.append(item)
    st['custom'] = custom
    _save_and_sync(st)
    print(json.dumps(item, ensure_ascii=False, indent=2))
    print('note: a new key is not written until the next rotation')
    return {'custom': custom}


ACTIONS = {
    'status': cmd_status,
    'children': cmd_children,
    'permissions': cmd_permissions,
    'independent': cmd_independent,
    'set-mode': cmd_set_mode,
    'secureboot': cmd_secureboot,
    'logs': cmd_logs,
    'sync': cmd_sync,
    'token': cmd_token,
    'rotate': cmd_rotate,
    'revoke-medium': cmd_revoke_medium,
    'add-permission': cmd_add_permission,
    'add-custom': cmd_add_custom,
}


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='ker console')
    p.add_argument('--admin-dev')
    p.add_argument('--assume-admin', action='store_true')
    p.add_argument('--yes', action='store_true')
    sub = p.add_subparsers(dest='action')
    sub.add_parser('status')
    sub.add_parser('children')
    sub.add_parser('permissions')
    sub.add_parser('secureboot')
    sub.add_parser('logs')
    sub.add_parser('sync')
    p_ind = sub.add_parser('independent')
    p_ind.add_argument('value', nargs='?', choices=['on', 'off'])
    p_mode = sub.add_parser('set-mode')
    p_mode.add_argument('value', choices=['test', 'enforce'])
    p_tok = sub.add_parser('token')
    p_tok.add_argument('--host', default='127.0.0.1')
    p_tok.add_argument('--port', type=int, default=DEFAULT_PORT)
    p_tok.add_argument('--name')
    p_rot = sub.add_parser('rotate')
    p_rot.add_argument('--assume-replug', action='store_true')
    p_rev = sub.add_parser('revoke-medium', help='revoke or replace a missing medium using remaining root or admin proof')
    p_rev.add_argument('--path', help='recorded path of the lost medium')
    p_rev.add_argument('--media-id', help='recorded media_id of the lost medium')
    p_rev.add_argument('--replace', help='device path that receives the replacement medium')
    p_rev.add_argument('--kind', default='disk')
    p_rev.add_argument('--drop', action='store_true', help='drop lost non-root media and the permissions that lived only on them')
    p_rev.add_argument('--assume-replug', action='store_true')
    p_ap = sub.add_parser('add-permission')
    p_ap.add_argument('permission')
    p_ac = sub.add_parser('add-custom')
    p_ac.add_argument('json')
    return p


def run(lang: str = 'zh-CN', argv: list[str] | None = None) -> int:
    if os.geteuid() != 0 and not os.environ.get('KER_PREFIX'):
        die(lang, 'need_root')
    st = load_state()
    if not st.get('initialized') or st.get('role') != 'master':
        print('ker console is only available on an initialized master host', flush=True)
        return 1
    argv = list(argv or [])
    args = _parser().parse_args(argv)
    args.lang = lang
    # Lost-media revocation is proved by a remaining root medium, or by the
    # admin medium when root itself is gone. Do not demand an admin disk
    # when root is still present. rotate() fails closed if both are missing.
    if args.action == 'revoke-medium':
        try:
            cmd_revoke_medium(load_state(), args)
            return 0
        except Exception as e:
            print(str(e), flush=True)
            return 1
    try:
        _require_admin(st, args)
    except ConsoleError as e:
        if str(e) == 'admin medium required':
            die(lang, 'console_need_admin')
        print(str(e), flush=True)
        return 1
    if not args.action:
        return _interactive(lang, args)
    fn = ACTIONS[args.action]
    try:
        fn(load_state(), args)
        return 0
    except Exception as e:
        print(str(e), flush=True)
        return 1


def _interactive(lang: str, args) -> int:
    menu = [
        '1. child independent media (default off)',
        '2. key rotation',
        '3. status',
        '4. children',
        '5. permissions / custom',
        '6. test mode / enforcement (confirmation required)',
        '7. Secure Boot / lockdown',
        '8. logs',
        '9. policy sync',
        '10. create join token',
        '11. quit',
    ]
    print('\n'.join(menu))
    while True:
        cmd = ask('ker-console')
        st = load_state()
        try:
            if cmd in ('11', 'q', 'quit', 'exit'):
                return 0
            elif cmd == '1':
                cmd_independent(st, argparse.Namespace(value=None))
                raw = ask('set on/off or empty')
                if raw in ('on', 'off'):
                    cmd_independent(load_state(), argparse.Namespace(value=raw))
            elif cmd == '2':
                if confirm_interactive():
                    cmd_rotate(st, argparse.Namespace(assume_replug=False, lang=lang))
            elif cmd == '3':
                cmd_status(st, args)
            elif cmd == '4':
                cmd_children(st, args)
            elif cmd == '5':
                cmd_permissions(st, args)
            elif cmd == '6':
                print('Test mode is the default. Enabling kernel enforcement requires an explicit y.')
                raw = ask('test or enforce')
                if raw in ('test', 'enforce'):
                    yes = raw == 'test'
                    if raw == 'enforce':
                        yes = ask('type y to enable kernel enforcement') == 'y'
                    cmd_set_mode(load_state(), argparse.Namespace(value=raw, yes=yes))
            elif cmd == '7':
                cmd_secureboot(st, args)
            elif cmd == '8':
                cmd_logs(st, args)
            elif cmd == '9':
                cmd_sync(st, args)
            elif cmd == '10':
                host = ask('master host (address children will use)')
                cmd_token(st, argparse.Namespace(host=host, port=DEFAULT_PORT, name=None))
            else:
                print('\n'.join(menu))
        except Exception as e:
            print(str(e))


def confirm_interactive() -> bool:
    return ask('type y to continue') == 'y'
