from __future__ import annotations

import argparse
import json
import os
import sys

from ker import __version__
from ker.cluster import addnet
from ker.console import run as console_run
from ker.i18n import t
from ker.state import initialized, state
from ker.trustcheck import secure_boot_status
from ker.ui import die
from ker.uninstall import run as uninstall_run
from ker.wizard import first_run


def _lang(ns) -> str:
    return getattr(ns, 'language', None) or state().get('lang') or 'zh-CN'


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog='ker', description='KER authorization system')
    parser.add_argument('--version', action='version', version=f'ker {__version__}')
    parser.add_argument('--language', choices=['en', 'zh-CN', 'zh-TW'], default=None)
    sub = parser.add_subparsers(dest='cmd')

    p_init = sub.add_parser('init', help='first-run wizard or noninteractive deploy')
    p_init.add_argument('--yes', action='store_true', help='noninteractive (requires --media JSON)')
    p_init.add_argument('--media-json', help='JSON list of {path,kind,keys,role}')
    p_init.add_argument('--permissions', default='', help='comma-separated built-in permission ids')
    p_init.add_argument('--assume-replug', action='store_true', help='skip physical unplug (VM/tests)')
    p_init.add_argument('--skip-replug', action='store_true')
    p_init.add_argument('--enable-enforcement', action='store_true',
                        help='after media verifies, enable kernel enforcement (VM or KER_ALLOW_HOST_BPF)')
    p_init.add_argument('--custom-json', default='', help='JSON list of custom authorizations')

    sub.add_parser('status')
    p_un = sub.add_parser('uninstall')
    p_un.add_argument('--yes', action='store_true')
    p_add = sub.add_parser('addnet')
    p_add.add_argument('--master', help='master host[:port]')
    p_add.add_argument('--token', help='signed join token from the master')
    p_add.add_argument('--name')
    p_add.add_argument('--yes', action='store_true')
    p_add.add_argument('--fingerprint', help='out-of-band GPG fingerprint or kernel cert sha256 of the master trust anchor')
    p_srv = sub.add_parser('serve', help='run master sync listener or child poll loop')
    p_srv.add_argument('--child', action='store_true')
    p_srv.add_argument('--host', default='0.0.0.0')
    p_srv.add_argument('--port', type=int, default=4170)
    p_tok = sub.add_parser('token', help='issue a one-time child join token (master)')
    p_tok.add_argument('--host', default='127.0.0.1')
    p_tok.add_argument('--port', type=int, default=4170)
    p_tok.add_argument('--name')
    p_enf = sub.add_parser('enforce', help='refresh or set kernel enforcement after media verifies')
    p_enf.add_argument('--set', choices=['test', 'enforce'])
    p_enf.add_argument('--yes', action='store_true')
    p_enf.add_argument('--refresh', action='store_true')
    p_enf.add_argument('--presence', action='store_true',
                       help='fail-closed presence check only; deny immediately if media is missing')
    p_enf.add_argument('--watch', action='store_true',
                       help='run the persistent media watcher (systemd ker-enforcer.service)')
    sub.add_parser('console')
    sub.add_parser(
        'revoke-medium',
        help='revoke or replace a missing medium; proof is the remaining root medium, or admin if root is lost',
    )
    p_test = sub.add_parser('test-media')
    p_test.add_argument('--assume-replug', action='store_true')

    p_up = sub.add_parser('upgrade', help='manual package takeover and state migration (never auto-updates)')
    p_up.add_argument('package', nargs='?', help='optional .deb/.rpm/.apk/.pkg.tar.zst to install')
    p_up.add_argument('--check', action='store_true', help='show the upgrade plan and exit')
    p_up.add_argument('--migrate', action='store_true', help='apply pending migrations')
    p_up.add_argument('--snapshot', action='store_true', help='take a snapshot only')
    p_up.add_argument('--rollback', action='store_true', help='restore the last upgrade snapshot')
    p_up.add_argument('--from-package', action='store_true', help='called from a package postinst')
    p_up.add_argument('--reason', default='manual')
    p_up.add_argument('--trust-package', action='store_true', help='allow an unsigned local package file')

    # bare `ker` enters first-run or status
    # console takes its own subcommands; keep leftovers for it
    if argv and 'console' in argv:
        # split at the first 'console'
        idx = argv.index('console')
        args = parser.parse_args(argv[:idx+1])
        args._console_rest = argv[idx+1:]
        args._revoke_rest = []
    elif argv and 'revoke-medium' in argv:
        # Flags belong to the console parser so root-or-admin proof stays in one place.
        idx = argv.index('revoke-medium')
        args = parser.parse_args(argv[:idx+1])
        args._console_rest = []
        args._revoke_rest = argv[idx+1:]
    else:
        args = parser.parse_args(argv)
        args._console_rest = []
        args._revoke_rest = []
    lang = args.language or 'zh-CN'

    if args.cmd is None:
        if not initialized():
            first_run()
            return 0
        return _status(lang)

    if args.cmd == 'init':
        if initialized():
            print('already initialized', file=sys.stderr)
            return 1
        if args.yes:
            if not args.media_json:
                print('--media-json is required with --yes', file=sys.stderr)
                return 2
            media = json.loads(args.media_json)
            if isinstance(media, str):
                media = json.loads(Path_read(media))
            perms = [p for p in args.permissions.split(',') if p]
            custom = json.loads(args.custom_json) if args.custom_json else []
            first_run({
                'lang': lang,
                'permissions': perms,
                'custom': custom,
                'media': media,
                'assume_replug': args.assume_replug,
                'skip_replug': args.skip_replug,
                'enable_enforcement': args.enable_enforcement,
            })
        else:
            first_run()
        return 0

    if args.cmd == 'status':
        return _status(lang)
    if args.cmd == 'uninstall':
        uninstall_run(lang, yes=getattr(args, 'yes', False))
        return 0
    if args.cmd == 'addnet':
        addnet(lang if (args.language or args.yes) else None, master=args.master, token=args.token, yes=args.yes, name=args.name, fingerprint=getattr(args, 'fingerprint', None))
        return 0
    if args.cmd == 'serve':
        from ker.cluster import run_serve
        return run_serve(lang, child=args.child, host=args.host, port=args.port)
    if args.cmd == 'token':
        from ker.cluster import create_join_token
        print(create_join_token(args.host, args.port, name=args.name))
        return 0
    if args.cmd == 'enforce':
        from ker.enforce import presence_refresh, refresh_media_flag, set_enforcement, watch_loop
        if args.watch:
            watch_loop()
            return 0
        if args.presence:
            print(__import__('json').dumps(presence_refresh(), ensure_ascii=False, indent=2))
            return 0
        if args.refresh:
            print(__import__('json').dumps(refresh_media_flag(), ensure_ascii=False, indent=2))
            return 0
        if not args.set:
            print('use --set test|enforce, --refresh, --presence or --watch', file=sys.stderr)
            return 2
        r = set_enforcement(args.set == 'enforce', already_confirmed=args.yes)
        print(__import__('json').dumps(r, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == 'console':
        # remaining argv after 'console' is parsed by the console itself
        # We need the original tokens after the console subcommand.
        rest = _console_argv(argv)
        return console_run(lang, rest)
    if args.cmd == 'revoke-medium':
        # Thin alias of `ker console revoke-medium`. The console path does
        # not ask for an admin disk for this action; rotate() accepts a
        # verified root medium, or the admin medium when root is missing.
        return console_run(lang, ['revoke-medium', *list(getattr(args, '_revoke_rest', None) or [])])

    if args.cmd == 'upgrade':
        return _upgrade(lang, args)
    if args.cmd == 'test-media':
        from ker.testmode import run_replug_tests, verify_all
        st = state()
        if args.assume_replug:
            print(json.dumps(verify_all(st), ensure_ascii=False, indent=2))
            return 0
        run_replug_tests(lang, st, assume=False)
        return 0
    return 2


def _console_argv(argv: list[str]) -> list[str]:
    return argv[argv.index('console')+1:] if 'console' in argv else []


def Path_read(p: str) -> str:
    return open(p, encoding='utf-8').read()


def _status(lang: str) -> int:
    if not initialized():
        print('KER is installed but not initialized. Run: ker')
        return 0
    st = state()
    sb = secure_boot_status()
    out = {
        'initialized': True,
        'role': st.get('role'),
        'mode': st.get('mode'),
        'kernel_enforcement': st.get('kernel_enforcement'),
        'permissions': st.get('permissions'),
        'media': st.get('media'),
        'cluster_id': st.get('cluster_id'),
        'vault': st.get('vault'),
        'package_version': st.get('package_version'),
        'state_schema': st.get('state_schema'),
        'upgrade': st.get('upgrade'),
        'secure_boot': sb,
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    if not sb['ok']:
        print(t(lang, 'secureboot_warn'))
    return 0



def _upgrade(lang: str, args) -> int:
    from ker.i18n import t
    from ker.upgrade import (
        UpgradeError, format_plan, install_package, latest_snapshot,
        migrate, preflight, rollback, snapshot,
    )
    try:
        if args.rollback:
            r = rollback()
            print(t(lang, 'upgrade_rollback_ok', path=r['snapshot']))
            return 0
        if args.snapshot:
            path = snapshot(args.reason)
            print(str(path))
            return 0
        if args.package:
            r = install_package(args.package, trust_package=args.trust_package)
            print(json.dumps(r, ensure_ascii=False, indent=2, default=str))
            return 0
        pf = preflight()
        print(format_plan(pf['plan'], lang))
        for wmsg in pf['warnings']:
            print(wmsg, file=sys.stderr)
        if not pf['ok']:
            print('; '.join(pf['errors']), file=sys.stderr)
            return 2
        if args.check and not args.migrate and not args.from_package:
            print(json.dumps(pf, ensure_ascii=False, indent=2, default=str))
            return 0
        if args.migrate or args.from_package:
            r = migrate(reason=args.reason, from_package=args.from_package)
            if r.get('skipped'):
                print(format_plan(preflight()['plan'], lang))
                return 0
            print(t(lang, 'upgrade_ok', src=r.get('from') or '', dst=r.get('to') or ''))
            print(json.dumps({k: v for k, v in r.items() if k != 'plan'}, ensure_ascii=False, indent=2, default=str))
            return 0
        # bare `ker upgrade` is a check
        print(json.dumps(pf, ensure_ascii=False, indent=2, default=str))
        return 0
    except UpgradeError as e:
        print(str(e), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
