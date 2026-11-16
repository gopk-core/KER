from __future__ import annotations

import os
import sys

from ker.catalog import BUILTIN
from ker.deploy import deploy
from ker.devices import candidates
from ker.i18n import t
from ker.testmode import run_replug_tests
from ker.trustcheck import secure_boot_status
from ker.ui import ask, choose, choose_language, confirm_y, die


def _need_root(lang: str) -> None:
    if os.geteuid() != 0:
        die(lang, 'need_root')


def _pick_devices(lang: str, at_least: int = 1) -> list[dict]:
    devs = candidates()
    if not devs:
        die(lang, 'no_devices')
    print()
    for i, d in enumerate(devs, 1):
        print(f"  {i}. {d['path']}  {d['size_h']}  {d['kind']}  "
              f"{(d.get('model') or '')} {(d.get('tran') or '')} {(d.get('serial') or '')}")
    raw = ask(t(lang, 'choose_language') and ('Select devices (e.g. 1 or 1,2)' if lang == 'en' else '选择设备（例如 1 或 1,2）'))
    idxs = []
    for part in raw.replace(' ', '').split(','):
        if not part.isdigit() or not (1 <= int(part) <= len(devs)):
            die(lang, 'no_devices')
        idxs.append(int(part) - 1)
    picked = [devs[i] for i in idxs]
    if len(picked) < at_least:
        die(lang, 'no_devices')
    return picked


def first_run(spec: dict | None = None) -> dict:
    """Interactive first-run, or a pre-filled spec for noninteractive/VM tests."""
    if spec:
        lang = spec.get('lang') or 'zh-CN'
        _need_root(lang)
        st = deploy(spec)
        print(t(lang, 'test_mode_intro'))
        if not spec.get('skip_replug'):
            run_replug_tests(lang, st, assume=spec.get('assume_replug', False))
        _sb_warn(lang)
        if spec.get('enable_enforcement'):
            from ker.enforce import set_enforcement
            set_enforcement(True, already_confirmed=True)
        print(t(lang, 'ok'))
        return st

    lang = choose_language()
    _need_root(lang)
    print()
    picked = _pick_devices(lang)
    if not confirm_y(t(lang, 'confirm_wipe')):
        raise SystemExit(1)
    for d in picked:
        if d['kind'] in ('dvd-r', 'optical', 'worm'):
            if not confirm_y(t(lang, 'write_once_warn')):
                raise SystemExit(1)
            if d['kind'] == 'worm':
                # emptiness is checked again at write time
                pass

    # single vs multi
    multi = False
    if len(picked) > 1:
        multi = confirm_y('Multi-media mode? y/n' if lang == 'en' else '启用多介质模式？输入 y 启用')

    print()
    labels = {'en': 1, 'zh-CN': 2, 'zh-TW': 3}
    col = labels.get(lang, 2)
    print('Permissions:' if lang == 'en' else '选择要由 KER 管理的权限（多选，逗号分隔，空则只保留根密钥）：')
    for i, item in enumerate(BUILTIN, 1):
        print(f'  {i}. {item[0]}  {item[col]}')
    raw = ask('#')
    permissions = []
    if raw.strip():
        for part in raw.replace(' ', '').split(','):
            if part.isdigit() and 1 <= int(part) <= len(BUILTIN):
                permissions.append(BUILTIN[int(part) - 1][0])
            elif part in [b[0] for b in BUILTIN]:
                permissions.append(part)

    # assign keys
    all_keys = ['root.pem'] + [f'{p}.pem' for p in permissions] + ['admin.pem']
    media_specs = []
    if not multi or len(picked) == 1:
        # default: all keys including admin go together? Scheme: admin should be dedicated.
        # If only one device, warn and put admin on the same medium for this first run? 
        # User said admin is a separate medium required to open console.
        # If one device only, we still write admin.pem on it but console will accept it
        # only if the medium role includes admin. Better: if one disk, all keys including admin.
        media_specs.append({
            'path': picked[0]['path'], 'kind': picked[0]['kind'],
            'keys': all_keys, 'role': 'root+admin' if len(picked) == 1 else 'root',
        })
        if len(picked) > 1:
            # remaining unused unless assigned - use 2nd as admin if present
            media_specs[0]['keys'] = [k for k in all_keys if k != 'admin.pem']
            media_specs[0]['role'] = 'root'
            media_specs.append({
                'path': picked[1]['path'], 'kind': picked[1]['kind'],
                'keys': ['admin.pem'], 'role': 'admin',
            })
    else:
        print('Assign keys to each medium (at least one key each). root.pem must be on one medium.')
        remaining = set(all_keys)
        for i, d in enumerate(picked, 1):
            print(f"  Device {i}: {d['path']}  remaining: {', '.join(sorted(remaining))}")
            raw = ask('keys')
            names = [x for x in raw.replace(' ', '').split(',') if x]
            if not names or any(n not in remaining and n not in all_keys for n in names):
                raise SystemExit('invalid key assignment')
            media_specs.append({'path': d['path'], 'kind': d['kind'], 'keys': names, 'role': 'root' if 'root.pem' in names else 'keys'})
            remaining -= set(names)
        if 'root.pem' not in {k for m in media_specs for k in m['keys']}:
            raise SystemExit('root.pem must be assigned')
        if remaining:
            raise SystemExit('unassigned keys: ' + ','.join(sorted(remaining)))

    st = deploy({'lang': lang, 'permissions': permissions, 'custom': [], 'media': media_specs})
    print(t(lang, 'test_mode_intro'))
    run_replug_tests(lang, st, assume=False)
    _sb_warn(lang)
    print(t(lang, 'ok'))
    return st


def _sb_warn(lang: str) -> None:
    st = secure_boot_status()
    if not st['ok']:
        print(t(lang, 'secureboot_warn'))
