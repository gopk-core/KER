from __future__ import annotations

import os
import shutil
import time

from ker.cluster import child_poll, dispatch_uninstall
from ker.i18n import t
from ker.paths import ETC, LOG_DIR, VAR
from ker.state import initialized, save_state, state as load_state
from ker.testmode import verify_all
from ker.ui import confirm_y, die


def purge_local() -> None:
    from ker.enforce import may_load_bpf, sync_enforcer_units, unload_bpf
    try:
        sync_enforcer_units(False)
    except Exception:
        pass
    if may_load_bpf():
        try:
            unload_bpf()
        except Exception:
            pass
    for p in (ETC, VAR, LOG_DIR):
        if p.exists():
            shutil.rmtree(p, ignore_errors=True)


def run(lang: str, *, yes: bool = False) -> None:
    if os.geteuid() != 0 and not os.environ.get('KER_PREFIX'):
        die(lang, 'need_root')
    st = load_state()
    if not initialized():
        purge_local()
        print(t(lang, 'ok'))
        return
    # never-enrolled / no-key host
    if not st.get('media') and not st.get('joined') and not st.get('children'):
        purge_local()
        print(t(lang, 'ok'))
        return
    # enrolled child receiving a local request: try a last poll so a queued
    # signed uninstall from the master can land; otherwise require media.
    if st.get('role') == 'child' and st.get('joined'):
        try:
            r = child_poll()
            if r.get('uninstalled'):
                print(t(lang, 'ok'))
                return
        except Exception:
            pass
    try:
        report = verify_all(st)
    except Exception:
        die(lang, 'uninstall_need_media')
    if not report.get('ok'):
        die(lang, 'uninstall_need_media')
    have = set()
    for m in st.get('media') or []:
        have.update(m.get('keys') or [])
    need = {'root.pem'}
    need.update(f'{p}.pem' for p in st.get('permissions') or [])
    need.update(c['key'] for c in st.get('custom') or [])
    if st.get('media') and not need.issubset(have):
        die(lang, 'uninstall_need_media')
    if st.get('role') == 'master':
        sent = dispatch_uninstall()
        online = [c for c in (st.get('children') or []) if c.get('online')]
        if online:
            nodes = '\n'.join(f"  - {c.get('name') or c.get('id')}" for c in online)
            if not yes and not confirm_y(t(lang, 'uninstall_children', nodes=nodes)):
                raise SystemExit(1)
            # give online children a brief window to poll the queued command
            deadline = time.time() + 8
            while time.time() < deadline and sent:
                time.sleep(0.4)
        offline = [c for c in (st.get('children') or []) if not c.get('online')]
        if offline:
            print('offline children must reconnect all media and run ker uninstall locally')
    purge_local()
    print(t(lang, 'ok'))
