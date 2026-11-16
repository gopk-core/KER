"""LAN cluster: join as a child, signed sync, fail-closed if the master is lost."""
from __future__ import annotations

import json
import os
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ker.i18n import t
from ker.paths import PRIVATE_DIR, TRUST_DIR
from ker.protocol import (
    ProtocolError, b64, b64d, hmac_message, recv_msg, send_msg,
    sign_message, verify_hmac, verify_message,
)
from ker.state import ensure_dirs, save_json, save_state, state as load_state
from ker.ui import ask, choose_language, confirm_y, die
from ker.upgrade import stamp_new_install


class ClusterError(RuntimeError):
    pass


DEFAULT_PORT = 4170
FAIL_CLOSED_AFTER = int(os.environ.get('KER_SYNC_TIMEOUT', '60'))

_lock = threading.RLock()
_stop = threading.Event()
_server_thread: threading.Thread | None = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _keys(st: dict | None = None) -> dict:
    st = st or load_state()
    return {
        'gpg_fingerprint': st['gpg_fingerprint'],
        'gpg_home': str(PRIVATE_DIR / 'gnupg'),
        'rsa_key': str(PRIVATE_DIR / 'kernel-signing.key'),
        'rsa_pub': str(TRUST_DIR / 'kernel-cert.pem'),
    }


def assert_not_fail_closed(st: dict | None = None) -> None:
    st = st or load_state()
    if check_fail_closed(st):
        raise ClusterError('fail-closed: master is unreachable; refusing policy changes until a signed sync')


def check_fail_closed(st: dict | None = None) -> bool:
    st = st or load_state()
    if st.get('role') != 'child':
        return False
    if st.get('fail_closed'):
        return True
    last = st.get('last_sync')
    if not last:
        return False
    try:
        ts = datetime.fromisoformat(last).timestamp()
    except ValueError:
        return True
    if time.time() - ts > FAIL_CLOSED_AFTER:
        st = dict(st)
        st['fail_closed'] = True
        save_state(st)
        return True
    return False


def mark_synced(st: dict | None = None) -> dict:
    st = dict(st or load_state())
    st['last_sync'] = _now()
    st['fail_closed'] = False
    save_state(st)
    return st


def policy_export(st: dict) -> dict:
    return {
        'cluster_id': st.get('cluster_id'),
        'permissions': st.get('permissions') or [],
        'custom': st.get('custom') or [],
        'independent_child_media': bool(st.get('independent_child_media', False)),
        'mode': st.get('mode'),
        'kernel_enforcement': bool(st.get('kernel_enforcement')),
        'gpg_fingerprint': st.get('gpg_fingerprint'),
        'kernel_cert_sha256': st.get('kernel_cert_sha256'),
        'key_generation': st.get('key_generation') or 1,
        'media_schema': st.get('media_schema'),
        'state_schema': st.get('state_schema'),
    }


def apply_policy(st: dict, policy: dict) -> dict:
    st = dict(st)
    for k in ('permissions', 'custom', 'independent_child_media', 'mode',
              'kernel_enforcement', 'gpg_fingerprint', 'kernel_cert_sha256',
              'key_generation', 'media_schema', 'state_schema', 'cluster_id'):
        if k in policy:
            st[k] = policy[k]
    return st


def _trust_blob() -> dict:
    gpg = (TRUST_DIR / 'media.gpg').read_bytes()
    cert = (TRUST_DIR / 'kernel-cert.pem').read_bytes()
    return {'media_gpg': b64(gpg), 'kernel_cert': b64(cert)}


def _write_trust(blob: dict) -> None:
    TRUST_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(TRUST_DIR, 0o700)
    payloads = {
        'media.gpg': b64d(blob['media_gpg']),
        'kernel-cert.pem': b64d(blob['kernel_cert']),
    }
    for name, data in payloads.items():
        path = TRUST_DIR / name
        # A previous anchor is mode 0400. Unlink it so a confirmed replacement
        # can be written by the owner, who cannot open a 0400 file for write.
        if path.exists():
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            path.unlink()
        path.write_bytes(data)
        os.chmod(path, 0o400)


def create_join_token(master_host: str, port: int = DEFAULT_PORT, name: str | None = None) -> str:
    st = load_state()
    if st.get('role') != 'master' or not st.get('initialized'):
        raise ClusterError('join tokens can only be issued by an initialized master')
    assert_not_fail_closed(st)
    body = {
        'type': 'join-token',
        'cluster_id': st['cluster_id'],
        'master': master_host,
        'port': int(port),
        'issued': _now(),
        'nonce': uuid.uuid4().hex,
        'name': name,
        'trust': _trust_blob(),
        'gpg_fingerprint': st['gpg_fingerprint'],
        'kernel_cert_sha256': st['kernel_cert_sha256'],
    }
    line = b64(json.dumps(sign_message(body, _keys(st)), separators=(',', ':')).encode())
    used = list(st.get('tokens_issued') or [])
    used.append({'nonce': body['nonce'], 'issued': body['issued'], 'name': name})
    st['tokens_issued'] = used[-32:]
    save_state(st)
    return line


def parse_join_token(token: str, keys: dict) -> dict:
    try:
        msg = json.loads(b64d(token).decode('utf-8'))
        body = verify_message(msg, keys)
    except Exception as e:
        raise ClusterError('invalid join token') from e
    if body.get('type') != 'join-token':
        raise ClusterError('invalid join token type')
    return body


def addnet(lang: str | None = None, *, master: str | None = None,
           token: str | None = None, yes: bool = False, name: str | None = None,
           fingerprint: str | None = None) -> dict:
    if not lang:
        try:
            lang = load_state().get('lang')
        except Exception:
            lang = None
        lang = lang or ('zh-CN' if yes else choose_language())
    if os.geteuid() != 0 and not os.environ.get('KER_PREFIX'):
        die(lang, 'need_root')
    print(t(lang, 'addnet_intro'))
    if not yes and not confirm_y('y to continue / 输入 y 继续'):
        raise SystemExit(1)
    if not master:
        master = ask('master host[:port]')
    if not token:
        token = ask('join token').strip()
    if not fingerprint and not yes:
        fingerprint = ask('trust fingerprint (out of band, not from the token text)').strip()
    host, port = _split_host(master)
    return join_master(host, port, token, name=name, confirm_fingerprint=fingerprint or None)


def _split_host(master: str) -> tuple[str, int]:
    master = master.strip()
    if master.startswith('['):
        host, _, rest = master[1:].partition(']')
        port = int(rest[1:]) if rest.startswith(':') else DEFAULT_PORT
        return host, port
    if master.count(':') == 1:
        host, port = master.split(':')
        return host, int(port)
    return master, DEFAULT_PORT


def _norm_fp(value: str | None) -> str:
    return ''.join((value or '').split()).upper()


def _fingerprint_keyring(blob: bytes) -> str:
    import tempfile
    with tempfile.TemporaryDirectory(prefix='ker-fpr-') as tmp:
        ring = Path(tmp) / 'pub.gpg'
        ring.write_bytes(blob)
        r = subprocess_run_gpg(ring)
    return r


def subprocess_run_gpg(ring: Path) -> str:
    import subprocess
    r = subprocess.run(
        ['gpg', '--batch', '--show-keys', '--with-colons', str(ring)],
        capture_output=True, text=True, timeout=20,
    )
    if r.returncode:
        raise ClusterError('trust anchor is not a public keyring')
    for line in r.stdout.splitlines():
        if line.startswith('fpr:'):
            return line.split(':')[9]
    raise ClusterError('trust anchor has no fingerprint')


def _trust_identities(blob: dict) -> tuple[bytes, bytes, str, str]:
    """Return (keyring, cert, computed fingerprint, computed cert sha256)."""
    import hashlib
    try:
        keyring = b64d(blob['media_gpg'])
        cert = b64d(blob['kernel_cert'])
    except Exception as e:
        raise ClusterError('join token trust anchor is malformed') from e
    if not keyring or not cert:
        raise ClusterError('join token trust anchor is empty')
    fpr = _fingerprint_keyring(keyring)
    sha = hashlib.sha256(cert).hexdigest()
    return keyring, cert, fpr, sha


def _existing_trust_files() -> tuple[Path, Path] | None:
    gpg = TRUST_DIR / 'media.gpg'
    cert = TRUST_DIR / 'kernel-cert.pem'
    if gpg.is_file() and cert.is_file() and gpg.stat().st_size and cert.stat().st_size:
        return gpg, cert
    return None


def _peek_token(token: str) -> tuple[dict, dict]:
    try:
        msg = json.loads(b64d(token).decode('utf-8'))
        peek = json.loads(b64d(msg['payload']).decode('utf-8'))
    except Exception as e:
        raise ClusterError('invalid join token') from e
    if not isinstance(peek, dict) or not peek.get('trust'):
        raise ClusterError('join token missing trust anchors')
    return msg, peek


def trust_matches_tree(keyring: bytes, cert: bytes, media_dir: Path) -> bool:
    """True when this public trust verifies bundle.json in an already-mounted tree."""
    import subprocess
    import tempfile
    bundle = media_dir / 'bundle.json'
    sig = media_dir / 'bundle.json.sig'
    ksig = media_dir / 'bundle.json.ksig'
    if not bundle.is_file() or not sig.is_file() or not ksig.is_file():
        return False
    with tempfile.TemporaryDirectory(prefix='ker-media-trust-') as tmp:
        ring = Path(tmp) / 'media.gpg'
        crt = Path(tmp) / 'cert.pem'
        pub = Path(tmp) / 'pub.pem'
        ring.write_bytes(keyring)
        crt.write_bytes(cert)
        gpg = subprocess.run(
            ['gpgv', '--keyring', str(ring), str(sig), str(bundle)],
            capture_output=True, text=True, timeout=20,
        )
        if gpg.returncode:
            return False
        extracted = subprocess.run(
            ['openssl', 'x509', '-in', str(crt), '-pubkey', '-noout', '-out', str(pub)],
            capture_output=True, text=True, timeout=20,
        )
        if extracted.returncode:
            return False
        rsa = subprocess.run(
            ['openssl', 'dgst', '-sha256', '-verify', str(pub), '-signature', str(ksig), str(bundle)],
            capture_output=True, text=True, timeout=20,
        )
        return rsa.returncode == 0


def _installed_media_matches(keyring: bytes, cert: bytes, st: dict | None = None) -> bool:
    """Out-of-band check: the token trust verifies a present root or admin medium."""
    from ker.devices import resolve_media_path
    from ker.testmode import _mount_ro, _umount
    from ker.paths import MOUNT_ROOT
    st = st or load_state()
    checked = False
    for i, medium in enumerate(st.get('media') or []):
        if not isinstance(medium, dict):
            continue
        keys = medium.get('keys') or []
        role = medium.get('role') or ''
        if 'root.pem' not in keys and 'admin.pem' not in keys and role not in ('root', 'admin', 'root+admin'):
            continue
        live = resolve_media_path(medium)
        if not live:
            continue
        dest = MOUNT_ROOT / f'join{i}'
        try:
            _mount_ro(live, dest)
        except Exception:
            continue
        try:
            checked = True
            if trust_matches_tree(keyring, cert, dest):
                return True
        finally:
            _umount(dest)
    return False if checked else False


def _confirm_matches(confirm: str | None, fpr: str, sha: str) -> bool:
    want = _norm_fp(confirm)
    if not want:
        return False
    return want == _norm_fp(fpr) or want == _norm_fp(sha)


def bootstrap_from_token(token: str, *, confirm_fingerprint: str | None = None,
                         state: dict | None = None) -> dict:
    """Accept a join token only after an out-of-band trust check.

    The token's trust blob is not installed and then used to verify itself.
    A new anchor is written only when one of these is true:

    - the operator confirms the fingerprint (or certificate sha256) out of band
    - the node already has that trust anchor and it verifies the token
    - a present root or admin medium verifies under the token's public keys

    The first join still works: pass the fingerprint copied from the master
    over a channel that is not the token string.
    """
    msg, peek = _peek_token(token)
    _keyring, _cert, fpr, sha = _trust_identities(peek['trust'])
    if _norm_fp(peek.get('gpg_fingerprint')) != _norm_fp(fpr):
        raise ClusterError('join token fingerprint does not match its trust blob')
    if _norm_fp(peek.get('kernel_cert_sha256')) != _norm_fp(sha):
        raise ClusterError('join token certificate hash does not match its trust blob')

    existing = _existing_trust_files()
    keys = {
        'gpg_fingerprint': fpr,
        'gpg_home': str(PRIVATE_DIR / 'gnupg'),
        'rsa_key': str(PRIVATE_DIR / 'kernel-signing.key'),
        'rsa_pub': str(TRUST_DIR / 'kernel-cert.pem'),
    }
    if existing is not None:
        try:
            body = verify_message(msg, keys, keyring=existing[0], cert=existing[1])
        except Exception:
            body = None
        if body is not None:
            if body.get('type') != 'join-token':
                raise ClusterError('invalid join token type')
            # Already-installed trust verified the token. Do not replace it
            # with whatever trust bytes the token carried.
            return body

    confirmed = _confirm_matches(confirm_fingerprint, fpr, sha)
    media_ok = False
    if not confirmed:
        media_ok = _installed_media_matches(_keyring, _cert, state)
    if not confirmed and not media_ok:
        raise ClusterError(
            'refusing to install a trust anchor without out-of-band fingerprint '
            'confirmation or a matching root/admin medium'
        )

    # Verify against the candidate files before anything is installed.
    import tempfile
    with tempfile.TemporaryDirectory(prefix='ker-join-trust-') as tmp:
        ring = Path(tmp) / 'media.gpg'
        crt = Path(tmp) / 'kernel-cert.pem'
        ring.write_bytes(_keyring)
        crt.write_bytes(_cert)
        try:
            body = verify_message(msg, keys, keyring=ring, cert=crt)
        except Exception as e:
            raise ClusterError('invalid join token') from e
    if body.get('type') != 'join-token':
        raise ClusterError('invalid join token type')
    ensure_dirs()
    previous = None
    if existing is not None:
        previous = (existing[0].read_bytes(), existing[1].read_bytes())
    try:
        _write_trust(peek['trust'])
    except Exception:
        if previous is not None:
            _write_trust({'media_gpg': b64(previous[0]), 'kernel_cert': b64(previous[1])})
        raise
    return body


def join_master(host: str, port: int, token: str, name: str | None = None,
                *, confirm_fingerprint: str | None = None) -> dict:
    ensure_dirs()
    st = load_state()
    if st.get('initialized') and st.get('role') == 'master':
        raise ClusterError('this host is already a master; it will not mint or replace root.pem via addnet')
    token_body = bootstrap_from_token(token, confirm_fingerprint=confirm_fingerprint, state=st)
    if host != token_body.get('master') or int(port) != int(token_body.get('port') or port):
        # allow the caller-supplied address if the token listed it; otherwise keep the token's address
        if not host:
            host = token_body['master']
            port = int(token_body['port'])
    sock = socket.create_connection((host, port), timeout=20)
    try:
        send_msg(sock, {'type': 'join', 'token': token, 'name': name or socket.gethostname()})
        reply = recv_msg(sock)
        if reply.get('type') == 'error':
            raise ClusterError(reply.get('error') or 'join rejected')
        if reply.get('type') != 'welcome':
            raise ClusterError('unexpected join reply')
        body = reply['body']
        trust = reply['trust']
        secret = b64d(reply['secret'])
        # The welcome frame is not signed. Only install trust that matches the
        # anchor already confirmed while checking the join token.
        _wkr, _wcert, wfpr, wsha = _trust_identities(trust)
        if _norm_fp(wfpr) != _norm_fp(token_body.get('gpg_fingerprint')) or _norm_fp(wsha) != _norm_fp(token_body.get('kernel_cert_sha256')):
            raise ClusterError('master welcome trust does not match the confirmed anchor')
        _write_trust(trust)
        child = {
            'initialized': True,
            'role': 'child',
            'joined': True,
            'cluster_id': body['cluster_id'],
            'child_id': body['child_id'],
            'master_host': host,
            'master_port': port,
            'child_secret': b64(secret),
            'media': [],
            'permissions': body['policy'].get('permissions') or [],
            'custom': body['policy'].get('custom') or [],
            'gpg_fingerprint': body['policy']['gpg_fingerprint'],
            'kernel_cert_sha256': body['policy']['kernel_cert_sha256'],
            'independent_child_media': body['policy'].get('independent_child_media', False),
            'mode': body['policy'].get('mode') or 'test',
            'kernel_enforcement': False,  # child never auto-enables
            'vault': 'memory-only',
            'children': [],
            'root_media_id': None,
        }
        child = stamp_new_install(child)
        child = apply_policy(child, body['policy'])
        child['kernel_enforcement'] = False
        child['role'] = 'child'
        child['joined'] = True
        child['child_secret'] = b64(secret)
        child = mark_synced(child)
        return child
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _handle_join(token: str, name: str, peer: str) -> dict:
    st = load_state()
    keys = _keys(st)
    body = parse_join_token(token, keys)
    if body['cluster_id'] != st['cluster_id']:
        raise ClusterError('token cluster mismatch')
    used = set()
    for tkn in st.get('tokens_consumed') or []:
        used.add(tkn)
    if body['nonce'] in used:
        raise ClusterError('join token already used')
    child_id = str(uuid.uuid4())
    secret = os.urandom(32)
    children = list(st.get('children') or [])
    rec = {
        'id': child_id,
        'name': name or body.get('name') or peer,
        'online': True,
        'last_seen': _now(),
        'secret': b64(secret),
        'peer': peer,
    }
    children.append(rec)
    st['children'] = children
    consumed = list(st.get('tokens_consumed') or [])
    consumed.append(body['nonce'])
    st['tokens_consumed'] = consumed[-64:]
    save_state(st)
    return {
        'type': 'welcome',
        'body': {
            'cluster_id': st['cluster_id'],
            'child_id': child_id,
            'policy': policy_export(st),
        },
        'trust': _trust_blob(),
        'secret': b64(secret),
    }


def _child_record(child_id: str) -> dict | None:
    st = load_state()
    for c in st.get('children') or []:
        if c.get('id') == child_id:
            return c
    return None


def _touch_child(child_id: str, **fields) -> None:
    st = load_state()
    kids = list(st.get('children') or [])
    for c in kids:
        if c.get('id') == child_id:
            c.update(fields)
            c['last_seen'] = _now()
            c['online'] = True
    st['children'] = kids
    save_state(st)


def _signed(st: dict, obj: dict) -> dict:
    return sign_message(obj, _keys(st))


def _master_client_request(st: dict, obj: dict, timeout: int = 20) -> dict:
    sock = socket.create_connection((st['master_host'], int(st['master_port'])), timeout=timeout)
    try:
        secret = b64d(st['child_secret'])
        send_msg(sock, {'type': 'auth', 'child_id': st['child_id'], **hmac_message(obj, secret)})
        reply = recv_msg(sock)
        if reply.get('signed'):
            return verify_message(reply['signed'], _keys(st))
        if reply.get('type') == 'error':
            raise ClusterError(reply.get('error') or 'master error')
        return reply
    finally:
        sock.close()


def handle_connection(conn: socket.socket, addr) -> None:
    try:
        conn.settimeout(30)
        msg = recv_msg(conn)
        typ = msg.get('type')
        with _lock:
            st = load_state()
            if typ == 'join':
                try:
                    reply = _handle_join(msg.get('token') or '', msg.get('name') or '', addr[0])
                    send_msg(conn, reply)
                except Exception as e:
                    send_msg(conn, {'type': 'error', 'error': str(e)})
                return
            if typ == 'auth':
                rec = _child_record(msg.get('child_id') or '')
                if not rec:
                    send_msg(conn, {'type': 'error', 'error': 'unknown child'})
                    return
                body = verify_hmac(msg, b64d(rec['secret']))
                _touch_child(rec['id'])
                send_msg(conn, {'signed': _signed(st, _master_reply(st, rec, body))})
                return
            send_msg(conn, {'type': 'error', 'error': 'unknown message'})
    except Exception:
        try:
            send_msg(conn, {'type': 'error', 'error': 'protocol error'})
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _master_reply(st: dict, rec: dict, body: dict) -> dict:
    typ = body.get('type')
    queued = list(rec.get('queued') or [])
    if typ == 'ping':
        # include queued commands then clear them
        kids = list(st.get('children') or [])
        for c in kids:
            if c.get('id') == rec['id']:
                c['queued'] = []
        st['children'] = kids
        save_state(st)
        return {'type': 'pong', 'policy': policy_export(st), 'trust': _trust_blob(), 'commands': queued, 'ts': _now()}
    if typ == 'ack':
        return {'type': 'ack-ok', 'ts': _now()}
    return {'type': 'error', 'error': f'unknown child request {typ}'}


def queue_command(child_id: str | None, command: dict) -> None:
    st = load_state()
    kids = list(st.get('children') or [])
    for c in kids:
        if child_id is None or c.get('id') == child_id:
            q = list(c.get('queued') or [])
            q.append(command)
            c['queued'] = q
    st['children'] = kids
    if command.get('type') in ('policy', 'cutover') and kids:
        st.setdefault('compat', {})['needs_child_sync'] = True
    save_state(st)


def queue_policy_sync() -> None:
    st = load_state()
    queue_command(None, {'type': 'policy', 'policy': policy_export(st), 'trust': _trust_blob(), 'ts': _now()})


def dispatch_uninstall() -> list[str]:
    """Queue a signed uninstall for every currently online child."""
    st = load_state()
    sent = []
    kids = list(st.get('children') or [])
    cmd = {'type': 'uninstall', 'cluster_id': st.get('cluster_id'), 'ts': _now()}
    for c in kids:
        if c.get('online'):
            q = list(c.get('queued') or [])
            q.append(cmd)
            c['queued'] = q
            sent.append(c.get('id'))
        else:
            c['pending_uninstall'] = True
    st['children'] = kids
    save_state(st)
    return sent


def apply_commands(commands: list[dict], st: dict | None = None) -> dict:
    st = dict(st or load_state())
    for cmd in commands or []:
        typ = cmd.get('type')
        if typ == 'policy':
            st = apply_policy(st, cmd['policy'])
            if cmd.get('trust'):
                _write_trust(cmd['trust'])
        elif typ == 'cutover':
            if cmd.get('trust'):
                _write_trust(cmd['trust'])
            st = apply_policy(st, cmd.get('policy') or {})
            st['key_generation'] = cmd.get('key_generation') or st.get('key_generation')
        elif typ == 'uninstall':
            from ker.uninstall import purge_local
            # signed uninstall from the master is sufficient for an enrolled child
            st = mark_synced(st)
            purge_local()
            return {'uninstalled': True}
    return mark_synced(st)


def child_poll() -> dict:
    st = load_state()
    if st.get('role') != 'child':
        raise ClusterError('not a child')
    try:
        reply = _master_client_request(st, {'type': 'ping', 'child_id': st.get('child_id'), 'ts': _now()})
    except Exception as e:
        check_fail_closed(st)
        raise ClusterError(f'master unreachable: {e}') from e
    if reply.get('type') != 'pong':
        raise ClusterError('unexpected pong')
    if reply.get('trust'):
        _write_trust(reply['trust'])
    st = apply_policy(load_state(), reply.get('policy') or {})
    st['role'] = 'child'
    result = apply_commands(reply.get('commands') or [], st)
    return result


def serve_forever(host: str = '0.0.0.0', port: int = DEFAULT_PORT, stopper: threading.Event | None = None) -> None:
    stopper = stopper or _stop
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(16)
    sock.settimeout(0.5)
    try:
        while not stopper.is_set():
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()
    finally:
        sock.close()


def start_server(host: str = '0.0.0.0', port: int = DEFAULT_PORT) -> threading.Event:
    global _server_thread
    stopper = threading.Event()
    t = threading.Thread(target=serve_forever, args=(host, port, stopper), daemon=True)
    t.start()
    _server_thread = t
    # wait until port is open
    for _ in range(50):
        s = socket.socket()
        try:
            s.settimeout(0.1)
            s.connect((host if host != '0.0.0.0' else '127.0.0.1', port))
            s.close()
            break
        except OSError:
            time.sleep(0.05)
    return stopper


def run_serve(lang: str, *, child: bool = False, host: str = '0.0.0.0', port: int = DEFAULT_PORT) -> int:
    st = load_state()
    if child or st.get('role') == 'child':
        while True:
            try:
                r = child_poll()
                if r.get('uninstalled'):
                    return 0
            except ClusterError as e:
                print(str(e))
            time.sleep(min(5, FAIL_CLOSED_AFTER / 3 or 1))
    if st.get('role') != 'master':
        raise ClusterError('ker serve without --child is for the master host')
    print(f'KER master sync listening on {host}:{port}')
    serve_forever(host, port)
    return 0
