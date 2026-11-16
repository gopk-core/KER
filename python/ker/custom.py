"""Custom authorization rules.

A custom rule is a constrained grant, lock, or replacement. It never becomes
a machine-wide LSM bit. Callers enforce the constraint at the hook or BPF
subject that performs the action. A constraint that cannot be checked exactly
does not authorize anything.
"""
from __future__ import annotations

import os
from pathlib import Path

from ker.catalog import CUSTOM_TYPES, GRANT_MODES


class CustomError(ValueError):
    pass


def validate_custom(item: dict) -> dict:
    name = (item.get('name') or '').strip()
    typ = item.get('type')
    mode = item.get('mode') or 'grant'
    constraints = item.get('constraints') or {}
    if not name or '/' in name:
        raise CustomError('invalid custom name')
    if typ not in CUSTOM_TYPES:
        raise CustomError('unsupported custom type')
    if mode not in GRANT_MODES:
        raise CustomError('invalid grant mode')
    if typ.startswith('file_') or typ in ('command', 'device'):
        paths = constraints.get('paths') or constraints.get('path')
        if isinstance(paths, str):
            paths = [paths]
        if not paths:
            raise CustomError('paths required')
        for p in paths:
            if not str(p).startswith('/') or '..' in Path(p).parts:
                raise CustomError('paths must be absolute and normalized')
        constraints = dict(constraints)
        constraints['paths'] = [str(Path(p)) for p in paths]
    elif typ == 'network':
        if not any(constraints.get(k) for k in ('ports', 'addrs', 'interfaces', 'direction')):
            raise CustomError('network constraints required')
    elif typ == 'login':
        if not (constraints.get('users') or constraints.get('uids')):
            raise CustomError('users required')
    elif typ == 'service':
        if not constraints.get('units'):
            raise CustomError('units required')
    # refuse unbounded "everything" scopes
    if constraints.get('paths') == ['/'] and typ.startswith('file_'):
        raise CustomError('custom authorization cannot cover all files')
    key_name = item.get('key') or (name.replace(' ', '_').lower() + '.pem')
    if not key_name.endswith('.pem') or '/' in key_name:
        raise CustomError('invalid key file name')
    return {
        'name': name,
        'type': typ,
        'mode': mode,
        'constraints': constraints,
        'key': key_name,
        'description': item.get('description') or '',
    }


_SHELLS = frozenset({
    '/bin/sh', '/bin/bash', '/bin/dash', '/bin/zsh', '/usr/bin/sh',
    '/usr/bin/bash', '/usr/bin/dash', '/usr/bin/zsh', '/bin/busybox',
})
_UNIT_DIRS = (
    Path('/etc/systemd/system'),
    Path('/usr/lib/systemd/system'),
    Path('/lib/systemd/system'),
)


def _norm_path(path: str) -> str:
    text = os.path.normpath(str(path or ''))
    if text != '/' and text.endswith('/'):
        text = text.rstrip('/')
    return text


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def ports_of(constraints: dict | None) -> list[int] | None:
    """Numeric destination ports, or None when the list is not an exact allow-list."""
    out: list[int] = []
    for raw in _as_list((constraints or {}).get('ports')):
        try:
            port = int(raw)
        except (TypeError, ValueError):
            return None
        if port <= 0 or port > 65535:
            return None
        out.append(port)
    return out


# connect() is outbound. These names are the only direction values that
# the hook can check exactly. Inbound needs a listen/accept hook, which is not
# installed, so it is not expressible.
_OUTBOUND = frozenset({'out', 'outbound', 'egress', 'connect'})
_INBOUND = frozenset({'in', 'inbound', 'ingress', 'listen', 'accept'})


def parse_exact_ip(value) -> tuple[str, bytes] | None:
    """One exact IPv4 or IPv6 address, or None.

    CIDR prefixes, hostnames, wildcards, and zone indexes are not a single
    destination the connect hook can name, so they are rejected.
    """
    import ipaddress
    raw = str(value or '').strip()
    if not raw or '/' in raw or '%' in raw or any(ch in raw for ch in '*?'):
        return None
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv4Address):
        return ('4', ip.packed)
    return ('6', ip.packed)


def _direction_list(constraints: dict | None) -> list[str] | None:
    """Named directions, an empty list when none are named, or None if not exact."""
    raw = (constraints or {}).get('direction')
    if raw is None or raw == '' or raw == []:
        return []
    vals = [str(v).strip().lower() for v in _as_list(raw)]
    vals = [v for v in vals if v]
    if not vals:
        return []
    if any(v not in _OUTBOUND and v not in _INBOUND for v in vals):
        return None
    return vals


def _interfaces_named(constraints: dict | None) -> bool:
    for raw in _as_list((constraints or {}).get('interfaces')):
        if str(raw or '').strip():
            return True
    return False


def network_scope(constraints: dict | None) -> dict | None:
    """Exact socket_connect scope, or None when the rule must authorize nothing.

    A ports-only rule (no addrs, interfaces, or direction) grants those
    destination ports to any address, because that is what the rule said.
    Addresses, when present, are an exact allow-list and are enforced
    together with the ports. The connect hook does not see the egress
    interface (routing is later; SO_BINDTODEVICE is a different constraint),
    so a named interface authorizes nothing. Direction is exact only when
    every named value is outbound. Inbound, or any address form that is
    not a single IP, authorizes nothing — the rule is not widened to the
    port alone or to the address alone.
    """
    constraints = constraints or {}
    if not isinstance(constraints, dict):
        return None
    if _interfaces_named(constraints):
        return None
    directions = _direction_list(constraints)
    if directions is None or any(v not in _OUTBOUND for v in directions):
        return None
    ports = ports_of(constraints)
    if not ports:
        return None
    addrs: list[tuple[str, bytes]] = []
    for raw in _as_list(constraints.get('addrs')):
        parsed = parse_exact_ip(raw)
        if parsed is None:
            return None
        if parsed not in addrs:
            addrs.append(parsed)
    return {
        'ports': ports,
        'addrs': addrs,
        'any_addr': not addrs,
        'outbound': bool(directions),
    }


def rule_expressible(item: dict | None) -> bool:
    """True when every constraint can be checked without widening the rule.

    A network rule that names only addresses, only an interface, or only a
    direction is not expressible. The same is true when it names a port and
    also a constraint the connect hook cannot check exactly: that rule
    authorizes nothing, rather than the port alone.
    """
    if not isinstance(item, dict):
        return False
    typ = item.get('type') or ''
    constraints = item.get('constraints') or {}
    if not isinstance(constraints, dict):
        return False
    if typ in ('file_read', 'file_write', 'file_exec', 'command', 'device'):
        paths = _as_list(constraints.get('paths') or constraints.get('path'))
        if not paths:
            return False
        for path in paths:
            text = str(path)
            if not text.startswith('/') or '..' in Path(text).parts:
                return False
        return True
    if typ == 'login':
        return bool(_as_list(constraints.get('users')) or _as_list(constraints.get('uids')))
    if typ == 'network':
        return network_scope(constraints) is not None
    if typ == 'service':
        units = _as_list(constraints.get('units'))
        return bool(units) and all(_unit_name_ok(u) for u in units)
    return False


def _unit_name_ok(name) -> bool:
    text = str(name or '')
    if not text or '/' in text or text.startswith('.') or '..' in text:
        return False
    return True


def subject_matches(item: dict, *, path: str | None = None, user: str | None = None,
                    uid: int | None = None, port: int | None = None,
                    unit: str | None = None, addr: str | None = None,
                    direction: str | None = None, interface: str | None = None) -> bool:
    """True only when this subject sits inside the rule's own constraints.

    A different path, user, port, or address never matches. An unexpressible
    rule matches nothing. A network rule that names an address does not
    match a port check that omits the address.
    """
    if not rule_expressible(item):
        return False
    typ = item.get('type') or ''
    constraints = item.get('constraints') or {}
    if typ in ('file_read', 'file_write', 'file_exec', 'command', 'device'):
        if path is None:
            return False
        want = _norm_path(path)
        for raw in _as_list(constraints.get('paths') or constraints.get('path')):
            if _norm_path(str(raw)) == want:
                return True
        return False
    if typ == 'login':
        users = {str(u) for u in _as_list(constraints.get('users'))}
        uids = set()
        for raw in _as_list(constraints.get('uids')):
            try:
                uids.add(int(raw))
            except (TypeError, ValueError):
                return False
        if user is not None and str(user) in users:
            return True
        if uid is not None and int(uid) in uids:
            return True
        return False
    if typ == 'network':
        scope = network_scope(constraints)
        if scope is None or port is None:
            return False
        try:
            port_n = int(port)
        except (TypeError, ValueError):
            return False
        if port_n not in scope['ports']:
            return False
        if scope['addrs']:
            parsed = parse_exact_ip(addr)
            if parsed is None or parsed not in scope['addrs']:
                return False
        if scope['outbound']:
            # connect() is outbound. A caller that does not say so has not
            # shown that this subject is the action the rule named.
            if str(direction or '').strip().lower() not in _OUTBOUND:
                return False
        if interface:
            return False
        return True
    if typ == 'service':
        if unit is None:
            return False
        return str(unit) in {str(u) for u in _as_list(constraints.get('units'))}
    return False


def _rule_active(item: dict, active_keys: set[str] | None) -> bool:
    if not active_keys:
        return False
    key = item.get('key')
    return bool(key) and key in active_keys


def iter_custom(st: dict | None, *, kind: str | None = None) -> list[dict]:
    out = []
    for item in (st or {}).get('custom') or []:
        if not isinstance(item, dict):
            continue
        if kind and item.get('type') != kind:
            continue
        out.append(item)
    return out


def custom_authorizes(st: dict | None, *, kind: str, path: str | None = None,
                      user: str | None = None, uid: int | None = None,
                      port: int | None = None, unit: str | None = None,
                      addr: str | None = None, direction: str | None = None,
                      interface: str | None = None,
                      active_keys: set[str] | None = None) -> bool:
    """True only when an active, expressible rule of this kind covers the subject.

    Inactive rules and rules whose constraints cannot be checked exactly return
    False. They do not authorize any other path, user, port, or unit.
    """
    for item in iter_custom(st, kind=kind):
        if not _rule_active(item, active_keys):
            continue
        if item.get('mode') not in (None, 'grant', 'lock', 'replace'):
            continue
        if subject_matches(
            item, path=path, user=user, uid=uid, port=port, unit=unit,
            addr=addr, direction=direction, interface=interface,
        ):
            return True
    return False


def governed_subject(st: dict | None, *, kind: str, path: str | None = None,
                     user: str | None = None, uid: int | None = None,
                     port: int | None = None, unit: str | None = None,
                     addr: str | None = None, direction: str | None = None,
                     interface: str | None = None) -> bool:
    """True when any expressible rule of this kind names the subject, active or not."""
    for item in iter_custom(st, kind=kind):
        if subject_matches(
            item, path=path, user=user, uid=uid, port=port, unit=unit,
            addr=addr, direction=direction, interface=interface,
        ):
            return True
    return False


def login_uids(item: dict) -> list[int]:
    """Uids a login rule can name. Unknown accounts are omitted (no kernel grant)."""
    if not rule_expressible(item) or item.get('type') != 'login':
        return []
    found: list[int] = []
    constraints = item.get('constraints') or {}
    for raw in _as_list(constraints.get('uids')):
        try:
            found.append(int(raw))
        except (TypeError, ValueError):
            continue
    try:
        import pwd
    except ImportError:
        pwd = None
    for name in _as_list(constraints.get('users')):
        if pwd is None:
            continue
        try:
            found.append(int(pwd.getpwnam(str(name)).pw_uid))
        except KeyError:
            continue
    # stable unique
    out: list[int] = []
    seen: set[int] = set()
    for uid in found:
        if uid in seen or uid < 0:
            continue
        seen.add(uid)
        out.append(uid)
    return out


def scope_paths(item: dict) -> list[str]:
    if not rule_expressible(item):
        return []
    if item.get('type') not in ('file_read', 'file_write', 'file_exec', 'command', 'device'):
        return []
    constraints = item.get('constraints') or {}
    return [_norm_path(str(p)) for p in _as_list(constraints.get('paths') or constraints.get('path'))]


def service_exec_path(unit: str, search: tuple[Path, ...] | None = None) -> str | None:
    """Absolute ExecStart binary for a unit, or None when that is not safe.

    Specifiers, relative paths, and shells are refused so a unit rule cannot
    become a machine-wide execute grant.
    """
    if not _unit_name_ok(unit):
        return None
    for base in search or _UNIT_DIRS:
        path = Path(base) / str(unit)
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.startswith('ExecStart='):
                continue
            argv = stripped.split('=', 1)[1].strip()
            if not argv:
                return None
            token = argv.split()[0]
            if token.startswith('-'):
                token = token[1:]
            if token.startswith('@'):
                token = token[1:]
            if (not token.startswith('/')) or '%' in token or token in _SHELLS:
                return None
            return token
        return None
    return None
