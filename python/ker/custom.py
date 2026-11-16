from __future__ import annotations

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
