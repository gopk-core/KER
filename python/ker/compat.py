"""Version contract for long-lived, manually upgraded KER installs."""
from __future__ import annotations

import json
from pathlib import Path

from ker import __version__

PACKAGE_NAME = 'ker'
PACKAGE_VERSION = __version__

# Monotonic integers. A package ships every migration up to STATE_SCHEMA
# so an install may jump several versions in one manual upgrade.
STATE_SCHEMA = 1
MEDIA_SCHEMA = 2
CRYPTO_EPOCH = 1

# Oldest package / state this code can take over.
MIN_UPGRADE_FROM_PACKAGE = '0.1.0'
MIN_STATE_SCHEMA = 0

# Unreleased development versions superseded by the first public release.
# The public line is 0.1.0. ver_tuple('0.1') == (0, 1, 0) == ver_tuple('0.1.0'),
# so an already-published 0.1 install compares equal and can be taken over.
# 0.1.0 may also take the unreleased predecessors below; they are not a
# downgrade. Do not reuse these numbers for a later public release.
UNRELEASED_PREDECESSORS = {
    (0, 2, 0),
    (0, 3, 0),
    (0, 4, 0),
    (0, 4, 1),
    (0, 4, 2),
}

# Formats this code can still read. Never drop a value still in the field.
SUPPORTED_MEDIA_SCHEMAS = (2,)
SUPPORTED_CRYPTO_EPOCHS = (1,)


def ver_tuple(s: str) -> tuple[int, int, int]:
    parts: list[int] = []
    for p in str(s or '0').replace('-', '.').split('.'):
        if p.isdigit():
            parts.append(int(p))
        else:
            break
        if len(parts) == 3:
            break
    while len(parts) < 3:
        parts.append(0)
    return parts[0], parts[1], parts[2]


def ver_cmp(a: str, b: str) -> int:
    ta, tb = ver_tuple(a), ver_tuple(b)
    return (ta > tb) - (ta < tb)


def manifest() -> dict:
    from ker.features import catalog_public
    return {
        'package': PACKAGE_NAME,
        'package_version': PACKAGE_VERSION,
        'state_schema': STATE_SCHEMA,
        'media_schema': MEDIA_SCHEMA,
        'crypto_epoch': CRYPTO_EPOCH,
        'min_upgrade_from_package': MIN_UPGRADE_FROM_PACKAGE,
        'min_state_schema': MIN_STATE_SCHEMA,
        'supported_media_schemas': list(SUPPORTED_MEDIA_SCHEMAS),
        'supported_crypto_epochs': list(SUPPORTED_CRYPTO_EPOCHS),
        'no_auto_update': True,
        'replaces_packages': [PACKAGE_NAME],
        'features': catalog_public(),
    }


def write_manifest(path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest(), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return path


def inspect_state(st: dict | None) -> dict:
    st = st or {}
    initialized = bool(st.get('initialized'))
    schema = st.get('state_schema')
    if schema is None:
        schema = 1 if initialized and st.get('package_version') else (0 if initialized else None)
    return {
        'initialized': initialized,
        'package_version': st.get('package_version') or ('0.1.0' if initialized else None),
        'state_schema': None if schema is None else int(schema),
        'media_schema': int(st['media_schema']) if st.get('media_schema') is not None else (MEDIA_SCHEMA if initialized else None),
        'crypto_epoch': int(st['crypto_epoch']) if st.get('crypto_epoch') is not None else (CRYPTO_EPOCH if initialized else None),
        'mode': st.get('mode'),
        'kernel_enforcement': st.get('kernel_enforcement'),
        'migrations_applied': list(st.get('migrations_applied') or []),
    }


def takeover_errors(st: dict | None, target: dict | None = None) -> list[str]:
    """Why the target package must not take over this state. Empty means it can."""
    target = target or manifest()
    info = inspect_state(st)
    errors: list[str] = []
    if not info['initialized']:
        return errors
    schema = info['state_schema'] or 0
    if schema > int(target['state_schema']):
        errors.append(
            f"state_schema {schema} is newer than this package ({target['state_schema']}); refusing downgrade"
        )
    if schema < int(target['min_state_schema']):
        errors.append(
            f"state_schema {schema} is older than this package can migrate "
            f"(min {target['min_state_schema']})"
        )
    media = info['media_schema']
    if media is not None and media not in set(target['supported_media_schemas']):
        errors.append(f'unsupported media_schema {media}')
    epoch = info['crypto_epoch']
    if epoch is not None and epoch not in set(target['supported_crypto_epochs']):
        errors.append(f'unsupported crypto_epoch {epoch}')
    pv = info['package_version'] or '0.0.0'
    if ver_cmp(pv, target['min_upgrade_from_package']) < 0 and ver_tuple(pv) not in UNRELEASED_PREDECESSORS:
        errors.append(
            f"package {pv} is older than min_upgrade_from_package "
            f"{target['min_upgrade_from_package']}"
        )
    superseded = (
        ver_tuple(pv) in UNRELEASED_PREDECESSORS
        and ver_tuple(target['package_version']) == (0, 1, 0)
    )
    if ver_cmp(pv, target['package_version']) > 0 and schema > int(target['state_schema']):
        errors.append(f"installed package {pv} is newer than {target['package_version']}")
    elif ver_cmp(pv, target['package_version']) > 0 and not superseded:
        errors.append(f'downgrade from {pv} to {target["package_version"]} is refused')
    return errors
