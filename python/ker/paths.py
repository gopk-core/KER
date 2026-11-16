from __future__ import annotations

import os
from pathlib import Path

PREFIX = Path(os.environ['KER_PREFIX']) if os.environ.get('KER_PREFIX') else None

def _p(*parts: str) -> Path:
    rel = Path(*parts)
    return (PREFIX / rel) if PREFIX else Path('/') / rel

ETC = _p('etc', 'ker')
STATE_PATH = ETC / 'state.json'
CONFIG_PATH = ETC / 'config.json'
TRUST_DIR = ETC / 'trust'
VAR = _p('var', 'lib', 'ker')
PRIVATE_DIR = VAR / 'private'
LOG_DIR = _p('var', 'log', 'ker')
MOUNT_ROOT = _p('run', 'ker', 'media')

UPGRADE_DIR = VAR / 'upgrade'
SNAPSHOT_DIR = UPGRADE_DIR / 'snapshots'
LIB_DIR = Path('/usr/lib/ker') if PREFIX is None else (PREFIX / 'usr' / 'lib' / 'ker')
