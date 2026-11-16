from __future__ import annotations

import json
import os
from pathlib import Path

from ker.paths import CONFIG_PATH, ETC, LOG_DIR, PRIVATE_DIR, STATE_PATH, TRUST_DIR, VAR


def ensure_dirs() -> None:
    for p in (ETC, TRUST_DIR, VAR, PRIVATE_DIR, LOG_DIR):
        p.mkdir(parents=True, exist_ok=True)
        os.chmod(p, 0o700)


def load_json(path: Path, default=None):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding='utf-8'))


def save_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def state() -> dict:
    return load_json(STATE_PATH, {}) or {}


def save_state(data: dict) -> None:
    save_json(STATE_PATH, data)


def initialized() -> bool:
    st = state()
    return bool(st.get('initialized'))
