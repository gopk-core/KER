"""Adopt versioned state for installs that predate the upgrade framework."""
from __future__ import annotations

ID = '0001_baseline'
TARGET_SCHEMA = 1


def apply(st: dict, ctx: dict) -> dict:
    st = dict(st)
    st['state_schema'] = TARGET_SCHEMA
    st.setdefault('media_schema', ctx.get('media_schema', 2))
    st.setdefault('crypto_epoch', ctx.get('crypto_epoch', 1))
    st.setdefault('feature_replacements', {})
    applied = list(st.get('migrations_applied') or [])
    if ID not in applied:
        applied.append(ID)
    st['migrations_applied'] = applied
    # Never touch mode or kernel_enforcement.
    return st


def verify(st: dict, ctx: dict) -> None:
    if int(st.get('state_schema') or 0) < TARGET_SCHEMA:
        raise RuntimeError('baseline did not set state_schema')
    if ID not in (st.get('migrations_applied') or []):
        raise RuntimeError('baseline id missing from migrations_applied')
