"""Ordered, idempotent state migrations shipped with every package."""
from __future__ import annotations

from ker.migrations import m0001_baseline

# Append new modules in order. Never renumber or delete a published migration.
REGISTRY = [
    m0001_baseline,
]


def pending(st: dict, up_to: int | None = None) -> list:
    from ker.compat import STATE_SCHEMA
    limit = STATE_SCHEMA if up_to is None else up_to
    applied = set(st.get('migrations_applied') or [])
    schema = int(st.get('state_schema') or 0)
    out = []
    for m in REGISTRY:
        if m.TARGET_SCHEMA > limit:
            continue
        if m.ID in applied and schema >= m.TARGET_SCHEMA:
            continue
        out.append(m)
    return out
