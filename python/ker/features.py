"""Feature catalog: new packages can add features and replace old ones."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ker.catalog import BUILTIN, CUSTOM_TYPES


@dataclass(frozen=True)
class Feature:
    id: str
    kind: str  # permission | custom_type | capability
    since_schema: int = 1
    status: str = 'active'  # active | deprecated | replaced
    replaced_by: str | None = None
    lossless: bool = False  # safe to rewrite ids automatically
    provision_needed: bool = False  # needs a key on media
    label_en: str = ''
    label_zh_cn: str = ''
    label_zh_tw: str = ''


FEATURES: dict[str, Feature] = {}


def _base() -> dict[str, Feature]:
    out: dict[str, Feature] = {}
    for fid, en, zh, tw in BUILTIN:
        out[fid] = Feature(
            fid, 'permission', 1,
            provision_needed=True,
            label_en=en, label_zh_cn=zh, label_zh_tw=tw,
        )
    for typ in CUSTOM_TYPES:
        out[typ] = Feature(typ, 'custom_type', 1, provision_needed=True, label_en=typ)
    for fid, en, zh, tw, prov in (
        ('admin', 'admin console key', '管理控制台密钥', '管理主控台金鑰', True),
        ('cluster', 'multi-node cluster', '多机集群', '多機叢集', False),
        ('console', 'ker console', 'ker console', 'ker console', False),
        ('test_mode', 'terminal test mode', '终端测试模式', '終端測試模式', False),
        ('upgrade', 'manual package upgrade', '手动升级框架', '手動升級框架', False),
    ):
        out[fid] = Feature(
            fid, 'capability', 1,
            provision_needed=prov,
            label_en=en, label_zh_cn=zh, label_zh_tw=tw,
        )
    return out


def _since_0_4() -> dict[str, Feature]:
    """Features added after the frozen schema-1 catalog."""
    out: dict[str, Feature] = {}
    for fid, en, zh, tw in (
        ('boot_hook', 'initramfs boot authorization hook',
         'initramfs 启动授权挂钩', 'initramfs 啟動授權掛鉤'),
        ('ssh_hook', 'SSH PAM and AuthorizedKeysCommand hook',
         'SSH PAM 与 AuthorizedKeysCommand 挂钩',
         'SSH PAM 與 AuthorizedKeysCommand 掛鉤'),
        ('multiarch_packages', 'multi-format multi-architecture packages',
         '多格式多架构软件包', '多格式多架構套件'),
    ):
        out[fid] = Feature(
            fid, 'capability', 1,
            provision_needed=False,
            label_en=en, label_zh_cn=zh, label_zh_tw=tw,
        )
    return out


def reset_features() -> None:
    FEATURES.clear()
    FEATURES.update(_base())
    FEATURES.update(_since_0_4())


def register_feature(feat: Feature) -> None:
    FEATURES[feat.id] = feat


reset_features()

# Frozen catalog as of state_schema 1. New features are added to FEATURES
# but must not be appended here, so a jump from an unversioned 0.1 install
# can report them as new.
SCHEMA1_FEATURE_IDS = frozenset(_base())


def catalog_public() -> list[dict]:
    rows = []
    for feat in FEATURES.values():
        rows.append({
            'id': feat.id,
            'kind': feat.kind,
            'since_schema': feat.since_schema,
            'status': feat.status,
            'replaced_by': feat.replaced_by,
            'lossless': feat.lossless,
            'provision_needed': feat.provision_needed,
        })
    rows.sort(key=lambda r: (r['kind'], r['id']))
    return rows


def available_ids() -> list[str]:
    return sorted(FEATURES)


def provisioned_ids(st: dict) -> list[str]:
    ids: list[str] = []
    for p in st.get('permissions') or []:
        ids.append(p)
    for item in st.get('custom') or []:
        typ = item.get('type') if isinstance(item, dict) else None
        if typ:
            ids.append(typ)
    if st.get('initialized'):
        ids.append('admin')
        ids.append('test_mode')
        ids.append('upgrade')
        ids.append('console')
        if st.get('role') in ('master', 'child') or st.get('children'):
            ids.append('cluster')
    # unique, stable order
    seen: set[str] = set()
    out: list[str] = []
    for i in ids:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def added_features(st: dict) -> list[str]:
    """Features this package adds that the installed state does not yet list."""
    known = set(st.get('features_known') or [])
    if not known:
        known = set(SCHEMA1_FEATURE_IDS)
    return sorted(
        f.id for f in FEATURES.values()
        if f.status == 'active' and f.id not in known and f.id not in provisioned_ids(st)
    )


def pending_replacements(st: dict) -> list[dict]:
    prov = set(provisioned_ids(st))
    already = dict(st.get('feature_replacements') or {})
    out = []
    for feat in FEATURES.values():
        if feat.status != 'replaced' or not feat.replaced_by:
            continue
        if feat.id in prov or feat.id in (st.get('permissions') or []) or feat.id in already:
            if already.get(feat.id) == feat.replaced_by and feat.id not in (st.get('permissions') or []):
                continue
            out.append({
                'old': feat.id,
                'new': feat.replaced_by,
                'lossless': feat.lossless,
                'kind': feat.kind,
            })
    return out


def apply_replacements(st: dict) -> tuple[dict, list[dict]]:
    """Rewrite lossless replaced feature ids. Non-lossless changes are recorded only."""
    st = dict(st)
    changes: list[dict] = []
    perms = list(st.get('permissions') or [])
    custom = list(st.get('custom') or [])
    mapping = dict(st.get('feature_replacements') or {})
    for feat in list(FEATURES.values()):
        if feat.status != 'replaced' or not feat.replaced_by:
            continue
        if feat.id in perms:
            if feat.lossless:
                perms = [feat.replaced_by if p == feat.id else p for p in perms]
                # keep order, drop dupes
                perms = list(dict.fromkeys(perms))
                mapping[feat.id] = feat.replaced_by
                changes.append({'old': feat.id, 'new': feat.replaced_by, 'applied': True})
            else:
                mapping.setdefault(feat.id, feat.replaced_by)
                changes.append({'old': feat.id, 'new': feat.replaced_by, 'applied': False, 'reason': 'not_lossless'})
        new_custom = []
        custom_changed = False
        for item in custom:
            if not isinstance(item, dict):
                new_custom.append(item)
                continue
            if item.get('type') == feat.id and feat.kind == 'custom_type':
                if feat.lossless:
                    item = dict(item)
                    item['type'] = feat.replaced_by
                    mapping[feat.id] = feat.replaced_by
                    custom_changed = True
                else:
                    mapping.setdefault(feat.id, feat.replaced_by)
            new_custom.append(item)
        if custom_changed:
            custom = new_custom
            if not any(c.get('old') == feat.id and c.get('applied') for c in changes):
                changes.append({'old': feat.id, 'new': feat.replaced_by, 'applied': True})
    st['permissions'] = perms
    st['custom'] = custom
    st['feature_replacements'] = mapping
    return st, changes


def stamp_known(st: dict) -> dict:
    st = dict(st)
    st['features_known'] = available_ids()
    return st
