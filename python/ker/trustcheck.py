from __future__ import annotations

from pathlib import Path


def secure_boot_status() -> dict:
    sb = Path('/sys/firmware/efi/efivars')
    result = {
        'efi': sb.parent.exists() or Path('/sys/firmware/efi').exists(),
        'secure_boot_supported': False,
        'secure_boot_enabled': False,
        'lockdown': None,
        'ok': False,
    }
    lockdown = Path('/sys/kernel/security/lockdown')
    if lockdown.exists():
        result['lockdown'] = lockdown.read_text(encoding='utf-8', errors='ignore').strip()
    # mokutil may say "doesn't support"
    ev = Path('/sys/firmware/efi/efivars')
    if ev.is_dir():
        for p in ev.iterdir():
            if p.name.startswith('SecureBoot-'):
                result['secure_boot_supported'] = True
                try:
                    data = p.read_bytes()
                    if len(data) >= 5 and data[4] == 1:
                        result['secure_boot_enabled'] = True
                except OSError:
                    pass
    result['ok'] = bool(result['secure_boot_enabled'] and result['lockdown'] and '[none]' not in (result['lockdown'] or ''))
    return result
