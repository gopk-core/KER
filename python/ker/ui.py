from __future__ import annotations

import sys

from ker.i18n import LANGS, t


def ask(prompt: str, default: str | None = None) -> str:
    suff = f' [{default}]' if default is not None else ''
    try:
        val = input(f'{prompt}{suff}: ').strip()
    except EOFError:
        val = ''
    return val or (default or '')


def confirm_y(prompt: str) -> bool:
    return ask(prompt).lower() == 'y'


def choose(prompt: str, options: list[tuple[str, str]]) -> str:
    print(prompt)
    for i, (key, label) in enumerate(options, 1):
        print(f'  {i}. {label}')
    while True:
        raw = ask('#')
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1][0]
        print('?')


def choose_language() -> str:
    print('Select language / 选择语言 / 選擇語言')
    return choose('', list(LANGS.items()))


def die(lang: str, key: str, code: int = 1, **kw) -> None:
    print(t(lang, key, **kw), file=sys.stderr)
    raise SystemExit(code)
