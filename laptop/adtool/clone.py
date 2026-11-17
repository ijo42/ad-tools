"""Клонер запроса: генерация pwntools-скрипта из захваченного payload.

Скрипт можно править (цель, payload) и запускать с игрового ноутбука:
    uv run --with pwntools python clone_det1.py

Клонер нужен для доводки эксплойта: вербатим-реплай мог не сработать из-за
изменчивой части (флаг, токен) — в клоне её видно и можно заменить.
"""

FLAG_RE_SRC = r"[A-Z0-9]{31}="

TEMPLATE = '''#!/usr/bin/env python3
# Клон запроса (детект #{det_id}, сервис {service}, {kind}).
# Захвачен: {captured}
# Источник: {src}
#
# Запуск: uv run --with pwntools python clone_det{det_id}.py
# Правьте TARGET/PAYLOAD — например, замените плейсхолдеры {{FLAG}}, {{UUID}}.
from pwn import *
import re

context.log_level = "info"

TARGET_HOST = {host!r}   # <-- цель из teams.yaml
TARGET_PORT = {port}         # <-- порт сервиса цели

PAYLOAD = {payload_repr}

def main():
    io = remote(TARGET_HOST, TARGET_PORT)
    io.send(PAYLOAD)
    resp = io.recvall(timeout=5)
    print("=== ответ ({{n}}B) ===".format(n=len(resp)))
    print(resp.decode("latin-1", "replace"))
    flags = sorted(set(re.findall({flag_re!r}, resp)))
    if flags:
        print("=== флаги ===")
        for f in flags:
            print(f.decode())

if __name__ == "__main__":
    main()
'''


def generate_script(payload: bytes, host="<HOST>", port=80, det_id=None,
                    service="", kind="", captured="", src=""):
    return TEMPLATE.format(
        det_id=det_id if det_id is not None else "-",
        service=service or "?",
        kind=kind or "?",
        captured=captured or "",
        src=src or "",
        host=host,
        port=port,
        payload_repr=repr(payload),
        flag_re=FLAG_RE_SRC,
    )
