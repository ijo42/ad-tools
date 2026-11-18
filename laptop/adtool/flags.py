"""Flag helpers: regex, queue (JSONL) and stream extraction.

extract_flags находит флаги не только в открытом виде, но и в типовых
обёртках, в которых флаг уезжает из сервиса в реальных играх:
URL-кодирование, gzip/zlib-тела, UTF-16 (протоколы «человеческим» текстом),
base64-блобы в HTTP/JSON/параметрах.
"""

import base64
import gzip
import json
import os
import re
import time
import zlib

DEFAULT_FLAG_RE = r"[A-Z0-9]{31}="

_B64_RE = re.compile(rb"[A-Za-z0-9+/=]{24,}")
_MAX_DECODE_BLOB = 65536


def flag_regex(pattern=None):
    if pattern is None:
        return re.compile(DEFAULT_FLAG_RE.encode())
    if isinstance(pattern, str):
        pattern = pattern.encode()
    return re.compile(pattern)  # bytes pattern


def _decode_variants(data: bytes):
    """Сгенерировать «раскрытые» представления data для поиска флага."""
    out = []
    if b"%" in data:
        try:
            from urllib.parse import unquote

            out.append(unquote(data.decode("latin-1")).encode("latin-1", "ignore"))
        except Exception:  # noqa: BLE001
            pass
    if data[:2] in (b"\x1f\x8b", b"\x78\x01", b"\x78\x9c", b"\x78\xda"):
        try:
            out.append(gzip.decompress(data))
        except Exception:  # noqa: BLE001
            try:
                out.append(zlib.decompress(data))
            except Exception:  # noqa: BLE001
                pass
    # gzip/zlib внутри буфера (HTTP-ответ: заголовки, потом тело)
    for magic in (b"\x1f\x8b", b"\x78\x01", b"\x78\x9c", b"\x78\xda"):
        pos = 0
        for _ in range(3):
            idx = data.find(magic, pos)
            if idx < 0:
                break
            pos = idx + 2
            try:
                if magic == b"\x1f\x8b":
                    out.append(gzip.decompress(data[idx:]))
                else:
                    out.append(zlib.decompress(data[idx:]))
            except Exception:  # noqa: BLE001
                continue
    try:
        out.append(data.decode("utf-16-le", "ignore").encode("latin-1", "ignore"))
    except Exception:  # noqa: BLE001
        pass
    for m in _B64_RE.finditer(data[:_MAX_DECODE_BLOB]):
        blob = m.group(0).rstrip(b"=")
        for pad in range(3):
            try:
                out.append(base64.b64decode(blob + b"=" * pad, validate=True))
                break
            except Exception:  # noqa: BLE001
                continue
    return out


def extract_flags(data, pattern=None):
    if isinstance(data, str):
        data = data.encode("latin-1")
    rx = flag_regex(pattern)
    found = set(rx.findall(data))
    for variant in _decode_variants(data):
        found |= set(rx.findall(variant))
    return sorted(m.decode("latin-1") for m in found)


class FlagQueue:
    """Append-only JSONL queue; a separate submitter process drains it.

    Each record: {"flag", "ts", "source", "meta"}.
    """

    def __init__(self, path="flags.queue.jsonl"):
        self.path = path

    def push(self, flag, source="manual", meta=None):
        rec = {"flag": flag, "ts": time.time(), "source": source, "meta": meta or {}}
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")

    def read_all(self, after_offset=0):
        if not os.path.exists(self.path):
            return [], after_offset
        out = []
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out, None
