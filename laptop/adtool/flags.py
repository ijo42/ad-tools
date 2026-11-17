"""Flag helpers: regex, queue (JSONL) and stream extraction."""

import json
import os
import re
import time

DEFAULT_FLAG_RE = r"[A-Z0-9]{31}="


def flag_regex(pattern=None):
    if pattern is None:
        return re.compile(DEFAULT_FLAG_RE.encode())
    if isinstance(pattern, str):
        pattern = pattern.encode()
    return re.compile(pattern)  # bytes pattern


def extract_flags(data, pattern=None):
    if isinstance(data, str):
        data = data.encode("latin-1")
    return sorted(
        m.decode("latin-1") for m in set(flag_regex(pattern).findall(data))
    )


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
