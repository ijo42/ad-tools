"""Payload generalization: verbatim exploit -> template with placeholders.

Goal of fast-track: an attack captured on OUR vulnbox usually works
verbatim against other teams; if it contains team-specific markers
(flags, session ids, uuids, hex-tokens), we swap them for placeholders and
render per-target.
"""

import re

FLAG_RE = re.compile(r"[A-Z0-9]{31}=")
UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
HEX32_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")
HEX64_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
# JWT (header.payload.signature) и длинные base64url-токены (сессии):
# требуют строчных букв/-/_ в середине, чтобы не задевать флаг [A-Z0-9]{31}=
JWT_RE = re.compile(
    r"\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)
B64URL_RE = re.compile(
    r"(?=[A-Za-z0-9_-]{24,}\b)[A-Za-z0-9_-]*[a-z_][A-Za-z0-9_-]*"
)

PLACEHOLDERS = [
    (FLAG_RE, "{FLAG}"),
    (UUID_RE, "{UUID}"),
    (HEX64_RE, "{HEX64}"),
    (HEX32_RE, "{HEX32}"),
    (JWT_RE, "{TOKEN}"),
    (B64URL_RE, "{TOKEN}"),
]


def generalize(payload: bytes):
    """Return (template_bytes, params) where params holds original values."""
    params = {}
    counters = {}
    out = payload
    for rx, name in PLACEHOLDERS:
        base = name.strip("{}").lower()
        for m in rx.finditer(out.decode("latin-1")):
            counters[base] = counters.get(base, 0) + 1
            key = f"{base}{counters[base]}" if counters[base] > 1 else base
            params[key] = m.group(0)
        if counters.get(base):
            # replace all occurrences of this class, first -> base, others -> baseN
            found = list(rx.finditer(out.decode("latin-1")))
            text = out.decode("latin-1")
            result = []
            last = 0
            for i, m in enumerate(found, start=1):
                key = f"{base}{i}" if i > 1 else base
                result.append(text[last : m.start()])
                result.append("{" + key.upper() + "}")
                last = m.end()
            result.append(text[last:])
            out = "".join(result).encode("latin-1")
    return out, params


def render(template: bytes, overrides: dict) -> bytes:
    """Fill placeholders. Unknown placeholders are left as-is (verbatim)."""
    text = template.decode("latin-1")
    for key, value in overrides.items():
        text = text.replace("{" + key.upper() + "}", value)
    return text.encode("latin-1")
