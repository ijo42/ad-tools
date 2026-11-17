"""Minimal TCP stream reassembly + HTTP request extraction.

Design: per (src, sport, dst, dport) stream, we accumulate payloads by
arrival order (competition traffic is one-way request bursts, so sequence
fidelity is good enough without full seq tracking; we do drop pure ACK/SYN
packets without data).
"""

from collections import defaultdict

_HTTP_METHODS = (
    # trailing space distinguishes real HTTP methods from payloads that merely
    # start with "GET..." (e.g. protocol commands like "GETFLAG\n")
    b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS ",
)

HTTP_LIMIT = 262144  # max bytes buffered per direction


class Stream:
    def __init__(self, key):
        self.key = key  # (src_ip, src_port, dst_ip, dst_port, proto)
        self.buf = b""
        self.ts_first = None
        self.ts_last = None
        self.bytes_seen = 0
        self.complete = False

    def push(self, ts, payload):
        if not payload:
            return []
        if self.ts_first is None:
            self.ts_first = ts
        self.ts_last = ts
        self.bytes_seen += len(payload)
        self.buf += payload
        if len(self.buf) > HTTP_LIMIT:
            self.buf = self.buf[-HTTP_LIMIT:]
        return self._try_parse_http()

    def _try_parse_http(self):
        """If buffer starts with an HTTP request, try to extract a full one."""
        if not self.buf.startswith(_HTTP_METHODS):
            return []
        head_end = self.buf.find(b"\r\n\r\n")
        if head_end == -1:
            if len(self.buf) > 16384:  # header flood — give up on this request
                self.buf = b""
            return []
        head = self.buf[:head_end]
        lines = head.split(b"\r\n")
        clen = 0
        for line in lines[1:]:
            if line[:14].lower() == b"content-length":
                try:
                    clen = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    clen = 0
        total = head_end + 4 + clen
        if len(self.buf) < total:
            return []
        request = self.buf[:total]
        self.buf = self.buf[total:]
        self.complete = True
        return [request]


class StreamReassembler:
    def __init__(self, on_http=None, on_raw=None):
        self.streams = defaultdict(lambda: None)
        self.on_http = on_http    # fn(key, request_bytes, stream)
        self.on_raw = on_raw      # fn(key, chunk, stream) — non-HTTP data

    def push(self, pkt):
        if not pkt.payload:
            return
        key = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, pkt.proto)
        st = self.streams[key]
        if st is None:
            st = Stream(key)
            self.streams[key] = st
        for request in st.push(pkt.ts, pkt.payload):
            if self.on_http:
                self.on_http(key, request, st)
        if st.complete:
            # stream served its purpose; reset for the next request on the
            # same tuple (keepalive/HTTP1.1 pipelines)
            st.complete = False
        # non-HTTP raw data: only report when buffer grows without a valid
        # HTTP prefix and looks like an exploit payload
        if (
            self.on_raw
            and not st.buf.startswith(_HTTP_METHODS)
            and len(st.buf) >= 4
        ):
            chunk = st.buf
            st.buf = b""
            self.on_raw(key, chunk, st)
