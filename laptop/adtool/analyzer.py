"""Live analyzer: packets -> events (flags, HTTP attacks, raw payloads).

Classification: traffic FROM checker_ips = checker (п. 3.4 регламента),
everything else hitting service ports (or any inbound if service_ports is
empty) = attack.
"""

import hashlib
import time

from .flags import extract_flags
from .streams import StreamReassembler


class Analyzer:
    def __init__(self, config=None, flag_pattern=None, event_cb=None,
                 payload_cb=None):
        cfg = config or {}
        self.checker_ips = set(cfg.get("checker_ips", []))
        self.service_ports = set(cfg.get("service_ports", []))
        self.verbosity = cfg.get("verbosity", "all")
        self.flag_pattern = flag_pattern
        self.event_cb = event_cb or print
        # payload_cb(dict) — structured event for http/raw attacks:
        # {kind, ts, src_ip, src_port, dst_ip, dst_port, payload, flags}
        self.payload_cb = payload_cb
        self._seen_payloads = set()   # fingerprint dedup of raw payloads
        self._seen_flags = set()
        reassembler = StreamReassembler(on_http=self._on_http, on_raw=self._on_raw)
        self.reassembler = reassembler

    # --- classification ----------------------------------------------------
    def classify(self, pkt):
        """Return 'checker' | 'attack' | 'other'."""
        if pkt.src_ip in self.checker_ips:
            return "checker"
        if self.service_ports and pkt.dst_port not in self.service_ports:
            return "other"
        if not self.service_ports and pkt.dst_port in (22, 53, 123):
            return "other"  # ssh/dns/ntp noise
        return "attack"

    # --- handlers ----------------------------------------------------------
    def _on_http(self, key, request, stream):
        src_ip, src_port, dst_ip, dst_port, _proto = key
        kind = "checker" if src_ip in self.checker_ips else "attack"
        flags = extract_flags(request, self.flag_pattern)
        first_line = request.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        if self.payload_cb:
            self.payload_cb(
                {
                    "type": "http",
                    "kind": kind,
                    "ts": stream.ts_last,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "payload": request,
                    "flags": flags,
                }
            )
        event = {
            "type": "http",
            "kind": kind,
            "ts": stream.ts_last,
            "src": f"{src_ip}:{src_port}",
            "dst": f"{dst_ip}:{dst_port}",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "request": first_line,
            "payload": request,
            "flags": flags,
        }
        self._emit(event)

    def _on_raw(self, key, chunk, stream):
        src_ip, src_port, dst_ip, dst_port, _proto = key
        if src_ip in self.checker_ips or dst_ip in self.checker_ips:
            return  # чекер в обе стороны: запросы и ответы с нашими флагами
        fp = hashlib.sha1(chunk).hexdigest()[:16]
        if fp in self._seen_payloads:
            return
        self._seen_payloads.add(fp)
        flags = extract_flags(chunk, self.flag_pattern)
        # флаг, утекающий ИЗ нашего сервиса (connect-back/UDP наружу),
        # — это «украденный у нас» флаг, а не атака: сабмитить его нельзя
        kind = "leak" if src_port in self.service_ports else "attack"
        preview = chunk[:160].decode("latin-1", "replace").replace("\n", "\\n")
        if self.payload_cb:
                self.payload_cb(
                    {
                        "type": "raw",
                        "kind": kind,
                        "ts": stream.ts_last,
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "payload": chunk,
                        "flags": flags,
                    }
                )
        event = {
            "type": "raw",
            "kind": kind,
            "ts": stream.ts_last,
            "src": f"{src_ip}:{src_port}",
            "dst": f"{dst_ip}:{dst_port}",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "request": preview,
            "payload": chunk,
            "flags": flags,
        }
        self._emit(event)

    def _emit(self, event):
        for flag in event.get("flags", []):
            if flag not in self._seen_flags:
                self._seen_flags.add(flag)
                self.event_cb(
                    {
                        "type": "flag",
                        "kind": event["kind"],
                        "ts": event.get("ts"),
                        "src": event.get("src"),
                        "dst": event.get("dst"),
                        # для атрибуции флага детекту: src/dst могут быть
                        # любой стороной (запрос или ответ)
                        "src_ip": event.get("src_ip"),
                        "src_port": event.get("src_port"),
                        "dst_ip": event.get("dst_ip"),
                        "dst_port": event.get("dst_port"),
                        "flag": flag,
                    }
                )
        if self.verbosity == "flags":
            return
        if event["type"] == "raw" and self.verbosity != "all":
            return
        if event.get("flags"):
            mark = "*** FLAG ***" if event["kind"] == "attack" else "[flag]"
        else:
            mark = "ATTACK" if event["kind"] == "attack" else "checker"
        ts = time.strftime("%H:%M:%S", time.localtime(event.get("ts") or time.time()))
        self.event_cb(
            f"{ts} {mark:12} {event['src']:<22} -> {event['dst']:<22} "
            f"{event.get('request', '')[:120]}"
        )

    # --- entry -------------------------------------------------------------
    def push_packet(self, pkt):
        self.reassembler.push(pkt)
