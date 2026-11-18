#!/usr/bin/env python3
"""ingest.py — приёмник трафика с vulnbox и live-анализатор.

Два канала (можно оба сразу):
- PCAP-over-IP на TCP :57012 (vulnbox/vulnbox/pcapstream.sh шлёт сюда tcpdump-стрим)
- HTTP POST /pcap с телом-pcap-файлом на :57013 (загрузка ротированных файлов)

Каждый pcap дополнительно сохраняется в --ingest-dir (каталог pkappa2),
так что pkappa2 подхватит его для ретроспективного поиска.

Usage:
  uv run --with pyyaml python ingest.py --config config.yaml
"""

import argparse
import http.server
import socketserver
import sys
import threading
import time

import yaml

from adtool.analyzer import Analyzer
from adtool.autoprobe import NpcProber
from adtool.flags import flag_regex, FlagQueue
from adtool.pcap import PcapParser
from adtool.store import DetectionStore

DEFAULT_PCAP_OVER_IP_PORT = 57012
DEFAULT_HTTP_PORT = 57013


def load_config(path):
    if not path:
        return {}
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


class Ingest:
    def __init__(self, config, ingest_dir, flag_queue_file=None, save_pcaps=True,
                 store_path="detections.db", npc_targets=None):
        flag_cfg = (config or {}).get("flags", {})
        self.flag_re = flag_pattern_of(flag_cfg)
        analyzer_cfg = (config or {}).get("analyzer", {})
        game_cfg = (config or {}).get("game") or {}
        self.game_start = float(game_cfg.get("start", 0) or 0)
        self.round_len = int(game_cfg.get("round_len", 60))
        # наш vulnbox: порт сервиса -> имя (определение атакуемого сервиса)
        self.services = {int(k): v for k, v in (game_cfg.get("services") or {}).items()}
        npc_cfg = (config or {}).get("npc_check") or {}
        queue_file = flag_queue_file or (config or {}).get("submit", {}).get(
            "queue_file", "flags.queue.jsonl"
        )
        self.flag_queue = FlagQueue(queue_file)
        self.ingest_dir = ingest_dir
        self.save_pcaps = save_pcaps
        self.store = DetectionStore(store_path)
        # hardening: опциональные токены приёма трафика (раздел ingest в
        # config.yaml). Пока заданы — клиенты обязаны их предъявить:
        # HTTP-upload — заголовок X-Ingest-Token, PCAP-over-IP — токен
        # первыми байтами потока (pcapstream.sh шлёт его перед стримом).
        ingest_cfg = (config or {}).get("ingest") or {}
        self.http_token = ingest_cfg.get("token") or None
        self.poip_token = ingest_cfg.get("poip_token") or None
        if self.http_token or self.poip_token:
            print("ingest auth: " + ", ".join(
                part for part, on in
                (("http-token", self.http_token), ("poip-token", self.poip_token))
                if on))
        self.npc_prober = None
        if npc_targets and npc_cfg.get("enabled", True):
            self.npc_prober = NpcProber(
                npc_targets,
                flag_pattern=self.flag_re.pattern.decode(),
                store=self.store,
            )
        self.analyzer = Analyzer(
            config={
                **analyzer_cfg,
                # порты наших сервисов — чтобы отличать «утечку» флага наружу
                # (leak) от входящей атаки (attack) в raw-канале
                "service_ports": list(self.services.keys())
                or analyzer_cfg.get("service_ports", []),
            },
            flag_pattern=self.flag_re.pattern.decode(),
            event_cb=make_event_logger(self.flag_queue, self._attribute_flag),
            payload_cb=self._record_payload,
        )
        self.pcap_parser = PcapParser(allow_resync=True)
        self.pcap_count = 0
        self._pkt_buf = []
        self._last_flush = 0.0

    def _flush_packets(self):
        if self._pkt_buf:
            self.store.insert_packets(self._pkt_buf)
            self._pkt_buf = []
        self._last_flush = time.time()

    def _record_packet(self, pkt):
        """Все пакеты (даже без флагов) — в БД для вкладки «Пакеты»."""
        if not pkt.payload:
            return
        src_port, dst_port = int(pkt.src_port), int(pkt.dst_port)
        if dst_port in self.services:
            direction, service = "in", self.services[dst_port]
        elif src_port in self.services:
            direction, service = "out", self.services[src_port]
        else:
            direction, service = "other", None
        has_flag = 1 if self.flag_re.search(pkt.payload) else 0
        ts = pkt.ts or time.time()
        self._pkt_buf.append(
            (
                ts, self.round_of(ts),
                f"{pkt.src_ip}:{src_port}", f"{pkt.dst_ip}:{dst_port}",
                pkt.proto, service, direction, len(pkt.payload),
                has_flag, pkt.payload[:160].decode("latin-1", "replace"),
            )
        )
        if len(self._pkt_buf) >= 200 or time.time() - self._last_flush > 2.0:
            self._flush_packets()

    def round_of(self, ts):
        if not self.game_start:
            return None
        return max(0, int((ts - self.game_start) / self.round_len))

    def service_of(self, dst_port):
        return self.services.get(int(dst_port), f"port-{dst_port}")

    def _record_payload(self, event):
        """payload_cb: structured attack event -> dedup store + NPC probe."""
        if event["kind"] != "attack":
            return  # checker traffic is not an attack detection
        dst_port = int(event["dst_port"])
        if self.services and dst_port not in self.services:
            return  # ответы наружу на эфемерные порты — не входящая атака
        payload = event["payload"]
        flags = [f for f in event["flags"] if isinstance(f, str)]
        det_id, is_new, fingerprint = self.store.record(
            payload=payload,
            kind=event["type"],
            src_ip=event["src_ip"],
            src_port=event["src_port"],
            dst_port=event["dst_port"],
            service=self.service_of(event["dst_port"]),
            ts=event.get("ts"),
            flags=flags,
            round_no=self.round_of(event.get("ts")),
        )
        tag = "NEW" if is_new else f"dup#{det_id}"
        first_line = payload.split(b"\r\n", 1)[0][:100].decode("latin-1", "replace")
        print(
            f"[detect {tag}] svc={self.service_of(event['dst_port'])} "
            f"from {event['src_ip']} {first_line}"
        )
        if is_new and self.npc_prober:
            # автопроба нового пейлоада на NPC — результат в UI
            self.npc_prober.probe_async(det_id, fingerprint, payload)

    def _attribute_flag(self, event):
        """Флаг, утёкший из сервиса (ответ атакующему), привязывается к
        детекту: service + attacker_ip + раунд. Совпадение (флаг, раунд)
        у разных детектов = одна и та же атака -> слияние."""
        if event.get("kind") != "attack" or not self.services:
            return
        src_port, dst_port = event.get("src_port"), event.get("dst_port")
        if src_port is None or dst_port is None:
            return
        if int(src_port) in self.services:
            service_port, attacker_ip = src_port, event.get("dst_ip")
        else:
            service_port, attacker_ip = dst_port, event.get("src_ip")
        det_id = self.store.attribute_flag(
            service=self.service_of(service_port),
            attacker_ip=attacker_ip or "",
            round_no=self.round_of(event.get("ts")),
            flag=event["flag"],
        )
        if det_id is not None:
            print(f"[flag->det#{det_id}] {event['flag']}")
            self.store.add_seen_flag(
                event["flag"], self.round_of(event.get("ts")),
                event.get("ts"), attacker_ip or "",
                self.service_of(service_port),
            )

    def handle_pcap_bytes(self, data: bytes, tag="stream", parser=None):
        if self.save_pcaps and self.ingest_dir:
            import os

            os.makedirs(self.ingest_dir, exist_ok=True)
            fname = os.path.join(
                self.ingest_dir,
                f"{tag}_{time.strftime('%Y%m%d_%H%M%S')}.pcap",
            )
            with open(fname, "wb") as fh:
                fh.write(data)
        # each PCAP-over-IP connection has its own global header -> own parser;
        # uploaded files go through the shared parser
        parser = parser or self.pcap_parser
        packets = parser.feed(data)
        for pkt in packets:
            self._record_packet(pkt)
            self.analyzer.push_packet(pkt)
        self.pcap_count += len(packets)
        # сбрасываем буфер пакетов на каждом чанке — иначе хвост застревает
        # в буфере до закрытия потока (а поток может не закрыться вовсе)
        self._flush_packets()

    def stats(self):
        return {"packets": self.pcap_count}


def flag_pattern_of(flag_cfg):
    return flag_regex(flag_cfg.get("regex")) if flag_cfg.get("regex") else flag_regex()


def make_event_logger(flag_queue, attribute_flag=None):
    """Print events; push attack flags to the queue; attribute flags to
    detections (service + attacker + round).

    kind=leak (флаг уходит ИЗ нашего сервиса) не сдаётся — это наш флаг,
    его можно только атрибутировать детекту/раунду."""

    def log(event):
        if isinstance(event, str):
            print(event)
            return
        if event["type"] == "flag":
            ts = time.strftime("%H:%M:%S", time.localtime(event.get("ts") or time.time()))
            print(
                f"{ts} *** FLAG *** {event['flag']} "
                f"(via {event['kind']} from {event.get('src')})"
            )
            if event["kind"] == "attack":
                flag_queue.push(event["flag"], source="traffic", meta=event.get("src"))
            if event["kind"] in ("attack", "leak") and attribute_flag:
                try:
                    attribute_flag(event)
                except Exception as exc:  # noqa: BLE001
                    print(f"[attr error] {exc}")
        else:
            print(event)

    return log


class _ReuseServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_pcap_over_ip_server(ingest, port, listen_ip):
    """Accept N concurrent PCAP-over-IP clients; each stream is its own parser.
    С poip_token: первые байты потока — токен, потом pcap-стрим."""

    def conn_handler(conn):
        parser = PcapParser(allow_resync=True)
        try:
            if ingest.poip_token:
                token = b""
                while len(token) < len(ingest.poip_token):
                    chunk = conn.recv(len(ingest.poip_token) - len(token))
                    if not chunk:
                        conn.close()
                        return
                    token += chunk
                if token != ingest.poip_token.encode():
                    print("[poip] неверный токен — соединение закрыто")
                    conn.close()
                    return
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                ingest.handle_pcap_bytes(data, tag="poip", parser=parser)
        except OSError:
            pass
        finally:
            conn.close()

    srv = _ReuseServer((listen_ip, port), lambda *a, **kw: None)

    def serve():
        while True:
            conn, _addr = srv.socket.accept()
            threading.Thread(target=conn_handler, args=(conn,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return srv


def start_http_server(ingest, port, listen_ip):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/pcap":
                self.send_error(404)
                return
            if ingest.http_token and \
                    self.headers.get("X-Ingest-Token") != ingest.http_token:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"bad or missing X-Ingest-Token")
                return
            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length)
            try:
                # каждый загруженный файл — полный pcap со своим заголовком:
                # общий парсер съедает второй и последующие файлы (resync
                # перескакивает их глобальный заголовок)
                ingest.handle_pcap_bytes(
                    data, tag="upload", parser=PcapParser(allow_resync=True)
                )
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
            except Exception as exc:  # noqa: BLE001
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(exc).encode())

        def log_message(self, *_args):  # silence default access log
            pass

    srv = _ReuseServer((listen_ip, port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--listen-ip", default="127.0.0.1",
                    help="по умолчанию только localhost; для приёма стрима с "
                         "vulnbox по сети укажите 0.0.0.0 (или IP ноутбука)")
    ap.add_argument("--pcap-over-ip-port", type=int, default=DEFAULT_PCAP_OVER_IP_PORT)
    ap.add_argument("--http-port", type=int, default=DEFAULT_HTTP_PORT)
    ap.add_argument("--ingest-dir", default="pkappa2-ingest")
    ap.add_argument("--teams", default=None,
                    help="teams.yaml с NPC-целью (npc: true) для автопроверки "
                         "новых детектов")
    ap.add_argument("--no-save", action="store_true", help="не сохранять pcap на диск")
    args = ap.parse_args()

    config = load_config(args.config)
    store_db = (
        (config.get("game") or {}).get("detections_db") or "detections.db"
    )
    npc_targets = []
    if args.teams:
        from adtool.replay import load_teams, split_npc

        _npc, npc_targets = split_npc(load_teams(args.teams))
    ingest = Ingest(config, args.ingest_dir, save_pcaps=not args.no_save,
                    store_path=store_db, npc_targets=npc_targets)
    print(f"detections db: {store_db}")
    if npc_targets and ingest.npc_prober:
        print(f"NPC auto-check: on ({len(npc_targets)} target(s))")
    elif args.teams:
        print("NPC auto-check: off (npc_check.enabled=false или нет npc-целей)")

    checker_ips = (config.get("analyzer") or {}).get("checker_ips") or []
    print(f"checker IPs: {checker_ips or '(не заданы — весь трафик считается атакой)'}")
    services = (config.get("game") or {}).get("services") or {}
    print(f"services: {services or '(не заданы — детекты будут port-XXXX)'}")
    start_pcap_over_ip_server(ingest, args.pcap_over_ip_port, args.listen_ip)
    print(f"PCAP-over-IP: {args.listen_ip}:{args.pcap_over_ip_port}")
    start_http_server(ingest, args.http_port, args.listen_ip)
    print(f"HTTP upload:  {args.listen_ip}:{args.http_port}/pcap")
    print(f"pkappa2 ingest dir: {args.ingest_dir}")
    print("Ctrl+C — выход")
    try:
        while True:
            time.sleep(5)
            st = ingest.stats()
            print(f"[stats] packets={st['packets']}")
    except KeyboardInterrupt:
        print("bye")


if __name__ == "__main__":
    sys.exit(main())
