#!/usr/bin/env python3
"""Мок «уязвимого сервиса» для dry-run тулкита (не для игры).

- HTTP :18080 — два «уязвимых» эндпоинта:
    POST /search?q=<SQLi>   — возвращает флаг при инъекции
    GET  /flag              — отдаёт флаг напрямую
- TCP  :18081 — сырой протокол: команда GETFLAG -> флаг.
Флаги генерируются в формате регламента [A-Z0-9]{31}= и меняются при
ENV FLAG_RESET=1.
"""

import os
import random
import socket
import socketserver
import string
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


def make_flag():
    chars = string.ascii_uppercase + string.digits
    return "".join(random.choice(chars) for _ in range(31)) + "="


FLAGS = {"http": make_flag(), "tcp": make_flag()}
# флаги, заложенные чекером (для проверки с реальным ForcAD): private_id -> flag
PLANTED = {}
LOCK = threading.Lock()


class HTTPService(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/flag":
            body = f"flag is here: {FLAGS['http']}".encode()
            self._reply(body)
        elif path == "/search":
            q = (parse_qs(urlparse(self.path).query).get("q") or [""])[0]
            # «SQL-инъекция»: кавычка в q открывает доступ к флагу
            if "'" in q:
                out = b"results:\n" + FLAGS["http"].encode()
            else:
                out = b"no results"
            self._reply(out)
        elif path == "/getflag":
            # для чекера (проверка, что прежние флаги на месте)
            flag_id = (parse_qs(urlparse(self.path).query).get("id") or [""])[0]
            with LOCK:
                body = PLANTED.get(flag_id, "NOTFOUND").encode()
            self._reply(body)
        else:
            self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path
        qs = parse_qs(urlparse(self.path).query)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        if path == "/search":
            q = (qs.get("q") or [""])[0]
            # «SQL-инъекция»: кавычка в q открывает доступ к флагу
            if "'" in q:
                out = b"results:\n" + FLAGS["http"].encode()
            else:
                out = b"no results"
            self._reply(out)
        elif path == "/notes":
            # эхо: отражает тело (XSS-ish) — используется fake_attacker'ом
            out = b"note saved: " + body
            self._reply(out)
        elif path == "/putflag":
            # для чекера: закладка нового флага (id + flag)
            data = parse_qs(body.decode("latin-1"))
            flag_id = (data.get("id") or [""])[0]
            flag = (data.get("flag") or [""])[0]
            with LOCK:
                PLANTED[flag_id] = flag
            self._reply(b"ok")
        else:
            self.send_error(404)

    def _reply(self, out):
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *_args):
        pass


class TCPService(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"DEMO protocol. commands: GETFLAG, PING\n")
        while True:
            try:
                data = self.request.recv(1024)
            except OSError:
                return
            if not data:
                return
            line = data.strip().upper()
            if line == b"GETFLAG":
                self.request.sendall(FLAGS["tcp"].encode() + b"\n")
            elif line == b"PING":
                self.request.sendall(b"PONG\n")
            else:
                self.request.sendall(b"ERR\n")


def main():
    bind = os.environ.get("BIND", "127.0.0.1")
    http_port = int(os.environ.get("HTTP_PORT", "18080"))
    tcp_port = int(os.environ.get("TCP_PORT", "18081"))
    http_srv = ThreadingHTTPServer((bind, http_port), HTTPService)
    tcp_srv = socketserver.ThreadingTCPServer((bind, tcp_port), TCPService)
    threading.Thread(target=http_srv.serve_forever, daemon=True).start()
    threading.Thread(target=tcp_srv.serve_forever, daemon=True).start()
    print(f"mock vuln service: http://127.0.0.1:{http_port}  "
          f"tcp://127.0.0.1:{tcp_port}")
    print("http flag:", FLAGS["http"])
    print("tcp  flag:", FLAGS["tcp"])
    try:
        while True:
            import time

            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
