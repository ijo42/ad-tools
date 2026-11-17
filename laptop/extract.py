#!/usr/bin/env python3
"""extract.py — офлайн-разбор pcap: потоки, HTTP-запросы, флаги, hexdump.

Usage:
  uv run python extract.py attack.pcap --checker-ips 10.100.0.1
  uv run python extract.py attack.pcap --payload 2 --out payload.bin
"""

import argparse
import sys

from adtool.flags import extract_flags
from adtool.pcap import read_pcap_file
from adtool.streams import StreamReassembler


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pcap")
    ap.add_argument("--checker-ips", default="", help="через запятую")
    ap.add_argument("--payload", type=int, metavar="N",
                    help="сохранить N-й attack-payload (1-based) в файл --out")
    ap.add_argument("--out", default="payload.bin")
    args = ap.parse_args()

    checker_ips = set(x.strip() for x in args.checker_ips.split(",") if x.strip())
    packets = read_pcap_file(args.pcap)
    print(f"packets: {len(packets)}")

    collected = []  # (kind, key, payload)
    done = set()

    def on_http(key, request, stream):
        kind = "checker" if key[0] in checker_ips else "attack"
        collected.append((kind, key, request))
        flags = extract_flags(request)
        first_line = request.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        print(f"[{kind}] {key[0]}:{key[1]} -> {key[2]}:{key[3]}  {first_line[:120]}")
        if flags:
            print(f"    flags: {flags}")

    def on_raw(key, chunk, stream):
        if key[0] in checker_ips:
            return
        collected.append(("attack", key, chunk))
        print(f"[attack] RAW {key[0]}:{key[1]} -> {key[2]}:{key[3]}  "
              f"{len(chunk)}B  {chunk[:80]!r}")
        flags = extract_flags(chunk)
        if flags:
            print(f"    flags: {flags}")

    reasm = StreamReassembler(on_http=on_http, on_raw=on_raw)
    for pkt in packets:
        reasm.push(pkt)

    attack_payloads = [p for kind, _key, p in collected if kind == "attack"]
    if args.payload:
        idx = args.payload - 1
        if 0 <= idx < len(attack_payloads):
            with open(args.out, "wb") as fh:
                fh.write(attack_payloads[idx])
            print(f"payload #{args.payload} -> {args.out} "
                  f"({len(attack_payloads[idx])}B)")
        else:
            print(f"нет payload #{args.payload} (всего {len(attack_payloads)})",
                  file=sys.stderr)
            sys.exit(1)
    else:
        print(f"\nattack payloads: {len(attack_payloads)} — "
              f"сохраните нужный через --payload N и реплайте replay.py")


if __name__ == "__main__":
    main()
