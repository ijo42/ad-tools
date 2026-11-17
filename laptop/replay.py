#!/usr/bin/env python3
"""replay.py — fast-track: реплай перехваченного эксплойта на все команды.

Usage:
  # payload из файла, вербатим на все команды:
  uv run --with pyyaml python replay.py --payload payload.bin --teams teams.yaml

  # payload из pcap (второй attack-payload), шаблонный режим, сдача в ForcAD:
  uv run --with pyyaml python replay.py --pcap attack.pcap --payload 2 \
      --mode template --teams teams.yaml --config config.yaml --submit
"""

import argparse
import sys

import yaml

from adtool.flags import FlagQueue, flag_regex
from adtool.pcap import read_pcap_file
from adtool.replay import harvest_flags, load_teams, replay
from adtool.streams import StreamReassembler


def payload_from_pcap(path, index, checker_ips=()):
    packets = read_pcap_file(path)
    collected = []

    def on_http(key, request, stream):
        if key[0] not in checker_ips:
            collected.append(request)

    def on_raw(key, chunk, stream):
        if key[0] not in checker_ips:
            collected.append(chunk)

    reasm = StreamReassembler(on_http=on_http, on_raw=on_raw)
    for pkt in packets:
        reasm.push(pkt)
    if not collected:
        sys.exit("в pcap не найдено attack-payload'ов")
    idx = index - 1
    if not (0 <= idx < len(collected)):
        sys.exit(f"payload #{index} не найден (всего {len(collected)})")
    return collected[idx]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--payload", metavar="FILE", help="файл с сырым payload")
    src.add_argument("--pcap", metavar="FILE",
                     help="взять attack-payload из pcap (номер через --index)")
    ap.add_argument("--index", type=int, default=1,
                    help="номер attack-payload в pcap (1-based, default 1)")
    ap.add_argument("--mode", choices=["verbatim", "template"], default="verbatim")
    ap.add_argument("--teams", default="teams.yaml")
    ap.add_argument("--config", default="config.yaml",
                    help="для regex флага и очереди сдачи")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--submit", action="store_true",
                    help="найденные флаги дописать в очередь сабмиттера")
    args = ap.parse_args()

    checker_ips = set()
    flag_pattern = None
    config = {}
    try:
        with open(args.config) as fh:
            config = yaml.safe_load(fh) or {}
        checker_ips = set(
            (config.get("analyzer") or {}).get("checker_ips") or []
        )
        flag_pattern = ((config.get("flags") or {}).get("regex")) or None
    except FileNotFoundError:
        pass

    if args.pcap:
        payload = payload_from_pcap(args.pcap, args.index, checker_ips)
    else:
        with open(args.payload, "rb") as fh:
            payload = fh.read()

    targets = load_teams(args.teams)
    print(f"payload: {len(payload)}B, mode={args.mode}, targets={len(targets)}")
    print("preview:", payload[:120])

    results = replay(
        payload, targets, mode=args.mode, flag_pattern=flag_pattern,
        timeout=args.timeout,
    )
    flags = harvest_flags(results, flag_pattern)
    print(f"\nитог: флагов {len(flags)}")
    for flag in flags:
        print("  ", flag)
    if flags and args.submit:
        queue_file = (config.get("submit") or {}).get("queue_file",
                                                      "flags.queue.jsonl")
        fq = FlagQueue(queue_file)
        for flag in flags:
            fq.push(flag, source="replay")
        print(f"→ очередь: {queue_file} (запустите submitter.py для сдачи)")


if __name__ == "__main__":
    main()
