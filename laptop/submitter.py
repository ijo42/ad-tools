#!/usr/bin/env python3
"""submitter.py — демон сдачи флагов в ForcAD (п. 4.3–4.4 регламента).

Читает JSONL-очередь (flags.queue.jsonl), дедупит (flags_seen.txt), шлёт
батчами <=100 флагов с ограничением 200 флагов/с (burst 400).

Usage:
  uv run python submitter.py --config config.yaml            # боевой режим
  uv run python submitter.py --config config.yaml --dry      # без отправки
"""

import argparse
import sys

import yaml

from adtool.submitter import Submitter


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--dry", action="store_true", help="не отправлять, только лог")
    args = ap.parse_args()

    with open(args.config) as fh:
        config = yaml.safe_load(fh) or {}

    forcad = config.get("forcad") or {}
    if not args.dry:
        if forcad.get("base_url", "").startswith("http://127.0.0.1") and \
                "127.0.0.1" == forcad.get("base_url", "").split("//")[1].split(":")[0]:
            print("!! base_url — localhost. Для игры укажите адрес ForcAD (п. 3.4)")
        if forcad.get("team_token") in (None, "", "PUT_TEAM_TOKEN_HERE"):
            sys.exit("заполните forcad.team_token в config.yaml")

    sub = Submitter(
        forcad.get("base_url", "http://127.0.0.1:5000"),
        forcad.get("team_token", ""),
        config=config.get("submit") or {},
    )
    try:
        sub.run(dry=args.dry)
    except KeyboardInterrupt:
        sub.stop()
        print("stopped")


if __name__ == "__main__":
    sys.exit(main())
