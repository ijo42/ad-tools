#!/usr/bin/env python3
"""web.py — запуск веб-интерфейса AD Toolkit (FastAPI + Vue 3, офлайн).

Основной режим (один процесс = UI + приём трафика + сабмиттер):
  uv run --with fastapi,uvicorn,pyyaml python web.py --config config.yaml \
      --teams teams.yaml --with-ingest --with-submitter
UI: http://127.0.0.1:57020   API docs: http://127.0.0.1:57020/api/docs

Режимы:
- --with-ingest      внутри процесса поднимаются PCAP-over-IP (:57012) и
                     HTTP-приём pcap (:57013) — тот же конвейер, что в
                     ingest.py, одна БД и одна очередь флагов;
- --with-submitter   сабмиттер крутится фоновым потоком; --dry — без
                     реальной отправки;
- без флагов         web.py только читает существующую detections.db
                     (ingest.py работает отдельным процессом).

Реализация UI: пакет webui/ (FastAPI-роутеры, Pydantic-схемы, Vue 3 SPA
в webui/static — vendored, без CDN).
"""

import argparse
import os
import threading

from webui.app import create_app
from webui.services import Ctx


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--teams", default="teams.yaml")
    ap.add_argument("--listen-ip", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=57020)
    ap.add_argument("--with-ingest", action="store_true",
                    help="поднять приём трафика (PCAP-over-IP + HTTP) "
                         "внутри этого процесса")
    ap.add_argument("--with-submitter", action="store_true",
                    help="поднять сабмиттер флагов фоновым потоком")
    ap.add_argument("--ingest-dir", default="pkappa2-ingest")
    ap.add_argument("--dry", action="store_true",
                    help="сабмиттер без реальной отправки")
    args = ap.parse_args()

    import yaml

    with open(args.config) as fh:
        config = yaml.safe_load(fh) or {}

    try:
        from adtool.replay import load_teams, split_npc

        teams = load_teams(args.teams)
    except FileNotFoundError:
        teams = []
        print(f"!! {args.teams} не найден — replay и NPC-проверка отключены")

    ingest = None
    store = None
    flag_queue = None
    if args.with_ingest:
        from ingest import (
            DEFAULT_HTTP_PORT,
            DEFAULT_PCAP_OVER_IP_PORT,
            Ingest,
            start_http_server,
            start_pcap_over_ip_server,
        )

        store_db = (config.get("game") or {}).get("detections_db") or "detections.db"
        _npc, npc_targets = split_npc(teams)
        ingest = Ingest(config, args.ingest_dir, store_path=store_db,
                        npc_targets=npc_targets)
        start_pcap_over_ip_server(ingest, DEFAULT_PCAP_OVER_IP_PORT, args.listen_ip)
        start_http_server(ingest, DEFAULT_HTTP_PORT, args.listen_ip)
        store = ingest.store
        flag_queue = ingest.flag_queue
        print(f"ingest: PCAP-over-IP :{DEFAULT_PCAP_OVER_IP_PORT}, "
              f"HTTP :{DEFAULT_HTTP_PORT}/pcap, db={store_db}")

    if args.with_submitter:
        from adtool.submitter import Submitter

        # dry: флаг --dry ИЛИ env WEB_DRY (удобно для docker compose)
        dry = args.dry or os.environ.get("WEB_DRY", "").lower() in ("1", "true", "yes")
        forcad = config.get("forcad") or {}
        submit_cfg = config.get("submit") or {}
        if dry or not forcad.get("team_token"):
            if not dry:
                print("!! forcad.team_token не задан — сабмиттер в dry-режиме")
            submit_cfg = dict(submit_cfg)
            submit_cfg.setdefault("queue_file", "flags.queue.jsonl")
            sub = Submitter("http://127.0.0.1:5000", "", config=submit_cfg)
            threading.Thread(target=sub.run, kwargs={"dry": True}, daemon=True).start()
            print("submitter: dry (флаги помечаются, не отправляются)")
        else:
            sub = Submitter(forcad["base_url"], forcad["team_token"],
                            config=submit_cfg)
            threading.Thread(target=sub.run, daemon=True).start()
            print(f"submitter: {forcad['base_url']}/flags")

    if store is None:
        from adtool.store import DetectionStore

        store = DetectionStore(
            (config.get("game") or {}).get("detections_db") or "detections.db"
        )
    if flag_queue is None:
        from adtool.flags import FlagQueue

        flag_queue = FlagQueue(
            (config.get("submit") or {}).get("queue_file", "flags.queue.jsonl")
        )

    from adtool.replay import split_npc

    npc_targets, team_only = split_npc(teams)  # NPC — только для автопроби
    flag_pattern = ((config.get("flags") or {}).get("regex")) or None
    ctx = Ctx(store=store, flag_queue=flag_queue, teams=team_only,
              npc_targets=npc_targets, flag_pattern=flag_pattern)
    app = create_app(ctx)

    import uvicorn

    print(f"UI: http://{args.listen_ip}:{args.port}  "
          f"teams: {sum(1 for t in teams if not t.get('npc'))}  "
          f"npc: {len(npc_targets)}")
    uvicorn.run(app, host=args.listen_ip, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
