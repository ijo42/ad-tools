"""Detection store: SQLite-backed, deduped by payload fingerprint.

Dedup, two levels:
1. Fingerprint: the same exploit template run against different flags
   (checker re-plants flags each round) or repeated across rounds ->
   ONE detection row: count, rounds seen, distinct flags, distinct sources.
2. Attack match: different templates that yielded THE SAME flag within the
   same round (e.g. two teams hit the same vuln via different payloads) ->
   merged into the earliest detection, the other payload is kept as a
   `variant` row.

Also stores automated NPC probe results per detection
(NPC is a safe test target: its flags give no points, п. 4.7).

WAL mode: ingest.py writes while web.py reads concurrently.
"""

import hashlib
import json
import sqlite3
import threading
import time

from .template import generalize


class DetectionStore:
    def __init__(self, path="detections.db"):
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._init_schema()

    def _init_schema(self):
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT UNIQUE,
                service TEXT,
                kind TEXT,               -- http | raw
                first_ts REAL,
                last_ts REAL,
                count INTEGER DEFAULT 1,
                rounds TEXT DEFAULT '[]',   -- json list of ints
                srcs TEXT DEFAULT '[]',     -- json list of "ip:port"
                sample BLOB,                -- first raw payload
                template BLOB,              -- generalized payload
                params TEXT DEFAULT '{}',   -- json of generalized-out values
                flags TEXT DEFAULT '[]',    -- json list of seen flags
                label TEXT DEFAULT '',
                note TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS replays (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detection_id INTEGER,
                ts REAL,
                mode TEXT,
                results TEXT,               -- json list of per-target results
                flags_found TEXT DEFAULT '[]'
            );
            CREATE TABLE IF NOT EXISTS variants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detection_id INTEGER,
                fingerprint TEXT,           -- fingerprint of the variant payload
                src TEXT,
                ts REAL,
                payload BLOB
            );
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL,
                round INTEGER,              -- номер раунда (0 — до старта)
                src TEXT,
                dst TEXT,
                proto INTEGER,
                service TEXT,               -- имя сервиса или NULL (прочее)
                direction TEXT,             -- in | out | other
                size INTEGER,
                has_flag INTEGER DEFAULT 0,
                preview TEXT                -- первые ~160 байт payload
            );
            CREATE INDEX IF NOT EXISTS idx_packets_round ON packets(round, ts);
            CREATE INDEX IF NOT EXISTS idx_packets_service ON packets(service);
            CREATE TABLE IF NOT EXISTS seen_flags (
                flag TEXT,
                round INTEGER,
                ts REAL,
                src TEXT,                   -- кому утёк (IP атакующего)
                service TEXT,
                PRIMARY KEY (flag, round, src)
            );
            """
        )
        # v2 columns: automated NPC probe results
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(detections)")}
        for col, ddl in [
            ("npc_status", "TEXT DEFAULT ''"),     # running|flags|noflags|error
            ("npc_results", "TEXT DEFAULT '[]'"),  # json list of per-target results
            ("npc_flags", "TEXT DEFAULT '[]'"),    # json list of flags from NPC
            ("npc_ts", "REAL"),
        ]:
            if col not in cols:
                self._conn.execute(
                    f"ALTER TABLE detections ADD COLUMN {col} {ddl}"
                )
        self._conn.commit()

    # --- upsert / dedup -----------------------------------------------------
    def record(self, payload: bytes, kind, src_ip, src_port, dst_port,
               service, ts, flags, round_no=None):
        """Add one captured attack payload; dedup by generalized fingerprint.

        Secondary dedup: a new template whose flags match an existing
        detection of the same service+round (the same vuln exploited by
        another team / another payload shape) is merged as a variant.

        Returns (detection_id, is_new).
        """
        template, params = generalize(payload)
        fingerprint = hashlib.sha1(template).hexdigest()
        now = ts or time.time()
        flags = sorted(set(flags))
        with self._lock:
            row = self._conn.execute(
                "SELECT id, count, rounds, srcs, flags, first_ts FROM detections "
                "WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if row is None and flags and round_no is not None:
                row = self._find_attack_match(service, flags, round_no)
                if row is not None:
                    self._conn.execute(
                        "INSERT INTO variants (detection_id, fingerprint, src, "
                        "ts, payload) VALUES (?,?,?,?,?)",
                        (row["id"], fingerprint, f"{src_ip}:{src_port}", now,
                         payload),
                    )

            if row is None:
                cur = self._conn.execute(
                    "INSERT INTO detections "
                    "(fingerprint, service, kind, first_ts, last_ts, count, "
                    " rounds, srcs, sample, template, params, flags) "
                    "VALUES (?,?,?,?,?,1,?,?,?,?,?,?)",
                    (
                        fingerprint, service, kind, now, now,
                        json.dumps([round_no] if round_no is not None else []),
                        json.dumps([f"{src_ip}:{src_port}"]),
                        payload, template, json.dumps(params),
                        json.dumps(flags),
                    ),
                )
                self._conn.commit()
                return cur.lastrowid, True, fingerprint

            rounds = json.loads(row["rounds"])
            if round_no is not None and round_no not in rounds:
                rounds.append(round_no)
                rounds.sort()
            srcs = json.loads(row["srcs"])
            src = f"{src_ip}:{src_port}"
            if src not in srcs:
                srcs.append(src)
            seen_flags = set(json.loads(row["flags"])) | set(flags)
            self._conn.execute(
                "UPDATE detections SET count=count+1, last_ts=?, rounds=?, "
                "srcs=?, flags=?, service=COALESCE(NULLIF(?,''), service) "
                "WHERE id=?",
                (
                    now, json.dumps(rounds), json.dumps(srcs),
                    json.dumps(sorted(seen_flags)), service or "",
                    row["id"],
                ),
            )
            self._conn.commit()
            return row["id"], False, fingerprint

    def _find_attack_match(self, service, flags, round_no):
        """Same service + same round + one of the flags already seen ->
        it is the same attack (п. dedup by attack match). Returns row or None.
        """
        for f in flags:
            rows = self._conn.execute(
                "SELECT * FROM detections WHERE service=? AND flags LIKE ?",
                (service or "", f'%"{f}"%'),
            ).fetchall()
            for r in rows:
                if round_no in json.loads(r["rounds"]):
                    return r
        return None

    def attribute_flag(self, service, attacker_ip, round_no, flag):
        """Tie a flag exfiltrated from `service` (response to `attacker_ip`)
        in `round_no` to the matching detection.

        Attack-match rule: if some detection of the same service+round
        already holds this flag (another team pulled the same flag -> same
        attack), the current detection is merged into it as a variant.
        Returns the canonical detection_id or None.
        """
        if not flag or round_no is None:
            return None
        with self._lock:
            all_rows = [
                dict(r)
                for r in self._conn.execute(
                    "SELECT * FROM detections WHERE service=?", (service or "",)
                )
            ]
            rows = [
                r for r in all_rows
                if round_no in json.loads(r["rounds"])
                and any(s.startswith(attacker_ip + ":")
                        for s in json.loads(r["srcs"]))
            ]
            if not rows:
                return None
            # каноничный детект: уже содержит этот флаг (его могла принести
            # другая команда в том же раунде — та же атака)
            canonical = next(
                (r for r in all_rows
                 if r["id"] not in {x["id"] for x in rows}
                 and round_no in json.loads(r["rounds"])
                 and flag in json.loads(r["flags"])),
                None,
            )
            if canonical is None:
                # нет канона — флаг получает самый свежий детект атакующего
                target = max(rows, key=lambda r: r["last_ts"])
                flags = set(json.loads(target["flags"])) | {flag}
                self._conn.execute(
                    "UPDATE detections SET flags=? WHERE id=?",
                    (json.dumps(sorted(flags)), target["id"]),
                )
                self._conn.commit()
                return target["id"]

            # остальные ветки атакующего в этом раунде — та же атака, если
            # их флаги ещё пусты или пересекаются с каноном
            for r in rows:
                if r["id"] == canonical["id"]:
                    continue
                rflags = json.loads(r["flags"])
                if not rflags or set(rflags) & set(json.loads(canonical["flags"])):
                    self._merge_locked(canonical, r)
            self._conn.commit()
            return canonical["id"]

    def _merge_locked(self, target, src):
        """Merge `src` detection into `target` (same attack, one flag/round).
        Caller holds the lock. """
        rounds = sorted(set(json.loads(target["rounds"]))
                        | set(json.loads(src["rounds"])))
        srcs = sorted(set(json.loads(target["srcs"]))
                      | set(json.loads(src["srcs"])))
        flags = sorted(set(json.loads(target["flags"]))
                       | set(json.loads(src["flags"])))
        self._conn.execute(
            "UPDATE variants SET detection_id=? WHERE detection_id=?",
            (target["id"], src["id"]),
        )
        self._conn.execute(
            "INSERT INTO variants (detection_id, fingerprint, src, ts, payload) "
            "SELECT ?, fingerprint, COALESCE(srcs, ''), last_ts, sample "
            "FROM detections WHERE id=?",
            (target["id"], src["id"]),
        )
        self._conn.execute(
            "UPDATE detections SET count=count+?, last_ts=MAX(last_ts, ?), "
            "rounds=?, srcs=?, flags=? WHERE id=?",
            (src["count"], target["last_ts"], json.dumps(rounds),
             json.dumps(srcs), json.dumps(flags), target["id"]),
        )
        self._conn.execute(
            "UPDATE replays SET detection_id=? WHERE detection_id=?",
            (target["id"], src["id"]),
        )
        self._conn.execute("DELETE FROM detections WHERE id=?", (src["id"],))

    # --- NPC auto-probe ------------------------------------------------------
    def set_npc_status(self, detection_id, status, results=None, flags=None):
        with self._lock:
            self._conn.execute(
                "UPDATE detections SET npc_status=?, npc_ts=?, "
                "npc_results=COALESCE(?, npc_results), "
                "npc_flags=COALESCE(?, npc_flags) WHERE id=?",
                (status, time.time(),
                 json.dumps(results) if results is not None else None,
                 json.dumps(sorted(flags)) if flags is not None else None,
                 detection_id),
            )
            self._conn.commit()

    # --- variants ------------------------------------------------------------
    def variants_for(self, detection_id):
        return [
            {
                "id": r["id"],
                "fingerprint": r["fingerprint"],
                "src": r["src"],
                "ts": r["ts"],
                "payload": (r["payload"] or b"").decode("latin-1"),
            }
            for r in self._conn.execute(
                "SELECT * FROM variants WHERE detection_id=? ORDER BY ts",
                (detection_id,),
            )
        ]

    # --- queries -------------------------------------------------------------
    def list_detections(self, service=None, label=None):
        q = "SELECT * FROM detections"
        conds, args = [], []
        if service:
            conds.append("service = ?")
            args.append(service)
        if label is not None and label != "":
            conds.append("label = ?")
            args.append(label)
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY last_ts DESC"
        return [dict(r) for r in self._conn.execute(q, args)]

    def get(self, detection_id):
        r = self._conn.execute(
            "SELECT * FROM detections WHERE id=?", (detection_id,)
        ).fetchone()
        return dict(r) if r else None

    def set_label(self, detection_id, label=None, note=None):
        with self._lock:
            if label is not None:
                self._conn.execute(
                    "UPDATE detections SET label=? WHERE id=?", (label, detection_id)
                )
            if note is not None:
                self._conn.execute(
                    "UPDATE detections SET note=? WHERE id=?", (note, detection_id)
                )
            self._conn.commit()

    def add_replay(self, detection_id, mode, results, flags_found):
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO replays (detection_id, ts, mode, results, flags_found) "
                "VALUES (?,?,?,?,?)",
                (detection_id, time.time(), mode, json.dumps(results),
                 json.dumps(flags_found)),
            )
            self._conn.commit()
            return cur.lastrowid

    def replays_for(self, detection_id):
        return [
            dict(r)
            for r in self._conn.execute(
                "SELECT * FROM replays WHERE detection_id=? ORDER BY ts DESC",
                (detection_id,),
            )
        ]

    def stats(self):
        row = self._conn.execute(
            "SELECT COUNT(*) AS n, SUM(count) AS hits FROM detections"
        ).fetchone()
        flags = self._conn.execute(
            "SELECT flags FROM detections"
        ).fetchall()
        unique_flags = set()
        for r in flags:
            unique_flags |= set(json.loads(r["flags"]))
        return {
            "detections": row["n"] or 0,
            "payloads": row["hits"] or 0,
            "unique_flags": len(unique_flags),
        }

    # --- packets (все пакеты, даже без флагов) --------------------------------
    def insert_packets(self, rows):
        """rows: list of (ts, round, src, dst, proto, service, direction,
        size, has_flag, preview). Batch insert in one transaction."""
        if not rows:
            return
        with self._lock:
            self._conn.executemany(
                "INSERT INTO packets (ts, round, src, dst, proto, service, "
                "direction, size, has_flag, preview) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
            self._conn.commit()

    def list_packets(self, round_no=None, service=None, has_flag=None,
                     q=None, direction=None, limit=200, offset=0):
        conds, args = [], []
        if round_no is not None and round_no != "":
            conds.append("round = ?")
            args.append(int(round_no))
        if service:
            conds.append("service = ?")
            args.append(service)
        if has_flag is not None and has_flag != "":
            conds.append("has_flag = ?")
            args.append(int(has_flag))
        if direction:
            conds.append("direction = ?")
            args.append(direction)
        if q:
            conds.append("(preview LIKE ? OR src LIKE ? OR dst LIKE ?)")
            like = f"%{q}%"
            args.extend([like, like, like])
        where = (" WHERE " + " AND ".join(conds)) if conds else ""
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM packets{where}", args
        ).fetchone()[0]
        rows = [
            {
                "id": r["id"], "ts": r["ts"], "round": r["round"],
                "src": r["src"], "dst": r["dst"], "proto": r["proto"],
                "service": r["service"], "direction": r["direction"],
                "size": r["size"], "has_flag": r["has_flag"],
                "preview": r["preview"],
            }
            for r in self._conn.execute(
                f"SELECT * FROM packets{where} ORDER BY ts LIMIT ? OFFSET ?",
                args + [limit, offset],
            )
        ]
        # список раундов для селектора/маркеров
        rounds = [
            {"round": r[0], "packets": r[1]}
            for r in self._conn.execute(
                "SELECT round, COUNT(*) FROM packets GROUP BY round ORDER BY round"
            )
        ]
        return {"rows": rows, "total": total, "rounds": rounds}

    def prune(self, packets_keep=500000, variants_keep=2000, seen_flags_keep=50000):
        """Retention: держим БД в пределах лимитов (долгие игры со сканерным
        шумом дают миллионы строк packets). Возвращает (packets_del, variants_del,
        flags_del). Дetections не трогаем — это суть инструмента."""
        out = []
        with self._lock:
            for table, keep in (("packets", packets_keep),
                                ("variants", variants_keep),
                                ("seen_flags", seen_flags_keep)):
                n = self._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                if n <= keep:
                    out.append(0)
                    continue
                rowid = "rowid"
                if table == "seen_flags":
                    # составной PRIMARY KEY (flag, round, src)
                    self._conn.execute(
                        f"DELETE FROM {table} WHERE rowid IN ("
                        f"SELECT rowid FROM {table} ORDER BY ts ASC LIMIT ?)",
                        (n - keep,),
                    )
                else:
                    self._conn.execute(
                        f"DELETE FROM {table} WHERE {rowid} IN ("
                        f"SELECT {rowid} FROM {table} ORDER BY {rowid} ASC LIMIT ?)",
                        (n - keep,),
                    )
                out.append(n - keep)
            self._conn.commit()
        return tuple(out)

    def add_seen_flag(self, flag, round_no, ts, src, service):
        if not flag:
            return
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO seen_flags (flag, round, ts, src, service) "
                "VALUES (?,?,?,?,?)",
                (flag, round_no, ts, src, service),
            )
            self._conn.commit()

    def bulk_set_label(self, ids, label=None, note=None):
        if not ids:
            return 0
        with self._lock:
            if label is not None and note is not None:
                self._conn.executemany(
                    "UPDATE detections SET label=?, note=? WHERE id=?",
                    [(label, note, i) for i in ids],
                )
            elif label is not None:
                self._conn.executemany(
                    "UPDATE detections SET label=? WHERE id=?",
                    [(label, i) for i in ids],
                )
            else:
                self._conn.executemany(
                    "UPDATE detections SET note=? WHERE id=?",
                    [(note, i) for i in ids],
                )
            self._conn.commit()
        return len(ids)

    def analytics(self):
        """Данные для графиков: по раундам, топ атакующих, по сервисам."""
        per_round = {}
        for r in self._conn.execute(
            "SELECT round, COUNT(*) n, SUM(has_flag) fl, MIN(ts) t0, MAX(ts) t1 "
            "FROM packets GROUP BY round ORDER BY round"
        ):
            per_round[r["round"]] = {
                "round": r["round"], "packets": r["n"], "flagged": r["fl"] or 0,
                "first_ts": r["t0"], "last_ts": r["t1"], "flags": 0, "hits": 0,
            }
        for r in self._conn.execute(
            "SELECT round, COUNT(DISTINCT flag) n FROM seen_flags GROUP BY round"
        ):
            if r["round"] in per_round:
                per_round[r["round"]]["flags"] = r["n"]
        for r in self._conn.execute("SELECT rounds, count FROM detections"):
            for round_no in json.loads(r["rounds"]):
                if round_no in per_round:
                    per_round[round_no]["hits"] += r["count"]
        top_srcs = [
            {"src": r["src"], "packets": r["n"], "flagged": r["fl"] or 0}
            for r in self._conn.execute(
                "SELECT src, COUNT(*) n, SUM(has_flag) fl FROM packets "
                "WHERE direction='in' GROUP BY src ORDER BY n DESC LIMIT 10"
            )
        ]
        services = [
            {"service": r["service"], "packets": r["n"], "flagged": r["fl"] or 0,
             "in_pkts": r["inn"], "out_pkts": r["out"]}
            for r in self._conn.execute(
                "SELECT service, COUNT(*) n, SUM(has_flag) fl, "
                "SUM(direction='in') inn, SUM(direction='out') out "
                "FROM packets WHERE service IS NOT NULL GROUP BY service"
            )
        ]
        return {
            "rounds": sorted(per_round.values(), key=lambda x: x["round"]),
            "top_srcs": top_srcs,
            "services": services,
        }
