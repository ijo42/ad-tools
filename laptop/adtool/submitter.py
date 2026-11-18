"""Flag submitter: JSONL queue -> ForcAD /flags, batched and rate-limited.

Regulation constraints (п. 4.3–4.4):
- JSON array to /flags, team token in X-Team-Token header
- <= 100 flags per request, <= 10 KiB body
- quota 200 flags/sec, burst 400

Вердикты соответствуют реальному ForcAD (проверено по исходникам):
PUT /flags возвращает [{"msg": ..., "flag": ...}, ...] на каждый флаг.
Просроченные флаги (current_round - flag_round > flag_lifetime) не
отправляются, если задан stale_fn (GameMonitor, P2).
"""

import json
import os
import threading
import time
import urllib.error
import urllib.request


class TokenBucket:
    def __init__(self, rate=200, burst=400):
        self.rate = rate
        self.burst = burst
        self.tokens = float(burst)
        self.updated = time.monotonic()

    def take(self, n):
        while True:
            now = time.monotonic()
            self.tokens = min(
                self.burst, self.tokens + (now - self.updated) * self.rate
            )
            self.updated = now
            if self.tokens >= n:
                self.tokens -= n
                return True
            need = (n - self.tokens) / self.rate
            time.sleep(need)


# строки-вердикты реального ForcAD (lib/helpers/exceptions.py + judge)
_REASONS = (
    ("your own", "own_flag"),
    ("already stolen", "already_stolen"),
    ("too old", "too_old"),
    ("service is down", "service_down"),
    ("not available", "game_off"),
)


def classify_verdict(msg):
    """Вердикт ForcAD -> (ok, reason). reason='' при успехе."""
    if "accepted" in msg:
        return True, ""
    low = msg.lower()
    for needle, reason in _REASONS:
        if needle in low:
            return False, reason
    return False, "other"


class Submitter:
    def __init__(self, base_url, team_token, config=None, queue_file="flags.queue.jsonl",
                 stale_fn=None):
        cfg = config or {}
        self.base_url = base_url.rstrip("/")
        self.team_token = team_token
        self.rate_per_sec = cfg.get("rate_per_sec", 200)
        self.burst = cfg.get("burst", 400)
        self.max_flags = cfg.get("max_flags_per_request", 100)
        self.max_body = cfg.get("max_body_bytes", 10240)
        self.queue_file = cfg.get("queue_file", queue_file)
        self.state_file = cfg.get("state_file", "flags_seen.txt")
        # stale_fn(ts) -> True: флаг из раунда с временем ts уже просрочен
        # (ForcAD вернул бы "Flag is too old"); предоставляется GameMonitor'ом
        self.stale_fn = stale_fn
        self.bucket = TokenBucket(self.rate_per_sec, self.burst)
        self._stop = threading.Event()
        self.log_fn = print
        self.stats = {"accepted": 0, "rejected": 0, "stale_skipped": 0,
                      "reasons": {}}
        self._stats_lock = threading.Lock()
        self._load_state()

    def _bump(self, reason, n=1):
        with self._stats_lock:
            self.stats[reason] = self.stats.get(reason, 0) + n

    def _load_state(self):
        self.seen = set()
        if os.path.exists(self.state_file):
            with open(self.state_file) as fh:
                self.seen = set(line.strip() for line in fh if line.strip())

    def _mark(self, flag):
        self.seen.add(flag)
        with open(self.state_file, "a") as fh:
            fh.write(flag + "\n")

    def submit_batch(self, flags, dry=False):
        """Submit one batch (list of flags); returns (sent, errors)."""
        sent, errors = [], []
        for flag in flags:
            if flag not in self.seen:
                sent.append(flag)
        if not sent:
            return [], []
        # enforce <=100 flags and <=10 KiB per request
        batches, cur, size = [], [], 0
        for flag in sent:
            if len(cur) >= self.max_flags or size + len(flag) > self.max_body:
                batches.append(cur)
                cur, size = [], 0
            cur.append(flag)
            size += len(flag)
        if cur:
            batches.append(cur)
        for batch in batches:
            self.bucket.take(len(batch))
            if dry:
                self.log_fn(f"[dry] would submit {len(batch)} flags: {batch[:3]}...")
                for flag in batch:
                    self._mark(flag)
                continue
            try:
                verdicts = self._post(batch)
                self._apply_verdicts(verdicts, batch)
                for flag in batch:
                    self._mark(flag)
            except (urllib.error.URLError, OSError, ValueError) as exc:
                self.log_fn(f"[!] submit failed: {exc} — флаги возвращены в очередь")
                errors.extend(batch)
                self._requeue(batch)
        return sent, errors

    def _apply_verdicts(self, verdicts, batch):
        """Разбор ответа ForcAD: [{msg, flag}, ...] на каждый флаг батча."""
        by_flag = {}
        if isinstance(verdicts, list):
            for item in verdicts:
                if isinstance(item, dict) and item.get("flag"):
                    by_flag[item["flag"]] = item.get("msg", "")
        ok = bad = 0
        reasons = {}
        for flag in batch:
            msg = by_flag.get(flag, "")
            good, reason = classify_verdict(msg) if msg else (False, "no_verdict")
            if good:
                ok += 1
            else:
                bad += 1
                reasons[reason] = reasons.get(reason, 0) + 1
            if msg:
                self.log_fn(f"[verdict] {flag[:12]}… {msg}")
        with self._stats_lock:
            self.stats["accepted"] += ok
            self.stats["rejected"] += bad
            for reason, n in reasons.items():
                self.stats["reasons"][reason] = self.stats["reasons"].get(reason, 0) + n
        self.log_fn(f"[+] submitted {len(batch)} flags (accepted={ok}, rejected={bad})")

    def _requeue(self, flags):
        """Вернуть недосданные флаги в конец очереди (offset сабмиттера уже
        за ними — иначе они терялись бы навсегда)."""
        with open(self.queue_file, "a", encoding="utf-8") as fh:
            for flag in flags:
                fh.write(json.dumps(
                    {"flag": flag, "ts": time.time(), "source": "retry",
                     "meta": {}}
                ) + "\n")

    def _post(self, flags):
        body = json.dumps(flags).encode()
        # настоящий ForcAD принимает PUT /flags/ (не POST)
        req = urllib.request.Request(
            self.base_url + "/flags",
            data=body,
            headers={
                "X-Team-Token": self.team_token,
                "Content-Type": "application/json",
            },
            method="PUT",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())

    def run(self, poll_interval=0.5, dry=False):
        """Daemon: drain queue_file, dedup, skip stale, submit in batches."""
        self.log_fn(
            f"submitter: queue={self.queue_file} -> {self.base_url}/flags "
            f"(rate {self.rate_per_sec}/s burst {self.burst}, "
            f"<={self.max_flags} per request)"
        )
        offset = 0
        pending = []
        while not self._stop.is_set():
            records = []
            try:
                with open(self.queue_file, "r", encoding="utf-8") as fh:
                    fh.seek(offset)
                    for line in fh:
                        line = line.strip()
                        if line:
                            try:
                                records.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass
                    offset = fh.tell()
            except FileNotFoundError:
                pass
            fresh = []
            for r in records:
                flag = r.get("flag")
                if not flag or flag in self.seen:
                    continue
                if self.stale_fn is not None and self.stale_fn(r.get("ts") or 0):
                    self._bump("stale_skipped")
                    self.log_fn(f"[stale] {flag[:12]}… пропущен (flag_lifetime истёк)")
                    self._mark(flag)  # чтобы не проверять повторно
                    continue
                fresh.append(flag)
            pending.extend(fresh)
            while pending:
                batch, rest = pending[: self.max_flags], pending[self.max_flags :]
                pending = rest
                self.submit_batch(batch, dry=dry)
            self._stop.wait(poll_interval)

    def stop(self):
        self._stop.set()
