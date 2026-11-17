"""Flag submitter: JSONL queue -> ForcAD /flags, batched and rate-limited.

Regulation constraints (п. 4.3–4.4):
- JSON array to /flags, team token in X-Team-Token header
- <= 100 flags per request, <= 10 KiB body
- quota 200 flags/sec, burst 400
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


class Submitter:
    def __init__(self, base_url, team_token, config=None, queue_file="flags.queue.jsonl"):
        cfg = config or {}
        self.base_url = base_url.rstrip("/")
        self.team_token = team_token
        self.rate_per_sec = cfg.get("rate_per_sec", 200)
        self.burst = cfg.get("burst", 400)
        self.max_flags = cfg.get("max_flags_per_request", 100)
        self.max_body = cfg.get("max_body_bytes", 10240)
        self.queue_file = cfg.get("queue_file", queue_file)
        self.state_file = cfg.get("state_file", "flags_seen.txt")
        self.bucket = TokenBucket(self.rate_per_sec, self.burst)
        self._stop = threading.Event()
        self.log_fn = print
        self._load_state()

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
                self._post(batch)
                self.log_fn(f"[+] submitted {len(batch)} flags")
                for flag in batch:
                    self._mark(flag)
            except (urllib.error.URLError, OSError, ValueError) as exc:
                self.log_fn(f"[!] submit failed: {exc}")
                errors.extend(batch)
        return sent, errors

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
        """Daemon: drain queue_file, dedup, submit in batches."""
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
            fresh = [
                r["flag"]
                for r in records
                if r.get("flag") and r["flag"] not in self.seen
            ]
            pending.extend(fresh)
            while pending:
                batch, rest = pending[: self.max_flags], pending[self.max_flags :]
                pending = rest
                self.submit_batch(batch, dry=dry)
            self._stop.wait(poll_interval)

    def stop(self):
        self._stop.set()
