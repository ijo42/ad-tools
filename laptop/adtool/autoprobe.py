"""Automated NPC probe: every NEW detection is replayed against NPC
services right away and the result is stored with the detection.

NPC is the ideal canary: its services are identical to the competitors'
ones and its flags give no points (п. 4.7), so probing it costs nothing
and instantly shows whether the captured exploit works at all.

Бюджет проб обязателен: сканер (sqlmap) генерирует тысячи уникальных
payload'ов за минуту — без лимита это тысячи исходящих запросов на NPC,
то есть «мусорный трафик» (п. 8.5) и риск санкций вместо пользы.
"""

import collections
import threading
import time


class NpcProber:
    # бюджет: не больше MAX_PER_WINDOW проб за окно и не больше MAX_CONCURRENT
    # одновременно; сканерный шум подавляется самим дедупом fingerprint'ов,
    # а всё, что его прорывает, — лимитом
    MAX_PER_WINDOW = 10
    WINDOW_SEC = 60
    MAX_CONCURRENT = 2

    def __init__(self, npc_targets, flag_pattern=None, store=None, timeout=5.0):
        self.npc_targets = [t for t in (npc_targets or []) if not t.get("disabled")]
        self.flag_pattern = flag_pattern
        self.store = store
        self.timeout = timeout
        self._lock = threading.Lock()
        self._probed = set()          # fingerprints already probed (skip dupes)
        self._window = collections.deque()
        self._slots = threading.Semaphore(self.MAX_CONCURRENT)
        self._enabled = True          # живой переключатель из UI

    def set_enabled(self, value):
        """Вкл/выкл автопробу новых детектов (переключатель в UI).

        Выключенная автопроба не шлёт НИЧЕГО на NPC; ручные реплеи (кнопка
        ↻ и режим npc) продолжают работать."""
        with self._lock:
            self._enabled = bool(value)

    @property
    def enabled(self):
        with self._lock:
            return self._enabled

    def probe_async(self, detection_id, fingerprint, payload):
        if not self.npc_targets or self.store is None:
            return
        with self._lock:
            if not self._enabled:
                return
            if fingerprint in self._probed:
                return
            self._probed.add(fingerprint)
            now = time.monotonic()
            while self._window and now - self._window[0] > self.WINDOW_SEC:
                self._window.popleft()
            if len(self._window) >= self.MAX_PER_WINDOW:
                return  # бюджет окна исчерпан — пробу можно повторить через ↻
            self._window.append(now)
        threading.Thread(
            target=self._guarded_run, args=(detection_id, payload), daemon=True
        ).start()

    def _guarded_run(self, detection_id, payload):
        with self._slots:
            self._run(detection_id, payload)

    def _run(self, detection_id, payload):
        from .replay import harvest_flags, replay  # local import avoids cycle

        self.store.set_npc_status(detection_id, "running")
        try:
            results = replay(
                payload, self.npc_targets, mode="verbatim",
                flag_pattern=self.flag_pattern, timeout=self.timeout,
                log_fn=lambda _msg: None,
            )
            flags = harvest_flags(results, self.flag_pattern)
            errors = [r for r in results if r["error"]]
            if errors and not flags and all(
                r["response_len"] == 0 for r in results
            ):
                status = "error"  # NPC unreachable
            elif flags:
                status = "flags"
            else:
                status = "noflags"
            self.store.set_npc_status(detection_id, status, results, flags)
        except Exception as exc:  # noqa: BLE001
            self.store.set_npc_status(
                detection_id, "error", results=[{"error": str(exc)}]
            )
