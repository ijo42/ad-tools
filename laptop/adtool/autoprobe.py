"""Automated NPC probe: every NEW detection is replayed against NPC
services right away and the result is stored with the detection.

NPC is the ideal canary: its services are identical to the competitors'
ones and its flags give no points (п. 4.7), so probing it costs nothing
and instantly shows whether the captured exploit works at all.
"""

import threading


class NpcProber:
    def __init__(self, npc_targets, flag_pattern=None, store=None, timeout=5.0):
        self.npc_targets = [t for t in (npc_targets or []) if not t.get("disabled")]
        self.flag_pattern = flag_pattern
        self.store = store
        self.timeout = timeout
        self._lock = threading.Lock()
        self._probed = set()  # fingerprints already probed (skip dupes)

    def probe_async(self, detection_id, fingerprint, payload):
        if not self.npc_targets or self.store is None:
            return
        with self._lock:
            if fingerprint in self._probed:
                return
            self._probed.add(fingerprint)
        threading.Thread(
            target=self._run, args=(detection_id, payload), daemon=True
        ).start()

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
