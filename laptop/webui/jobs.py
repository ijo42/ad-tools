"""JobRegistry: фоновые задачи replay (потоки) + поллинг статуса из UI."""

import threading
import uuid


class JobRegistry:
    def __init__(self):
        self._jobs: dict[str, dict] = {}
        self._lock = threading.Lock()

    def start(self, fn, *args, **kwargs) -> str:
        """Запустить fn(job, *args, **kwargs) в отдельном потоке."""
        job_id = uuid.uuid4().hex[:12]
        job = {"job_id": job_id, "status": "running", "results": None,
               "flags": None, "error": None, "log": [],
               "mode": kwargs.get("mode", ""),
               "det_id": kwargs.get("det_id")}
        with self._lock:
            self._jobs[job_id] = job

        def runner():
            try:
                fn(job, *args, **kwargs)
                if job["status"] == "running":
                    job["status"] = "done"
            except Exception as exc:  # noqa: BLE001
                job["status"] = "error"
                job["error"] = str(exc)

        threading.Thread(target=runner, daemon=True).start()
        return job_id

    def get(self, job_id: str) -> dict | None:
        return self._jobs.get(job_id)
