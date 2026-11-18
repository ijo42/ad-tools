"""ForcAD API client + game monitor (ситуационная осведомлённость).

Endpoints проверены по исходникам ForcAD (pomo-mondreganto/ForcAD):
- GET /api/client/config/  -> GameConfig: {real_round, flag_lifetime,
  round_time, start_time, game_running, timezone, ...}
- PUT /flags (X-Team-Token) -> [{"msg": ..., "flag": ...}, ...] на каждый
  флаг; success: "Flag accepted! Earned X flag points!"; отказы:
  "Flag is invalid or too old." / "Flag is too old" / "Flag is your own" /
  "Flag already stolen" / "Game is not available." /
  "Cannot submit flags while service is down"
- GET /api/client/teams/ -> [{id, name, ...}]
- GET /api/client/teams/<id>/ -> история teamtasks команды: {status,
  task_id, timestamp, message} — статусы чекера для SLA-алертов.

GameMonitor — фоновый поток: раз в интервал опрашивает config, держит
актуальный раунд/время жизни флага, калибрует game.start по API (когда
в конфиге не задан) и публикует алерты (чекер не UP, игра не идёт,
API недоступен).
"""

import collections
import datetime
import json
import threading
import time
import urllib.error
import urllib.request

# коды возврата чекеров Hackerdom/ForcAD
CHECKER_OK = 101
CHECKER_CORRUPT = 102
CHECKER_MUMBLE = 103
CHECKER_DOWN = 104

STATUS_LABELS = {
    CHECKER_OK: "UP",
    CHECKER_CORRUPT: "CORRUPT",
    CHECKER_MUMBLE: "MUMBLE",
    CHECKER_DOWN: "DOWN",
}


class ForcadApi:
    def __init__(self, base_url, team_token="", timeout=5.0):
        self.base_url = base_url.rstrip("/")
        self.team_token = team_token
        self.timeout = timeout

    def _get(self, path):
        req = urllib.request.Request(self.base_url + path)
        headers = {}
        if self.team_token:
            headers["X-Team-Token"] = self.team_token
        for k, v in headers.items():
            req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode())

    def game_config(self):
        """GET /api/client/config/ -> dict или None (недоступен)."""
        try:
            return self._get("/api/client/config/")
        except (urllib.error.URLError, OSError, ValueError):
            return None

    def teams(self):
        try:
            return self._get("/api/client/teams/")
        except (urllib.error.URLError, OSError, ValueError):
            return []

    def team_history(self, team_id):
        """История teamtasks: [{status, task_id, timestamp, message}, ...]."""
        try:
            return self._get(f"/api/client/teams/{team_id}/")
        except (urllib.error.URLError, OSError, ValueError):
            return []

    def resolve_team_id(self, team_name=None, team_id=None):
        """Найти id своей команды по имени (или проверить заданный id)."""
        if team_id:
            return int(team_id)
        if not team_name:
            return None
        for t in self.teams():
            if t.get("name") == team_name:
                return t.get("id")
        return None


def parse_start_epoch(cfg, now=None):
    """start_time из GameConfig -> unix epoch (с учётом timezone).

    ForcAD хранит naive datetime; тайзуим берём из поля config.timezone,
    при ошибке — UTC. Fallback: оценка по текущему раунду."""
    now = now or time.time()
    raw = cfg.get("start_time")
    round_len = int(cfg.get("round_time") or 60)
    rnd = cfg.get("real_round")
    if isinstance(rnd, int) and rnd >= 0:
        approx = now - (rnd + 0.5) * round_len
    else:
        approx = now
    if not raw:
        return approx
    try:
        dt = datetime.datetime.fromisoformat(str(raw))
    except ValueError:
        return approx
    if dt.tzinfo is None:
        tzname = cfg.get("timezone")
        tz = datetime.timezone.utc
        if tzname:
            try:
                from zoneinfo import ZoneInfo

                tz = ZoneInfo(tzname)
            except Exception:  # noqa: BLE001
                pass
        dt = dt.replace(tzinfo=tz)
    return dt.timestamp()


class GameMonitor:
    """Фоновый опрос ForcAD: раунд, lifetime, статусы чекеров, алерты."""

    def __init__(self, api, config=None, on_update=None, interval=15.0):
        cfg = config or {}
        self.api = api
        self.interval = float(cfg.get("poll_interval", interval))
        self.team_name = cfg.get("team_name")
        self.team_id = cfg.get("team_id")
        self.on_update = on_update  # fn(state_dict) — например, калибровка game.start
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self.state = {
            "available": False,       # API отвечал хотя бы раз
            "running": None,          # game_running из ForcAD
            "round": None,            # real_round
            "round_len": None,
            "flag_lifetime": None,
            "start_epoch": None,      # калиброванное начало игры
            "team_id": None,
        }
        self.alerts = collections.deque(maxlen=100)  # {ts, level, text}
        self._last_statuses = {}  # task_id -> статус (для алертов об изменениях)

    def alert(self, level, text):
        rec = {"ts": time.time(), "level": level, "text": text}
        with self._lock:
            self.alerts.append(rec)
        print(f"[game] [{level}] {text}")

    def snapshot(self):
        with self._lock:
            return {
                "game": dict(self.state),
                "alerts": list(self.alerts)[-30:],
            }

    def round_of_ts(self, ts):
        """(round, lifetime) по калиброванному start; (None, None) без данных."""
        st = self.state
        if not st["available"] or st["start_epoch"] is None or not st["round_len"]:
            return None, None
        rnd = max(0, int((ts - st["start_epoch"]) / st["round_len"]))
        return rnd, st["flag_lifetime"]

    def stale_of(self, ts):
        """True, если флаг с временем утечки ts уже вне flag_lifetime
        (ForcAD отклонил бы: current_round - flag_round > flag_lifetime)."""
        st = self.state
        if not st["available"] or st["start_epoch"] is None \
                or not st["round_len"] or not st["flag_lifetime"] \
                or st["round"] is None:
            return False
        flag_round = max(0, int((ts - st["start_epoch"]) / st["round_len"]))
        return (st["round"] - flag_round) > st["flag_lifetime"]

    def start(self):
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        first = True
        while not self._stop.is_set():
            try:
                self._poll(first)
                first = False
            except Exception as exc:  # noqa: BLE001
                self.alert("warn", f"game monitor: {exc}")
            self._stop.wait(self.interval)

    def _poll(self, first):
        cfg = self.api.game_config()
        if not cfg:
            if first:
                self.alert("warn", "ForcAD API недоступен — раунды/алерты от API выключены")
            self.state["available"] = False
            return
        if not self.state["available"] and first:
            self.alert("info", "ForcAD API подключён")
        rnd = cfg.get("real_round")
        start_epoch = parse_start_epoch(cfg)
        with self._lock:
            self.state.update({
                "available": True,
                "running": bool(cfg.get("game_running")),
                "round": rnd,
                "round_len": int(cfg.get("round_time") or 60),
                "flag_lifetime": int(cfg.get("flag_lifetime") or 0),
                "start_epoch": start_epoch,
            })
        if rnd is not None and not bool(cfg.get("game_running")):
            # игра ещё не началась/закончилась — не спамим, один алерт на смену
            if self.state.get("_last_running") is not False:
                self.alert("warn", f"игра не идёт (round={rnd})")
            self.state["_last_running"] = False
        else:
            self.state["_last_running"] = True
        if self.on_update:
            try:
                self.on_update(dict(self.state))
            except Exception:  # noqa: BLE001
                pass
        self._poll_team(first)

    def _poll_team(self, first):
        if not (self.team_name or self.team_id):
            return
        if self.state["team_id"] is None:
            self.state["team_id"] = self.api.resolve_team_id(
                self.team_name, self.team_id)
            if self.state["team_id"] is None:
                if first:
                    self.alert("warn", f"команда {self.team_name or self.team_id} не найдена в ForcAD")
                return
        history = self.api.team_history(self.state["team_id"])
        latest = {}
        for rec in history:
            latest[rec.get("task_id")] = rec  # идут по времени, последнее — актуальное
        for task_id, rec in sorted(latest.items(), key=lambda kv: (kv[0] or 0)):
            status = rec.get("status")
            prev = self._last_statuses.get(task_id)
            if status == prev:
                continue
            label = STATUS_LABELS.get(status, str(status))
            if status != CHECKER_OK:
                self.alert(
                    "alarm",
                    f"чекер: task {task_id} -> {label}"
                    + (f" ({rec.get('message', '')[:80]})" if rec.get("message") else ""),
                )
            elif prev is not None and prev != CHECKER_OK:
                self.alert("info", f"чекер: task {task_id} -> UP")
            self._last_statuses[task_id] = status
