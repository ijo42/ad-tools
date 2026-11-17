"""Сервисный слой: выполнение replay-задач и разбор их результатов."""

from adtool.flags import FlagQueue  # noqa: F401 (типизация)
from adtool.replay import harvest_flags, replay
from adtool.store import DetectionStore  # noqa: F401


class Ctx:
    """Общий контекст приложения: стор, цели, очередь флагов."""

    def __init__(self, store, flag_queue, teams, npc_targets, flag_pattern):
        self.store = store
        self.flag_queue = flag_queue
        self.teams = teams            # команды без NPC
        self.npc_targets = npc_targets
        self.flag_pattern = flag_pattern


def run_replay(job, ctx: Ctx, payload: bytes, targets, mode: str, det_id=None):
    """Тело фонового job (JobRegistry вызывает fn(job, *args)):
    реплай payload на targets, сдача флагов, статусы NPC."""
    results = replay(
        payload, targets, mode=("verbatim" if mode == "npc" else mode),
        flag_pattern=ctx.flag_pattern,
        log_fn=lambda msg: job["log"].append(msg),
    )
    flags = harvest_flags(results, ctx.flag_pattern)
    # флаги NPC очков не дают (п. 4.7) — не тратим квоту сабмиттера
    if mode != "npc":
        source = f"replay:det{det_id}" if det_id is not None else "custom"
        for flag in flags:
            ctx.flag_queue.push(flag, source=source)
    if det_id is not None:
        ctx.store.add_replay(det_id, mode, results, flags)
    job["results"] = results
    job["flags"] = flags
    if mode == "npc" and det_id is not None:
        update_npc_status(ctx.store, det_id, results, flags)


def update_npc_status(store: DetectionStore, det_id, results, flags):
    errors = [r for r in results if r["error"]]
    if errors and not flags and all(r["response_len"] == 0 for r in results):
        store.set_npc_status(det_id, "error", results, flags)
    elif flags:
        store.set_npc_status(det_id, "flags", results, flags)
    else:
        store.set_npc_status(det_id, "noflags", results, flags)


def targets_for(ctx: Ctx, mode: str):
    return ctx.npc_targets if mode == "npc" else ctx.teams
