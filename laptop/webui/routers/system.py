"""APIRouter: meta, статусы фоновых задач, статус игры, NPC-автопроба."""

from fastapi import APIRouter, HTTPException, Request

from ..schemas import NpcAutoprobeRequest

router = APIRouter(prefix="/api")


@router.get("/meta")
def meta(request: Request):
    ctx = request.app.state.ctx
    return {
        "teams": [t["name"] for t in ctx.teams],
        "npc_count": len(ctx.npc_targets),
        "stats": ctx.store.stats(),
    }


@router.get("/jobs/{job_id}")
def job_status(request: Request, job_id: str):
    job = request.app.state.jobs.get(job_id)
    if not job:
        raise HTTPException(404, "no such job")
    return {k: v for k, v in job.items() if not k.startswith("_")}


@router.get("/system/status")
def system_status(request: Request):
    """Сводка для шапки UI: игра (раунд/lifetime), сабмиттер, алерты."""
    ctx = request.app.state.ctx
    out = {"game": None, "submitter": None, "npc_autoprobe": None}
    gm = ctx.game_monitor
    if gm is not None:
        snap = gm.snapshot()
        out["game"] = snap["game"]
        out["alerts"] = snap["alerts"]
    prober = ctx.npc_prober
    if prober is not None:
        out["npc_autoprobe"] = prober.enabled
    sub = ctx.submitter
    if sub is not None:
        out["submitter"] = dict(sub.stats)
    return out


@router.get("/system/npc_autoprobe")
def get_npc_autoprobe(request: Request):
    ctx = request.app.state.ctx
    if ctx.npc_prober is None:
        raise HTTPException(400, "NPC-автопроба недоступна (ingest выключен или нет npc-целей)")
    return {"enabled": ctx.npc_prober.enabled}


@router.post("/system/npc_autoprobe")
def set_npc_autoprobe(request: Request, body: NpcAutoprobeRequest):
    """Переключатель автопробы новых детектов на NPC (без рестарта)."""
    ctx = request.app.state.ctx
    if ctx.npc_prober is None:
        raise HTTPException(400, "NPC-автопроба недоступна (ingest выключен или нет npc-целей)")
    ctx.npc_prober.set_enabled(body.enabled)
    return {"enabled": ctx.npc_prober.enabled}
