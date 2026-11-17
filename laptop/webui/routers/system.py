"""APIRouter: meta и статусы фоновых задач."""

from fastapi import APIRouter, HTTPException, Request

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
    return job
