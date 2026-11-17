"""APIRouter: все пакеты (с раундами) и аналитика."""

from fastapi import APIRouter, Request

router = APIRouter(prefix="/api")


@router.get("/packets")
def list_packets(request: Request,
                 round: int | None = None,
                 service: str | None = None,
                 has_flag: int | None = None,
                 q: str | None = None,
                 direction: str | None = None,
                 limit: int = 200,
                 offset: int = 0):
    ctx = request.app.state.ctx
    return ctx.store.list_packets(
        round_no=round, service=service, has_flag=has_flag, q=q,
        direction=direction, limit=min(limit, 1000), offset=max(offset, 0),
    )


@router.get("/analytics")
def analytics(request: Request):
    ctx = request.app.state.ctx
    return ctx.store.analytics()
