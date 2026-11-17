"""Фабрика FastAPI-приложения веб-интерфейса AD Toolkit.

create_app(ctx) собирает:
- APIRouter'ы (detections / packets+analytics / system);
- раздачу статики: Vue 3 SPA (vendored в static/, без CDN — офлайн-совместимо).

ctx: webui.services.Ctx (store, flag_queue, teams, npc_targets, flag_pattern)
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .jobs import JobRegistry
from .routers import detections, packets, system
from .services import Ctx

STATIC_DIR = Path(__file__).parent / "static"


def create_app(ctx: Ctx) -> FastAPI:
    app = FastAPI(
        title="AD Toolkit",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    app.state.ctx = ctx
    app.state.jobs = JobRegistry()

    app.include_router(detections.router)
    app.include_router(packets.router)
    app.include_router(system.router)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    return app
