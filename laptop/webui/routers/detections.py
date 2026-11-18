"""APIRouter: детекты — список, детали, разметка, replay, клонер."""

import json
import time

from fastapi import APIRouter, HTTPException, Request

from ..schemas import BulkLabelRequest, CustomReplayRequest, LabelRequest, ReplayRequest
from ..services import run_replay

router = APIRouter(prefix="/api")


def _det_to_dict(r) -> dict:
    preview = (r["sample"] or b"")[:160].decode("latin-1", "replace")
    first_line = preview.split("\n", 1)[0].split("\r", 1)[0]
    return {
        "id": r["id"],
        "service": r["service"],
        "kind": r["kind"],
        "count": r["count"],
        "rounds": json.loads(r["rounds"]),
        "srcs": json.loads(r["srcs"]),
        "flags": json.loads(r["flags"]),
        "label": r["label"],
        "note": r["note"],
        "first_ts": r["first_ts"],
        "last_ts": r["last_ts"],
        "npc_status": r["npc_status"],
        "npc_flags": json.loads(r["npc_flags"] or "[]"),
        "preview": first_line,
    }


@router.get("/detections")
def list_detections(request: Request, service: str | None = None,
                    label: str | None = None):
    ctx = request.app.state.ctx
    if label == "":
        label = None  # не задан фильтр метки
    rows = ctx.store.list_detections(service=service, label=label)
    return {
        "detections": [_det_to_dict(r) for r in rows],
        "stats": ctx.store.stats(),
    }


@router.get("/detections/{det_id}")
def detection_detail(request: Request, det_id: int):
    ctx = request.app.state.ctx
    r = ctx.store.get(det_id)
    if not r:
        raise HTTPException(404, "detection not found")
    payload = r["sample"] or b""
    return {
        "id": r["id"],
        "service": r["service"],
        "kind": r["kind"],
        "count": r["count"],
        "rounds": json.loads(r["rounds"]),
        "srcs": json.loads(r["srcs"]),
        "flags": json.loads(r["flags"]),
        "label": r["label"],
        "note": r["note"],
        "template": (r["template"] or b"").decode("latin-1"),
        "payload_text": payload.decode("latin-1"),
        "payload_hex": payload[:2048].hex(),
        "npc_status": r["npc_status"],
        "npc_flags": json.loads(r["npc_flags"] or "[]"),
        "npc_results": json.loads(r["npc_results"] or "[]"),
        "variants": ctx.store.variants_for(det_id),
        "replays": [
            {
                "id": rp["id"],
                "ts": rp["ts"],
                "mode": rp["mode"],
                "results": json.loads(rp["results"]),
                "flags_found": json.loads(rp["flags_found"]),
            }
            for rp in ctx.store.replays_for(det_id)
        ],
    }


@router.post("/detections/{det_id}/label")
def set_label(request: Request, det_id: int, body: LabelRequest):
    ctx = request.app.state.ctx
    if not ctx.store.get(det_id):
        raise HTTPException(404, "detection not found")
    ctx.store.set_label(det_id, label=body.label, note=body.note)
    return {"ok": True}


@router.post("/detections/bulk-label")
def bulk_label(request: Request, body: BulkLabelRequest):
    ctx = request.app.state.ctx
    n = ctx.store.bulk_set_label(body.ids, label=body.label, note=body.note)
    return {"ok": True, "updated": n}


@router.post("/detections/{det_id}/replay")
def replay_detection(request: Request, det_id: int, body: ReplayRequest):
    ctx = request.app.state.ctx
    det = ctx.store.get(det_id)
    if not det:
        raise HTTPException(404, "detection not found")
    if body.mode not in ("verbatim", "template", "npc"):
        raise HTTPException(400, "bad mode")
    if body.mode == "npc" and not ctx.npc_targets:
        raise HTTPException(400, "нет NPC-целей в teams.yaml")
    targets = ctx.npc_targets if body.mode == "npc" else ctx.teams
    job_id = request.app.state.jobs.start(
        run_replay, ctx, det["sample"], targets,
        det_id=det_id, mode=body.mode, service=det["service"],
    )
    return {"job_id": job_id}


@router.get("/detections/{det_id}/clone")
def clone_detection(request: Request, det_id: int):
    """Клонер: pwntools-скрипт с payload детекта для правки и запуска."""
    from adtool.clone import generate_script

    ctx = request.app.state.ctx
    r = ctx.store.get(det_id)
    if not r:
        raise HTTPException(404, "detection not found")
    host, port = "<HOST>", 80
    if ctx.teams:
        host = ctx.teams[0]["host"]
        port = ctx.teams[0]["ports"][0]
    script = generate_script(
        r["sample"] or b"", host=host, port=port,
        det_id=det_id, service=r["service"], kind=r["kind"],
        captured=time.strftime("%H:%M:%S", time.localtime(r["first_ts"])),
        src=",".join(json.loads(r["srcs"])[:2]),
    )
    return {"script": script}


@router.post("/replay_custom")
def replay_custom(request: Request, body: CustomReplayRequest):
    """Клонер: отправка изменённого payload на произвольную цель."""
    import json as _json

    ctx = request.app.state.ctx
    payload = body.payload.encode("latin-1", "replace")
    targets = [{"name": "custom", "host": body.host, "ports": [body.port]}]
    job_id = request.app.state.jobs.start(
        run_replay, ctx, payload, targets, "verbatim",
        det_id=None, mode="verbatim",
    )
    return {"job_id": job_id}
