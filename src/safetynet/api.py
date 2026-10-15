"""SafetyNet HTTP API + static frontend (ARCHITECTURE.md §6).

The backend only orchestrates. It validates the target against the local
whitelist and maps a scan type to a fixed goal BEFORE any engine runs — the user
never supplies free-text scope, and the agent never chooses a target.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .audit import record_scan
from .config import (
    SCAN_TYPES,
    InvalidRunId,
    TargetNotAllowed,
    goal_for,
    validate_run_id,
    validate_target,
)
from .engines.live import LiveAgentEngine
from .engines.replay import ReplayEngine
from .pipeline import build_report
from .report import to_markdown

_REPO = Path(__file__).resolve().parents[2]
_WEB_DIR = _REPO / "web"
_SAMPLES = _REPO / "samples" / "runs"
_LIVE_RUNS = _REPO / "runs"

# Live-scan resource guards (single-host tool — keep Docker containers bounded).
_MAX_CONCURRENT_SCANS = 2
_MAX_JOBS = 200  # hard cap on retained job records
_JOB_TTL_S = 60 * 60  # prune finished jobs after an hour

app = FastAPI(title="SafetyNet", version="0.1.0")

replay_engine = ReplayEngine(runs_root=_SAMPLES)
live_engine = LiveAgentEngine(runs_root=_LIVE_RUNS)

# In-memory job store (single-user tool; no DB by design — ARCHITECTURE.md §4).
_jobs: dict[str, dict[str, Any]] = {}
_scan_sema = asyncio.Semaphore(_MAX_CONCURRENT_SCANS)


def _prune_jobs() -> None:
    """Drop old finished jobs so the in-memory store cannot grow without bound."""
    now = time.time()
    done = {"done", "error"}
    stale = [
        jid
        for jid, j in _jobs.items()
        if j.get("status") in done and now - j.get("finished_at", now) > _JOB_TTL_S
    ]
    for jid in stale:
        _jobs.pop(jid, None)
    # Fallback if a burst outpaces the TTL: evict oldest finished jobs first.
    if len(_jobs) > _MAX_JOBS:
        evictable = sorted(
            (j.get("finished_at", now), jid)
            for jid, j in _jobs.items()
            if j.get("status") in done
        )
        for _, jid in evictable[: len(_jobs) - _MAX_JOBS]:
            _jobs.pop(jid, None)


class ScanRequest(BaseModel):
    target: str
    scan_type: str = "general"


@app.get("/api/scan-types")
def scan_types() -> list[dict[str, str]]:
    return [{"key": s.key, "label": s.label} for s in SCAN_TYPES.values()]


@app.get("/api/runs")
def list_runs() -> list[dict[str, Any]]:
    """Saved runs available for replay / demo mode."""
    out = []
    for run_id in replay_engine.list_runs():
        rr = replay_engine.load(run_id)
        out.append({
            "run_id": run_id,
            "goal": rr.summary.get("goal"),
            "status": rr.status,
            "targets": rr.summary.get("targets", []),
        })
    return out


def _engine_for(source: str, run_id: str) -> tuple[ReplayEngine, str]:
    """Validate run_id (path-traversal gate) and pick the engine for `source`."""
    try:
        safe_id = validate_run_id(run_id)
    except InvalidRunId as exc:
        raise HTTPException(400, str(exc)) from None
    engine = replay_engine if source == "sample" else ReplayEngine(runs_root=_LIVE_RUNS)
    return engine, safe_id


@app.get("/api/report/{source}/{run_id}")
def get_report(source: str, run_id: str) -> dict[str, Any]:
    """source = 'sample' (replay fixtures) or 'live' (runs/ from a live scan)."""
    engine, run_id = _engine_for(source, run_id)
    try:
        rr = engine.load(run_id)
    except FileNotFoundError:
        raise HTTPException(404, f"run {run_id!r} not found") from None
    return build_report(rr).model_dump()


@app.get("/api/report/{source}/{run_id}/markdown")
def get_report_markdown(source: str, run_id: str) -> PlainTextResponse:
    engine, run_id = _engine_for(source, run_id)
    try:
        rr = engine.load(run_id)
    except FileNotFoundError:
        raise HTTPException(404, f"run {run_id!r} not found") from None
    md = to_markdown(build_report(rr))
    return PlainTextResponse(md, media_type="text/markdown; charset=utf-8")


async def _run_live_job(
    job_id: str, target: str, goal: str, scan_type: str, run_id: str
) -> None:
    # Bound concurrent Docker containers (ARCHITECTURE.md §2.3 isolation boundary).
    async with _scan_sema:
        _jobs[job_id].update(status="running")
        try:
            rr = await live_engine.run(target=target, goal=goal, run_id=run_id)
            _jobs[job_id].update(status="done", run_id=run_id,
                                 report=build_report(rr).model_dump())
            record_scan(_LIVE_RUNS, event="scan_done", run_id=run_id, target=target,
                        goal=goal, scan_type=scan_type, status=rr.status)
        except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
            _jobs[job_id].update(status="error", error=f"{type(exc).__name__}: {exc}")
            record_scan(_LIVE_RUNS, event="scan_error", run_id=run_id, target=target,
                        goal=goal, scan_type=scan_type, error=str(exc))
        finally:
            _jobs[job_id]["finished_at"] = time.time()


@app.post("/api/scan")
async def start_scan(req: ScanRequest) -> dict[str, str]:
    # Hard gate (ARCHITECTURE.md §2.1) — before anything is spawned.
    try:
        target = validate_target(req.target)
    except TargetNotAllowed as exc:
        raise HTTPException(400, f"target not allowed: {exc}") from None
    try:
        goal = goal_for(req.scan_type)  # fixed scope (§2.2)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None

    _prune_jobs()
    job_id = uuid.uuid4().hex[:12]
    run_id = f"live-{job_id}"
    _jobs[job_id] = {"status": "queued", "run_id": run_id, "report": None, "error": None}
    # Audit the authorized scope BEFORE anything is spawned (ARCHITECTURE.md §2.5).
    record_scan(_LIVE_RUNS, event="scan_requested", run_id=run_id, target=target,
                goal=goal, scan_type=req.scan_type)
    asyncio.create_task(_run_live_job(job_id, target, goal, req.scan_type, run_id))
    return {"job_id": job_id, "run_id": run_id}


@app.get("/api/scan/{job_id}")
def scan_status(job_id: str) -> dict[str, Any]:
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown job")
    return job


@app.get("/")
def index() -> FileResponse:
    return FileResponse(_WEB_DIR / "index.html")


if _WEB_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(_WEB_DIR)), name="static")
