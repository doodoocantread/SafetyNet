"""SafetyWebbing HTTP API + static frontend (ARCHITECTURE.md §6).

The backend only orchestrates. It validates the target against the local
whitelist and maps a scan type to a fixed goal BEFORE any engine runs — the user
never supplies free-text scope, and the agent never chooses a target.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .audit import record_scan
from .config import (
    AGENTS,
    DEFAULT_AGENT,
    DIRECT_MODE_ENV,
    LLM_PROVIDERS,
    SCAN_TYPES,
    AgentNotAllowed,
    InvalidLLMProvider,
    InvalidModel,
    InvalidProject,
    InvalidRunId,
    InvalidTimeout,
    ModeNotAllowed,
    TargetNotAllowed,
    agent_for,
    direct_mode_enabled,
    goal_for,
    validate_llm_provider,
    validate_mode,
    validate_model,
    validate_project,
    validate_run_id,
    validate_target,
    validate_timeout,
)
from .engines.base import Engine
from .engines.live import LiveAgentEngine
from .engines.local import LocalAgentEngine
from .engines.replay import ReplayEngine
from .history import get_history_item, list_history, load_cached_report, save_report
from .insights import InvalidTriage, build_overview, collect_vulns, set_triage
from .live_log import JobLog, tail_traces
from .pipeline import build_report
from .report import to_markdown
from .system import recent_audit, system_status

_REPO = Path(__file__).resolve().parents[2]
_WEB_DIR = _REPO / "web"
_SAMPLES = _REPO / "samples" / "runs"
_LIVE_RUNS = _REPO / "runs"

# Live-scan resource guards (single-host tool — keep Docker containers bounded).
_MAX_CONCURRENT_SCANS = 2
_MAX_JOBS = 200  # hard cap on retained job records
_JOB_TTL_S = 60 * 60  # prune finished jobs after an hour

app = FastAPI(title="SafetyWebbing", version="0.1.0")

replay_engine = ReplayEngine(runs_root=_SAMPLES)
live_engine = LiveAgentEngine(runs_root=_LIVE_RUNS)  # mode "docker" (isolated)
local_engine = LocalAgentEngine(runs_root=_LIVE_RUNS, search_dirs=(_REPO,))  # mode "direct"

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


class TriageRequest(BaseModel):
    status: str
    note: str = ""


class ScanRequest(BaseModel):
    target: str
    scan_type: str = "general"
    agent: str = DEFAULT_AGENT  # which pentest agent runs (config.AGENTS)
    mode: str = "docker"  # "docker" (isolated, default) | "direct" (host process, opt-in)
    model: str | None = None  # agent model id; None = the agent CLI's default
    timeout_s: float | None = None  # wall-clock budget; None = config.py default
    project: str | None = None  # free-text label to group scans by app; display only
    # For llm_api_key agents (hackingBuddy): the LLM provider + a key entered in the
    # UI. The key is used for this scan only — injected into the container, NEVER
    # written to disk or the audit log. Omit the key to use the server's env key.
    llm_provider: str | None = None
    llm_api_key: str | None = None


@app.get("/api/scan-types")
def scan_types() -> list[dict[str, str]]:
    return [{"key": s.key, "label": s.label} for s in SCAN_TYPES.values()]


@app.get("/api/agents")
def agents() -> list[dict[str, Any]]:
    """Pentest agents the UI may offer. An `llm_api_key` agent needs a provider key;
    it can come from the server env OR be entered per-scan in the UI, so the agent is
    selectable either way — `needs_key` / `has_server_key` tell the UI what to prompt."""
    have_server_key = any(os.environ.get(k) for k in live_engine.llm_key_env)
    out = []
    for a in AGENTS.values():
        needs_key = a.auth == "llm_api_key"
        out.append({
            "key": a.key, "label": a.label, "description": a.description,
            "modes": list(a.modes), "available": True, "reason": None,
            "needs_key": needs_key,
            "has_server_key": needs_key and have_server_key,
        })
    return out


@app.get("/api/llm-providers")
def llm_providers() -> list[dict[str, Any]]:
    """LLM providers a UI-entered key may target (for the hackingBuddy agent).
    `has_server_key` says the server env already holds one, so a key is optional."""
    return [
        {"key": p.key, "label": p.label, "has_server_key": bool(os.environ.get(p.env_name))}
        for p in LLM_PROVIDERS.values()
    ]


@app.get("/api/modes")
def modes() -> list[dict[str, Any]]:
    """Execution modes the UI may offer. `direct` is only `available` when the server
    opted in AND the agent CLI can be found — the UI never decides that itself."""
    direct_reason = None
    if not direct_mode_enabled():
        direct_reason = f"Server chưa bật. Khởi động với {DIRECT_MODE_ENV}=1."
    elif local_engine.command() is None:
        direct_reason = "Không tìm thấy lệnh pentestgpt-agent (xem README)."
    return [
        {"key": "docker", "label": "Docker (cô lập)", "available": True, "reason": None},
        {"key": "direct", "label": "Trực tiếp trên máy (không cô lập)",
         "available": direct_reason is None, "reason": direct_reason},
    ]


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


def _live_status() -> dict[str, str]:
    """run_id → status for scans this process still knows about (queued/running/…)."""
    return {j["run_id"]: j["status"] for j in _jobs.values()}


@app.get("/api/history")
def history() -> list[dict[str, Any]]:
    """Past live scans, newest first: target, scan type, mode, model, status, outcome."""
    return list_history(_LIVE_RUNS, _live_status())


@app.get("/api/history/{run_id}")
def history_item(run_id: str) -> dict[str, Any]:
    """One past scan: its settings (`meta`) plus its report. `report` is null when the
    scan produced none (still running, failed before the agent wrote a summary, …)."""
    try:
        meta = get_history_item(_LIVE_RUNS, run_id, _live_status())
    except InvalidRunId as exc:
        raise HTTPException(400, str(exc)) from None
    if meta is None:
        raise HTTPException(404, f"run {run_id!r} not found in scan history")
    report = load_cached_report(_LIVE_RUNS, run_id)
    if report is None and meta["has_report"]:
        # Scan predates report caching: rebuild from summary.json + traces.
        rr = replace(ReplayEngine(runs_root=_LIVE_RUNS).load(run_id),
                     engine=meta.get("mode") or "live")
        report = build_report(rr).model_dump()
    return {"meta": meta, "report": report}


@app.get("/api/overview")
def overview() -> dict[str, Any]:
    """Dashboard totals across every scan: severity mix, OWASP spread, per-target risk."""
    rows = list_history(_LIVE_RUNS, _live_status(), limit=1000)
    return build_overview(rows, collect_vulns(_LIVE_RUNS, rows=rows))


@app.get("/api/vulns")
def vulns() -> list[dict[str, Any]]:
    """Findings deduplicated across scans, worst first, with the user's triage decision."""
    return collect_vulns(_LIVE_RUNS, _live_status())


@app.put("/api/vulns/{vuln_id}/triage")
def triage_vuln(vuln_id: str, req: TriageRequest) -> dict[str, Any]:
    """Record a decision (fixing / fixed / false positive / accepted) on one vulnerability."""
    try:
        if not any(v["id"] == vuln_id for v in collect_vulns(_LIVE_RUNS, _live_status())):
            raise HTTPException(404, f"vulnerability {vuln_id!r} not found")
        return set_triage(_LIVE_RUNS, vuln_id, req.status, req.note)
    except InvalidTriage as exc:
        raise HTTPException(400, str(exc)) from None


@app.get("/api/system")
def system() -> dict[str, Any]:
    """Health of what a scan depends on (Docker, agent CLI, labeler) plus the active limits."""
    return system_status(
        runs_root=_LIVE_RUNS, docker_image=live_engine.image,
        agent_command=local_engine.command(), max_concurrent=_MAX_CONCURRENT_SCANS,
        jobs=_jobs, app_version=app.version,
    )


@app.get("/api/audit")
def audit_log(limit: int = 100) -> list[dict[str, Any]]:
    """Newest-first tail of runs/audit.log (safety rule 5: every scan is recorded)."""
    return recent_audit(_LIVE_RUNS, limit)


async def _run_live_job(
    job_id: str, engine: Engine, agent: str, mode: str, model: str | None,
    target: str, goal: str, scan_type: str, run_id: str,
) -> None:
    log: JobLog = _jobs[job_id]["log"]
    log.append(f"Đang chờ slot quét (tối đa {_MAX_CONCURRENT_SCANS} song song)…")
    try:
        # Bound concurrent agent processes/containers (ARCHITECTURE.md §2.3).
        # This `async with` is inside the try/except so a cancel while still
        # queued (never acquired the semaphore) is caught too.
        async with _scan_sema:
            _jobs[job_id].update(status="running")
            log.append(
                f"Bắt đầu quét · agent={agent} · mode={mode} · "
                f"model={model or 'mặc định'} · target={target}"
            )
            # Tail the agent's trace files live so the UI shows real progress, not
            # a spinner — independent of which engine is running (CODEMAP.md §6.4).
            stop_tailing = asyncio.Event()
            tailer_task = asyncio.create_task(
                tail_traces(_LIVE_RUNS / run_id / "traces", log, stop_tailing)
            )
            try:
                rr = await engine.run(target=target, goal=goal, run_id=run_id)
                # Off the event loop: LLM labeling is a blocking network call per finding.
                report = (await asyncio.to_thread(build_report, rr)).model_dump()
                save_report(_LIVE_RUNS, run_id, report)  # history reopens this exact report
                log.append(
                    f"Quét xong — status={rr.status}",
                    level="ok" if rr.status == "completed" else "error",
                )
                _jobs[job_id].update(status="done", run_id=run_id, report=report)
                record_scan(_LIVE_RUNS, event="scan_done", run_id=run_id, target=target,
                            goal=goal, scan_type=scan_type, agent=agent, mode=mode, model=model,
                            status=rr.status)
            except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
                # asyncio.CancelledError is a BaseException, not caught here — it
                # falls through to the outer handler below.
                log.append(f"LỖI: {type(exc).__name__}: {exc}", level="error")
                _jobs[job_id].update(status="error", error=f"{type(exc).__name__}: {exc}")
                record_scan(_LIVE_RUNS, event="scan_error", run_id=run_id, target=target,
                            goal=goal, scan_type=scan_type, agent=agent, mode=mode, model=model,
                            error=str(exc))
            finally:
                stop_tailing.set()
                await tailer_task
    except asyncio.CancelledError:
        # cancel_scan() called task.cancel() — the engine (if it had started)
        # already killed the real process/container on its way out; this is
        # just recording the final state, not a crash.
        log.append("Người dùng đã hủy quét", level="warn")
        _jobs[job_id].update(status="cancelled", error="Đã hủy theo yêu cầu người dùng")
        record_scan(_LIVE_RUNS, event="scan_cancelled", run_id=run_id, target=target,
                    goal=goal, scan_type=scan_type, agent=agent, mode=mode, model=model)
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
    try:
        mode = validate_mode(req.mode)  # `direct` only if the server opted in
    except ModeNotAllowed as exc:
        raise HTTPException(400, str(exc)) from None
    try:
        agent = agent_for(req.agent)  # which pentest agent runs (before model: see below)
    except AgentNotAllowed as exc:
        raise HTTPException(400, str(exc)) from None
    try:
        # hackingBuddy models are litellm ids (provider/model), so allow a slash there.
        model = validate_model(req.model, allow_slash=(agent.auth == "llm_api_key"))
    except InvalidModel as exc:
        raise HTTPException(400, str(exc)) from None
    try:
        timeout_s = validate_timeout(req.timeout_s)
    except InvalidTimeout as exc:
        raise HTTPException(400, str(exc)) from None
    try:
        project = validate_project(req.project)
    except InvalidProject as exc:
        raise HTTPException(400, str(exc)) from None
    if mode not in agent.modes:
        raise HTTPException(
            400,
            f"agent {agent.key!r} does not support mode {mode!r} "
            f"(supported: {', '.join(agent.modes)})",
        )

    # LLM key for an llm_api_key agent (hackingBuddy): a per-scan key entered in the
    # UI — used for this scan only, never written to disk or the audit log — or the
    # server's env key. Decide the source + provider here; the engine injects it.
    llm_api_key: str | None = None
    llm_env_name: str | None = None
    if agent.auth == "llm_api_key":
        user_key = (req.llm_api_key or "").strip() or None
        provider = None
        if req.llm_provider:
            try:
                provider = validate_llm_provider(req.llm_provider)
            except InvalidLLMProvider as exc:
                raise HTTPException(400, str(exc)) from None
        if user_key and provider is None:
            raise HTTPException(400, "llm_provider is required when an API key is supplied")
        if provider is not None:
            # A provider was chosen: that provider's key must be present — from the
            # UI (used for this scan only) or already in the server environment.
            env_name = LLM_PROVIDERS[provider].env_name
            if user_key is None and not os.environ.get(env_name):
                raise HTTPException(
                    400,
                    f"no API key for provider {provider!r} — enter one in the UI, or set "
                    f"{env_name} in the server environment",
                )
            llm_env_name = env_name
            llm_api_key = user_key
        elif not any(os.environ.get(k) for k in live_engine.llm_key_env):
            raise HTTPException(
                400,
                f"agent {agent.key!r} needs an LLM API key — enter one in the UI, or set "
                f"one of {', '.join(live_engine.llm_key_env)} in the server environment",
            )

    # Per-scan copy so a requested model/timeout — or the chosen agent's image /
    # auth / key — never leaks into the shared engine used by the next scan.
    if mode == "direct":
        if local_engine.command() is None:
            raise HTTPException(400, "direct mode: pentestgpt-agent CLI not found (see README)")
        engine: Engine = replace(local_engine, model=model, timeout_s=timeout_s)
    else:
        engine = replace(
            live_engine, image=agent.image, auth=agent.auth, model=model, timeout_s=timeout_s,
            llm_api_key=llm_api_key, llm_env_name=llm_env_name,
        )

    _prune_jobs()
    job_id = uuid.uuid4().hex[:12]
    run_id = f"live-{job_id}"
    _jobs[job_id] = {"status": "queued", "run_id": run_id, "agent": agent.key, "mode": mode,
                     "model": model, "timeout_s": timeout_s, "project": project,
                     "report": None, "error": None, "log": JobLog()}
    # Audit the authorized scope BEFORE anything is spawned (ARCHITECTURE.md §2.5).
    record_scan(_LIVE_RUNS, event="scan_requested", run_id=run_id, target=target,
                goal=goal, scan_type=req.scan_type, agent=agent.key, mode=mode, model=model,
                timeout_s=timeout_s, project=project)
    task = asyncio.create_task(
        _run_live_job(job_id, engine, agent.key, mode, model, target, goal, req.scan_type, run_id)
    )
    _jobs[job_id]["task"] = task
    return {"job_id": job_id, "run_id": run_id, "agent": agent.key, "mode": mode}


@app.get("/api/scan/{job_id}")
def scan_status(job_id: str) -> dict[str, Any]:
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown job")
    return {k: v for k, v in job.items() if k not in ("log", "task")}


@app.post("/api/scan/{job_id}/cancel")
async def cancel_scan(job_id: str) -> dict[str, Any]:
    """Stop a queued/running scan. Cancels the backing asyncio task, which (for
    the Docker engine) `docker kill`s the actual container and (for direct mode)
    kills the whole process tree — not just the asyncio await point — before the
    job settles into status 'cancelled' (see _run_live_job, engines/live.py).

    `async def` (unlike the other status endpoints) so this runs on the event
    loop itself: Task.cancel() is not meant to be called from another thread,
    and a plain `def` endpoint would run in FastAPI's threadpool."""
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown job")
    if job["status"] not in ("queued", "running"):
        return {"status": job["status"], "cancelled": False}
    job["task"].cancel()
    return {"status": "cancelling", "cancelled": True}


@app.get("/api/scan/{job_id}/log")
def scan_log(job_id: str, after: int = 0) -> dict[str, Any]:
    """Incremental terminal feed: lines appended since index `after`. Polled
    frequently by the UI while a scan is running (see live_log.py)."""
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown job")
    log: JobLog = job["log"]
    after = max(0, after)
    new_lines = log.lines[after:]
    return {"lines": new_lines, "cursor": after + len(new_lines), "status": job["status"]}


@app.get("/")
def overview_page() -> FileResponse:
    """Dashboard: totals across all scans (landing page)."""
    return FileResponse(_WEB_DIR / "overview.html")


@app.get("/scan")
def scan_page() -> FileResponse:
    return FileResponse(_WEB_DIR / "scan.html")


@app.get("/vulns")
def vulns_page() -> FileResponse:
    """Vulnerabilities across all scans, with triage."""
    return FileResponse(_WEB_DIR / "vulns.html")


@app.get("/system")
def system_page() -> FileResponse:
    """Runtime health, limits, scope and audit log."""
    return FileResponse(_WEB_DIR / "system.html")


@app.get("/history")
def history_page() -> FileResponse:
    """Past live scans: list on the left, report on the right (deep link: /history?run=<id>)."""
    return FileResponse(_WEB_DIR / "history.html")


@app.get("/about")
def about() -> FileResponse:
    """Explainer page: how the pipeline works and what SafetyWebbing adds on top of PentestGPT."""
    return FileResponse(_WEB_DIR / "about.html")


if _WEB_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(_WEB_DIR)), name="static")
