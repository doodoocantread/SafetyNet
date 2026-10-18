"""Scan history — rebuilt from artifacts that already exist on disk.

No new store: `runs/audit.log` (Rule 5) already records, per scan, the target, scan
type, mode, model and timeout, and `runs/<run_id>/summary.json` holds the outcome.
This module folds the two into one row per run, so the UI can list past scans and
reopen their reports. The audit log stays the single source of truth for *what was
authorized*; nothing here writes to it.

`report.json` (written once when a scan finishes) caches the labeled report so that
reopening a scan neither re-calls the LLM labeler nor changes its wording between views.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .audit import read_entries
from .config import InvalidRunId, validate_run_id

REPORT_CACHE = "report.json"
_ACTIVE = frozenset({"queued", "running"})


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _safe_run_id(raw: Any) -> str | None:
    """run_id becomes a path segment below — never trust the log for that."""
    if not isinstance(raw, str):
        return None
    try:
        return validate_run_id(raw)
    except InvalidRunId:
        return None


def _fold_audit(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """One record per run_id from its scan_requested / scan_done / scan_error events."""
    runs: dict[str, dict[str, Any]] = {}
    for e in entries:
        run_id = _safe_run_id(e.get("run_id"))
        if run_id is None:
            continue
        rec = runs.setdefault(run_id, {"run_id": run_id})
        event = e.get("event")
        if event == "scan_requested":
            rec.update(
                created_at=e.get("ts"), target=e.get("target"), goal=e.get("goal"),
                scan_type=e.get("scan_type"), mode=e.get("mode"), model=e.get("model"),
                timeout_s=e.get("timeout_s"), project=e.get("project"),
            )
        elif event in ("scan_done", "scan_error", "scan_cancelled"):
            rec["finished_at"] = e.get("ts")
            rec["audit_status"] = (
                e.get("status") if event == "scan_done"
                else "cancelled" if event == "scan_cancelled"
                else "error"
            )
            if e.get("error"):
                rec["error"] = e["error"]
            # Fall back to the terminal event if the request line was lost.
            for key in ("target", "goal", "scan_type", "mode", "model"):
                rec.setdefault(key, e.get(key))
    return runs


def _status(rec: dict[str, Any], live_status: Mapping[str, str]) -> str:
    run_id = rec["run_id"]
    if live_status.get(run_id) in _ACTIVE:
        return live_status[run_id]
    if rec.get("summary_status"):
        return str(rec["summary_status"])
    if rec.get("audit_status"):
        return str(rec["audit_status"])
    # Requested but never finished and not running in this process → the server
    # restarted (or crashed) mid-scan.
    return "interrupted"


def _enrich(
    rec: dict[str, Any], runs_root: Path, live_status: Mapping[str, str]
) -> dict[str, Any]:
    """Add outcome fields from summary.json and resolve the final status."""
    summary = _read_json(runs_root / rec["run_id"] / "summary.json")
    if summary:
        rec["summary_status"] = summary.get("status")
        rec["cost_usd"] = float(summary.get("cost_usd") or 0)
        rec["wall_duration_s"] = float(summary.get("wall_duration_s") or 0)
        rec["observations"] = len(summary.get("observations") or [])
        rec.setdefault("goal", summary.get("goal"))
        if not rec.get("target") and summary.get("targets"):
            rec["target"] = summary["targets"][0]
        if summary.get("error"):
            rec.setdefault("error", summary["error"])
    rec["status"] = _status(rec, live_status)
    rec["has_report"] = summary is not None
    rec.pop("summary_status", None)
    rec.pop("audit_status", None)
    return rec


def list_history(
    runs_root: Path, live_status: Mapping[str, str] | None = None, *, limit: int = 200
) -> list[dict[str, Any]]:
    """Newest first. `live_status` maps run_id → in-memory job status for scans this
    process is still running."""
    live_status = live_status or {}
    runs = _fold_audit(read_entries(runs_root))
    rows = sorted(runs.values(), key=lambda r: r.get("created_at") or "", reverse=True)[:limit]
    return [_enrich(rec, runs_root, live_status) for rec in rows]


def get_history_item(
    runs_root: Path, run_id: str, live_status: Mapping[str, str] | None = None
) -> dict[str, Any] | None:
    """The history row for one run, or None if the audit log never saw it."""
    run_id = validate_run_id(run_id)
    rec = _fold_audit(read_entries(runs_root)).get(run_id)
    return _enrich(rec, runs_root, live_status or {}) if rec else None


def load_cached_report(runs_root: Path, run_id: str) -> dict[str, Any] | None:
    return _read_json(runs_root / validate_run_id(run_id) / REPORT_CACHE)


def save_report(runs_root: Path, run_id: str, report: dict[str, Any]) -> None:
    """Best-effort, like the audit log: a cache write must never fail a finished scan."""
    try:
        path = runs_root / validate_run_id(run_id) / REPORT_CACHE
        path.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass
