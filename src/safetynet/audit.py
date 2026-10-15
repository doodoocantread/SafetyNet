"""Scan audit log — safety invariant Rule 5 (ARCHITECTURE.md §2.5).

Every scan request is recorded (target, goal, scan_type, run_id, time) as one
JSON object per line in ``runs/audit.log``. Append-only, deterministic, no
dependency — this is the tamper-evident record that a scan was authorized and
what scope it ran with. Writing the log must never break a scan, so failures are
swallowed after a best-effort stderr note.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# One slug so the run_id in the log is never attacker-controlled free text.
_AUDIT_FILENAME = "audit.log"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def record_scan(
    runs_root: Path,
    *,
    event: str,
    run_id: str,
    target: str,
    goal: str,
    scan_type: str,
    **extra: Any,
) -> None:
    """Append one audit entry. Best-effort: never raises into the caller."""
    entry = {
        "ts": _now_iso(),
        "event": event,  # e.g. "scan_requested" | "scan_done" | "scan_error"
        "run_id": run_id,
        "target": target,
        "goal": goal,
        "scan_type": scan_type,
        **extra,
    }
    try:
        runs_root.mkdir(parents=True, exist_ok=True)
        path = runs_root / _AUDIT_FILENAME
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as exc:  # disk full, permissions… — don't fail the scan
        print(f"[audit] failed to write entry: {exc}", file=sys.stderr)
