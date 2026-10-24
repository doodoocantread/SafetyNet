"""Runtime health for the "Hệ thống" page: what is installed, what is switched on, which
limits apply — so a missing Docker or API key shows up *before* a scan fails on it.

Read-only. It reports whether secrets exist (a bool), never their values.
"""

from __future__ import annotations

import importlib.util
import os
import platform
import shutil
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import config
from .audit import read_entries
from .history import REPORT_CACHE
from .insights import TRIAGE_FILE
from .pipeline import default_llm_model

_DOCKER_TTL_S = 10.0
_DOCKER_TIMEOUT_S = 6.0
_docker_cache: dict[str, Any] = {"at": 0.0, "key": None, "value": None}

# Fields of an audit entry the UI may show. `goal` is a fixed template per scan type,
# so it would only repeat itself on every line.
_AUDIT_FIELDS = ("ts", "event", "run_id", "target", "scan_type", "mode", "model",
                 "timeout_s", "status", "error")


def _run(argv: list[str]) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=_DOCKER_TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired):
        return None


def docker_status(image: str) -> dict[str, Any]:
    """Is the `docker` CLI there, is the daemon answering, is our image built?
    Cached briefly: the page can be refreshed often and `docker info` is not free."""
    now = time.monotonic()
    if _docker_cache["key"] == image and now - _docker_cache["at"] < _DOCKER_TTL_S:
        return _docker_cache["value"]

    exe = shutil.which("docker")
    status: dict[str, Any] = {"installed": exe is not None, "daemon": False,
                              "server_version": None, "image": image, "image_built": False}
    if exe:
        info = _run([exe, "info", "--format", "{{.ServerVersion}}"])
        if info is not None and info.returncode == 0:
            status["daemon"] = True
            status["server_version"] = info.stdout.strip() or None
            built = _run([exe, "image", "inspect", image])
            status["image_built"] = built is not None and built.returncode == 0
    status["ok"] = status["installed"] and status["daemon"] and status["image_built"]
    _docker_cache.update(at=now, key=image, value=status)
    return status


def labeler_status() -> dict[str, Any]:
    has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    has_sdk = importlib.util.find_spec("anthropic") is not None
    effective = "llm" if has_key and has_sdk else "heuristic"
    note = None
    if has_key and not has_sdk:
        note = ("Đã đặt ANTHROPIC_API_KEY nhưng chưa cài package `anthropic` — "
                "mọi finding đang âm thầm rơi về heuristic.")
    elif not has_key:
        note = "Chưa đặt ANTHROPIC_API_KEY — nhãn do bộ luật heuristic offline gán."
    return {"api_key_set": has_key, "sdk_installed": has_sdk, "effective": effective,
            "model": default_llm_model() if effective == "llm" else None, "note": note}


def recent_audit(runs_root: Path, limit: int = 100) -> list[dict[str, Any]]:
    """Newest first, whitelisted fields only."""
    limit = max(1, min(limit, 500))
    entries = read_entries(runs_root)[-limit:]
    return [{k: e[k] for k in _AUDIT_FIELDS if k in e} for e in reversed(entries)]


def system_status(
    *,
    runs_root: Path,
    docker_image: str,
    agent_command: list[str] | None,
    max_concurrent: int,
    jobs: Mapping[str, Mapping[str, Any]],
    app_version: str,
) -> dict[str, Any]:
    direct_on = config.direct_mode_enabled()
    run_dirs = [p for p in runs_root.iterdir() if p.is_dir()] if runs_root.is_dir() else []
    audit_path = runs_root / "audit.log"
    try:
        audit_bytes = audit_path.stat().st_size
    except OSError:
        audit_bytes = 0

    return {
        "app": {"version": app_version, "python": platform.python_version(),
                "platform": f"{platform.system()} {platform.release()}",
                "executable": sys.executable},
        "docker": docker_status(docker_image),
        "direct": {
            "enabled": direct_on, "env": config.DIRECT_MODE_ENV,
            "agent_found": agent_command is not None,
            # Only the launcher, not its arguments: SAFETYWEBBING_AGENT_CMD is free-form.
            "agent_cmd": agent_command[0] if agent_command else None,
        },
        "labeler": labeler_status(),
        "limits": {
            "max_concurrent_scans": max_concurrent,
            "default_timeout_s": config._DEFAULT_TIMEOUT_S,
            "min_timeout_s": config._MIN_TIMEOUT_S,
            "max_timeout_s": config._MAX_TIMEOUT_S,
        },
        "scope": {
            "allowed_hosts": ["localhost", "127.0.0.0/8", "::1"],
            "schemes": ["http", "https"],
            "scan_types": [{"key": s.key, "label": s.label, "goal": s.goal}
                           for s in config.SCAN_TYPES.values()],
            "modes": list(config.MODES),
        },
        "storage": {
            "runs_dir": str(runs_root.resolve()),
            "runs": len(run_dirs),
            "cached_reports": sum(1 for p in run_dirs if (p / REPORT_CACHE).is_file()),
            "audit_entries": len(read_entries(runs_root)),
            "audit_bytes": audit_bytes,
            "triage_file": (runs_root / TRIAGE_FILE).is_file(),
        },
        "jobs": dict(Counter(j.get("status", "unknown") for j in jobs.values())),
    }
