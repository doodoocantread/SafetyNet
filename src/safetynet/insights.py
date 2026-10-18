"""Cross-scan views: deduplicated vulnerabilities, triage state, dashboard totals.

Each scan is one report; this module looks *across* them. A "vulnerability" is a
finding fingerprinted by (target origin, CWE or class, endpoint path), so the same
SQLi on `/rest/user/login` found by three scans is one row seen three times, not three
rows. Nothing new is stored about scans: everything is folded from the history rows
and the cached `report.json` files. The one thing the user *decides* — "fixed", "false
positive", … — is kept in `runs/triage.json`, never mixed into the scan evidence.

Limitation, by design: the fingerprint trusts the labeler's CWE/class. If an LLM labels
the same bug differently in two scans, they appear as two vulnerabilities rather than
being merged on a guess.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .config import _is_loopback_host
from .engines.replay import ReplayEngine
from .history import list_history, load_cached_report
from .labeling import HeuristicLabeler
from .models import Severity
from .pipeline import build_report

TRIAGE_FILE = "triage.json"
TRIAGE_STATUSES = ("open", "fixing", "fixed", "false_positive", "accepted")
_ACTIVE_TRIAGE = frozenset({"open", "fixing"})
_MAX_NOTE = 500
_MAX_ROWS = 1000  # history rows considered when folding vulnerabilities
_FINGERPRINT_RE = re.compile(r"[0-9a-f]{16}")
_URL_RE = re.compile(r"https?://[^\s'\"\\;|&)`]+")  # stop at shell punctuation
_ID_SEGMENT_RE = re.compile(r"\d+|[0-9a-fA-F]{8,}")
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]

_triage_lock = threading.Lock()


class InvalidTriage(ValueError):
    """Raised for an unknown triage status, a malformed fingerprint or an oversized note."""


# --- fingerprint ---------------------------------------------------------------


def origin_of(url: str | None) -> str:
    """`scheme://host:port`, with every loopback spelling folded to `localhost` so
    `127.0.0.1:3000` and `localhost:3000` are the same app."""
    parts = urlsplit((url or "").strip())
    host = (parts.hostname or "").lower()
    if not host or not parts.scheme:
        return ""
    if _is_loopback_host(host):
        host = "localhost"
    try:
        port = parts.port
    except ValueError:
        port = None
    port = port or {"http": 80, "https": 443}.get(parts.scheme)
    return f"{parts.scheme}://{host}" + (f":{port}" if port else "")


def endpoint_of(request: str | None) -> str:
    """Path of the first URL in the executed command, query dropped, numeric / hex id
    segments collapsed (`/api/Users/7` and `/api/Users/8` are one endpoint)."""
    m = _URL_RE.search(request or "")
    if not m:
        return ""
    path = urlsplit(m.group(0)).path
    segments = [":id" if _ID_SEGMENT_RE.fullmatch(s) else s for s in path.split("/") if s]
    return "/" + "/".join(segments)


def fingerprint(origin: str, kind: str, endpoint: str) -> str:
    raw = "|".join((origin, kind.strip().lower(), endpoint))
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


# --- triage state ----------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def load_triage(runs_root: Path) -> dict[str, dict[str, Any]]:
    try:
        data = json.loads((runs_root / TRIAGE_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        fp: {"status": e["status"], "note": str(e.get("note") or ""),
             "updated_at": e.get("updated_at")}
        for fp, e in data.items()
        if isinstance(e, dict) and e.get("status") in TRIAGE_STATUSES
        and _FINGERPRINT_RE.fullmatch(str(fp))
    }


def set_triage(runs_root: Path, fp: str, status: str, note: str = "") -> dict[str, Any]:
    """Record the user's decision on one vulnerability. Setting it back to `open` with
    no note just forgets the entry. Unlike the audit log this is NOT best-effort: if
    the decision cannot be saved the caller must hear about it."""
    if not _FINGERPRINT_RE.fullmatch(fp or ""):
        raise InvalidTriage(f"invalid vulnerability id {fp!r}")
    if status not in TRIAGE_STATUSES:
        raise InvalidTriage(f"unknown status {status!r}; valid: {', '.join(TRIAGE_STATUSES)}")
    note = (note or "").strip()
    if len(note) > _MAX_NOTE:
        raise InvalidTriage(f"note is longer than {_MAX_NOTE} characters")
    entry = {"status": status, "note": note, "updated_at": _now_iso()}
    with _triage_lock:
        data = load_triage(runs_root)
        if status == "open" and not note:
            data.pop(fp, None)
        else:
            data[fp] = entry
        runs_root.mkdir(parents=True, exist_ok=True)
        tmp = runs_root / (TRIAGE_FILE + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, runs_root / TRIAGE_FILE)  # atomic: a crash never leaves half a file
    return entry


# --- folding scans into vulnerabilities ---------------------------------------------


def _sev_rank(value: Any) -> int:
    try:
        return Severity(value).rank
    except ValueError:
        return 0


def _report_for(runs_root: Path, run_id: str) -> dict[str, Any] | None:
    """The cached report, else a rebuild from summary.json + traces. The rebuild uses the
    offline heuristic labeler on purpose: folding every scan must never call the LLM (cost,
    latency, and wording that could differ from what the history page shows)."""
    cached = load_cached_report(runs_root, run_id)
    if cached is not None:
        return cached
    try:
        rr = ReplayEngine(runs_root=runs_root).load(run_id)
        return build_report(rr, HeuristicLabeler()).model_dump(mode="json")
    except (OSError, ValueError, KeyError, TypeError):
        return None  # one unreadable run must not blank the whole page


def collect_vulns(
    runs_root: Path,
    live_status: Mapping[str, str] | None = None,
    rows: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Deduplicated vulnerabilities across all scans, worst first.

    `rows` (newest first, as `list_history` returns) may be passed in by a caller that
    already has them.
    """
    if rows is None:
        rows = list_history(runs_root, live_status, limit=_MAX_ROWS)
    triage = load_triage(runs_root)

    scans: list[dict[str, Any]] = []   # one per report, for the "not seen since" hint
    vulns: dict[str, dict[str, Any]] = {}
    for row in rows:                    # newest first → first sight of a vuln is its latest
        if not row.get("has_report"):
            continue
        report = _report_for(runs_root, row["run_id"])
        if report is None:
            continue
        default_origin = origin_of(row.get("target") or next(iter(report.get("targets") or []), ""))
        seen: set[str] = set()
        for f in report.get("findings") or []:
            label = f.get("label") or {}
            origin = origin_of(f.get("target")) or default_origin
            kind = label.get("cwe") or label.get("vuln_class") or "observation"
            endpoint = endpoint_of(f.get("request"))
            fp = fingerprint(origin, kind, endpoint)
            seen.add(fp)
            severity = label.get("severity") or "info"
            v = vulns.get(fp)
            if v is None:
                v = vulns[fp] = {
                    "id": fp, "target": origin, "endpoint": endpoint,
                    "occurrences": 0, "scans": [], "first_seen": None, "last_seen": None,
                    "last_scan_type": row.get("scan_type"), "last_run": row["run_id"],
                    "severity": severity, "_rank": -1, "projects": [],
                }
            if row.get("project") and row["project"] not in v["projects"]:
                v["projects"].append(row["project"])
            if row["run_id"] not in v["scans"]:
                v["scans"].append(row["run_id"])
                v["occurrences"] += 1
            created = row.get("created_at")
            if created and (v["first_seen"] is None or created < v["first_seen"]):
                v["first_seen"] = created
            if created and (v["last_seen"] is None or created > v["last_seen"]):
                v["last_seen"] = created
            # Describe the vuln by its most severe sighting; the newest wins a tie.
            if _sev_rank(severity) > v["_rank"]:
                v.update(
                    _rank=_sev_rank(severity), severity=severity,
                    vuln_class=label.get("vuln_class") or "Observation",
                    cwe=label.get("cwe"), owasp=label.get("owasp"),
                    explanation=label.get("explanation") or "",
                    rationale=label.get("rationale") or [],
                    agent_note=f.get("agent_note"),
                    remediation=label.get("remediation") or "",
                    confidence=label.get("confidence"),
                    labeled_by=label.get("labeled_by"),
                    request=f.get("request"),
                    response=(f.get("response") or "")[:1400],
                )
        scans.append({
            "origin": default_origin, "scan_type": row.get("scan_type"),
            "created_at": row.get("created_at") or "",
            # A failed/errored run says nothing about what is *absent* — inconclusive.
            "conclusive": row.get("status") == "completed", "fingerprints": seen,
        })

    out = []
    for v in vulns.values():
        v.pop("_rank")
        t = triage.get(v["id"], {})
        v["triage"] = t.get("status", "open")
        v["triage_note"] = t.get("note", "")
        v["triage_updated_at"] = t.get("updated_at")
        # Marked fixed, then seen again by a later scan → it came back.
        v["regressed"] = bool(
            v["triage"] == "fixed" and t.get("updated_at") and v["last_seen"]
            and v["last_seen"] > t["updated_at"]
        )
        # Later conclusive scans of the same target + scan type that did NOT find it.
        v["clean_scans_since"] = sum(
            1 for s in scans
            if s["conclusive"] and s["origin"] == v["target"]
            and s["scan_type"] == v["last_scan_type"]
            and s["created_at"] > (v["last_seen"] or "")
            and v["id"] not in s["fingerprints"]
        )
        out.append(v)
    # Two stable passes: newest sighting first, then worst severity first.
    out.sort(key=lambda v: v["last_seen"] or "", reverse=True)
    out.sort(key=lambda v: _sev_rank(v["severity"]), reverse=True)
    return out


# --- dashboard ----------------------------------------------------------------------


def build_overview(rows: list[dict[str, Any]], vulns: list[dict[str, Any]]) -> dict[str, Any]:
    """Totals for the dashboard. Pure: takes history rows and folded vulnerabilities."""
    durations = [r["wall_duration_s"] for r in rows if r.get("has_report") and r.get("wall_duration_s")]
    active = [v for v in vulns if v["triage"] in _ACTIVE_TRIAGE]
    by_sev = Counter(v["severity"] for v in active)
    owasp = Counter(
        v.get("owasp") or "Chưa ánh xạ OWASP" for v in active if v["severity"] != "info"
    )

    targets: dict[str, dict[str, Any]] = {}
    for r in rows:
        origin = origin_of(r.get("target"))
        if not origin:
            continue
        t = targets.setdefault(origin, {"target": origin, "scans": 0, "last_scan": None,
                                        "open_vulns": 0, "worst": None})
        t["scans"] += 1
        if r.get("created_at") and (t["last_scan"] is None or r["created_at"] > t["last_scan"]):
            t["last_scan"] = r["created_at"]
    for v in active:
        t = targets.get(v["target"])
        if t is None or v["severity"] == "info":
            continue
        t["open_vulns"] += 1
        if t["worst"] is None or _sev_rank(v["severity"]) > _sev_rank(t["worst"]):
            t["worst"] = v["severity"]

    return {
        "scans": {
            "total": len(rows),
            "by_status": dict(Counter(r.get("status") or "unknown" for r in rows)),
            "cost_usd": round(sum(float(r.get("cost_usd") or 0) for r in rows), 4),
            "avg_duration_s": round(sum(durations) / len(durations), 1) if durations else 0,
        },
        "vulns": {
            "total": len(vulns),
            "active": len(active),
            "open_actionable": sum(1 for v in active if v["severity"] != "info"),
            "by_severity": {s: by_sev.get(s, 0) for s in _SEV_ORDER},
            "by_triage": {s: sum(1 for v in vulns if v["triage"] == s) for s in TRIAGE_STATUSES},
            "regressed": sum(1 for v in vulns if v["regressed"]),
        },
        "owasp": [{"label": k, "count": n} for k, n in owasp.most_common()],
        "targets": sorted(
            targets.values(),
            key=lambda t: (_sev_rank(t["worst"]) if t["worst"] else -1, t["open_vulns"]),
            reverse=True,
        ),
    }
