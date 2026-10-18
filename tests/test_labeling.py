"""HeuristicLabeler rules — the offline NARRATIVE layer (ARCHITECTURE.md §6).

Pins the signals a key-less run depends on. Two shapes are covered:

  - the curated raw-HTTP sample (`samples/runs/sqli-claude-03`), where the
    observation statement is the full `HTTP/1.1 ...` response, and
  - the COMPACT shape a weaker agent (e.g. Haiku) reports instead — `status=200
    len=...`, a leaked `SQLITE_ERROR`, or a TRUE/FALSE boolean probe in one
    statement. Before these rules those compact findings all fell through to the
    INFO "needs review" default even when the agent had, in fact, found SQLi.
"""

from __future__ import annotations

import json
from pathlib import Path

from safetynet.adapter import adapt
from safetynet.labeling import HeuristicLabeler, _http_status, label_findings
from safetynet.models import Finding, Severity

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "runs" / "sqli-claude-03"


# --- status parsing: raw line AND the compact `status=NNN` form --------------

def test_http_status_parses_raw_line():
    assert _http_status("HTTP/1.1 401 Unauthorized\r\n\r\nInvalid email or password.") == 401


def test_http_status_parses_compact_form():
    assert _http_status("q=[apple' OR 1=1 OR '] status=200 len=26978") == 200
    assert _http_status("== category=banh%27\nstatus=500 length=111576") == 500


def test_http_status_none_when_absent():
    assert _http_status("href=\"/san-pham?category=banh\"") is None


# --- rule: database error string in the response → error-based SQLi ----------
# Shape taken from runs/live-c2d455d4a989 obs 1 (Juice Shop leaks SQLITE_ERROR).

def test_sql_error_string_flagged_error_based():
    f = Finding(
        id="o1",
        task_kind="test",
        request="curl -s --max-time 10 \"http://localhost:3000/rest/products/search?q=apple'\"",
        response="SQLITE_ERROR: near \"'%'\": syntax error",
    )
    lbl = HeuristicLabeler().label(f)
    assert lbl.cwe == "CWE-89"
    assert lbl.severity == Severity.medium
    assert "SQL Injection" in lbl.vuln_class
    assert any("lỗi cơ sở dữ liệu" in r for r in lbl.rationale)


# --- rule: boolean-based blind SQLi (TRUE vs FALSE differential) -------------
# Shape taken from runs/live-c2d455d4a989 obs 3 (verify task).

def test_boolean_differential_flagged_high():
    f = Finding(
        id="o3",
        task_kind="verify",
        request="for q in \"apple' OR 1=1 OR '\" \"apple' AND '1'='2\"; do curl ...; done",
        response=(
            "q=[apple' AND '1'='2] status=200 len=30\r\nresult_count=0\n"
            "q=[apple' OR 1=1 OR '] status=200 len=26978\r\nresult_count=46"
        ),
    )
    lbl = HeuristicLabeler().label(f)
    assert lbl.cwe == "CWE-89"
    assert lbl.severity == Severity.high
    assert "boolean" in lbl.vuln_class.lower()
    assert lbl.confidence == "high"
    assert any("boolean-based" in r for r in lbl.rationale)


# --- no false positives: a benign probe must stay informational -------------

def test_benign_probe_not_escalated():
    # `--max-time` matches the loose `--` payload pattern and status is 200, but
    # there is no token, no SQL error and no TRUE/FALSE differential → not a vuln.
    f = Finding(
        id="b",
        request="curl -s --max-time 15 'http://127.0.0.1:3000/rest/products/search?q=apple'",
        response="q=[apple] status=200 len=5000",
    )
    lbl = HeuristicLabeler().label(f)
    assert lbl.severity == Severity.info
    assert lbl.cwe is None


def test_compact_401_is_baseline():
    lbl = HeuristicLabeler().label(Finding(id="x", response="status=401 Invalid email or password."))
    assert lbl.severity == Severity.info
    assert lbl.vuln_class == "Baseline / expected rejection"


# --- golden: the raw-HTTP sample must still produce the critical finding ------

def test_sample_run_still_flags_auth_bypass_critical():
    summary = json.loads((SAMPLE / "summary.json").read_text(encoding="utf-8"))
    labeled = label_findings(adapt(summary, SAMPLE / "traces"), HeuristicLabeler())
    top = labeled[0].label  # label_findings sorts most-severe first
    assert top.severity == Severity.critical
    assert top.cwe == "CWE-89"
    assert top.vuln_class == "SQL Injection (authentication bypass)"
    # the 401 response in the same run is a baseline, not a vuln
    assert any(
        f.label.severity == Severity.info and f.label.cwe is None for f in labeled
    )
