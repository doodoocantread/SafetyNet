"""Cross-scan vulnerabilities, triage and dashboard totals (insights.py + endpoints)."""

import json

import pytest
from fastapi import HTTPException

from safetywebbing import api
from safetywebbing.audit import record_scan
from safetywebbing.history import save_report
from safetywebbing.insights import (
    InvalidTriage,
    build_overview,
    collect_vulns,
    endpoint_of,
    fingerprint,
    load_triage,
    origin_of,
    set_triage,
)

LOGIN = "curl -s -X POST http://127.0.0.1:3000/rest/user/login -d '{\"email\":\"a\"}'"


def _finding(*, request=LOGIN, cwe="CWE-89", vuln_class="SQL Injection", severity="critical",
             owasp="A03:2021 Injection", target="http://localhost:3000/"):
    return {"id": "f", "target": target, "request": request, "response": "HTTP/1.1 200",
            "label": {"vuln_class": vuln_class, "severity": severity, "cwe": cwe, "owasp": owasp,
                      "explanation": "e", "remediation": "r", "confidence": "high",
                      "labeled_by": "heuristic"}}


def _scan(root, run_id, ts, findings, *, scan_type="sqli", status="completed",
          target="http://localhost:3000/"):
    """A finished scan: audit lines + cached report (+ summary.json so has_report is true)."""
    base = dict(run_id=run_id, target=target, goal="g", scan_type=scan_type, mode="docker",
                model=None)
    root.mkdir(parents=True, exist_ok=True)
    with (root / "audit.log").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": ts, "event": "scan_requested", **base}) + "\n")
    record_scan(root, event="scan_done", status=status, **base)
    (root / run_id).mkdir(exist_ok=True)
    (root / run_id / "summary.json").write_text(
        json.dumps({"status": status, "cost_usd": 0.25, "wall_duration_s": 10}), encoding="utf-8")
    save_report(root, run_id, {"run_id": run_id, "status": status, "targets": [target],
                               "findings": findings})


# --- fingerprint helpers ---------------------------------------------------------


def test_loopback_spellings_share_an_origin():
    assert origin_of("http://127.0.0.1:3000/x") == origin_of("http://localhost:3000") \
        == "http://localhost:3000"
    assert origin_of("http://localhost/") == "http://localhost:80"
    assert origin_of("not a url") == ""
    assert origin_of(None) == ""


def test_endpoint_drops_query_and_collapses_ids():
    assert endpoint_of("curl http://localhost:3000/api/Users/7?x=1") == "/api/Users/:id"
    assert endpoint_of("curl 'http://localhost:3000/api/Users/8'") == "/api/Users/:id"
    assert endpoint_of("curl http://localhost:3000/") == "/"
    assert endpoint_of("curl http://localhost:3000/_next/chunks; echo done") == "/_next/chunks"
    assert endpoint_of("curl http://localhost:3000/a|head") == "/a"
    assert endpoint_of("echo nothing") == ""
    assert endpoint_of(None) == ""


def test_fingerprint_is_stable_and_case_insensitive_on_kind():
    a = fingerprint("http://localhost:3000", "CWE-89", "/x")
    assert a == fingerprint("http://localhost:3000", "cwe-89", "/x")
    assert a != fingerprint("http://localhost:3000", "CWE-79", "/x")
    assert len(a) == 16


# --- folding ---------------------------------------------------------------------


def test_same_bug_across_scans_is_one_vuln_seen_twice(tmp_path):
    _scan(tmp_path, "live-a", "2026-01-01T00:00:00+00:00", [_finding()])
    _scan(tmp_path, "live-b", "2026-01-02T00:00:00+00:00",
          [_finding(request=LOGIN.replace("127.0.0.1", "localhost"))])
    (v,) = collect_vulns(tmp_path)
    assert (v["occurrences"], v["scans"]) == (2, ["live-b", "live-a"])
    assert (v["first_seen"], v["last_seen"]) == ("2026-01-01T00:00:00+00:00",
                                                 "2026-01-02T00:00:00+00:00")
    assert (v["target"], v["endpoint"]) == ("http://localhost:3000", "/rest/user/login")
    assert v["triage"] == "open"


def test_worst_first_then_newest(tmp_path):
    _scan(tmp_path, "live-a", "2026-01-01T00:00:00+00:00", [
        _finding(cwe="CWE-200", vuln_class="Info leak", severity="low", request="curl http://localhost:3000/a"),
        _finding(cwe="CWE-79", vuln_class="XSS", severity="high", request="curl http://localhost:3000/b"),
    ])
    _scan(tmp_path, "live-b", "2026-01-02T00:00:00+00:00", [
        _finding(cwe="CWE-1", vuln_class="Other", severity="low", request="curl http://localhost:3000/c"),
    ])
    assert [v["cwe"] for v in collect_vulns(tmp_path)] == ["CWE-79", "CWE-1", "CWE-200"]


def test_vuln_keeps_its_most_severe_description(tmp_path):
    _scan(tmp_path, "live-a", "2026-01-01T00:00:00+00:00", [_finding(severity="critical")])
    _scan(tmp_path, "live-b", "2026-01-02T00:00:00+00:00", [_finding(severity="medium")])
    (v,) = collect_vulns(tmp_path)
    assert v["severity"] == "critical"


def test_scan_without_report_is_ignored(tmp_path):
    record_scan(tmp_path, event="scan_requested", run_id="live-x", target="http://localhost:3000/",
                goal="g", scan_type="sqli")
    assert collect_vulns(tmp_path) == []


def test_legacy_scan_without_report_cache_is_rebuilt_offline(tmp_path):
    """No report.json (scan predates caching): rebuilt from summary + traces, heuristically."""
    import shutil
    from pathlib import Path

    sample = Path(__file__).resolve().parents[1] / "samples" / "runs" / "sqli-claude-03"
    shutil.copytree(sample, tmp_path / "live-old")
    record_scan(tmp_path, event="scan_requested", run_id="live-old",
                target="http://localhost:3000/", goal="g", scan_type="sqli")
    found = collect_vulns(tmp_path)
    assert found, "sample run should yield at least one vulnerability"
    assert {v["labeled_by"] for v in found} == {"heuristic"}


def test_unreadable_scan_does_not_blank_the_list(tmp_path):
    _scan(tmp_path, "live-ok", "2026-01-02T00:00:00+00:00", [_finding()])
    record_scan(tmp_path, event="scan_requested", run_id="live-bad",
                target="http://localhost:3000/", goal="g", scan_type="sqli")
    (tmp_path / "live-bad").mkdir()
    (tmp_path / "live-bad" / "summary.json").write_text("{not json", encoding="utf-8")
    assert len(collect_vulns(tmp_path)) == 1


def test_clean_scans_since_counts_only_conclusive_same_scope_scans(tmp_path):
    _scan(tmp_path, "live-1", "2026-01-01T00:00:00+00:00", [_finding()])
    _scan(tmp_path, "live-2", "2026-01-02T00:00:00+00:00", [])                       # clean
    _scan(tmp_path, "live-3", "2026-01-03T00:00:00+00:00", [], status="failed")      # inconclusive
    _scan(tmp_path, "live-4", "2026-01-04T00:00:00+00:00", [], scan_type="xss")      # other scope
    _scan(tmp_path, "live-5", "2026-01-05T00:00:00+00:00", [], target="http://localhost:9999/")
    (v,) = collect_vulns(tmp_path)
    assert v["clean_scans_since"] == 1


# --- triage ----------------------------------------------------------------------


def test_triage_roundtrip_and_reset(tmp_path):
    _scan(tmp_path, "live-a", "2026-01-01T00:00:00+00:00", [_finding()])
    (v,) = collect_vulns(tmp_path)
    set_triage(tmp_path, v["id"], "fixing", " dang sua ")
    (v,) = collect_vulns(tmp_path)
    assert (v["triage"], v["triage_note"]) == ("fixing", "dang sua")
    set_triage(tmp_path, v["id"], "open")
    assert load_triage(tmp_path) == {}
    assert collect_vulns(tmp_path)[0]["triage"] == "open"


def test_fixed_then_seen_again_is_flagged_as_regression(tmp_path):
    _scan(tmp_path, "live-a", "2026-01-01T00:00:00+00:00", [_finding()])
    (v,) = collect_vulns(tmp_path)
    set_triage(tmp_path, v["id"], "fixed")
    assert collect_vulns(tmp_path)[0]["regressed"] is False
    _scan(tmp_path, "live-b", "2999-01-01T00:00:00+00:00", [_finding()])  # seen after the fix
    assert collect_vulns(tmp_path)[0]["regressed"] is True


@pytest.mark.parametrize("fp,status,note", [
    ("../../x", "fixed", ""),
    ("0123456789abcdef", "wontfix", ""),
    ("0123456789abcdef", "fixed", "x" * 501),
])
def test_set_triage_rejects_bad_input(tmp_path, fp, status, note):
    with pytest.raises(InvalidTriage):
        set_triage(tmp_path, fp, status, note)
    assert not (tmp_path / "triage.json").exists()


def test_load_triage_ignores_garbage(tmp_path):
    (tmp_path / "triage.json").write_text(json.dumps({
        "0123456789abcdef": {"status": "fixed", "note": "ok"},
        "0123456789abcde0": {"status": "bogus"},
        "../escape": {"status": "fixed"},
        "0123456789abcde1": "nope",
    }), encoding="utf-8")
    assert list(load_triage(tmp_path)) == ["0123456789abcdef"]
    (tmp_path / "triage.json").write_text("{torn", encoding="utf-8")
    assert load_triage(tmp_path) == {}


# --- overview --------------------------------------------------------------------


def test_overview_totals(tmp_path):
    from safetywebbing.history import list_history

    _scan(tmp_path, "live-a", "2026-01-01T00:00:00+00:00", [
        _finding(),
        _finding(cwe="CWE-79", vuln_class="XSS", severity="high", owasp=None,
                 request="curl http://localhost:3000/s"),
        _finding(cwe="CWE-1", vuln_class="Noise", severity="info", request="curl http://localhost:3000/n"),
    ])
    _scan(tmp_path, "live-b", "2026-01-02T00:00:00+00:00", [], status="failed")
    rows = list_history(tmp_path)
    vulns = collect_vulns(tmp_path, rows=rows)
    set_triage(tmp_path, next(v["id"] for v in vulns if v["cwe"] == "CWE-79"), "false_positive")
    ov = build_overview(rows, collect_vulns(tmp_path, rows=rows))

    assert ov["scans"]["total"] == 2
    assert ov["scans"]["by_status"] == {"completed": 1, "failed": 1}
    assert ov["scans"]["cost_usd"] == 0.5
    assert ov["vulns"]["total"] == 3 and ov["vulns"]["active"] == 2
    assert ov["vulns"]["open_actionable"] == 1            # info is not actionable, fp is closed
    assert ov["vulns"]["by_severity"]["critical"] == 1 and ov["vulns"]["by_severity"]["high"] == 0
    assert ov["vulns"]["by_triage"]["false_positive"] == 1
    assert ov["owasp"] == [{"label": "A03:2021 Injection", "count": 1}]
    (t,) = ov["targets"]
    assert (t["target"], t["scans"], t["open_vulns"], t["worst"]) == (
        "http://localhost:3000", 2, 1, "critical")


def test_overview_of_nothing(tmp_path):
    ov = build_overview([], [])
    assert ov["scans"]["total"] == 0 and ov["vulns"]["total"] == 0
    assert ov["owasp"] == [] and ov["targets"] == []


# --- endpoints -------------------------------------------------------------------


@pytest.fixture
def runs(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "_LIVE_RUNS", tmp_path)
    return tmp_path


def test_endpoints_list_overview_and_triage(runs):
    _scan(runs, "live-a", "2026-01-01T00:00:00+00:00", [_finding()])
    (v,) = api.vulns()
    assert api.overview()["vulns"]["open_actionable"] == 1
    out = api.triage_vuln(v["id"], api.TriageRequest(status="fixed", note="patched"))
    assert out["status"] == "fixed"
    assert api.vulns()[0]["triage"] == "fixed"
    assert api.overview()["vulns"]["open_actionable"] == 0


def test_triage_endpoint_rejects_unknown_vuln_and_bad_status(runs):
    _scan(runs, "live-a", "2026-01-01T00:00:00+00:00", [_finding()])
    with pytest.raises(HTTPException) as e404:
        api.triage_vuln("0123456789abcdef", api.TriageRequest(status="fixed"))
    assert e404.value.status_code == 404
    (v,) = api.vulns()
    with pytest.raises(HTTPException) as e400:
        api.triage_vuln(v["id"], api.TriageRequest(status="wontfix"))
    assert e400.value.status_code == 400
    assert not (runs / "triage.json").exists()
