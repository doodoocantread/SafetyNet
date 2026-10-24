"""Scan history: folds runs/audit.log + summary.json into one row per run."""

import json

import pytest

from safetywebbing import api
from safetywebbing.audit import record_scan
from safetywebbing.config import InvalidRunId
from safetywebbing.history import (
    get_history_item,
    list_history,
    load_cached_report,
    save_report,
)


def _scan(root, run_id, *, outcome=None, **extra):
    base = dict(run_id=run_id, target="http://localhost:3000/", goal="g",
                scan_type="sqli", mode="docker", model="claude-haiku-5-5")
    record_scan(root, event="scan_requested", timeout_s=600.0, **base, **extra)
    if outcome == "done":
        record_scan(root, event="scan_done", status="completed", **base, **extra)
    elif outcome == "error":
        record_scan(root, event="scan_error", error="boom", **base, **extra)


def _summary(root, run_id, **fields):
    d = root / run_id
    d.mkdir(parents=True, exist_ok=True)
    data = {"status": "completed", "cost_usd": 0.5, "wall_duration_s": 12,
            "observations": [{}, {}], **fields}
    (d / "summary.json").write_text(json.dumps(data), encoding="utf-8")


def test_empty_when_no_audit_log(tmp_path):
    assert list_history(tmp_path) == []


def test_row_carries_scan_settings(tmp_path):
    _scan(tmp_path, "live-a", outcome="done", )
    _summary(tmp_path, "live-a")
    (row,) = list_history(tmp_path)
    assert row["target"] == "http://localhost:3000/"
    assert row["scan_type"] == "sqli"
    assert row["mode"] == "docker"
    assert row["model"] == "claude-haiku-5-5"
    assert row["timeout_s"] == 600.0
    assert (row["status"], row["observations"], row["cost_usd"]) == ("completed", 2, 0.5)
    assert row["has_report"] is True


def test_newest_first(tmp_path):
    for rid, ts in (("live-old", "2026-01-01T00:00:00+00:00"),
                    ("live-new", "2026-02-01T00:00:00+00:00")):
        (tmp_path / "audit.log").open("a", encoding="utf-8").write(json.dumps(
            {"ts": ts, "event": "scan_requested", "run_id": rid, "target": "t",
             "goal": "g", "scan_type": "xss"}) + "\n")
    assert [r["run_id"] for r in list_history(tmp_path)] == ["live-new", "live-old"]


def test_errored_scan_has_no_report_but_keeps_error(tmp_path):
    _scan(tmp_path, "live-e", outcome="error")
    (row,) = list_history(tmp_path)
    assert (row["status"], row["error"], row["has_report"]) == ("error", "boom", False)


def test_unfinished_scan_is_interrupted_unless_this_process_runs_it(tmp_path):
    _scan(tmp_path, "live-r")
    assert list_history(tmp_path)[0]["status"] == "interrupted"
    assert list_history(tmp_path, {"live-r": "running"})[0]["status"] == "running"


def test_scan_without_audit_request_line_is_still_listed_from_terminal_event(tmp_path):
    base = dict(run_id="live-x", target="t", goal="g", scan_type="auth")
    record_scan(tmp_path, event="scan_done", status="completed", **base)
    (row,) = list_history(tmp_path)
    assert (row["scan_type"], row["status"]) == ("auth", "completed")


def test_garbled_and_hostile_audit_lines_are_skipped(tmp_path):
    _scan(tmp_path, "live-ok", outcome="done")
    with (tmp_path / "audit.log").open("a", encoding="utf-8") as fh:
        fh.write("{not json\n")
        fh.write(json.dumps({"event": "scan_requested", "run_id": "../../etc"}) + "\n")
        fh.write(json.dumps({"event": "scan_requested", "run_id": 7}) + "\n")
    assert [r["run_id"] for r in list_history(tmp_path)] == ["live-ok"]


def test_limit(tmp_path):
    for i in range(5):
        _scan(tmp_path, f"live-{i}")
    assert len(list_history(tmp_path, limit=3)) == 3


def test_get_item(tmp_path):
    _scan(tmp_path, "live-a", outcome="done")
    assert get_history_item(tmp_path, "live-a")["run_id"] == "live-a"
    assert get_history_item(tmp_path, "live-missing") is None
    with pytest.raises(InvalidRunId):
        get_history_item(tmp_path, "../x")


def test_report_cache_roundtrip(tmp_path):
    (tmp_path / "live-a").mkdir()
    assert load_cached_report(tmp_path, "live-a") is None
    save_report(tmp_path, "live-a", {"run_id": "live-a", "findings": []})
    assert load_cached_report(tmp_path, "live-a") == {"run_id": "live-a", "findings": []}


def test_save_report_never_raises_if_run_dir_missing(tmp_path):
    save_report(tmp_path, "live-nope", {"a": 1})  # no directory → OSError swallowed


# --- endpoint wiring ---------------------------------------------------------


@pytest.fixture
def runs(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "_LIVE_RUNS", tmp_path)
    return tmp_path


def test_endpoint_list_and_detail_with_cached_report(runs):
    _scan(runs, "live-a", outcome="done")
    _summary(runs, "live-a")
    save_report(runs, "live-a", {"run_id": "live-a", "findings": [], "engine": "docker"})
    assert [r["run_id"] for r in api.history()] == ["live-a"]
    item = api.history_item("live-a")
    assert item["meta"]["mode"] == "docker"
    assert item["report"]["run_id"] == "live-a"


def test_endpoint_detail_for_errored_scan_has_meta_and_no_report(runs):
    _scan(runs, "live-e", outcome="error")
    item = api.history_item("live-e")
    assert item["report"] is None
    assert item["meta"]["error"] == "boom"


def test_endpoint_unknown_and_traversal(runs):
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as e404:
        api.history_item("live-nope")
    assert e404.value.status_code == 404
    with pytest.raises(HTTPException) as e400:
        api.history_item("..")
    assert e400.value.status_code == 400
