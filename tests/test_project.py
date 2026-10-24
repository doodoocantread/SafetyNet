"""Project name: validated, carried from the scan request into the history rows."""

import asyncio

import pytest
from fastapi import HTTPException

from safetywebbing import api
from safetywebbing.audit import record_scan
from safetywebbing.config import InvalidProject, validate_project
from safetywebbing.history import list_history


@pytest.mark.parametrize("raw, want", [
    (None, None), ("", None), ("   ", None),
    ("  Shop   backend ", "Shop backend"),
    ("Đồ án web\n2026", "Đồ án web 2026"),  # newlines collapse, diacritics kept
])
def test_validate_project_normalizes(raw, want):
    assert validate_project(raw) == want


@pytest.mark.parametrize("raw", ["a\x00b", "bell\x07", "x" * 61])
def test_validate_project_rejects(raw):
    with pytest.raises(InvalidProject):
        validate_project(raw)


def test_history_row_carries_project(tmp_path):
    record_scan(tmp_path, event="scan_requested", run_id="live-a", target="http://localhost:3000/",
                goal="g", scan_type="sqli", project="Shop backend")
    record_scan(tmp_path, event="scan_requested", run_id="live-b", target="http://localhost:8080/",
                goal="g", scan_type="sqli")
    rows = {r["run_id"]: r for r in list_history(tmp_path)}
    assert rows["live-a"]["project"] == "Shop backend"
    assert rows["live-b"]["project"] is None


def test_scan_endpoint_rejects_bad_project_before_spawning(monkeypatch, tmp_path):
    monkeypatch.setattr(api, "_LIVE_RUNS", tmp_path)
    req = api.ScanRequest(target="http://127.0.0.1:3000", project="x" * 61)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(api.start_scan(req))
    assert exc.value.status_code == 400 and "project" in exc.value.detail
    assert not (tmp_path / "audit.log").exists()
