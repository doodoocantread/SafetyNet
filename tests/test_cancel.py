"""Tests for cancelling a running/queued scan (POST /api/scan/{job_id}/cancel).

No Docker/agent needed: `LocalAgentEngine.run` is monkeypatched to hang until
cancelled, the same pattern test_direct_mode.py uses for mode="direct".
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException

from safetywebbing import api
from safetywebbing.engines.local import LocalAgentEngine


async def test_cancel_unknown_job_404():
    with pytest.raises(HTTPException) as exc:
        await api.cancel_scan("does-not-exist")
    assert exc.value.status_code == 404


async def test_cancel_already_finished_job_is_a_noop():
    api._jobs["finished-job"] = {"status": "done", "task": None}
    try:
        out = await api.cancel_scan("finished-job")
        assert out == {"status": "done", "cancelled": False}
    finally:
        api._jobs.clear()


async def test_cancel_running_job_kills_the_engine_and_settles_as_cancelled(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFETYWEBBING_ALLOW_DIRECT", "1")
    monkeypatch.setattr(api, "_LIVE_RUNS", tmp_path / "runs")
    monkeypatch.setattr(api.local_engine, "agent_cmd", ["agent"])

    started = asyncio.Event()
    engine_saw_cancel = asyncio.Event()

    async def fake_run(self, **_):
        started.set()
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            # Mirrors what the real engines do: clean up the real process/
            # container, then let the cancellation keep propagating.
            engine_saw_cancel.set()
            raise
        raise AssertionError("should have been cancelled, not run to completion")

    monkeypatch.setattr(LocalAgentEngine, "run", fake_run)

    out = await api.start_scan(
        api.ScanRequest(target="http://127.0.0.1:3000", scan_type="sqli", mode="direct")
    )
    job_id = out["job_id"]
    try:
        await asyncio.wait_for(started.wait(), timeout=2)
        assert api._jobs[job_id]["status"] == "running"

        result = await api.cancel_scan(job_id)
        assert result == {"status": "cancelling", "cancelled": True}

        await asyncio.wait_for(engine_saw_cancel.wait(), timeout=2)
        for _ in range(100):  # let _run_live_job's outer handler settle the job
            if api._jobs[job_id]["status"] == "cancelled":
                break
            await asyncio.sleep(0.02)
        assert api._jobs[job_id]["status"] == "cancelled"
        assert api._jobs[job_id]["error"] == "Đã hủy theo yêu cầu người dùng"

        # The user must see *why* it stopped in the live terminal too.
        lines = [line["text"] for line in api._jobs[job_id]["log"].lines]
        assert any("hủy" in text.lower() for text in lines)

        # A second cancel on an already-settled job is a harmless no-op.
        again = await api.cancel_scan(job_id)
        assert again == {"status": "cancelled", "cancelled": False}
    finally:
        api._jobs.clear()


async def test_cancel_while_still_queued_never_runs_the_engine(tmp_path, monkeypatch):
    """Cancelling before the concurrency semaphore is even acquired must not
    leave the job stuck — and must not let the engine start afterwards."""
    monkeypatch.setenv("SAFETYWEBBING_ALLOW_DIRECT", "1")
    monkeypatch.setattr(api, "_LIVE_RUNS", tmp_path / "runs")
    monkeypatch.setattr(api.local_engine, "agent_cmd", ["agent"])

    ran = False

    async def fake_run(self, **_):
        nonlocal ran
        ran = True
        await asyncio.sleep(60)

    monkeypatch.setattr(LocalAgentEngine, "run", fake_run)

    # Saturate the concurrency slots so the next job stays "queued".
    for _ in range(api._MAX_CONCURRENT_SCANS):
        await api._scan_sema.acquire()
    try:
        out = await api.start_scan(
            api.ScanRequest(target="http://127.0.0.1:3000", scan_type="sqli", mode="direct")
        )
        job_id = out["job_id"]
        await asyncio.sleep(0.05)
        assert api._jobs[job_id]["status"] == "queued"

        result = await api.cancel_scan(job_id)
        assert result["cancelled"] is True

        for _ in range(100):
            if api._jobs[job_id]["status"] == "cancelled":
                break
            await asyncio.sleep(0.02)
        assert api._jobs[job_id]["status"] == "cancelled"
        assert ran is False  # never got the semaphore, so the engine never ran
    finally:
        for _ in range(api._MAX_CONCURRENT_SCANS):
            api._scan_sema.release()
        api._jobs.clear()
