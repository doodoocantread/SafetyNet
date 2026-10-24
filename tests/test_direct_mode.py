"""Tests for the opt-in `direct` (no-Docker) mode.

No Docker, LLM or real agent: a tiny stub script plays the `pentestgpt-agent` CLI by
writing the same summary.json the real one does.
"""

import json
import sys
import textwrap
import time

import pytest

from safetywebbing.config import ModeNotAllowed, direct_mode_enabled, validate_mode
from safetywebbing.engines.base import ScanFailed
from safetywebbing.engines.local import (
    AGENT_CMD_ENV,
    LocalAgentEngine,
    agent_env,
    resolve_agent_command,
)

# --- Gate: direct must be opted into by the server ---------------------------


def test_docker_mode_always_allowed(monkeypatch):
    monkeypatch.delenv("SAFETYWEBBING_ALLOW_DIRECT", raising=False)
    assert validate_mode("docker") == "docker"


def test_direct_mode_blocked_by_default(monkeypatch):
    monkeypatch.delenv("SAFETYWEBBING_ALLOW_DIRECT", raising=False)
    assert not direct_mode_enabled()
    with pytest.raises(ModeNotAllowed):
        validate_mode("direct")


@pytest.mark.parametrize("value", ["0", "", "no", "false"])
def test_direct_mode_blocked_for_falsey_values(monkeypatch, value):
    monkeypatch.setenv("SAFETYWEBBING_ALLOW_DIRECT", value)
    with pytest.raises(ModeNotAllowed):
        validate_mode("direct")


@pytest.mark.parametrize("value", ["1", "true", "YES"])
def test_direct_mode_allowed_when_opted_in(monkeypatch, value):
    monkeypatch.setenv("SAFETYWEBBING_ALLOW_DIRECT", value)
    assert validate_mode("direct") == "direct"


@pytest.mark.parametrize("mode", ["", "DIRECT", "host", "docker; rm -rf /"])
def test_unknown_mode_rejected(monkeypatch, mode):
    monkeypatch.setenv("SAFETYWEBBING_ALLOW_DIRECT", "1")
    with pytest.raises(ModeNotAllowed):
        validate_mode(mode)


# --- Command shape ------------------------------------------------------------


def test_build_command_keeps_loopback_target(tmp_path):
    eng = LocalAgentEngine(runs_root=tmp_path / "runs", agent_cmd=["pentestgpt-agent"])
    cmd = eng.build_command(target="http://127.0.0.1:3000", goal="g", run_id="r1")
    assert cmd[0] == "pentestgpt-agent"
    assert cmd[cmd.index("--target") + 1] == "http://127.0.0.1:3000"  # no docker rewrite
    assert cmd[cmd.index("--backend") + 1] == "claude"
    assert cmd[cmd.index("--run-id") + 1] == "r1"
    # workspaces live beside runs/, never inside it
    ws = cmd[cmd.index("--workspace-root") + 1]
    assert ws.endswith("agent-workspaces") and "runs" not in ws.replace(str(tmp_path), "")


def test_build_command_without_agent_raises(tmp_path, monkeypatch):
    monkeypatch.delenv(AGENT_CMD_ENV, raising=False)
    monkeypatch.setattr("safetywebbing.engines.local.shutil.which", lambda _: None)
    eng = LocalAgentEngine(runs_root=tmp_path / "runs", search_dirs=(tmp_path,))
    assert eng.command() is None
    with pytest.raises(ScanFailed, match="agent CLI not found"):
        eng.build_command(target="http://127.0.0.1:3000", goal="g", run_id="r1")


def test_resolve_prefers_env_override():
    got = resolve_agent_command(env={AGENT_CMD_ENV: "uv run --project agent_image pentestgpt-agent"})
    assert got == ["uv", "run", "--project", "agent_image", "pentestgpt-agent"]


def test_resolve_finds_dedicated_venv(tmp_path, monkeypatch):
    import os

    bin_dir, exe = ("Scripts", "pentestgpt-agent.exe") if os.name == "nt" else ("bin", "pentestgpt-agent")
    exe_path = tmp_path / ".agent-venv" / bin_dir / exe
    exe_path.parent.mkdir(parents=True)
    exe_path.write_text("", encoding="utf-8")
    assert resolve_agent_command((tmp_path,), env={}) == [str(exe_path)]


# --- Environment handed to the agent -------------------------------------------


def test_agent_env_scrubs_labeler_api_key():
    env = agent_env({"ANTHROPIC_API_KEY": "sk-secret", "PATH": "/bin"})
    assert "ANTHROPIC_API_KEY" not in env  # parity with the Docker agent
    assert env["PATH"] == "/bin"
    assert env["DISABLE_AUTOUPDATER"] == "1"


# --- End to end with a stub agent -----------------------------------------------

_STUB = textwrap.dedent(
    """
    import argparse, json, pathlib, sys, time
    p = argparse.ArgumentParser()
    for a in ("--goal", "--target", "--backend", "--run-id", "--runs-root",
              "--workspace-root", "--max-decisions", "--model"):
        p.add_argument(a)
    a = p.parse_args()
    if a.goal == "HANG":
        time.sleep(60)
    run = pathlib.Path(a.runs_root) / a.run_id
    (run / "traces").mkdir(parents=True)
    (run / "summary.json").write_text(json.dumps({
        "run_id": a.run_id, "goal": a.goal, "targets": [a.target], "status": "completed",
        "tasks": [], "observations": [],
    }), encoding="utf-8")
    print("stub done")
    """
)


def _engine(tmp_path, **kw):
    stub = tmp_path / "stub_agent.py"
    stub.write_text(_STUB, encoding="utf-8")
    return LocalAgentEngine(
        runs_root=tmp_path / "runs", agent_cmd=[sys.executable, str(stub)], **kw
    )


async def test_run_reads_summary_written_by_agent(tmp_path):
    result = await _engine(tmp_path).run(target="http://127.0.0.1:3000", goal="g", run_id="r1")
    assert result.engine == "direct"
    assert result.completed
    assert result.summary["targets"] == ["http://127.0.0.1:3000"]
    assert result.traces_dir == tmp_path / "runs" / "r1" / "traces"
    assert "stub done" in result.raw_stdout


async def test_run_without_summary_is_scan_failed(tmp_path):
    eng = _engine(tmp_path)
    eng.agent_cmd = [sys.executable, "-c", "print('crashed before writing anything')"]
    with pytest.raises(ScanFailed, match="no summary.json"):
        await eng.run(target="http://127.0.0.1:3000", goal="g", run_id="r2")


async def test_timeout_kills_agent_and_raises(tmp_path):
    eng = _engine(tmp_path, timeout_s=1.0)
    started = time.monotonic()
    with pytest.raises(ScanFailed, match="timed out"):
        await eng.run(target="http://127.0.0.1:3000", goal="HANG", run_id="r3")
    assert time.monotonic() - started < 15  # did not wait for the 60s sleep


# --- API wiring ---------------------------------------------------------------


def test_modes_endpoint_reports_direct_unavailable_by_default(monkeypatch):
    from safetywebbing import api

    monkeypatch.delenv("SAFETYWEBBING_ALLOW_DIRECT", raising=False)
    by_key = {m["key"]: m for m in api.modes()}
    assert by_key["docker"]["available"] is True
    assert by_key["direct"]["available"] is False
    assert "SAFETYWEBBING_ALLOW_DIRECT" in by_key["direct"]["reason"]


async def test_start_scan_rejects_direct_when_not_opted_in(monkeypatch):
    from fastapi import HTTPException

    from safetywebbing import api

    monkeypatch.delenv("SAFETYWEBBING_ALLOW_DIRECT", raising=False)
    with pytest.raises(HTTPException) as exc:
        await api.start_scan(
            api.ScanRequest(target="http://127.0.0.1:3000", scan_type="sqli", mode="direct")
        )
    assert exc.value.status_code == 400
    assert "disabled" in exc.value.detail


async def test_direct_scan_is_audited_with_mode(tmp_path, monkeypatch):
    """Whitelist still applies in direct mode, and the audit log records the mode."""
    from fastapi import HTTPException

    from safetywebbing import api

    monkeypatch.setenv("SAFETYWEBBING_ALLOW_DIRECT", "1")
    monkeypatch.setattr(api, "_LIVE_RUNS", tmp_path / "runs")
    monkeypatch.setattr(api.local_engine, "agent_cmd", ["pentestgpt-agent"])

    with pytest.raises(HTTPException) as exc:  # non-local target: blocked even in direct mode
        await api.start_scan(
            api.ScanRequest(target="http://example.com", scan_type="sqli", mode="direct")
        )
    assert exc.value.status_code == 400

    async def fake_run(self, **_):
        raise ScanFailed("stop here")

    # Patch the class, not the shared instance: monkeypatch's undo of an instance
    # attribute leaves the original bound method behind and shadows later class patches.
    monkeypatch.setattr(LocalAgentEngine, "run", fake_run)
    out = await api.start_scan(
        api.ScanRequest(target="http://127.0.0.1:3000", scan_type="sqli", mode="direct")
    )
    assert out["mode"] == "direct"
    import asyncio

    await asyncio.sleep(0.2)  # let the background job run and log scan_error
    events = [
        json.loads(line)
        for line in (tmp_path / "runs" / "audit.log").read_text(encoding="utf-8").splitlines()
    ]
    assert {e["event"] for e in events} == {"scan_requested", "scan_error"}
    assert all(e["mode"] == "direct" for e in events)
    api._jobs.clear()


# --- Per-scan model --------------------------------------------------------------


@pytest.mark.parametrize("model", ["claude-sonnet-5-5", "sonnet", "claude-opus-5-5[1m]", "a.b_c:1-2"])
def test_valid_model_ids_pass(model):
    from safetywebbing.config import validate_model

    assert validate_model(model) == model


@pytest.mark.parametrize("model", ["--dangerously-x", "-m", "a b", "a;rm", "../x", "a\nb", "x" * 65])
def test_unsafe_model_ids_blocked(model):
    from safetywebbing.config import InvalidModel, validate_model

    with pytest.raises(InvalidModel):
        validate_model(model)


@pytest.mark.parametrize("empty", [None, "", "   "])
def test_empty_model_means_default(empty):
    from safetywebbing.config import validate_model

    assert validate_model(empty) is None


def test_build_command_passes_model_only_when_set(tmp_path):
    eng = LocalAgentEngine(runs_root=tmp_path / "runs", agent_cmd=["agent"])
    assert "--model" not in eng.build_command(target="http://localhost", goal="g", run_id="r")
    cmd = LocalAgentEngine(
        runs_root=tmp_path / "runs", agent_cmd=["agent"], model="claude-sonnet-5-5"
    ).build_command(target="http://localhost", goal="g", run_id="r")
    assert cmd[cmd.index("--model") + 1] == "claude-sonnet-5-5"


async def test_requested_model_reaches_engine_without_leaking(tmp_path, monkeypatch):
    import asyncio

    from fastapi import HTTPException

    from safetywebbing import api

    monkeypatch.setenv("SAFETYWEBBING_ALLOW_DIRECT", "1")
    monkeypatch.setattr(api, "_LIVE_RUNS", tmp_path / "runs")
    monkeypatch.setattr(api.local_engine, "agent_cmd", ["agent"])
    seen = []

    async def fake_run(self, **_):
        seen.append(self.model)
        raise ScanFailed("stop")

    monkeypatch.setattr(LocalAgentEngine, "run", fake_run)
    await api.start_scan(api.ScanRequest(
        target="http://127.0.0.1:3000", scan_type="sqli", mode="direct", model="claude-sonnet-5-5"))
    await api.start_scan(api.ScanRequest(
        target="http://127.0.0.1:3000", scan_type="sqli", mode="direct"))
    await asyncio.sleep(0.3)
    assert sorted(seen, key=str) == [None, "claude-sonnet-5-5"]
    assert api.local_engine.model is None  # shared engine untouched

    with pytest.raises(HTTPException) as exc:
        await api.start_scan(api.ScanRequest(
            target="http://127.0.0.1:3000", scan_type="sqli", mode="direct", model="--evil"))
    assert exc.value.status_code == 400
    api._jobs.clear()


# --- Per-scan timeout -----------------------------------------------------------


def test_default_timeout_when_unset():
    from safetywebbing.config import validate_timeout

    assert validate_timeout(None) == 600.0


@pytest.mark.parametrize("value", [30, 30.0, 600, 3600, "120"])
def test_valid_timeouts_pass(value):
    from safetywebbing.config import validate_timeout

    assert validate_timeout(value) == float(value)


@pytest.mark.parametrize("value", [29, 3601, 0, -5, float("inf"), float("nan"), "not-a-number"])
def test_unsafe_timeouts_blocked(value):
    from safetywebbing.config import InvalidTimeout, validate_timeout

    with pytest.raises(InvalidTimeout):
        validate_timeout(value)


async def test_requested_timeout_reaches_engine(tmp_path, monkeypatch):
    import asyncio

    from safetywebbing import api

    monkeypatch.setenv("SAFETYWEBBING_ALLOW_DIRECT", "1")
    monkeypatch.setattr(api, "_LIVE_RUNS", tmp_path / "runs")
    monkeypatch.setattr(api.local_engine, "agent_cmd", ["agent"])
    seen = []

    async def fake_run(self, **_):
        seen.append(self.timeout_s)
        raise ScanFailed("stop")

    monkeypatch.setattr(LocalAgentEngine, "run", fake_run)
    await api.start_scan(api.ScanRequest(
        target="http://127.0.0.1:3000", scan_type="sqli", mode="direct", timeout_s=1800))
    await api.start_scan(api.ScanRequest(target="http://127.0.0.1:3000", scan_type="sqli", mode="direct"))
    await asyncio.sleep(0.3)
    assert sorted(seen) == [600.0, 1800.0]
    assert api.local_engine.timeout_s == 600.0  # shared engine untouched
    api._jobs.clear()


async def test_start_scan_rejects_out_of_range_timeout(monkeypatch):
    from fastapi import HTTPException

    from safetywebbing import api

    with pytest.raises(HTTPException) as exc:
        await api.start_scan(api.ScanRequest(
            target="http://127.0.0.1:3000", scan_type="sqli", timeout_s=99999))
    assert exc.value.status_code == 400
