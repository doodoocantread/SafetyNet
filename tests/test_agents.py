"""Tests for the agent selector (PentestGPT | hackingBuddy).

No Docker, LLM or real agent: these pin the deterministic wiring — which agent a
request may pick, how it maps to a container image + auth, and that the choice is
audited and never leaks into the shared engine.
"""

import asyncio
import json

import pytest

from safetywebbing.config import (
    DEFAULT_AGENT,
    LLM_KEY_ENV,
    LLM_PROVIDERS,
    AgentNotAllowed,
    InvalidLLMProvider,
    InvalidModel,
    agent_for,
    validate_agent,
    validate_llm_provider,
    validate_model,
)
from safetywebbing.engines.base import ScanFailed
from safetywebbing.engines.live import LiveAgentEngine

# --- config: which agents exist ----------------------------------------------


def test_default_agent_is_pentestgpt():
    assert DEFAULT_AGENT == "pentestgpt"
    assert validate_agent("pentestgpt") == "pentestgpt"


@pytest.mark.parametrize("key", ["hackingbuddy", "pentestgpt"])
def test_known_agents_pass(key):
    assert validate_agent(key) == key


@pytest.mark.parametrize("key", ["", "PENTESTGPT", "../x", "nope", "docker; rm -rf /"])
def test_unknown_agents_rejected(key):
    with pytest.raises(AgentNotAllowed):
        validate_agent(key)


def test_agent_records_carry_image_and_auth():
    pg = agent_for("pentestgpt")
    assert pg.image == "safetywebbing-agent" and pg.auth == "claude_oauth"
    assert "direct" in pg.modes and "docker" in pg.modes
    hb = agent_for("hackingbuddy")
    assert hb.image == "safetywebbing-hackingbuddy" and hb.auth == "llm_api_key"
    assert hb.modes == ("docker",)  # hackingBuddy is container-only


# --- engine: image swap + key passthrough, no creds for llm_api_key ----------


def test_build_command_hackingbuddy_forwards_key_without_creds(tmp_path):
    eng = LiveAgentEngine(
        runs_root=tmp_path / "runs", image="safetywebbing-hackingbuddy",
        auth="llm_api_key", claude_creds_dir=tmp_path / "nope",
    )
    cmd = eng.build_command(
        target="http://127.0.0.1:3000", goal="g", run_id="r1",
        env={"ANTHROPIC_API_KEY": "sk-secret", "PATH": "/bin"},
    )
    joined = " ".join(cmd)
    assert "safetywebbing-hackingbuddy" in cmd
    # key forwarded by NAME only — the value never appears on the argv
    assert cmd[cmd.index("-e") + 1] == "ANTHROPIC_API_KEY"
    assert "sk-secret" not in joined
    # no credential mount for an llm_api_key agent
    assert "/home/agent/.claude" not in joined
    # target still rewritten to the container-visible host
    assert cmd[cmd.index("--target") + 1] == "http://host.docker.internal:3000"


def test_build_command_hackingbuddy_only_forwards_present_keys(tmp_path):
    eng = LiveAgentEngine(runs_root=tmp_path / "runs", auth="llm_api_key")
    cmd = eng.build_command(
        target="http://localhost", goal="g", run_id="r1",
        env={"OPENAI_API_KEY": "x"},  # only one of the three is set
    )
    forwarded = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-e"]
    assert forwarded == ["OPENAI_API_KEY"]


def test_build_command_pentestgpt_has_no_key_passthrough(tmp_path):
    eng = LiveAgentEngine(runs_root=tmp_path / "runs", auth="claude_oauth")
    cmd = eng.build_command(
        target="http://localhost", goal="g", run_id="r1",
        env={"ANTHROPIC_API_KEY": "x"},
    )
    assert "-e" not in cmd  # OAuth agent never forwards provider keys


# --- LLM providers (config) ---------------------------------------------------


def test_gemini_is_a_provider():
    assert "gemini" in LLM_PROVIDERS
    assert LLM_PROVIDERS["gemini"].env_name == "GEMINI_API_KEY"
    assert "GEMINI_API_KEY" in LLM_KEY_ENV


@pytest.mark.parametrize("p", ["anthropic", "gemini", "openai", "openrouter"])
def test_known_providers_pass(p):
    assert validate_llm_provider(p) == p


@pytest.mark.parametrize("p", ["", "google", "claude", "../x"])
def test_unknown_providers_rejected(p):
    with pytest.raises(InvalidLLMProvider):
        validate_llm_provider(p)


def test_litellm_model_slash_allowed_only_when_requested():
    # hackingBuddy path: provider/model id is allowed
    assert validate_model("gemini/gemini-1.5-pro", allow_slash=True) == "gemini/gemini-1.5-pro"
    # PentestGPT path (default): a slash is rejected, and a leading dash never passes
    with pytest.raises(InvalidModel):
        validate_model("gemini/gemini-1.5-pro")
    with pytest.raises(InvalidModel):
        validate_model("--evil/x", allow_slash=True)


# --- Per-scan key injection (engine) -----------------------------------------


def test_container_env_injects_scan_key_under_provider_name(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    eng = LiveAgentEngine(
        auth="llm_api_key", llm_api_key="g-secret", llm_env_name="GEMINI_API_KEY",
    )
    env = eng.container_env()
    assert env["GEMINI_API_KEY"] == "g-secret"
    # and build_command forwards ONLY that provider's key, by name
    cmd = eng.build_command(target="http://localhost", goal="g", run_id="r1", env=env)
    forwarded = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-e"]
    assert forwarded == ["GEMINI_API_KEY"]
    assert "g-secret" not in " ".join(cmd)  # value never on the argv


def test_container_env_none_for_oauth_agent():
    assert LiveAgentEngine(auth="claude_oauth").container_env() is None


# --- API: /api/agents availability -------------------------------------------


def test_agents_endpoint_flags_key_requirement(monkeypatch):
    from safetywebbing import api

    for k in LiveAgentEngine().llm_key_env:
        monkeypatch.delenv(k, raising=False)
    by_key = {a["key"]: a for a in api.agents()}
    # Both are selectable; hackingBuddy flags that it needs a key (none on server yet).
    assert by_key["pentestgpt"]["available"] is True
    assert by_key["pentestgpt"]["needs_key"] is False
    assert by_key["hackingbuddy"]["available"] is True
    assert by_key["hackingbuddy"]["needs_key"] is True
    assert by_key["hackingbuddy"]["has_server_key"] is False
    assert by_key["hackingbuddy"]["modes"] == ["docker"]


def test_agents_endpoint_reports_server_key(monkeypatch):
    from safetywebbing import api

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    by_key = {a["key"]: a for a in api.agents()}
    assert by_key["hackingbuddy"]["has_server_key"] is True


def test_llm_providers_endpoint_lists_gemini(monkeypatch):
    from safetywebbing import api

    for k in LLM_KEY_ENV:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    by_key = {p["key"]: p for p in api.llm_providers()}
    assert set(by_key) == {"anthropic", "gemini", "openai", "openrouter"}
    assert by_key["gemini"]["has_server_key"] is True
    assert by_key["anthropic"]["has_server_key"] is False


# --- API: start_scan validates + routes the agent ----------------------------


async def test_start_scan_rejects_unknown_agent():
    from fastapi import HTTPException

    from safetywebbing import api

    with pytest.raises(HTTPException) as exc:
        await api.start_scan(api.ScanRequest(
            target="http://127.0.0.1:3000", scan_type="sqli", agent="nope"))
    assert exc.value.status_code == 400


async def test_start_scan_rejects_hackingbuddy_in_direct_mode(monkeypatch):
    from fastapi import HTTPException

    from safetywebbing import api

    monkeypatch.setenv("SAFETYWEBBING_ALLOW_DIRECT", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    with pytest.raises(HTTPException) as exc:
        await api.start_scan(api.ScanRequest(
            target="http://127.0.0.1:3000", scan_type="sqli", agent="hackingbuddy", mode="direct"))
    assert exc.value.status_code == 400
    assert "mode" in exc.value.detail


async def test_start_scan_rejects_hackingbuddy_without_llm_key(monkeypatch):
    from fastapi import HTTPException

    from safetywebbing import api

    for k in LiveAgentEngine().llm_key_env:
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(HTTPException) as exc:
        await api.start_scan(api.ScanRequest(
            target="http://127.0.0.1:3000", scan_type="sqli", agent="hackingbuddy"))
    assert exc.value.status_code == 400
    assert "API key" in exc.value.detail


async def test_hackingbuddy_scan_routes_image_and_audits_agent(tmp_path, monkeypatch):
    from safetywebbing import api

    monkeypatch.setattr(api, "_LIVE_RUNS", tmp_path / "runs")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    seen = {}

    async def fake_run(self, **_):
        seen["image"] = self.image
        seen["auth"] = self.auth
        raise ScanFailed("stop here")

    monkeypatch.setattr(LiveAgentEngine, "run", fake_run)
    out = await api.start_scan(api.ScanRequest(
        target="http://127.0.0.1:3000", scan_type="sqli", agent="hackingbuddy"))
    assert out["agent"] == "hackingbuddy"

    await asyncio.sleep(0.2)  # let the background job log scan_error
    # The per-scan engine used hackingBuddy's image + auth…
    assert seen == {"image": "safetywebbing-hackingbuddy", "auth": "llm_api_key"}
    # …the shared engine is untouched…
    assert api.live_engine.image == "safetywebbing-agent"
    assert api.live_engine.auth == "claude_oauth"
    # …and every audit line records the agent.
    events = [
        json.loads(line)
        for line in (tmp_path / "runs" / "audit.log").read_text(encoding="utf-8").splitlines()
    ]
    assert {e["event"] for e in events} == {"scan_requested", "scan_error"}
    assert all(e["agent"] == "hackingbuddy" for e in events)
    api._jobs.clear()


async def test_hackingbuddy_scan_routes_per_scan_key(tmp_path, monkeypatch):
    """A UI-entered key + provider reach the engine as llm_api_key/llm_env_name,
    are NOT written to the audit log, and do not need any server env key."""
    from safetywebbing import api

    monkeypatch.setattr(api, "_LIVE_RUNS", tmp_path / "runs")
    for k in LLM_KEY_ENV:
        monkeypatch.delenv(k, raising=False)
    seen = {}

    async def fake_run(self, **_):
        seen["key"] = self.llm_api_key
        seen["env_name"] = self.llm_env_name
        raise ScanFailed("stop here")

    monkeypatch.setattr(LiveAgentEngine, "run", fake_run)
    await api.start_scan(api.ScanRequest(
        target="http://127.0.0.1:3000", scan_type="sqli", agent="hackingbuddy",
        llm_provider="gemini", llm_api_key="g-secret", model="gemini-1.5-pro"))
    await asyncio.sleep(0.2)
    assert seen == {"key": "g-secret", "env_name": "GEMINI_API_KEY"}
    # the key must never be written to the audit log
    audit = (tmp_path / "runs" / "audit.log").read_text(encoding="utf-8")
    assert "g-secret" not in audit
    assert '"agent": "hackingbuddy"' in audit
    api._jobs.clear()


async def test_hackingbuddy_provider_without_any_key_rejected(monkeypatch):
    from fastapi import HTTPException

    from safetywebbing import api

    for k in LLM_KEY_ENV:
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(HTTPException) as exc:
        await api.start_scan(api.ScanRequest(
            target="http://127.0.0.1:3000", scan_type="sqli", agent="hackingbuddy",
            llm_provider="gemini"))  # provider chosen, but no key anywhere
    assert exc.value.status_code == 400
    assert "GEMINI_API_KEY" in exc.value.detail


async def test_hackingbuddy_accepts_litellm_model_slash(tmp_path, monkeypatch):
    from safetywebbing import api

    monkeypatch.setattr(api, "_LIVE_RUNS", tmp_path / "runs")

    async def fake_run(self, **_):
        raise ScanFailed("stop here")

    monkeypatch.setattr(LiveAgentEngine, "run", fake_run)
    out = await api.start_scan(api.ScanRequest(
        target="http://127.0.0.1:3000", scan_type="sqli", agent="hackingbuddy",
        llm_provider="openrouter", llm_api_key="or-key",
        model="openrouter/anthropic/claude-3.5-sonnet"))
    assert out["agent"] == "hackingbuddy"
    await asyncio.sleep(0.1)
    api._jobs.clear()


async def test_pentestgpt_rejects_slash_model(monkeypatch):
    from fastapi import HTTPException

    from safetywebbing import api

    with pytest.raises(HTTPException) as exc:
        await api.start_scan(api.ScanRequest(
            target="http://127.0.0.1:3000", scan_type="sqli", model="anthropic/claude"))
    assert exc.value.status_code == 400


async def test_default_scan_still_uses_pentestgpt(tmp_path, monkeypatch):
    from safetywebbing import api

    monkeypatch.setattr(api, "_LIVE_RUNS", tmp_path / "runs")
    seen = {}

    async def fake_run(self, **_):
        seen["image"] = self.image
        seen["auth"] = self.auth
        raise ScanFailed("stop here")

    monkeypatch.setattr(LiveAgentEngine, "run", fake_run)
    out = await api.start_scan(api.ScanRequest(target="http://127.0.0.1:3000", scan_type="sqli"))
    assert out["agent"] == "pentestgpt"
    await asyncio.sleep(0.2)
    assert seen == {"image": "safetywebbing-agent", "auth": "claude_oauth"}
    api._jobs.clear()
