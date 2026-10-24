"""Tests for the hackingBuddy wrapper's LLM resolution (agent_image_hackingbuddy).

Pure env logic — no Docker, no hackingBuddy, no network. Pins how a scan's model
choice + the server's provider key become a litellm model string, including the
"use Claude via the Anthropic API" path.
"""

import pytest
from safetywebbing_hb_agent.cli import _resolve_llm  # made importable by conftest.py

_KEYS = ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY",
         "SAFETYWEBBING_HB_LLM_MODEL", "SAFETYWEBBING_HB_LLM_API_BASE")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in _KEYS:
        monkeypatch.delenv(k, raising=False)


def test_no_key_exits(monkeypatch):
    with pytest.raises(SystemExit):
        _resolve_llm("claude-sonnet-5-5")


def test_claude_id_maps_to_anthropic_api(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    api_key, model, api_base = _resolve_llm("claude-sonnet-5-5")
    assert api_key == "sk-ant"
    assert model == "anthropic/claude-sonnet-5-5"  # Claude id → Anthropic via litellm
    assert api_base is None


def test_anthropic_default_model_when_none(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    _, model, _ = _resolve_llm(None)
    assert model.startswith("anthropic/")


def test_litellm_format_model_passes_through(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    _, model, _ = _resolve_llm("anthropic/claude-3-5-sonnet-20241022")
    assert model == "anthropic/claude-3-5-sonnet-20241022"


def test_explicit_env_model_wins(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    monkeypatch.setenv("SAFETYWEBBING_HB_LLM_MODEL", "openrouter/anthropic/claude-3.5-sonnet")
    _, model, _ = _resolve_llm("claude-sonnet-5-5")
    assert model == "openrouter/anthropic/claude-3.5-sonnet"


def test_gemini_id_maps_to_gemini_provider(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    api_key, model, base = _resolve_llm("gemini-1.5-pro")
    assert api_key == "g-key"
    assert model == "gemini/gemini-1.5-pro"  # bare Gemini id → Google AI Studio via litellm
    assert base is None


def test_gemini_default_model_when_none(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    _, model, _ = _resolve_llm(None)
    assert model.startswith("gemini/")


def test_openai_bare_id_passes_through(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-oai")
    _, model, base = _resolve_llm("gpt-4o")
    assert model == "gpt-4o" and base is None


def test_openrouter_sets_api_base_and_default(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or")
    # a bare Claude id is NOT force-mapped under OpenRouter (routing is provider-specific)
    _, model, base = _resolve_llm("claude-sonnet-5-5")
    assert model.startswith("openrouter/")
    assert base == "https://openrouter.ai/api"


def test_anthropic_preferred_over_others(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-oai")
    api_key, model, _ = _resolve_llm(None)
    assert api_key == "sk-ant" and model.startswith("anthropic/")
