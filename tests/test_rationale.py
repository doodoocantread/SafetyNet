"""'Why was this flagged?' — agent note join + labeler rationale."""

from __future__ import annotations

import json
from types import SimpleNamespace

from safetywebbing.adapter import adapt
from safetywebbing.labeling import HeuristicLabeler
from safetywebbing.labeling_llm import LLMLabeler
from safetywebbing.models import Finding
from safetywebbing.report import to_markdown
from safetywebbing.models import Report


def test_adapter_attaches_agent_note_by_attempt(tmp_path):
    summary = {
        "targets": ["http://127.0.0.1:3000"],
        "tasks": [{"id": "t1", "kind": "test"}],
        "attempts": [{"id": "a1", "trace_episode_id": "ep1", "summary": "Login bypassed with a quote payload."}],
        "observations": [{"id": "o1", "task_id": "t1", "attempt_id": "a1", "statement": "HTTP/1.1 200 OK"}],
    }
    [f] = adapt(summary, tmp_path)
    assert f.agent_note == "Login bypassed with a quote payload."


def test_adapter_agent_note_falls_back_to_episode(tmp_path):
    summary = {
        "attempts": [{"id": "a1", "trace_episode_id": "ep1", "summary": "note"}],
        "observations": [{"id": "o1", "trace_episode_id": "ep1", "statement": ""}],
    }
    [f] = adapt(summary, tmp_path)
    assert f.agent_note == "note"


def test_heuristic_rationale_cites_concrete_signals():
    f = Finding(
        id="x",
        request="curl -X POST http://127.0.0.1:3000/rest/user/login -d \"{'email':\\\"' OR 1=1--\\\"}\"",
        response='HTTP/1.1 200 OK\r\n\r\n{"authentication":{"token":"t"}}',
    )
    lbl = HeuristicLabeler().label(f)
    assert lbl.cwe == "CWE-89"
    joined = " ".join(lbl.rationale)
    assert "HTTP 200" in joined
    assert "SQL" in joined and "authentication" in joined
    assert "chứa" in joined  # Vietnamese with diacritics


def test_heuristic_rationale_notes_missing_request():
    lbl = HeuristicLabeler().label(Finding(id="x", response="HTTP/1.1 401 Unauthorized"))
    assert any("request" in r for r in lbl.rationale)
    assert any("401" in r for r in lbl.rationale)


def _fake_client(payload: dict, seen: list):
    def create(**kw):
        seen.append(kw)
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=json.dumps(payload))])
    return SimpleNamespace(messages=SimpleNamespace(create=create))


def test_llm_labeler_parses_rationale_and_sends_agent_note():
    seen: list = []
    lab = LLMLabeler(model="m", api_key="k")
    lab._client = _fake_client({
        "vuln_class": "SQL Injection", "severity": "critical", "cwe": "CWE-89",
        "explanation": "e", "rationale": ["payload ' OR 1=1--", "HTTP 200 + token"],
        "remediation": "r", "confidence": "high",
    }, seen)
    lbl = lab.label(Finding(id="x", request="curl ...", response="HTTP/1.1 200 OK", agent_note="AGENT SAYS"))
    assert lbl.rationale == ["payload ' OR 1=1--", "HTTP 200 + token"]
    assert "AGENT SAYS" in seen[0]["messages"][0]["content"]


def test_llm_rationale_tolerates_string_or_garbage():
    for raw, want in (("one reason", ["one reason"]), (42, []), (None, [])):
        lab = LLMLabeler(model="m", api_key="k")
        lab._client = _fake_client({"vuln_class": "X", "severity": "info", "rationale": raw}, [])
        assert lab.label(Finding(id="x")).rationale == want


def test_markdown_includes_rationale_and_agent_note():
    f = Finding(id="x", response="HTTP/1.1 500 Internal Server Error", agent_note="agent note here")
    f.label = HeuristicLabeler().label(f)
    md = to_markdown(Report(run_id="r", goal="g", targets=[], status="completed", engine="e", findings=[f]))
    assert "Vì sao bắt lỗi này" in md and "HTTP 500" in md
    assert "agent note here" in md
