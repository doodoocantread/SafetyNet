"""Tests for the hackingBuddyGPT → SafetyWebbing translator (agent_image_hackingbuddy).

The translator is pure, so it needs no Docker, hackingBuddy or LLM. We build a
synthetic hackingBuddy span log, translate it, and then feed the result through
SafetyWebbing's own adapter to prove the two agents land on the SAME FACT contract
(request → response + agent note behind every observation).
"""

import json

import pytest
from safetywebbing_hb_agent.translate import translate  # made importable by conftest.py

from safetywebbing.adapter import adapt

# hackingBuddy attribute keys (utils/log_storage.py).
_OP = "gen_ai.operation.name"
_TOOL_NAME = "gen_ai.tool.name"
_TOOL_CALL_ID = "gen_ai.tool.call.id"
_TOOL_ARGS = "gen_ai.tool.call.arguments"
_OUT_MSGS = "gen_ai.output.messages"
_MODEL = "gen_ai.request.model"
_COST = "hackingbuddygpt.cost.usd"
_RUN_STATE = "hackingbuddygpt.run.state"
_TOOL_RESULT = "hackingbuddygpt.tool.result"


def _span(span_id, parent, attrs, *, status="OK", start="2026-10-24T10:00:00", end=None):
    return {
        "trace_id": "trace", "span_id": span_id, "parent_span_id": parent,
        "name": span_id, "kind": "INTERNAL", "start_time": start, "end_time": end,
        "attributes": attrs, "status": {"code": status, "message": ""},
    }


def _assistant(text):
    return [{"role": "assistant", "parts": [{"type": "text", "content": text}]}]


def _run_spans(*, run_state="got root", root_status="OK"):
    """A minimal but realistic root + chat + one HTTP tool call."""
    root_initial = _span("root", None, {}, start="2026-10-24T10:00:00", end=None)
    root_final = _span(
        "root", None, {_RUN_STATE: run_state}, status=root_status,
        start="2026-10-24T10:00:00", end="2026-10-24T10:00:30",
    )
    chat = _span("c1", "root", {
        _OP: "chat",
        _OUT_MSGS: _assistant("I will probe the login endpoint for SQL injection."),
        _MODEL: "anthropic/claude-3-5-sonnet", _COST: 0.0123,
    })
    tool = _span("e1", "c1", {
        _OP: "execute_tool", _TOOL_NAME: "http_request", _TOOL_CALL_ID: "call_1",
        _TOOL_ARGS: '{"method":"POST","path":"/rest/user/login","body":"email=\' OR 1=1--"}',
        _TOOL_RESULT: "HTTP/1.1 200 OK\r\n\r\n{\"authentication\":{\"token\":\"ey...\"}}",
    })
    return [root_initial, chat, tool, root_final]


def test_translate_builds_summary_and_traces():
    summary, traces = translate(
        _run_spans(), run_id="live-x", goal="Tim SQL injection", target="http://127.0.0.1:3000",
    )
    assert summary["run_id"] == "live-x"
    assert summary["targets"] == ["http://127.0.0.1:3000"]
    assert summary["status"] == "completed"  # root ended OK
    assert summary["backend"] == "hackingbuddy"
    assert summary["model"] == "anthropic/claude-3-5-sonnet"
    assert summary["cost_usd"] == pytest.approx(0.0123)
    assert summary["wall_duration_s"] == pytest.approx(30.0)
    assert len(summary["observations"]) == 1 and len(summary["attempts"]) == 1

    # one trace episode with the request (tool_call) and response (tool_result)
    (episode,) = traces.keys()
    kinds = [e["type"] for e in traces[episode]]
    assert kinds == ["tool_call", "tool_result"]
    assert "OR 1=1" in traces[episode][0]["input"]["command"]


def test_translate_output_round_trips_through_adapter(tmp_path):
    summary, traces = translate(
        _run_spans(), run_id="live-x", goal="g", target="http://127.0.0.1:3000",
    )
    # Write traces exactly as the wrapper would, then read them back with the adapter.
    traces_dir = tmp_path / "traces"
    for episode, events in traces.items():
        ep = traces_dir / episode
        ep.mkdir(parents=True)
        (ep / "events.jsonl").write_text(
            "\n".join(json.dumps(e) for e in events), encoding="utf-8"
        )

    findings = adapt(summary, traces_dir)
    assert len(findings) == 1
    f = findings[0]
    assert f.target == "http://127.0.0.1:3000"
    assert "OR 1=1" in (f.request or "")                 # recovered from tool_call
    assert "authentication" in f.response                # the tool_result statement
    assert f.agent_note and "login endpoint" in f.agent_note  # the chat turn's text


@pytest.mark.parametrize(
    "run_state,root_status,expected",
    [
        ("got root", "OK", "completed"),
        ("Reached maximum rounds (100)", "ERROR", "completed"),
        ("exception occurred", "ERROR", "error"),
    ],
)
def test_status_mapping(run_state, root_status, expected):
    summary, _ = translate(
        _run_spans(run_state=run_state, root_status=root_status),
        run_id="r", goal="g", target="http://localhost",
    )
    assert summary["status"] == expected
    if expected == "error":
        assert summary["error"] == run_state


def test_no_tool_calls_yields_empty_observations():
    root = _span("root", None, {_RUN_STATE: "Reached maximum rounds (1)"}, status="ERROR",
                 end="2026-10-24T10:00:05")
    summary, traces = translate([root], run_id="r", goal="g", target="http://localhost")
    assert summary["observations"] == [] and traces == {}
    assert summary["status"] == "completed"  # ran its budget, just found nothing
