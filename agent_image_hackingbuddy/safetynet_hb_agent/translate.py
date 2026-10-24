"""Translate a hackingBuddyGPT run log into SafetyNet's summary.json + traces/.

hackingBuddyGPT writes one OpenTelemetry/GenAI JSONL file per run: a root span
plus ``chat`` spans (one LLM turn each) and ``execute_tool`` spans (one tool call
each — for the web use-case, an HTTP request). SafetyNet's pipeline instead
expects, per run:

    summary.json                    — tasks / attempts / observations + metadata
    traces/<episode>/events.jsonl   — the tool_call + tool_result behind each
                                      observation (adapter.py recovers the request
                                      from the tool_call and the response from the
                                      tool_result)

This module is the deterministic bridge. It is pure (spans in, dicts out) so it
can be unit-tested without Docker, hackingBuddyGPT or an LLM. It copies the few
hackingBuddy attribute-key strings it needs rather than importing them, so the
translator stands on its own and the test suite needs no hackingBuddy install.
"""

from __future__ import annotations

import datetime
from typing import Any

# --- hackingBuddy span attribute keys (mirror utils/log_storage.py) ----------
_OPERATION_NAME = "gen_ai.operation.name"
_TOOL_NAME = "gen_ai.tool.name"
_TOOL_CALL_ID = "gen_ai.tool.call.id"
_TOOL_CALL_ARGUMENTS = "gen_ai.tool.call.arguments"
_OUTPUT_MESSAGES = "gen_ai.output.messages"
_REQUEST_MODEL = "gen_ai.request.model"
_COST_USD = "hackingbuddygpt.cost.usd"
_RUN_STATE = "hackingbuddygpt.run.state"
_TOOL_RESULT = "hackingbuddygpt.tool.result"

_OP_CHAT = "chat"
_OP_EXECUTE_TOOL = "execute_tool"
_STATUS_OK = "OK"
_STATUS_ERROR = "ERROR"


def _assistant_text(output_messages: Any) -> str | None:
    """Join the text parts of a span's output messages — the agent's own words,
    shown later as an unverified ``agent_note`` next to the finding it produced."""
    if not isinstance(output_messages, list):
        return None
    chunks: list[str] = []
    for msg in output_messages:
        if not isinstance(msg, dict):
            continue
        for part in msg.get("parts") or []:
            if isinstance(part, dict) and part.get("type") == "text":
                content = part.get("content")
                if content:
                    chunks.append(str(content))
    text = "\n".join(chunks).strip()
    return text or None


def _parse_ts(value: Any) -> datetime.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.datetime.fromisoformat(value)
    except ValueError:
        return None


def _run_duration_s(roots: list[dict[str, Any]]) -> float:
    """Wall-clock from the run's first-emitted start to its final end_time."""
    if not roots:
        return 0.0
    start = _parse_ts(roots[0].get("start_time"))
    end = _parse_ts(roots[-1].get("end_time"))
    if start and end:
        return max(0.0, (end - start).total_seconds())
    return 0.0


def _map_status(status_code: str, state: str) -> str:
    """hackingBuddy outcome → SafetyNet run status (completed | failed | error).

    A solved run (``got root``/explicit completion) ends OK → ``completed``. An
    ERROR that is merely a resource-limit reason (max rounds/tokens/cost/time)
    still ran its full budget → ``completed`` (like PentestGPT finishing its loop).
    An ERROR from a thrown exception is a real failure → ``error``."""
    if status_code == _STATUS_OK:
        return "completed"
    low = (state or "").lower()
    if any(w in low for w in ("exception", "traceback", "crash")):
        return "error"
    if low.startswith("reached maximum") or "limit" in low:
        return "completed"
    # Unknown non-OK terminal state: inconclusive, not a hard crash.
    return "failed" if state else "error"


def translate(
    spans: list[dict[str, Any]],
    *,
    run_id: str,
    goal: str,
    target: str,
    model: str | None = None,
    backend: str = "hackingbuddy",
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    """Fold hackingBuddy spans into ``(summary_dict, {episode_id: [events]})``.

    Each ``execute_tool`` span becomes one attempt + one observation + one trace
    episode holding the tool_call (the HTTP request) and tool_result (the HTTP
    response). The assistant text of the ``chat`` span that requested the tool is
    carried as the attempt summary (the agent's unverified note)."""
    roots = [s for s in spans if s.get("parent_span_id") is None]
    root = roots[-1] if roots else {}
    rattrs = root.get("attributes", {}) if isinstance(root, dict) else {}
    rstatus = root.get("status", {}) if isinstance(root, dict) else {}
    state = rattrs.get(_RUN_STATE) or rstatus.get("message") or ""
    status_code = rstatus.get("code", "")

    # chat spans: accumulate cost + model, and remember each one's assistant text
    # so a tool call can borrow the note of the turn that requested it.
    chat_text: dict[str, str | None] = {}
    cost = 0.0
    run_model = model or ""
    for s in spans:
        attrs = s.get("attributes", {})
        if attrs.get(_OPERATION_NAME) == _OP_CHAT:
            cost += attrs.get(_COST_USD, 0.0) or 0.0
            if not run_model:
                run_model = attrs.get(_REQUEST_MODEL, "") or ""
            chat_text[s.get("span_id")] = _assistant_text(attrs.get(_OUTPUT_MESSAGES))

    tool_spans = [
        s for s in spans if s.get("attributes", {}).get(_OPERATION_NAME) == _OP_EXECUTE_TOOL
    ]
    tool_spans.sort(key=lambda s: s.get("start_time") or "")

    tasks = [{"id": "t1", "kind": "web", "target": target}]
    attempts: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    traces: dict[str, list[dict[str, Any]]] = {}

    for i, s in enumerate(tool_spans):
        attrs = s["attributes"]
        episode = f"hb-{s.get('span_id') or i}"
        call_id = str(attrs.get(_TOOL_CALL_ID) or f"call-{i}")
        arguments = attrs.get(_TOOL_CALL_ARGUMENTS) or ""
        result_text = attrs.get(_TOOL_RESULT) or ""
        tool_name = attrs.get(_TOOL_NAME) or ""
        is_error = s.get("status", {}).get("code") == _STATUS_ERROR

        # The adapter recovers the request from the tool_call's input.command and
        # the response from the tool_result referenced by evidence_sequences.
        traces[episode] = [
            {"type": "tool_call", "sequence": 1, "call_id": call_id,
             "tool": tool_name, "input": {"command": arguments}},
            {"type": "tool_result", "sequence": 2, "call_id": call_id,
             "is_error": is_error, "statement": result_text},
        ]

        note = chat_text.get(s.get("parent_span_id"))
        attempts.append({
            "id": call_id,
            "summary": note,
            "task_id": "t1",
            "trace_episode_id": episode,
            "status": "failed" if is_error else "done",
            "failure_kind": None,
            "failure_message": None,
        })
        observations.append({
            "id": f"{episode}:observation",
            "task_id": "t1",
            "attempt_id": call_id,
            "trace_episode_id": episode,
            "evidence_sequences": [2],
            "statement": result_text,
        })

    status = _map_status(status_code, state)
    summary = {
        "run_id": run_id,
        "goal": goal,
        "targets": [target],
        "status": status,
        "backend": backend,
        "model": run_model or None,
        "cost_usd": round(cost, 6),
        "wall_duration_s": _run_duration_s(roots),
        "error": state if status == "error" else None,
        "tasks": tasks,
        "attempts": attempts,
        "observations": observations,
        # Keep the raw hackingBuddy outcome for debugging / the system page.
        "hackingbuddy_run_state": state,
    }
    return summary, traces
