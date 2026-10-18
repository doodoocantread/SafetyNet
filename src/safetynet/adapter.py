"""Adapter: join summary.json ⨝ traces/ → list[Finding] (ARCHITECTURE.md §6).

Deterministic FACT layer. No LLM here. The key join:

    observation.trace_episode_id  → traces/<episode>/events.jsonl
    observation.evidence_sequences → the tool_result event(s)   [the response]
    tool_result.call_id           → matching tool_call          [the request/payload]

summary.json observations only carry the raw HTTP *response*; the request that
produced it (e.g. the `curl ... -d "' OR 1=1--"` command) lives in the trace,
so we recover it here to make each Finding show request → response.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Finding


def _load_events(episode_dir: Path) -> list[dict[str, Any]]:
    path = episode_dir / "events.jsonl"
    if not path.is_file():
        return []
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events


def _recover_request(events: list[dict[str, Any]], evidence_sequences: list[int]) -> tuple[str | None, bool]:
    """From the evidence sequences (tool_result events), find the request command
    in the matching tool_call. Returns (request_text, is_error)."""
    by_seq = {e.get("sequence"): e for e in events}
    calls_by_id = {
        e.get("call_id"): e for e in events if e.get("type") == "tool_call"
    }
    request_text: str | None = None
    is_error = False
    for seq in evidence_sequences:
        ev = by_seq.get(seq)
        if not ev:
            continue
        call_id = None
        if ev.get("type") == "tool_result":
            is_error = is_error or bool(ev.get("is_error"))
            call_id = ev.get("call_id")
        elif ev.get("type") == "tool_call":
            call_id = ev.get("call_id")
        call = calls_by_id.get(call_id) if call_id else None
        if call and request_text is None:
            inp = call.get("input") or {}
            # Bash tool: the command string. Fall back to the whole input.
            request_text = inp.get("command") if isinstance(inp, dict) else None
            if request_text is None:
                request_text = json.dumps(inp, ensure_ascii=False)
    return request_text, is_error


def adapt(summary: dict[str, Any], traces_dir: Path) -> list[Finding]:
    """Turn one run's summary + traces into fact-only Findings."""
    task_kind = {t["id"]: t.get("kind") for t in summary.get("tasks", [])}
    task_target = {t["id"]: t.get("target") for t in summary.get("tasks", [])}
    default_target = (summary.get("targets") or [None])[0]
    attempts = summary.get("attempts", [])
    note_by_attempt = {a.get("id"): a.get("summary") for a in attempts}
    note_by_episode = {a.get("trace_episode_id"): a.get("summary") for a in attempts}

    findings: list[Finding] = []
    for i, obs in enumerate(summary.get("observations", [])):
        episode = obs.get("trace_episode_id")
        seqs = list(obs.get("evidence_sequences", []))
        request_text: str | None = None
        is_error = False
        if episode:
            events = _load_events(traces_dir / episode)
            request_text, is_error = _recover_request(events, seqs)

        task_id = obs.get("task_id")
        findings.append(
            Finding(
                id=obs.get("id") or f"obs-{i}",
                task_id=task_id,
                task_kind=task_kind.get(task_id),
                target=task_target.get(task_id) or default_target,
                request=request_text,
                response=obs.get("statement", ""),
                is_error=is_error,
                evidence_sequences=seqs,
                trace_episode_id=episode,
                agent_note=note_by_attempt.get(obs.get("attempt_id"))
                or note_by_episode.get(episode) or None,
            )
        )
    return findings
