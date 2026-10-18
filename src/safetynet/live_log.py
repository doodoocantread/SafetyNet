"""Real-time terminal feed for a running scan.

The agent writes its trace (`runs/<run_id>/traces/*/events.jsonl`) incrementally,
append-only with fsync, while it runs (CODEMAP.md §6.4). This module tails those
files as new lines land and turns them into a human-readable, timestamped log the
frontend can poll — so "quét mới" shows what the agent is actually doing (and
where it fails) instead of just a spinner.

No engine changes needed: both `LiveAgentEngine` (Docker) and `LocalAgentEngine`
(direct) leave the same trace files on the host filesystem, so the tailer reads
`runs/<run_id>/traces/` directly and does not care which engine is running.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_HTTP_STATUS = re.compile(r"^HTTP/\d\.\d (\d{3})")
_MAX_LINE_CHARS = 500


@dataclass
class JobLog:
    """Append-only log for one scan job. Read via index, like a growing file:
    the `/api/scan/{job_id}/log?after=N` endpoint returns `lines[N:]`."""

    lines: list[dict[str, Any]] = field(default_factory=list)

    def append(self, text: str, level: str = "info", ts: float | None = None) -> None:
        self.lines.append({"ts": ts if ts is not None else time.time(), "level": level, "text": text})

    def extend(self, items: list[tuple[float, str, str]]) -> None:
        for ts, level, text in items:
            self.lines.append({"ts": ts, "level": level, "text": text})


def _role(episode: str) -> str:
    if episode.startswith("executor"):
        return "executor"
    if episode.startswith("supervisor"):
        return "supervisor"
    return episode


def _truncate(text: str, limit: int = _MAX_LINE_CHARS) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def _short_json(value: Any, limit: int = 200) -> str:
    try:
        text = json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        text = str(value)
    return _truncate(text, limit)


def format_event(episode: str, event: dict[str, Any]) -> tuple[str, str] | None:
    """One trace event -> (level, text), or None to skip (noise: reasoning
    content is redacted at the source anyway, raw_event is provider chatter)."""
    tag = f"[{_role(episode)}]"
    etype = event.get("type")

    if etype == "session_started":
        return "info", f"{tag} phiên mới bắt đầu"

    if etype == "tool_call":
        name = event.get("name") or "?"
        inp = event.get("input") or {}
        if name == "Bash" and "command" in inp:
            return "info", f"{tag} $ {_truncate(str(inp['command']), 300)}"
        return "info", f"{tag} {name}({_short_json(inp)})"

    if etype == "tool_result":
        output = _truncate(str(event.get("output", "")))
        is_error = bool(event.get("is_error"))
        level = "error" if is_error else "info"
        m = _HTTP_STATUS.match(output)
        if m:
            code = int(m.group(1))
            if code >= 500:
                level = "error"
            elif code >= 400 and level == "info":
                level = "warn"
        marker = "✗" if is_error else "→"
        return level, f"{tag} {marker} {output}"

    return None  # reasoning / raw_event / turn_completed / … — too noisy, nothing actionable


class TraceTailer:
    """Tracks a byte offset per `events.jsonl` file so repeated polls only read
    what's new. Only commits whole lines — a write caught mid-flush is read on
    the next poll instead of risking a truncated-JSON parse error."""

    def __init__(self, traces_dir: Path) -> None:
        self.traces_dir = traces_dir
        self._offsets: dict[Path, int] = {}

    def poll(self) -> list[tuple[float, str, str]]:
        if not self.traces_dir.is_dir():
            return []
        batch: list[tuple[float, str, str]] = []
        for path in sorted(self.traces_dir.glob("*/events.jsonl")):
            offset = self._offsets.get(path, 0)
            try:
                with path.open("rb") as f:
                    f.seek(offset)
                    chunk = f.read()
            except OSError:
                continue
            if not chunk:
                continue
            last_nl = chunk.rfind(b"\n")
            if last_nl == -1:
                continue  # no complete line yet
            self._offsets[path] = offset + last_nl + 1
            episode = path.parent.name
            for raw_line in chunk[:last_nl].decode("utf-8", errors="replace").split("\n"):
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    event = json.loads(raw_line)
                except ValueError:
                    continue
                formatted = format_event(episode, event)
                if formatted is None:
                    continue
                level, text = formatted
                ts = float(event.get("recorded_at") or time.time())
                batch.append((ts, level, text))
        batch.sort(key=lambda item: item[0])
        return batch


async def tail_traces(
    traces_dir: Path, log: JobLog, stop_event: asyncio.Event, interval: float = 0.7
) -> None:
    """Poll `traces_dir` into `log` until `stop_event` fires, then do one last
    poll to catch whatever was written right at the end of the run."""
    tailer = TraceTailer(traces_dir)
    while not stop_event.is_set():
        log.extend(tailer.poll())
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
    log.extend(tailer.poll())
