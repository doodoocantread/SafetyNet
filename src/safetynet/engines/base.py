"""The engine contract every scan backend shares (ARCHITECTURE.md §6)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class RunResult:
    """Structured output of one scan, consumed by the adapter.

    `summary` is the parsed summary.json. `traces_dir` points at the run's
    traces/ directory (joined with summary by the adapter to recover the
    request/payload behind each observation). Both are raw FACT — no LLM yet.
    """

    run_id: str
    summary: dict[str, Any]
    traces_dir: Path
    engine: str
    raw_stdout: str = field(default="", repr=False)

    @property
    def status(self) -> str:
        return str(self.summary.get("status", "error"))

    @property
    def completed(self) -> bool:
        return self.status == "completed"


class Engine(Protocol):
    """A scan engine. Must not widen scope: it receives an already-validated
    local target and a fixed goal, and only runs the scan."""

    name: str

    async def run(self, *, target: str, goal: str, run_id: str) -> RunResult: ...
