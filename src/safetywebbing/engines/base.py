"""The engine contract every scan backend shares (ARCHITECTURE.md §6)."""

from __future__ import annotations

import json
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


class ScanFailed(RuntimeError):
    """The agent ran (or was supposed to) but produced no readable summary.json."""


def load_run_result(
    runs_root: Path, run_id: str, *, engine: str, stdout: str, returncode: int | None
) -> RunResult:
    """Read the artifacts an agent run leaves behind. Shared by every engine that
    launches the agent as a process, so Docker and direct runs hand the pipeline
    exactly the same shape (the agent always writes summary.json, even on failure)."""
    summary_path = runs_root / run_id / "summary.json"
    if not summary_path.is_file():
        raise ScanFailed(
            f"no summary.json for {run_id} (agent exit {returncode}).\n{stdout[-2000:]}"
        )
    return RunResult(
        run_id=run_id,
        summary=json.loads(summary_path.read_text(encoding="utf-8")),
        traces_dir=runs_root / run_id / "traces",
        engine=engine,
        raw_stdout=stdout,
    )


class Engine(Protocol):
    """A scan engine. Must not widen scope: it receives an already-validated
    local target and a fixed goal, and only runs the scan."""

    name: str

    async def run(self, *, target: str, goal: str, run_id: str) -> RunResult: ...
