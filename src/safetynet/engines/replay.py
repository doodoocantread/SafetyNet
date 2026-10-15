"""ReplayEngine — replay a saved run through the same pipeline.

No Docker, no network, no LLM, no cost, fully deterministic. This is what powers
demo mode and lets the whole report pipeline be built and tested without a live
target (ARCHITECTURE.md §6). It reads exactly the artifacts a live run writes:
runs/<id>/summary.json + runs/<id>/traces/.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .base import RunResult


@dataclass
class ReplayEngine:
    name: str = "replay"
    runs_root: Path = Path("samples/runs")

    def list_runs(self) -> list[str]:
        if not self.runs_root.is_dir():
            return []
        return sorted(
            p.name for p in self.runs_root.iterdir()
            if (p / "summary.json").is_file()
        )

    async def run(self, *, target: str, goal: str, run_id: str) -> RunResult:
        """`target`/`goal` are ignored — a replay just loads run_id's artifacts."""
        return self.load(run_id)

    def load(self, run_id: str) -> RunResult:
        run_dir = self.runs_root / run_id
        summary_path = run_dir / "summary.json"
        if not summary_path.is_file():
            raise FileNotFoundError(f"no saved run {run_id!r} under {self.runs_root}")
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        return RunResult(
            run_id=run_id,
            summary=summary,
            traces_dir=run_dir / "traces",
            engine=self.name,
        )
