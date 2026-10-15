"""Pipeline orchestration: RunResult → Report (ARCHITECTURE.md §5).

engine output → adapter (fact) → labeler (narrative) → Report.
"""

from __future__ import annotations

import os

from .adapter import adapt
from .engines.base import RunResult
from .labeling import HeuristicLabeler, Labeler, label_findings
from .models import Report


def default_labeler() -> Labeler:
    """LLM labeler when a key is set, else the offline heuristic one."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        from .labeling_llm import LLMLabeler

        model = os.environ.get("SAFETYNET_LLM_MODEL", "claude-opus-5-5")
        return LLMLabeler(model=model)
    return HeuristicLabeler()


def build_report(result: RunResult, labeler: Labeler | None = None) -> Report:
    labeler = labeler or default_labeler()
    findings = adapt(result.summary, result.traces_dir)
    findings = label_findings(findings, labeler)
    s = result.summary
    return Report(
        run_id=result.run_id,
        goal=s.get("goal", ""),
        targets=list(s.get("targets", [])),
        status=result.status,
        engine=result.engine,
        cost_usd=float(s.get("cost_usd", 0) or 0),
        wall_duration_s=float(s.get("wall_duration_s", 0) or 0),
        error=s.get("error"),
        findings=findings,
        labeled_by=getattr(labeler, "name", "unknown"),
    )
