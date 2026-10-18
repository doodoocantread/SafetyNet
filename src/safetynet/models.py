"""Data models shared across the pipeline (ARCHITECTURE.md §6).

Two layers, kept separate on purpose:
  - FACT (from the adapter, deterministic): request, response, task context.
  - NARRATIVE (from the labeler, LLM or heuristic): vuln class, severity, CWE,
    OWASP, explanation, remediation. Every narrative field is nullable until a
    labeler fills it, so the UI can always render facts even with no LLM.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def rank(self) -> int:
        order = ["info", "low", "medium", "high", "critical"]
        return order.index(self.value)


class Label(BaseModel):
    """Narrative layer — produced by a labeler, never by the adapter."""

    vuln_class: str
    severity: Severity
    cwe: str | None = None
    owasp: str | None = None
    explanation: str = ""
    # Why THIS finding was flagged: the concrete signals in its own request/response
    # (payload seen, status code, marker in the body) — not a generic class blurb.
    rationale: list[str] = Field(default_factory=list)
    remediation: str = ""
    confidence: str = "medium"  # low | medium | high
    labeled_by: str = "unknown"  # "heuristic" or "llm:<model>"


class Finding(BaseModel):
    """One joined observation. Fact fields are always present; `label` is the
    narrative, attached later."""

    id: str
    task_id: str | None = None
    task_kind: str | None = None
    target: str | None = None

    # FACT — recovered by joining summary.json observation with traces/.
    request: str | None = None  # the exact command/curl the executor ran
    response: str = ""  # the raw HTTP response (observation.statement)
    is_error: bool = False
    evidence_sequences: list[int] = Field(default_factory=list)
    trace_episode_id: str | None = None
    # The agent's own summary of the attempt that produced this observation
    # (summary.json attempts[].summary). Written by an LLM that read untrusted web
    # content — shown as the agent's claim, never treated as verified fact.
    agent_note: str | None = None

    # NARRATIVE — None until labeled.
    label: Label | None = None


class Report(BaseModel):
    """The full report for one run."""

    run_id: str
    goal: str
    targets: list[str]
    status: str  # completed | failed | error
    engine: str
    cost_usd: float = 0.0
    wall_duration_s: float = 0.0
    error: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    labeled_by: str = "none"

    @property
    def conclusive(self) -> bool:
        """A failed/errored run is NOT 'no vulnerabilities' — it is inconclusive."""
        return self.status == "completed"
