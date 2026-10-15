"""Scan engines. Each engine takes (target, goal) and returns a RunResult.

Implementations:
  - LiveAgentEngine  — runs the PentestGPT agent inside Docker (live scan).
  - ReplayEngine     — replays a saved run (demo mode, no auth, deterministic). [Day 3]
  - ZapEngine        — OWASP ZAP baseline. [later, if time permits]
"""

from .base import Engine, RunResult
from .live import LiveAgentEngine
from .replay import ReplayEngine

__all__ = ["Engine", "LiveAgentEngine", "ReplayEngine", "RunResult"]
