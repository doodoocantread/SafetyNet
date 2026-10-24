"""Scan engines. Each engine takes (target, goal) and returns a RunResult.

Implementations:
  - LiveAgentEngine  — runs a pentest-agent container inside Docker (live scan).
                       WHICH agent is a per-scan choice (config.AGENTS): the engine
                       just swaps the image + auth. Every agent writes the same
                       summary.json + traces/, so the pipeline below is identical.
  - LocalAgentEngine — the same PentestGPT CLI as a host process (opt-in "direct").
  - ReplayEngine     — replays a saved run (demo mode, no auth, deterministic).
"""

from .base import Engine, RunResult
from .live import LiveAgentEngine
from .replay import ReplayEngine

__all__ = ["Engine", "LiveAgentEngine", "ReplayEngine", "RunResult"]
