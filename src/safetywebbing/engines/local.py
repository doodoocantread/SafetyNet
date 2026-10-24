"""LocalAgentEngine — run the vendored PentestGPT agent directly on the host.

This is the "direct" mode: the same `pentestgpt-agent` CLI that the Docker image
runs, started as a plain subprocess against the original loopback target. There is
NO container, so the FULL_ACCESS agent shares the user's machine, files and network
(ARCHITECTURE.md §2.3 is deliberately not met). It is for fast local iteration on a
trusted dev box; config.validate_mode gates it behind a server-side opt-in.

Like LiveAgentEngine it never imports the agent or unified-agent — the agent lives
in its own environment and the only contract is summary.json + traces/ on disk.

Differences from the Docker engine, all consequences of having no container:
  - Target is used as-is (no host.docker.internal rewrite): loopback is the host.
  - Auth is the host's own, already logged-in Claude Code — nothing to copy.
  - A timeout must kill the whole process tree (claude, node, curl…), not just the
    launcher, otherwise the agent keeps running after we report failure.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import shutil
import signal
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .base import RunResult, ScanFailed, load_run_result

AGENT_CMD_ENV = "SAFETYWEBBING_AGENT_CMD"
_AGENT_EXE = "pentestgpt-agent"

# Mirrors the ENV block of agent_image/Dockerfile.
_AGENT_ENV_DEFAULTS = {
    "PYTHONUNBUFFERED": "1",
    "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    "DISABLE_AUTOUPDATER": "1",
}
# The host app may hold this for the LLM labeler. The Docker agent never sees it, so
# the direct agent must not either: it reads untrusted web content (prompt injection).
_SCRUBBED_ENV = ("ANTHROPIC_API_KEY",)


def resolve_agent_command(
    search_dirs: tuple[Path, ...] = (), env: Mapping[str, str] | None = None
) -> list[str] | None:
    """Find the argv prefix that launches the agent CLI, or None.

    Order: $SAFETYWEBBING_AGENT_CMD (may be several words, e.g. `uv run --project
    agent_image pentestgpt-agent`) → a dedicated `.agent-venv` in `search_dirs`
    → `pentestgpt-agent` on PATH.
    """
    env = os.environ if env is None else env
    explicit = (env.get(AGENT_CMD_ENV) or "").strip()
    if explicit:
        posix = os.name != "nt"
        return [t.strip('"') for t in shlex.split(explicit, posix=posix)]
    bin_dir, exe = ("Scripts", f"{_AGENT_EXE}.exe") if os.name == "nt" else ("bin", _AGENT_EXE)
    for base in search_dirs:
        candidate = base / ".agent-venv" / bin_dir / exe
        if candidate.is_file():
            return [str(candidate)]
    found = shutil.which(_AGENT_EXE)
    return [found] if found else None


def agent_env(base: Mapping[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if base is None else base)
    for key in _SCRUBBED_ENV:
        env.pop(key, None)
    env.update(_AGENT_ENV_DEFAULTS)
    return env


async def _kill_tree(proc: asyncio.subprocess.Process) -> None:
    """Terminate `proc` and everything it spawned."""
    if proc.returncode is not None:
        return
    if sys.platform == "win32":
        killer = await asyncio.create_subprocess_exec(
            "taskkill", "/PID", str(proc.pid), "/T", "/F",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await killer.wait()
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)  # started with start_new_session=True
        except ProcessLookupError:
            pass
    try:
        proc.kill()  # no-op if the tree kill already got it
    except ProcessLookupError:
        pass
    await proc.wait()


@dataclass
class LocalAgentEngine:
    """Runs one scan per call. Inputs are already validated by config.py."""

    name: str = "direct"
    runs_root: Path = Path("runs")
    # Extra places to look for `.agent-venv` (the repo root, normally).
    search_dirs: tuple[Path, ...] = ()
    agent_cmd: list[str] | None = None  # explicit override; skips discovery
    backend: str = "claude"
    model: str | None = None
    max_decisions: int = 20
    timeout_s: float = 600.0

    def command(self) -> list[str] | None:
        return self.agent_cmd or resolve_agent_command(self.search_dirs)

    @property
    def workspace_root(self) -> Path:
        # Next to runs/, not inside it, so it never shows up as a scan result.
        return self.runs_root.resolve().parent / "agent-workspaces"

    def build_command(self, *, target: str, goal: str, run_id: str) -> list[str]:
        """The exact argv. Pure given a resolvable agent command — unit-testable."""
        prefix = self.command()
        if not prefix:
            raise ScanFailed(
                f"agent CLI not found. Install it (`uv venv .agent-venv && uv pip install "
                f"--python .agent-venv ./agent_image`) or set {AGENT_CMD_ENV}."
            )
        cmd = [
            *prefix,
            "--goal", goal,
            "--target", target,  # loopback is the host here: no rewrite
            "--backend", self.backend,
            "--run-id", run_id,
            "--runs-root", str(self.runs_root.resolve()),
            "--workspace-root", str(self.workspace_root),
            "--max-decisions", str(self.max_decisions),
        ]
        if self.model:
            cmd += ["--model", self.model]
        return cmd

    async def run(self, *, target: str, goal: str, run_id: str) -> RunResult:
        cmd = self.build_command(target=target, goal=goal, run_id=run_id)
        self.runs_root.mkdir(parents=True, exist_ok=True)
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=agent_env(),
            cwd=str(self.workspace_root.parent),
            start_new_session=(sys.platform != "win32"),  # own process group for killpg
        )
        try:
            raw, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_s)
        except TimeoutError:
            await _kill_tree(proc)
            raise ScanFailed(f"scan {run_id} timed out after {self.timeout_s}s") from None
        except asyncio.CancelledError:
            await _kill_tree(proc)
            raise
        return load_run_result(
            self.runs_root, run_id, engine=self.name,
            stdout=raw.decode("utf-8", errors="replace"), returncode=proc.returncode,
        )
