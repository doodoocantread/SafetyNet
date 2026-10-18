"""LiveAgentEngine — run the vendored PentestGPT agent inside Docker.

The agent runs with FULL_ACCESS, so it only ever runs inside a container; the
container is the isolation boundary (ARCHITECTURE.md §2.3). This class never
imports the agent or unified-agent — it shells out to `docker run`.

Two integration seams handled here (ARCHITECTURE.md §7):
  - Auth: the "claude" backend authenticates with the host's Claude Code OAuth
    session. The access token expires every few hours, and the CLI refreshes it
    in place — so the credential dir must be WRITABLE inside the container. We do
    NOT give a FULL_ACCESS pentest container write access to the host's real
    credentials; instead each run gets an ephemeral COPY of just the credential
    files, mounted read-write and deleted afterwards. The container can refresh
    its own copy; the host credentials are never exposed to agent writes.
  - Networking: a loopback target (127.0.0.1 / localhost) means the *host* from
    the user's point of view, but inside the container loopback is the container
    itself. We translate the host to `host.docker.internal` for the container.
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .base import RunResult, ScanFailed, load_run_result  # noqa: F401 - ScanFailed re-exported

# Target host as seen from inside the container (Docker Desktop / host-gateway).
_CONTAINER_HOST = "host.docker.internal"

# Home of the non-root container user (see agent_image/Dockerfile). Credentials
# are mounted here, not into /root — Claude Code refuses to run as root.
_CONTAINER_HOME = "/home/agent"


def container_name(run_id: str) -> str:
    """Deterministic `docker run --name`. Without a name there is nothing to
    `docker kill` on cancel/timeout — the client process can be killed, but
    `docker run` (attached, no `-d`) does not forward SIGKILL to the container,
    so the scan would keep running after the user "cancelled" it."""
    return f"safetynet-{run_id}"


def target_for_container(url: str) -> str:
    """Rewrite a loopback target to the address the container uses to reach the
    host. Port, scheme and path are preserved."""
    parts = urlsplit(url)
    host = (parts.hostname or "").strip("[]").lower()
    if host in ("localhost", "127.0.0.1", "::1") or host.startswith("127."):
        netloc = _CONTAINER_HOST
        if parts.port:
            netloc = f"{_CONTAINER_HOST}:{parts.port}"
        parts = parts._replace(netloc=netloc)
    return urlunsplit(parts)


@dataclass
class LiveAgentEngine:
    """Runs one scan per call. Inputs are already validated by config.py."""

    name: str = "live"
    image: str = "safetynet-agent"
    runs_root: Path = Path("runs")
    # Host directory holding Claude Code credentials, mounted read-only.
    claude_creds_dir: Path = Path.home() / ".claude"
    backend: str = "claude"
    model: str | None = None
    max_decisions: int = 20
    timeout_s: float = 600.0

    def build_command(
        self,
        *,
        target: str,
        goal: str,
        run_id: str,
        creds_dir: Path | None = None,
        claude_json: Path | None = None,
    ) -> list[str]:
        """The exact `docker run` argv. Pure function — unit-testable without Docker.

        `creds_dir` / `claude_json`, when given, are an EPHEMERAL copy of the
        host credentials (see `_prepare_creds`); they are mounted read-write so
        the Claude CLI can refresh its OAuth token inside the container.
        """
        runs_abs = str(self.runs_root.resolve())
        cmd = [
            "docker", "run", "--rm",
            # So a cancel/timeout can `docker kill` the real container, not just
            # the attached CLI client (see container_name()).
            "--name", container_name(run_id),
            # Reach the host's loopback services from inside the container.
            "--add-host", "host.docker.internal:host-gateway",
            # Persist runs/ back to the host so the backend can read results.
            "-v", f"{runs_abs}:/work/runs",
        ]
        # Writable (NOT :ro) so the CLI can persist a refreshed access token.
        if creds_dir is not None:
            cmd += ["-v", f"{creds_dir.resolve()!s}:{_CONTAINER_HOME}/.claude"]
        if claude_json is not None:
            cmd += ["-v", f"{claude_json.resolve()!s}:{_CONTAINER_HOME}/.claude.json"]
        cmd += [
            self.image,
            "--goal", goal,
            "--target", target_for_container(target),
            "--backend", self.backend,
            "--run-id", run_id,
            "--runs-root", "/work/runs",
            "--workspace-root", "/work/agent-workspaces",
            "--max-decisions", str(self.max_decisions),
        ]
        if self.model:
            cmd += ["--model", self.model]
        return cmd

    def _prepare_creds(self) -> Path | None:
        """Copy the host's Claude credential files into a fresh temp dir so the
        container can refresh its OAuth token without touching host creds.

        Returns the temp root (containing `.claude/` and optionally
        `.claude.json`), or None when no credentials are present on the host.
        The caller must delete the returned dir after the run.
        """
        src = self.claude_creds_dir
        cred_file = src / ".credentials.json"
        if not cred_file.is_file():
            return None
        tmp_root = Path(tempfile.mkdtemp(prefix="safetynet-creds-"))
        claude_dir = tmp_root / ".claude"
        claude_dir.mkdir()
        shutil.copy2(cred_file, claude_dir / ".credentials.json")
        # settings.json is small and harmless; carry it so CLI prefs apply.
        settings = src / "settings.json"
        if settings.is_file():
            shutil.copy2(settings, claude_dir / "settings.json")
        host_json = src.parent / ".claude.json"
        if host_json.is_file():
            shutil.copy2(host_json, tmp_root / ".claude.json")
        return tmp_root

    async def _kill_container(self, run_id: str) -> None:
        """Best-effort `docker kill` on the named container. Needed on both the
        timeout path and a user cancel: killing the attached `docker run` CLI
        client alone leaves the container running (see container_name())."""
        try:
            killer = await asyncio.create_subprocess_exec(
                "docker", "kill", container_name(run_id),
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            await killer.wait()
        except OSError:
            pass  # docker CLI missing/unreachable — nothing more we can do here

    async def run(self, *, target: str, goal: str, run_id: str) -> RunResult:
        creds_root = self._prepare_creds()
        creds_dir = (creds_root / ".claude") if creds_root else None
        claude_json = creds_root / ".claude.json" if creds_root else None
        if claude_json is not None and not claude_json.is_file():
            claude_json = None
        try:
            cmd = self.build_command(
                target=target, goal=goal, run_id=run_id,
                creds_dir=creds_dir, claude_json=claude_json,
            )
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            try:
                raw, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_s)
            except TimeoutError:
                await self._kill_container(run_id)
                proc.kill()
                await proc.wait()
                raise ScanFailed(f"scan {run_id} timed out after {self.timeout_s}s") from None
            except asyncio.CancelledError:
                # The user cancelled: stop the container for real, then let the
                # cancellation keep propagating so the caller sees it as cancelled.
                await self._kill_container(run_id)
                proc.kill()
                await proc.wait()
                raise
            stdout = raw.decode("utf-8", errors="replace")
            # The agent always writes summary.json, even on failure (trial.run_trial).
            return load_run_result(
                self.runs_root, run_id, engine=self.name,
                stdout=stdout, returncode=proc.returncode,
            )
        finally:
            if creds_root is not None:
                shutil.rmtree(creds_root, ignore_errors=True)
