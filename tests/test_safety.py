"""Unit tests for the two safety invariants + container plumbing.

These run without Docker, a network, or any LLM — they pin the deterministic
parts of the pipeline (ARCHITECTURE.md §2).
"""

import json

import pytest

from safetynet.audit import record_scan
from safetynet.config import (
    InvalidRunId,
    TargetNotAllowed,
    goal_for,
    validate_run_id,
    validate_target,
)
from safetynet.engines.live import LiveAgentEngine, target_for_container

# --- Rule 1: whitelist -------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:3000",
        "http://localhost:3000/",
        "https://localhost",
        "http://[::1]:8080",
        "http://127.0.0.5:3000",
    ],
)
def test_local_targets_allowed(url):
    assert validate_target(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "http://10.0.0.5:3000",
        "http://169.254.169.254/",  # cloud metadata — must be blocked
        "ftp://localhost",
        "http://localhost.evil.com",
        "file:///etc/passwd",
    ],
)
def test_remote_targets_blocked(url):
    with pytest.raises(TargetNotAllowed):
        validate_target(url)


# --- Rule 2: fixed scope -----------------------------------------------------

def test_goal_templates_are_fixed():
    assert "SQL" in goal_for("sqli")
    with pytest.raises(ValueError):
        goal_for("../../etc/passwd")  # user cannot inject free-text scope


# --- Path safety: run_id gate (traversal) ------------------------------------

@pytest.mark.parametrize(
    "run_id",
    ["live-abc123", "sqli-claude-03", "r1", "A.B_c-9"],
)
def test_valid_run_ids_pass(run_id):
    assert validate_run_id(run_id) == run_id


@pytest.mark.parametrize(
    "run_id",
    [
        "..",
        "../etc",
        "../../secrets",
        "a/b",
        "a\\b",
        "/abs",
        "C:\\win",
        ".hidden",
        "",
        "x" * 65,  # too long
        "a/../b",
    ],
)
def test_traversal_run_ids_blocked(run_id):
    with pytest.raises(InvalidRunId):
        validate_run_id(run_id)


# --- Rule 5: audit log -------------------------------------------------------

def test_record_scan_appends_jsonl(tmp_path):
    runs = tmp_path / "runs"
    record_scan(runs, event="scan_requested", run_id="live-1",
                target="http://127.0.0.1:3000", goal="g", scan_type="sqli")
    record_scan(runs, event="scan_done", run_id="live-1",
                target="http://127.0.0.1:3000", goal="g", scan_type="sqli",
                status="completed")
    lines = (runs / "audit.log").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["event"] == "scan_requested"
    assert first["run_id"] == "live-1"
    assert first["target"] == "http://127.0.0.1:3000"
    assert "ts" in first
    assert json.loads(lines[1])["status"] == "completed"


# --- Job store eviction (no unbounded growth) --------------------------------

def test_prune_jobs_drops_stale_and_caps_size():
    import time

    from safetynet import api

    api._jobs.clear()
    now = time.time()
    # A fresh running job must survive; an old finished one must be pruned.
    api._jobs["running"] = {"status": "running"}
    api._jobs["old"] = {"status": "done", "finished_at": now - api._JOB_TTL_S - 10}
    api._jobs["recent"] = {"status": "done", "finished_at": now}
    api._prune_jobs()
    assert "running" in api._jobs
    assert "recent" in api._jobs
    assert "old" not in api._jobs

    # Size cap: a flood of finished jobs is evicted down to _MAX_JOBS.
    api._jobs.clear()
    for i in range(api._MAX_JOBS + 50):
        api._jobs[f"j{i}"] = {"status": "done", "finished_at": now + i}
    api._prune_jobs()
    assert len(api._jobs) <= api._MAX_JOBS
    api._jobs.clear()


# --- Container networking translation ----------------------------------------

def test_loopback_rewritten_for_container():
    assert target_for_container("http://127.0.0.1:3000") == "http://host.docker.internal:3000"
    assert target_for_container("http://localhost:3000/x") == "http://host.docker.internal:3000/x"


# --- docker run command shape (no Docker needed) -----------------------------

def test_build_command_mounts_runs_and_translates_target(tmp_path):
    eng = LiveAgentEngine(runs_root=tmp_path / "runs", claude_creds_dir=tmp_path / "nope")
    cmd = eng.build_command(
        target="http://127.0.0.1:3000", goal="Tim SQL injection", run_id="r1"
    )
    assert cmd[0:2] == ["docker", "run"]
    assert "safetynet-agent" in cmd
    # target handed to the agent is the container-visible host
    i = cmd.index("--target")
    assert cmd[i + 1] == "http://host.docker.internal:3000"
    # runs dir is bind-mounted
    assert any("/work/runs" in a for a in cmd)
    # backend fixed to claude
    j = cmd.index("--backend")
    assert cmd[j + 1] == "claude"


def test_build_command_mounts_creds_writable(tmp_path):
    """Credential copy must be mounted read-write so the CLI can refresh the
    OAuth token inside the container (read-only was the exit-1 auth bug)."""
    eng = LiveAgentEngine(runs_root=tmp_path / "runs")
    cmd = eng.build_command(
        target="http://127.0.0.1:3000", goal="g", run_id="r1",
        creds_dir=tmp_path / ".claude", claude_json=tmp_path / ".claude.json",
    )
    joined = " ".join(cmd)
    # Credentials mount into the non-root user's home, never /root.
    assert "/home/agent/.claude" in joined
    assert "/home/agent/.claude.json" in joined
    assert "/root/.claude" not in joined
    # The creds mount must NOT be read-only.
    assert ":/home/agent/.claude:ro" not in joined
    assert ":/home/agent/.claude.json:ro" not in joined


def test_prepare_creds_copies_without_touching_host(tmp_path):
    """_prepare_creds makes an isolated copy; host credentials are untouched."""
    host = tmp_path / "home" / ".claude"
    host.mkdir(parents=True)
    (host / ".credentials.json").write_text('{"token": "secret"}', encoding="utf-8")
    (host.parent / ".claude.json").write_text("{}", encoding="utf-8")

    eng = LiveAgentEngine(runs_root=tmp_path / "runs", claude_creds_dir=host)
    creds_root = eng._prepare_creds()
    try:
        assert creds_root is not None
        copied = creds_root / ".claude" / ".credentials.json"
        assert copied.is_file()
        # It is a real copy, in a different location from the host file.
        assert copied.resolve() != (host / ".credentials.json").resolve()
        assert (creds_root / ".claude.json").is_file()
    finally:
        import shutil as _sh
        if creds_root is not None:
            _sh.rmtree(creds_root, ignore_errors=True)


def test_prepare_creds_none_when_no_host_creds(tmp_path):
    eng = LiveAgentEngine(runs_root=tmp_path / "runs", claude_creds_dir=tmp_path / "absent")
    assert eng._prepare_creds() is None
