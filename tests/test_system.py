"""System health + audit tail (system.py and its endpoints)."""

import json

import pytest

from safetynet import api, system
from safetynet.audit import record_scan
from safetynet.config import DIRECT_MODE_ENV


@pytest.fixture(autouse=True)
def _no_real_docker(monkeypatch):
    """Never shell out to the developer's actual Docker from a unit test."""
    monkeypatch.setattr(system, "_docker_cache", {"at": 0.0, "key": None, "value": None})
    monkeypatch.setattr(system.shutil, "which", lambda name: None)


def test_docker_missing_is_reported_not_raised():
    d = system.docker_status("safetynet-agent")
    assert (d["installed"], d["daemon"], d["image_built"], d["ok"]) == (False, False, False, False)


def test_docker_reports_each_layer(monkeypatch):
    monkeypatch.setattr(system.shutil, "which", lambda name: "/usr/bin/docker")
    calls = []

    def fake_run(argv):
        calls.append(argv[1])
        ok = system.subprocess.CompletedProcess(argv, 0, stdout="27.1\n", stderr="")
        bad = system.subprocess.CompletedProcess(argv, 1, stdout="", stderr="no such image")
        return ok if argv[1] == "info" else bad

    monkeypatch.setattr(system, "_run", fake_run)
    d = system.docker_status("safetynet-agent")
    assert (d["installed"], d["daemon"], d["server_version"]) == (True, True, "27.1")
    assert (d["image_built"], d["ok"]) == (False, False)
    system.docker_status("safetynet-agent")
    assert calls == ["info", "image"]          # second call served from the short cache


def test_docker_daemon_down_skips_image_check(monkeypatch):
    monkeypatch.setattr(system.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(system, "_run", lambda argv: None)  # timeout / OSError
    d = system.docker_status("safetynet-agent")
    assert (d["installed"], d["daemon"], d["image_built"]) == (True, False, False)


def test_labeler_states(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert system.labeler_status()["effective"] == "heuristic"

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret-value")
    monkeypatch.setattr(system.importlib.util, "find_spec", lambda name: None)
    st = system.labeler_status()
    assert (st["effective"], st["sdk_installed"]) == ("heuristic", False)
    assert "anthropic" in st["note"]

    monkeypatch.setattr(system.importlib.util, "find_spec", lambda name: object())
    monkeypatch.setenv("SAFETYNET_LLM_MODEL", "claude-haiku-5-5")
    st = system.labeler_status()
    assert (st["effective"], st["model"]) == ("llm", "claude-haiku-5-5")
    assert "sk-secret-value" not in json.dumps(st)       # a bool, never the key


def test_recent_audit_is_newest_first_and_whitelists_fields(tmp_path):
    for i in range(3):
        record_scan(tmp_path, event="scan_requested", run_id=f"live-{i}", target="t", goal="g",
                    scan_type="sqli", mode="docker", secret_extra="nope")
    out = system.recent_audit(tmp_path, limit=2)
    assert [e["run_id"] for e in out] == ["live-2", "live-1"]
    assert "secret_extra" not in out[0] and "goal" not in out[0]
    assert system.recent_audit(tmp_path / "missing") == []


def test_status_shape_and_counts(tmp_path, monkeypatch):
    monkeypatch.setenv(DIRECT_MODE_ENV, "1")
    record_scan(tmp_path, event="scan_requested", run_id="live-a", target="t", goal="g",
                scan_type="sqli")
    (tmp_path / "live-a").mkdir()
    (tmp_path / "live-a" / "report.json").write_text("{}", encoding="utf-8")
    st = system.system_status(
        runs_root=tmp_path, docker_image="img", agent_command=["C:/x/pentestgpt-agent.exe", "--secret"],
        max_concurrent=2, jobs={"1": {"status": "running"}, "2": {"status": "done"},
                                "3": {"status": "done"}},
        app_version="9.9",
    )
    assert st["direct"] == {"enabled": True, "env": DIRECT_MODE_ENV, "agent_found": True,
                            "agent_cmd": "C:/x/pentestgpt-agent.exe"}
    assert st["storage"]["runs"] == 1 and st["storage"]["cached_reports"] == 1
    assert st["storage"]["audit_entries"] == 1 and st["storage"]["audit_bytes"] > 0
    assert st["jobs"] == {"running": 1, "done": 2}
    assert {s["key"] for s in st["scope"]["scan_types"]} == {"sqli", "xss", "auth", "general"}
    assert st["limits"]["max_concurrent_scans"] == 2


def test_status_with_no_runs_dir_and_no_agent(tmp_path):
    st = system.system_status(runs_root=tmp_path / "nope", docker_image="img", agent_command=None,
                              max_concurrent=2, jobs={}, app_version="1")
    assert st["storage"]["runs"] == 0 and st["direct"]["agent_found"] is False
    assert st["direct"]["agent_cmd"] is None


def test_endpoints(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "_LIVE_RUNS", tmp_path)
    record_scan(tmp_path, event="scan_requested", run_id="live-a", target="t", goal="g",
                scan_type="sqli")
    assert api.system()["storage"]["audit_entries"] == 1
    assert api.audit_log(limit=10)[0]["run_id"] == "live-a"
