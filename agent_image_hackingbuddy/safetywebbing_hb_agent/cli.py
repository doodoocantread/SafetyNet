"""SafetyWebbing ⇄ hackingBuddyGPT wrapper CLI.

This is the entrypoint of the ``safetywebbing-hackingbuddy`` Docker image. It presents
the SAME command-line contract as the PentestGPT agent image (``--goal --target
--run-id --runs-root …``) and writes the SAME on-disk result (``runs/<run_id>/
summary.json`` + ``traces/``), so SafetyWebbing's engine and pipeline treat the two
agents identically. Internally it:

  1. maps the SafetyWebbing request onto hackingBuddyGPT's ``WebTestingWithExplanation``
     web use-case (``wintermute WebTestingWithExplanation --host … --hints …``);
  2. resolves an LLM for litellm from the environment (hackingBuddy does not use
     the Claude Code CLI that PentestGPT uses — see the model note below);
  3. runs it, then translates the run's JSONL span log into summary.json + traces
     via :mod:`safetywebbing_hb_agent.translate`.

Model note: PentestGPT takes a Claude Code model id (``claude-sonnet-5-5``);
hackingBuddy takes a *litellm* model string (``anthropic/claude-3-5-sonnet-latest``,
``openrouter/…``, ``gpt-4o``). They are not interchangeable, so the litellm model
is resolved from ``SAFETYWEBBING_HB_LLM_MODEL`` (preferred), or a ``--model`` already in
litellm form, or a per-provider default chosen from whichever API key is present.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from .translate import translate

_USECASE = "WebTestingWithExplanation"

# Provider API keys, in the order we prefer them, with the default litellm model
# and api_base to use when the operator did not pin one via SAFETYWEBBING_HB_LLM_MODEL.
_PROVIDERS = [
    ("ANTHROPIC_API_KEY", "anthropic/claude-3-5-sonnet-latest", None),
    ("GEMINI_API_KEY", "gemini/gemini-1.5-pro", None),
    ("OPENAI_API_KEY", "gpt-4o", None),
    ("OPENROUTER_API_KEY", "openrouter/anthropic/claude-3.5-sonnet", "https://openrouter.ai/api"),
]


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="safetywebbing-hackingbuddy-agent")
    # The PentestGPT-image contract. Unused-by-hackingBuddy args are accepted and
    # ignored so a single engine can launch either image with one argv shape.
    for a in ("--goal", "--target", "--backend", "--model", "--run-id", "--runs-root",
              "--workspace-root"):
        p.add_argument(a)
    p.add_argument("--max-decisions", type=int, default=20)
    return p.parse_args(argv)


def _resolve_llm(model_arg: str | None) -> tuple[str, str, str | None]:
    """Return ``(api_key, litellm_model, api_base|None)`` for litellm, or exit if
    no provider key is set (the engine should have gated this, but be explicit)."""
    api_key = ""
    provider_env: str | None = None
    provider_model: str | None = None
    provider_base: str | None = None
    for env_name, default_model, default_base in _PROVIDERS:
        if os.environ.get(env_name):
            api_key = os.environ[env_name]
            provider_env, provider_model, provider_base = env_name, default_model, default_base
            break
    if not api_key:
        sys.exit(
            "no LLM API key in environment; set one of "
            + ", ".join(name for name, _, _ in _PROVIDERS)
        )

    # Resolve the litellm model string. Precedence: an explicit SAFETYWEBBING_HB_LLM_MODEL,
    # then --model (a Claude Code id like `claude-sonnet-5-5` is mapped onto the
    # Anthropic API so the UI's model field "just works" with Claude; an id that is
    # already litellm-format is used as-is), else the provider's default.
    model = os.environ.get("SAFETYWEBBING_HB_LLM_MODEL") or ""
    if not model and model_arg:
        if "/" in model_arg:
            model = model_arg  # already a litellm-format string (e.g. anthropic/…)
        elif model_arg.startswith("claude-") and provider_env == "ANTHROPIC_API_KEY":
            model = f"anthropic/{model_arg}"  # Claude id → Anthropic API via litellm
        elif model_arg.startswith("gemini-") and provider_env == "GEMINI_API_KEY":
            model = f"gemini/{model_arg}"  # Gemini id → Google AI Studio via litellm
        elif provider_env == "OPENAI_API_KEY":
            model = model_arg  # bare OpenAI ids (gpt-4o, …) are already litellm-valid
    if not model:
        model = provider_model or ""
    api_base = os.environ.get("SAFETYWEBBING_HB_LLM_API_BASE") or provider_base
    return api_key, model, api_base


def _write_env_file(cwd: Path, api_key: str) -> None:
    """Keep the secret off the argv: hackingBuddy reads llm.api_key from .env in CWD."""
    (cwd / ".env").write_text(f"llm.api_key={api_key}\n", encoding="utf-8")


def _build_wintermute_cmd(
    *, target: str, goal: str, model: str, api_base: str | None, max_rounds: int, log_dir: Path,
    run_id: str, context_size: str,
) -> list[str]:
    cmd = [
        "wintermute", _USECASE,
        f"--host={target}",
        f"--llm.model={model}",
        f"--llm.context_size={context_size}",
        f"--limits.max_rounds={max_rounds}",
        f"--log.log_dir={log_dir}",
        f"--log.tag={run_id}",
    ]
    if goal:
        # Steer the flag-hunting web agent toward the fixed SafetyWebbing scan goal.
        cmd.append(f"--hints={goal}")
    if api_base:
        cmd.append(f"--llm.api_base={api_base}")
    return cmd


def _newest_log(log_dir: Path) -> Path | None:
    logs = sorted(glob.glob(str(log_dir / "log-*.jsonl")), key=os.path.getmtime)
    return Path(logs[-1]) if logs else None


def _load_spans(path: Path) -> list[dict]:
    spans = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                spans.append(json.loads(line))
            except ValueError:
                continue
    return spans


def _write_result(runs_root: Path, run_id: str, summary: dict, traces: dict) -> None:
    run_dir = runs_root / run_id
    traces_dir = run_dir / "traces"
    traces_dir.mkdir(parents=True, exist_ok=True)
    for episode, events in traces.items():
        ep_dir = traces_dir / episode
        ep_dir.mkdir(parents=True, exist_ok=True)
        with (ep_dir / "events.jsonl").open("w", encoding="utf-8") as fh:
            for event in events:
                fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    (run_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _failed_summary(run_id: str, goal: str, target: str, error: str) -> dict:
    return {
        "run_id": run_id, "goal": goal, "targets": [target], "status": "error",
        "backend": "hackingbuddy", "model": None, "cost_usd": 0.0, "wall_duration_s": 0.0,
        "error": error, "tasks": [], "attempts": [], "observations": [],
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    run_id = args.run_id
    goal = args.goal or ""
    target = args.target or ""
    runs_root = Path(args.runs_root or "runs")

    # Always leave a summary.json behind, even on failure, so the engine's
    # load_run_result never raises ScanFailed for a run that actually started.
    try:
        api_key, model, api_base = _resolve_llm(args.model)
        context_size = os.environ.get("SAFETYWEBBING_HB_LLM_CONTEXT_SIZE", "30000")

        workspace = Path(args.workspace_root) if args.workspace_root else runs_root.parent
        workspace.mkdir(parents=True, exist_ok=True)
        cwd = Path(tempfile.mkdtemp(prefix=f"hb-{run_id}-", dir=str(workspace)))
        log_dir = cwd / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        _write_env_file(cwd, api_key)

        cmd = _build_wintermute_cmd(
            target=target, goal=goal, model=model, api_base=api_base,
            max_rounds=args.max_decisions, log_dir=log_dir, run_id=run_id,
            context_size=context_size,
        )
        print(f"[safetywebbing-hb] running: {' '.join(cmd)}", flush=True)
        # Fixed argv, no shell; we inspect the result ourselves rather than raising.
        proc = subprocess.run(cmd, cwd=str(cwd), check=False)

        log_path = _newest_log(log_dir)
        if log_path is None:
            _write_result(
                runs_root, run_id,
                _failed_summary(run_id, goal, target,
                                f"hackingBuddy produced no log (exit {proc.returncode})"),
                {},
            )
            return 1

        spans = _load_spans(log_path)
        summary, traces = translate(
            spans, run_id=run_id, goal=goal, target=target, model=model,
        )
        _write_result(runs_root, run_id, summary, traces)
        print(f"[safetywebbing-hb] wrote summary.json (status={summary['status']})", flush=True)
        return 0 if summary["status"] != "error" else 1
    except Exception as exc:  # noqa: BLE001 - must still leave a readable summary
        import traceback

        traceback.print_exc()
        _write_result(runs_root, run_id, _failed_summary(run_id, goal, target, str(exc)), {})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
