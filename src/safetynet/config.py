"""Safety invariants and scan scope, expressed as code (ARCHITECTURE.md §2).

Two hard rules live here:
  1. Whitelist gate — only local targets may ever be scanned.
  2. Fixed scope — a scan type maps to a goal template written here, never to
     free text from the user. The agent does not choose what to look for.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

# --- Rule 1: target whitelist ------------------------------------------------

_ALLOWED_HOSTNAMES = frozenset({"localhost"})


def _is_loopback_host(host: str) -> bool:
    host = host.strip("[]").lower()  # strip IPv6 brackets
    if host in _ALLOWED_HOSTNAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class TargetNotAllowed(ValueError):
    """Raised when a target is outside the local whitelist."""


def validate_target(url: str) -> str:
    """Return a normalized URL if it is a local target, else raise.

    Accepts only http/https on a loopback host (localhost, 127.0.0.0/8, ::1).
    This is the single gate every scan must pass before anything is spawned.
    """
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https"):
        raise TargetNotAllowed(f"scheme must be http/https, got {parts.scheme!r}")
    if not parts.hostname:
        raise TargetNotAllowed("target has no host")
    if not _is_loopback_host(parts.hostname):
        raise TargetNotAllowed(
            f"only local targets are allowed (localhost / 127.0.0.0/8 / ::1), got {parts.hostname!r}"
        )
    return parts.geturl()


# --- Rule 2: fixed scan scope ------------------------------------------------


@dataclass(frozen=True)
class ScanType:
    key: str
    label: str
    goal: str  # goal template handed verbatim to the agent


SCAN_TYPES: dict[str, ScanType] = {
    "sqli": ScanType(
        key="sqli",
        label="SQL Injection",
        goal="Tim SQL injection tren web app duoc phep kiem thu.",
    ),
    "xss": ScanType(
        key="xss",
        label="Cross-Site Scripting (XSS)",
        goal="Tim cac lo hong Cross-Site Scripting tren web app duoc phep kiem thu.",
    ),
    "auth": ScanType(
        key="auth",
        label="Broken Authentication / Access Control",
        goal="Tim cac lo hong xac thuc va kiem soat truy cap tren web app duoc phep kiem thu.",
    ),
    "general": ScanType(
        key="general",
        label="General vulnerability assessment",
        goal="Danh gia web app duoc phep kiem thu de tim cac lo hong khai thac duoc.",
    ),
}


def goal_for(scan_type: str) -> str:
    try:
        return SCAN_TYPES[scan_type].goal
    except KeyError:
        valid = ", ".join(sorted(SCAN_TYPES))
        raise ValueError(f"unknown scan_type {scan_type!r}; valid: {valid}") from None


# --- Rule 3: execution mode --------------------------------------------------
#
# "docker" is the default and the only mode that keeps the isolation boundary
# (ARCHITECTURE.md §2.3). "direct" runs the FULL_ACCESS agent as an ordinary host
# process: no container, so a prompt-injected agent can touch the whole machine.
# It therefore needs an explicit opt-in set by whoever starts the SERVER — it can
# never be switched on from the request body or the UI.

DIRECT_MODE_ENV = "SAFETYNET_ALLOW_DIRECT"
MODES = ("docker", "direct")


class ModeNotAllowed(ValueError):
    """Raised for an unknown mode, or for `direct` when the server did not opt in."""


def direct_mode_enabled() -> bool:
    return os.environ.get(DIRECT_MODE_ENV, "").strip().lower() in ("1", "true", "yes")


def validate_mode(mode: str) -> str:
    if mode not in MODES:
        raise ModeNotAllowed(f"unknown mode {mode!r}; valid: {', '.join(MODES)}")
    if mode == "direct" and not direct_mode_enabled():
        raise ModeNotAllowed(
            f"direct mode is disabled. It runs the agent WITHOUT a container; start the "
            f"server with {DIRECT_MODE_ENV}=1 to opt in."
        )
    return mode


# --- Agent model ---------------------------------------------------------------

# The model name lands in the agent's argv (`--model <name>`), so it must be a plain
# model id: no leading dash (option injection), no whitespace, no shell/path chars.
_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:\[\]-]{0,63}")


class InvalidModel(ValueError):
    """Raised when a requested model name is not a plain model id."""


def validate_model(model: str | None) -> str | None:
    """Return a safe model id, or None to use the agent's default."""
    if model is None or not model.strip():
        return None
    model = model.strip()
    if not _MODEL_RE.fullmatch(model):
        raise InvalidModel(f"invalid model {model!r}")
    return model


# --- Agent timeout ---------------------------------------------------------------

# Bounds on the per-scan wall-clock budget. The agent is FULL_ACCESS, so an
# unbounded timeout is itself a safety knob (esp. in `direct` mode, with no
# container to fall back on) — never let a request set an unlimited one.
_DEFAULT_TIMEOUT_S = 600.0
_MIN_TIMEOUT_S = 30.0
_MAX_TIMEOUT_S = 3600.0  # 1h hard ceiling regardless of what the request asks for


class InvalidTimeout(ValueError):
    """Raised when a requested timeout is not a finite number in range."""


def validate_timeout(timeout_s: float | None) -> float:
    """Return a safe timeout in seconds, or the default when none was requested."""
    if timeout_s is None:
        return _DEFAULT_TIMEOUT_S
    try:
        value = float(timeout_s)
    except (TypeError, ValueError):
        raise InvalidTimeout(f"invalid timeout_s {timeout_s!r}") from None
    if not (_MIN_TIMEOUT_S <= value <= _MAX_TIMEOUT_S) or value != value:  # value!=value → NaN
        raise InvalidTimeout(
            f"timeout_s must be between {_MIN_TIMEOUT_S:g} and {_MAX_TIMEOUT_S:g}, got {timeout_s!r}"
        )
    return value


# --- Project name ------------------------------------------------------------------

# A free-text label ("Shop backend", "Đồ án web") so scans of the same app can be
# traced together. Display/filter only: it never reaches argv, a path or the goal.
_MAX_PROJECT_LEN = 60


class InvalidProject(ValueError):
    """Raised when a project name has control characters or is too long."""


def validate_project(name: str | None) -> str | None:
    """Return a tidy project name, or None when none was given."""
    if name is None:
        return None
    name = " ".join(name.split())  # trim + collapse inner whitespace/newlines
    if not name:
        return None
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise InvalidProject("project name must not contain control characters")
    if len(name) > _MAX_PROJECT_LEN:
        raise InvalidProject(f"project name must be at most {_MAX_PROJECT_LEN} characters")
    return name


# --- Path safety: run_id is used to build filesystem paths -------------------

# A run_id ends up in `runs_root / run_id`, so it must not be able to escape
# that directory (path traversal) or name anything but a plain run folder.
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class InvalidRunId(ValueError):
    """Raised when a run_id is not a safe single path segment."""


def validate_run_id(run_id: str) -> str:
    """Return run_id unchanged if it is a safe path segment, else raise.

    Rejects separators, `..`, absolute/drive prefixes and anything that could
    escape the runs directory. This is the gate every path-building endpoint
    must pass user input through.
    """
    if not _RUN_ID_RE.match(run_id) or run_id in (".", "..") or ".." in run_id:
        raise InvalidRunId(f"invalid run_id {run_id!r}")
    return run_id
