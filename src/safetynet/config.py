"""Safety invariants and scan scope, expressed as code (ARCHITECTURE.md §2).

Two hard rules live here:
  1. Whitelist gate — only local targets may ever be scanned.
  2. Fixed scope — a scan type maps to a goal template written here, never to
     free text from the user. The agent does not choose what to look for.
"""

from __future__ import annotations

import ipaddress
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
