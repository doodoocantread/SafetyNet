"""Static CWE → OWASP Top 10 (2021) mapping (ARCHITECTURE.md §6).

Deterministic on purpose: the LLM decides *which CWE* an observation is, but the
CWE → OWASP category lookup is a fixed table so it cannot be hallucinated.
"""

from __future__ import annotations

# CWE id (without the "CWE-" prefix) → OWASP 2021 category label.
CWE_TO_OWASP: dict[str, str] = {
    "89": "A03:2021 - Injection",
    "79": "A03:2021 - Injection",
    "78": "A03:2021 - Injection",
    "77": "A03:2021 - Injection",
    "90": "A03:2021 - Injection",
    "943": "A03:2021 - Injection",
    "287": "A07:2021 - Identification and Authentication Failures",
    "384": "A07:2021 - Identification and Authentication Failures",
    "307": "A07:2021 - Identification and Authentication Failures",
    "798": "A07:2021 - Identification and Authentication Failures",
    "639": "A01:2021 - Broken Access Control",
    "862": "A01:2021 - Broken Access Control",
    "863": "A01:2021 - Broken Access Control",
    "22": "A01:2021 - Broken Access Control",
    "200": "A01:2021 - Broken Access Control",
    "209": "A05:2021 - Security Misconfiguration",
    "16": "A05:2021 - Security Misconfiguration",
    "611": "A05:2021 - Security Misconfiguration",
    "327": "A02:2021 - Cryptographic Failures",
    "311": "A02:2021 - Cryptographic Failures",
    "502": "A08:2021 - Software and Data Integrity Failures",
    "918": "A10:2021 - Server-Side Request Forgery (SSRF)",
}


def owasp_for_cwe(cwe: str | None) -> str | None:
    """Map 'CWE-89' or '89' to its OWASP 2021 category, or None if unknown."""
    if not cwe:
        return None
    key = cwe.upper().removeprefix("CWE-").strip()
    return CWE_TO_OWASP.get(key)
