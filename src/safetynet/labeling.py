"""Labeler: the NARRATIVE layer (ARCHITECTURE.md §6).

Takes fact-only Findings and attaches a Label (vuln class, severity, CWE, OWASP,
explanation, remediation). Two implementations:

  - HeuristicLabeler: offline, rule-based. No key, no network, deterministic.
    Lets the whole app (and UI) run without an LLM. Confidence is marked lower.
  - LLMLabeler: uses the Anthropic API when a key is configured. Richer and the
    scientific point of the project; it must cite evidence and may only label
    from the facts it is given.

The CWE → OWASP step always goes through owasp.py (static table), whichever
labeler is used, so that mapping is never hallucinated.
"""

from __future__ import annotations

import re
from typing import Protocol

from .models import Finding, Label, Severity
from .owasp import owasp_for_cwe


def _http_status(response: str) -> int | None:
    m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", response.strip())
    return int(m.group(1)) if m else None


class Labeler(Protocol):
    name: str

    def label(self, finding: Finding) -> Label: ...


class HeuristicLabeler:
    """Rule-based offline labeler. Covers the common Juice-Shop-style signals so
    the pipeline produces a real-looking report with no LLM."""

    name = "heuristic"

    _SQLI_PAYLOAD = re.compile(r"(' *or *1 *= *1|--|union +select|' *or *')", re.IGNORECASE)
    _XSS_PAYLOAD = re.compile(r"(<script|onerror=|onload=|<img|javascript:)", re.IGNORECASE)

    def label(self, finding: Finding) -> Label:
        req = finding.request or ""
        resp = finding.response or ""
        status = _http_status(resp)

        # SQLi: payload in request + a successful auth/token response.
        if self._SQLI_PAYLOAD.search(req) and status == 200 and (
            "authentication" in resp or "token" in resp
        ):
            return self._mk(
                "SQL Injection (authentication bypass)", Severity.critical, "CWE-89",
                "Payload chua cu phap SQL ('OR 1=1--) duoc gui vao truong dang nhap va "
                "server tra ve 200 kem token xac thuc — dang nhap bi vuot qua ma khong "
                "can mat khau hop le.",
                "Dung truy van tham so hoa (prepared statements / ORM), khong noi chuoi "
                "SQL truc tiep tu input. Xac thuc va chuan hoa input phia server.",
                confidence="high",
            )
        # SQLi probe that errored the server (500 on a quote) — weaker signal.
        if self._SQLI_PAYLOAD.search(req) and status == 500:
            return self._mk(
                "Possible SQL Injection (error-based)", Severity.medium, "CWE-89",
                "Input chua ky tu SQL lam server tra ve 500 — co the cau truy van bi "
                "input tac dong, dau hieu cua SQL injection can xac minh them.",
                "Tham so hoa truy van; khong de thong bao loi SQL lo ra client.",
                confidence="medium",
            )
        # XSS payload reflected.
        if self._XSS_PAYLOAD.search(req) and any(
            t in resp for t in ("<script", "onerror=", "onload=")
        ):
            return self._mk(
                "Reflected Cross-Site Scripting (XSS)", Severity.high, "CWE-79",
                "Payload script trong request duoc phan chieu nguyen van trong response "
                "— trinh duyet nan nhan co the thuc thi ma cua ke tan cong.",
                "Ma hoa output theo ngu canh (HTML/attr/JS), ap dung Content-Security-Policy.",
                confidence="medium",
            )
        # Server error / stack leak.
        if status == 500:
            return self._mk(
                "Server error / information disclosure", Severity.low, "CWE-209",
                "Server tra ve 500 kem noi dung loi — co the lo thong tin noi bo.",
                "Tra ve trang loi chung; ghi chi tiet loi vao log phia server.",
                confidence="low",
            )
        # Expected rejects / baseline (401/403) — informational, not a finding.
        if status in (401, 403):
            return self._mk(
                "Baseline / expected rejection", Severity.info, None,
                "Phan hoi tu choi hop le (401/403) — dung lam baseline so sanh, khong "
                "phai lo hong.",
                "Khong can hanh dong.",
                confidence="high",
            )
        return self._mk(
            "Observation (needs review)", Severity.info, None,
            "Quan sat duoc ghi lai; chua du tin hieu de phan loai tu dong.",
            "Xem lai request/response thu cong.",
            confidence="low",
        )

    def _mk(self, vuln, sev, cwe, explanation, remediation, *, confidence) -> Label:
        return Label(
            vuln_class=vuln,
            severity=sev,
            cwe=cwe,
            owasp=owasp_for_cwe(cwe),
            explanation=explanation,
            remediation=remediation,
            confidence=confidence,
            labeled_by=self.name,
        )


def label_findings(findings: list[Finding], labeler: Labeler) -> list[Finding]:
    for f in findings:
        f.label = labeler.label(f)
    # Most severe first.
    findings.sort(
        key=lambda f: f.label.severity.rank if f.label else -1, reverse=True
    )
    return findings
