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
    """HTTP status from a raw response line (`HTTP/1.1 200 ...`) OR the compact
    form some agents report instead of pasting the whole response
    (`status=200`, `STATUS=200 SIZE=...`). Without the compact fallback, every
    observation an agent summarises rather than quotes raw parses as "no status"
    and falls through to the INFO default."""
    text = response.strip()
    m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", text)
    if m:
        return int(m.group(1))
    m = re.search(r"\bstatus\s*=\s*(\d{3})\b", text, re.IGNORECASE)
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
    # Database error signatures leaking into a response — strong SQLi evidence on
    # their own, independent of the HTTP status (e.g. Juice Shop leaks
    # `SQLITE_ERROR: near "'%'": syntax error`).
    _SQL_ERROR = re.compile(
        r"(SQLITE_ERROR|unrecognized token|unterminated quoted string"
        r"|you have an error in your SQL syntax|near \"[^\"]*\": syntax error"
        r"|ORA-\d{5}|PG::\w*Error|psycopg2|SQLSTATE\["
        r"|ERROR:\s+syntax error at or near)",
        re.IGNORECASE,
    )
    # Boolean-based blind SQLi: a TRUE and a FALSE condition, often reported in a
    # single observation (`q=[..OR 1=1..] len=26978` vs `q=[..AND 1=2..] len=30`).
    # Quotes are optional on both sides: agents often log the payload truncated
    # (`'1'='2]`), so requiring a closing quote would miss the real signal.
    _SQLI_TRUE = re.compile(r"or +'?1'? *= *'?1", re.IGNORECASE)
    _SQLI_FALSE = re.compile(r"and +'?1'? *= *'?[20]", re.IGNORECASE)

    def label(self, finding: Finding) -> Label:
        lbl = self._classify(finding)
        lbl.rationale = self._signals(finding)
        return lbl

    def _signals(self, finding: Finding) -> list[str]:
        """The concrete facts the rules looked at, so a reader can see WHY this
        observation got its label instead of only a generic class description."""
        req = finding.request or ""
        resp = finding.response or ""
        status = _http_status(resp)
        out: list[str] = []
        if not req:
            out.append("Không khôi phục được request từ trace — chỉ dựa trên response.")
        if m := self._SQLI_PAYLOAD.search(req):
            out.append(f"Request chứa mẫu cú pháp SQL: `{m.group(0)}`.")
        if m := self._XSS_PAYLOAD.search(req):
            out.append(f"Request chứa mẫu payload script: `{m.group(0)}`.")
        if status is not None:
            out.append(f"Response trả về HTTP {status}.")
        else:
            out.append("Không đọc được mã trạng thái HTTP trong response.")
        hits = [k for k in ("authentication", "token") if k in resp]
        if hits:
            out.append(f"Body response chứa {', '.join(repr(h) for h in hits)} — dấu hiệu đăng nhập thành công.")
        reflected = [t for t in ("<script", "onerror=", "onload=") if t in resp]
        if reflected:
            out.append(f"Response phản chiếu lại {', '.join(repr(t) for t in reflected)} nguyên văn.")
        if m := self._SQL_ERROR.search(resp):
            out.append(f"Response chứa thông báo lỗi cơ sở dữ liệu: `{m.group(0)}`.")
        if self._boolean_differential(f"{req}\n{resp}"):
            out.append(
                "Điều kiện TRUE ('OR 1=1') và FALSE ('AND 1=2') trả về số kết quả / "
                "kích thước khác nhau — dấu hiệu boolean-based SQL injection."
            )
        if finding.is_error:
            out.append("Lệnh của agent kết thúc với lỗi (tool_result is_error).")
        return out

    def _boolean_differential(self, text: str) -> bool:
        """True when `text` shows a TRUE and a FALSE SQL condition that produced
        different results (distinct `result_count` / `len` / `size` values) —
        the classic boolean-based blind SQLi signal. Agents often report both
        probes in one observation, so we look within a single finding."""
        if not (self._SQLI_TRUE.search(text) and self._SQLI_FALSE.search(text)):
            return False
        counts = set(re.findall(r"result_count\s*=\s*(\d+)", text, re.IGNORECASE))
        sizes = set(re.findall(r"\b(?:len|size)\s*=\s*(\d+)", text, re.IGNORECASE))
        return len(counts) >= 2 or len(sizes) >= 2

    def _classify(self, finding: Finding) -> Label:
        req = finding.request or ""
        resp = finding.response or ""
        status = _http_status(resp)

        # SQLi: payload in request + a successful auth/token response.
        if self._SQLI_PAYLOAD.search(req) and status == 200 and (
            "authentication" in resp or "token" in resp
        ):
            return self._mk(
                "SQL Injection (authentication bypass)", Severity.critical, "CWE-89",
                "Payload chứa cú pháp SQL ('OR 1=1--) được gửi vào trường đăng nhập và "
                "server trả về 200 kèm token xác thực — đăng nhập bị vượt qua mà không "
                "cần mật khẩu hợp lệ.",
                "Dùng truy vấn tham số hoá (prepared statements / ORM), không nối chuỗi "
                "SQL trực tiếp từ input. Xác thực và chuẩn hoá input phía server.",
                confidence="high",
            )
        # Boolean-based blind SQLi: a TRUE vs FALSE condition yielding different
        # results (len / result_count), reported within one observation.
        if self._boolean_differential(f"{req}\n{resp}"):
            return self._mk(
                "SQL Injection (boolean-based blind)", Severity.high, "CWE-89",
                "Hai điều kiện SQL đối lập (TRUE '…OR 1=1' và FALSE '…AND 1=2') gửi "
                "vào cùng một tham số trả về số kết quả / kích thước khác nhau — ứng "
                "dụng diễn giải input như một phần của câu truy vấn SQL, khai thác được.",
                "Dùng truy vấn tham số hoá (prepared statements / ORM); không nối chuỗi "
                "SQL từ input. Chuẩn hoá và kiểm tra input phía server.",
                confidence="high",
            )
        # Error-based SQLi: a DB error leaked into the response, or a SQL char
        # drove the server to 500 — either way the query took the input.
        if self._SQL_ERROR.search(resp) or (self._SQLI_PAYLOAD.search(req) and status == 500):
            return self._mk(
                "Possible SQL Injection (error-based)", Severity.medium, "CWE-89",
                "Input chứa ký tự SQL khiến server trả về lỗi cơ sở dữ liệu (thông báo "
                "lỗi SQL hoặc HTTP 500) — câu truy vấn bị input tác động, dấu hiệu SQL "
                "injection cần xác minh thêm.",
                "Tham số hoá truy vấn; không để thông báo lỗi SQL lộ ra client.",
                confidence="medium",
            )
        # XSS payload reflected.
        if self._XSS_PAYLOAD.search(req) and any(
            t in resp for t in ("<script", "onerror=", "onload=")
        ):
            return self._mk(
                "Reflected Cross-Site Scripting (XSS)", Severity.high, "CWE-79",
                "Payload script trong request được phản chiếu nguyên văn trong response "
                "— trình duyệt nạn nhân có thể thực thi mã của kẻ tấn công.",
                "Mã hoá output theo ngữ cảnh (HTML/attr/JS), áp dụng Content-Security-Policy.",
                confidence="medium",
            )
        # Server error / stack leak.
        if status == 500:
            return self._mk(
                "Server error / information disclosure", Severity.low, "CWE-209",
                "Server trả về 500 kèm nội dung lỗi — có thể lộ thông tin nội bộ.",
                "Trả về trang lỗi chung; ghi chi tiết lỗi vào log phía server.",
                confidence="low",
            )
        # Expected rejects / baseline (401/403) — informational, not a finding.
        if status in (401, 403):
            return self._mk(
                "Baseline / expected rejection", Severity.info, None,
                "Phản hồi từ chối hợp lệ (401/403) — dùng làm baseline so sánh, không "
                "phải lỗ hổng.",
                "Không cần hành động.",
                confidence="high",
            )
        return self._mk(
            "Observation (needs review)", Severity.info, None,
            "Quan sát được ghi lại; chưa đủ tín hiệu để phân loại tự động.",
            "Xem lại request/response thủ công.",
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
