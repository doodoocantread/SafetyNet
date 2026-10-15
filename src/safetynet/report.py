"""Render a Report as Markdown (ARCHITECTURE.md §5).

Markdown is the portable export. The web UI renders the same Report JSON live and
uses the browser's print-to-PDF for the PDF deliverable (no heavy PDF dependency;
WeasyPrint can be added later if a server-side PDF is required).
"""

from __future__ import annotations

from .models import Report, Severity

_SEV_BADGE = {
    Severity.critical: "🔴 CRITICAL",
    Severity.high: "🟠 HIGH",
    Severity.medium: "🟡 MEDIUM",
    Severity.low: "🔵 LOW",
    Severity.info: "⚪ INFO",
}


def to_markdown(report: Report) -> str:
    lines: list[str] = []
    lines.append(f"# Bao cao kiem thu bao mat — {report.run_id}")
    lines.append("")
    lines.append(f"- **Muc tieu (goal):** {report.goal}")
    lines.append(f"- **Target:** {', '.join(report.targets) or '—'}")
    lines.append(f"- **Engine:** {report.engine}")
    lines.append(f"- **Trang thai run:** {report.status}")
    lines.append(f"- **Phan loai boi:** {report.labeled_by}")
    lines.append(f"- **Chi phi:** ${report.cost_usd:.4f} · **Thoi gian:** {report.wall_duration_s:.0f}s")
    lines.append("")

    if not report.conclusive:
        lines.append("> ⚠️ **Run khong hoan tat** — ket qua KHONG ket luan duoc "
                     "('khong tim thay' khac 'run loi'). Loi:")
        lines.append(f"> `{report.error or 'unknown'}`")
        lines.append("")

    # Summary counts
    counts: dict[str, int] = {}
    for f in report.findings:
        if f.label:
            counts[f.label.severity.value] = counts.get(f.label.severity.value, 0) + 1
    if counts:
        summary = " · ".join(f"{_SEV_BADGE[Severity(k)]}: {v}" for k, v in
                             sorted(counts.items(), key=lambda kv: -Severity(kv[0]).rank))
        lines.append(f"## Tong quan: {summary}")
        lines.append("")

    lines.append("## Chi tiet")
    lines.append("")
    for i, f in enumerate(report.findings, 1):
        L = f.label
        sev = _SEV_BADGE[L.severity] if L else "⚪ INFO"
        lines.append(f"### {i}. {L.vuln_class if L else 'Observation'} — {sev}")
        lines.append("")
        if L:
            meta = []
            if L.cwe:
                meta.append(f"**{L.cwe}**")
            if L.owasp:
                meta.append(L.owasp)
            meta.append(f"confidence: {L.confidence}")
            lines.append(" · ".join(meta))
            lines.append("")
            lines.append(f"**Giai thich:** {L.explanation}")
            lines.append("")
            lines.append(f"**Khac phuc:** {L.remediation}")
            lines.append("")
        lines.append(f"- **Task:** {f.task_kind or '—'} · **Target:** {f.target or '—'}")
        if f.request:
            lines.append("- **Request (bang chung):**")
            lines.append("")
            lines.append("```bash")
            lines.append(f.request)
            lines.append("```")
        if f.response:
            lines.append("- **Response:**")
            lines.append("")
            lines.append("```http")
            lines.append(f.response[:1200])
            lines.append("```")
        lines.append("")
    return "\n".join(lines)
