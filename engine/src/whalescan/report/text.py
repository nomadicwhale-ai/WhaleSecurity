"""Human-readable terminal report (spec §12.1)."""

from __future__ import annotations

from ..model import Finding, ScanResult, Severity
from ._common import SEVERITY_ORDER, clean, ordered, severity_counts, suppressed_counts

_COLORS = {
    Severity.CRITICAL: "31",
    Severity.HIGH: "35",
    Severity.MEDIUM: "33",
    Severity.LOW: "36",
    Severity.INFO: "36",
}


def _paint(s: str, code: str, color: bool) -> str:
    return f"\x1b[{code}m{s}\x1b[0m" if color else s


def _finding(f: Finding, color: bool) -> list[str]:
    head = f"{f.severity.label.upper():<9} {f.rule_id}  {clean(f.file)}:{f.line}:{f.col}  {clean(f.title)}"
    lines = [_paint(head, _COLORS[f.severity], color)]
    snippet = clean(f.snippet).splitlines() or [""]
    lines += [f"          │ {s}" for s in snippet[:3]]
    if f.fix:
        lines.append(f"          fix: {clean(f.fix)}")
    return lines


def render(result: ScanResult, color: bool = False) -> str:
    findings = ordered(result)
    out: list[str] = []
    for f in findings:
        out += _finding(f, color)
    for d in result.diagnostics:
        if d.level in ("warning", "error"):
            where = f" ({clean(d.file)}{':' + str(d.line) if d.line else ''})" if d.file else ""
            out.append(f"{d.level}: {d.code}: {clean(d.message)}{where}")
    if out:
        out.append("")
    counts = severity_counts(findings)
    breakdown = ", ".join(f"{counts[s]} {s.label}" for s in SEVERITY_ORDER if counts[s])
    summary = f"{len(findings)} finding{'' if len(findings) == 1 else 's'}" + (
        f" ({breakdown})" if breakdown else ""
    )
    parts = [summary, f"{result.stats.files_scanned:,} files"]
    if result.run.duration_ms:
        parts.append(f"{result.run.duration_ms / 1000:.2f} s")
    sup = suppressed_counts(result)
    if sup:
        parts.append(
            f"{sum(sup.values())} suppressed (" + ", ".join(f"{k} {v}" for k, v in sorted(sup.items())) + ")"
        )
    if result.run.truncated or result.stats.truncated:
        parts.append("truncated")
    parts.append(f"fail-on {result.run.fail_on} → exit {result.run.exit_code}")
    out.append(" · ".join(parts))
    return "\n".join(out) + "\n"
