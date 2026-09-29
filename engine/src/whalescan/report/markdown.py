"""Markdown report for PR comments and ``/whale-audit`` (spec §12.4).

Every finding string is untrusted: it is HTML-escaped outside code fences, and ``|``, backticks,
brackets and ``@`` are neutralized so a finding cannot inject HTML, links or mentions.
"""

from __future__ import annotations

import re

from ..model import Finding, ScanResult, Severity
from ._common import SEVERITY_ORDER, clean, ordered, severity_counts

_BACKTICKS = re.compile(r"`+")


def escape(text: str) -> str:
    """Escape text for use in a Markdown paragraph or table cell."""
    t = clean(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    for ch in ("\\", "`", "[", "]", "|", "*", "_", "~"):
        t = t.replace(ch, "\\" + ch)
    t = t.replace("@", "&#64;")
    return re.sub(r"\s*\n\s*", " ", t)


def code_span(text: str) -> str:
    t = clean(text).replace("\n", " ")
    ticks = "`" * (max((len(m) for m in _BACKTICKS.findall(t)), default=0) + 1)
    pad = " " if t.startswith("`") or t.endswith("`") else ""
    return f"{ticks}{pad}{t}{pad}{ticks}"


def fence(text: str, lang: str = "") -> str:
    t = clean(text)
    ticks = "`" * max(3, max((len(m) for m in _BACKTICKS.findall(t)), default=0) + 1)
    return f"{ticks}{lang}\n{t}\n{ticks}"


def _loc(f: Finding) -> str:
    return code_span(f"{f.file}:{f.line}")


def _detail(f: Finding) -> list[str]:
    meta = [_loc(f)]
    if f.cwe:
        meta.append(escape(", ".join(f.cwe)))
    if f.owasp:
        meta.append(escape(", ".join(f.owasp)))
    meta.append(f"confidence {f.confidence.label}")
    lines = [
        f"#### {f.severity.label.upper()} · {code_span(f.rule_id)} · {escape(f.title)}",
        "",
        " · ".join(meta),
        "",
    ]
    lines += [escape(f.message), ""]
    if f.snippet:
        lines += [fence(f.snippet), ""]
    if f.fix:
        lines += [f"**Fix:** {escape(f.fix)}", ""]
    if f.references:
        lines += [
            "References: "
            + ", ".join(
                f"<{u}>" if re.fullmatch(r"https://[\w./%~:@+=?&#-]+", u) else code_span(u)
                for u in f.references
            ),
            "",
        ]
    return lines


def _table(findings: list[Finding]) -> list[str]:
    rows = ["| Sev | Rule | Location | Title |", "|---|---|---|---|"]
    rows += [
        f"| {f.severity.label} | {code_span(f.rule_id)} | {_loc(f)} | {escape(f.title)} |" for f in findings
    ]
    return rows


def render(result: ScanResult, max_findings: int = 200) -> str:
    findings = ordered(result)
    counts = severity_counts(findings)
    parts = " · ".join(f"{counts[s]} {s.label}" for s in SEVERITY_ORDER if counts[s])
    out = [f"## whalescan: {parts}" if parts else "## whalescan: no findings", ""]
    shown = findings[:max_findings] if max_findings > 0 else findings
    if shown:
        out += [*_table(shown), ""]
        for f in shown:
            if f.severity >= Severity.HIGH:
                out += _detail(f)
        rest = [f for f in shown if f.severity < Severity.HIGH]
        if rest:
            out += [f"<details><summary>{len(rest)} lower-severity finding(s)</summary>", ""]
            for f in rest:
                out += [f"- **{f.severity.label}** {code_span(f.rule_id)} {_loc(f)} — {escape(f.title)}"]
            out += ["", "</details>", ""]
    if len(findings) > len(shown):
        out += [
            f"_{len(findings) - len(shown)} more finding(s) omitted (limit {max_findings})._",
            "",
        ]
    warn = [d for d in result.diagnostics if d.level in ("warning", "error")]
    if warn:
        out += [f"_{len(warn)} diagnostic(s): " + escape(", ".join(sorted({d.code for d in warn}))) + "_", ""]
    return "\n".join(out).rstrip("\n") + "\n"
