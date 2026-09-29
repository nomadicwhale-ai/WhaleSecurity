"""Core data model shared by every engine module (spec §8.1, §12.2, §16).

This module is the contract between the walker, matchers, severity/dedupe/suppress stages,
reporters and the public API. Keep it dependency-free and stable.
"""

from __future__ import annotations

import bisect
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Literal

FINDING_SCHEMA = "whalescan/finding@1"
REPORT_SCHEMA = "whalescan/report@1"
BASELINE_SCHEMA = "whalescan/baseline@1"
MCP_PINS_SCHEMA = "whalescan/mcp-pins@1"

Kind = Literal["code", "iac", "ci", "agent-config", "doc", "data"]
KINDS: tuple[str, ...] = ("code", "iac", "ci", "agent-config", "doc", "data")
Reachability = Literal["tainted", "unknown", "constant"]
Exposure = Literal["internet", "default", "internal", "vendored", "test"]
Source = Literal["engine", "semgrep", "gitleaks", "trivy", "osv", "llm"]


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity: {value!r}") from None

    @property
    def label(self) -> str:
        return self.name.lower()

    def __str__(self) -> str:
        return self.label


class Confidence(IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2

    @classmethod
    def parse(cls, value: str | Confidence) -> Confidence:
        if isinstance(value, Confidence):
            return value
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown confidence: {value!r}") from None

    @property
    def label(self) -> str:
        return self.name.lower()

    def lowered(self, steps: int = 1) -> Confidence:
        return Confidence(max(0, int(self) - steps))

    def __str__(self) -> str:
        return self.label


# --------------------------------------------------------------------------- rules


@dataclass(frozen=True, slots=True)
class AppliesTo:
    kinds: frozenset[str] = frozenset()        # empty = any kind
    langs: frozenset[str] = frozenset()        # empty = any lang
    globs: tuple[str, ...] = ()                # empty = any path
    exclude_globs: tuple[str, ...] = ()
    tags_any: frozenset[str] = frozenset()
    tags_none: frozenset[str] = frozenset()
    include_minified: bool = False
    max_bytes: int | None = None


@dataclass(frozen=True, slots=True)
class Rule:
    """A normalized, validated rule. `match` is the raw matcher expression (spec §7.2 `expr`)."""

    id: str
    title: str
    pack: str
    severity: Severity
    confidence: Confidence
    owner: str
    applies_to: AppliesTo
    match: Mapping[str, Any]
    message: str
    references: tuple[str, ...]
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    atlas: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    fix: str | None = None
    keywords: tuple[str, ...] = ()
    keywords_case: Literal["insensitive", "sensitive"] = "insensitive"
    filters: Mapping[str, Any] = field(default_factory=dict)
    redact: bool = False
    exposure_sensitive: bool = True
    supersedes: tuple[str, ...] = ()
    max_hits_per_file: int = 50
    enabled_by_default: bool = True
    deprecated: bool = False
    replaced_by: str | None = None
    since: str | None = None
    source_file: str | None = None             # pack file the rule came from (diagnostics only)

    @property
    def pack_root(self) -> str:
        """`secrets/cloud` -> `secrets`."""
        return self.pack.split("/", 1)[0]

    @property
    def is_secret_rule(self) -> bool:
        return self.pack_root == "secrets" or self.redact


# --------------------------------------------------------------------------- files


@dataclass(slots=True)
class FileCtx:
    """One decoded file (or stdin/tool-output document) being scanned.

    `text` is never newline-normalized. Only "\\n" is a line break (spec §5.5-§5.6).
    Offsets are code-point offsets into `text`; lines and columns are 1-based.
    """

    path: str                                  # root-relative POSIX path, or virtual name
    text: str
    lang: str = "text"
    kind: str = "data"
    tags: frozenset[str] = frozenset()
    size: int = 0                              # bytes on disk / input
    encoding: str = "utf-8"
    encoding_fallback: bool = False            # latin-1 fallback: unicode matcher disabled
    abs_path: str | None = None
    source_label: str | None = None            # inject: web:<url>, mcp:<server>/<tool>, ...
    cache: dict[str, Any] = field(default_factory=dict)   # parsed trees shared by rules
    _line_starts: list[int] | None = None

    @property
    def line_starts(self) -> list[int]:
        if self._line_starts is None:
            starts = [0]
            find = self.text.find
            i = find("\n")
            while i != -1:
                starts.append(i + 1)
                i = find("\n", i + 1)
            self._line_starts = starts
        return self._line_starts

    def line_of(self, off: int) -> int:
        return bisect.bisect_right(self.line_starts, off)

    def pos(self, off: int) -> tuple[int, int]:
        starts = self.line_starts
        i = bisect.bisect_right(starts, off) - 1
        return i + 1, off - starts[i] + 1

    def end_pos(self, end: int) -> tuple[int, int]:
        """Position just after the last char of a span with exclusive `end`."""
        if end <= 0:
            return 1, 1
        line, col = self.pos(end - 1)
        return line, col + 1

    @property
    def line_count(self) -> int:
        return len(self.line_starts)

    def line_text(self, line: int) -> str:
        """Text of 1-based `line` without its trailing newline."""
        starts = self.line_starts
        if line < 1 or line > len(starts):
            return ""
        s = starts[line - 1]
        e = starts[line] - 1 if line < len(starts) else len(self.text)
        return self.text[s:e]

    def line_span(self, line: int) -> tuple[int, int]:
        starts = self.line_starts
        s = starts[line - 1]
        e = starts[line] - 1 if line < len(starts) else len(self.text)
        return s, e


# --------------------------------------------------------------------------- hits & findings


@dataclass(slots=True)
class Hit:
    """A raw matcher result, before severity, suppression, redaction and dedupe."""

    start: int
    end: int                                   # exclusive
    line: int
    col: int
    end_line: int
    end_col: int                               # exclusive
    captures: dict[str, str] = field(default_factory=dict)
    secret_spans: list[tuple[int, int]] = field(default_factory=list)
    reachability: str = "unknown"
    confidence_delta: int = 0                  # -1 = one step lower than rule.confidence
    props: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def at(cls, ctx: FileCtx, start: int, end: int, **kw: Any) -> Hit:
        line, col = ctx.pos(start)
        end_line, end_col = ctx.end_pos(max(end, start + 1))
        return cls(start, end, line, col, end_line, end_col, **kw)


@dataclass(frozen=True, slots=True)
class Suppression:
    kind: Literal["inline", "baseline", "config"]
    reason: str | None = None
    until: str | None = None
    ticket: str | None = None
    marker_line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"kind": self.kind}
        for k in ("reason", "until", "ticket", "marker_line"):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        return d


@dataclass(frozen=True, slots=True)
class Finding:
    """Mirrors finding@1 (spec §12.2). Text fields are already redacted and revealed."""

    rule_id: str
    title: str
    severity: Severity
    base_severity: Severity
    score: float
    confidence: Confidence
    reachability: str
    exposure: str
    pack: str
    file: str
    file_kind: str
    line: int
    col: int
    end_line: int
    end_col: int
    snippet: str
    cwe: tuple[str, ...]
    owasp: tuple[str, ...]
    message: str
    fix: str | None
    references: tuple[str, ...]
    fingerprint: str
    content_fingerprint: str
    source: str = "engine"
    atlas: tuple[str, ...] = ()
    also_reported_by: tuple[str, ...] = ()
    suppressed: Suppression | None = None
    verification: Mapping[str, Any] | None = None
    properties: Mapping[str, Any] = field(default_factory=dict)

    @property
    def sort_key(self) -> tuple[float, str, int, int, str]:
        weight = {Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.8, Confidence.LOW: 0.5}[self.confidence]
        return (-(self.score * weight), self.file, self.line, self.col, self.rule_id)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "schema": FINDING_SCHEMA,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "base_severity": self.base_severity.label,
            "score": round(self.score, 2),
            "confidence": self.confidence.label,
            "reachability": self.reachability,
            "exposure": self.exposure,
            "pack": self.pack,
            "file": self.file,
            "file_kind": self.file_kind,
            "line": self.line,
            "col": self.col,
            "end_line": self.end_line,
            "end_col": self.end_col,
            "snippet": self.snippet,
            "cwe": list(self.cwe),
            "owasp": list(self.owasp),
            "message": self.message,
            "fix": self.fix,
            "references": list(self.references),
            "fingerprint": self.fingerprint,
            "content_fingerprint": self.content_fingerprint,
            "source": self.source,
        }
        if self.atlas:
            d["atlas"] = list(self.atlas)
        if self.also_reported_by:
            d["also_reported_by"] = list(self.also_reported_by)
        d["suppressed"] = self.suppressed.to_dict() if self.suppressed else None
        if self.verification:
            d["verification"] = dict(self.verification)
        if self.properties:
            d["properties"] = dict(self.properties)
        return d


@dataclass(frozen=True, slots=True)
class Diagnostic:
    level: Literal["error", "warning", "info"]
    code: str                                  # e.g. parse-error, decode-fallback-latin1
    message: str
    file: str | None = None
    line: int | None = None
    rule_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"level": self.level, "code": self.code, "message": self.message}
        for k in ("file", "line", "rule_id"):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        return d


@dataclass(slots=True)
class Stats:
    files_scanned: int = 0
    files_skipped: dict[str, int] = field(
        default_factory=lambda: {"binary": 0, "too_large": 0, "ignored": 0, "symlink": 0}
    )
    bytes_scanned: int = 0
    rules_evaluated: int = 0
    capped: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    suppressed: dict[str, int] = field(default_factory=lambda: {"inline": 0, "baseline": 0, "config": 0})
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "files_skipped": dict(self.files_skipped),
            "bytes_scanned": self.bytes_scanned,
            "rules_evaluated": self.rules_evaluated,
            "capped": dict(sorted(self.capped.items())),
            "by_severity": dict(self.by_severity),
            "suppressed": dict(self.suppressed),
            "truncated": self.truncated,
        }


@dataclass(slots=True)
class RunInfo:
    started_at: str = ""
    duration_ms: int = 0
    root: str = "."
    argv: list[str] = field(default_factory=list)
    packs: list[str] = field(default_factory=list)
    config_sources: list[str] = field(default_factory=list)
    config_changes: list[str] = field(default_factory=list)
    fail_on: str = "high"
    exit_code: int = 0
    truncated: bool = False
    error: dict[str, str] | None = None
    tool_version: str = ""
    rules_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "duration_ms": self.duration_ms,
            "root": self.root,
            "argv": list(self.argv),
            "packs": list(self.packs),
            "config_sources": list(self.config_sources),
            "config_changes": list(self.config_changes),
            "fail_on": self.fail_on,
            "exit_code": self.exit_code,
            "truncated": self.truncated,
            "error": self.error,
        }


def severity_at_or_above(sev: Severity, threshold: str) -> bool:
    return threshold != "never" and sev >= Severity.parse(threshold)


@dataclass(frozen=True, slots=True)
class ScanResult:
    findings: tuple[Finding, ...]
    diagnostics: tuple[Diagnostic, ...]
    stats: Stats
    run: RunInfo

    @property
    def active(self) -> tuple[Finding, ...]:
        """Findings that are not suppressed."""
        return tuple(f for f in self.findings if f.suppressed is None)

    def exit_code(self, fail_on: str = "high") -> int:
        return 1 if any(severity_at_or_above(f.severity, fail_on) for f in self.active) else 0

    # Reporters are imported lazily to keep hook start-up cheap.
    def to_json(self) -> str:
        from .report import json as _json

        return _json.render(self)

    def to_jsonl(self) -> str:
        from .report import json as _json

        return _json.render_jsonl(self)

    def to_sarif(self) -> str:
        from .report import sarif

        return sarif.render(self)

    def to_markdown(self) -> str:
        from .report import markdown

        return markdown.render(self)

    def to_text(self, color: bool = False) -> str:
        from .report import text

        return text.render(self, color=color)
