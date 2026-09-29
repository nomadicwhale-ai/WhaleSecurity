"""Inline suppressions and the baseline file (spec §11).

Inline markers are attacker-controllable text, so they are never honored for ``inject`` input or
for ``WS-AGT-*`` findings in agent-config and doc files (:func:`inline_allowed`). The baseline
stores fingerprints only, never snippets, so it can never hold a secret.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
from collections.abc import Callable, Collection, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import SuppressConfig
from .errors import ConfigError, UsageError
from .ignore import rule_glob_match
from .model import BASELINE_SCHEMA, Diagnostic, FileCtx, Finding, Severity, Suppression

MARKER = re.compile(
    r"(?:#|//|--|/\*|<!--|;|\{#)\s*whalescan:ignore(?P<scope>-next-line|-file|-start|-end)?"
    r"(?:\[(?P<ids>[A-Za-z0-9*,\s-]{1,200})\])?(?P<tail>[^\n]{0,400})"
)
KV = re.compile(r"""(?P<k>reason|until|ticket)=(?:"(?P<q>(?:[^"\\\n]|\\.){0,300})"|(?P<v>[^\s"]{1,120}))""")
_FILE_LEVEL_WINDOW = 20


# --------------------------------------------------------------------------- inline


@dataclass(slots=True)
class Marker:
    line: int
    scope: str  # line | next-line | file | start | end
    ids: tuple[str, ...]
    reason: str | None
    until: str | None
    ticket: str | None
    first: int = 0  # first covered line (inclusive)
    last: int = 0  # last covered line (inclusive)
    active: bool = True
    used: bool = False

    def covers_rule(self, rule_id: str, allow_wildcard: bool) -> bool:
        for pat in self.ids:
            if pat == "*":
                if allow_wildcard:
                    return True
            elif pat == rule_id or ("*" in pat and rule_glob_match(pat, rule_id)):
                return True
        return False


@dataclass(slots=True)
class SuppressIndex:
    markers: list[Marker] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    allow_wildcard: bool = False

    def match(self, line: int, rule_id: str) -> Marker | None:
        """The active marker covering ``line`` for ``rule_id``, marking it used."""
        for m in self.markers:
            if m.active and m.first <= line <= m.last and m.covers_rule(rule_id, self.allow_wildcard):
                m.used = True
                return m
        return None

    def unused(self, path: str) -> list[Diagnostic]:
        return [
            Diagnostic(
                "info", "suppression-unused", "whalescan:ignore marker matched no finding", path, m.line
            )
            for m in self.markers
            if m.active and not m.used
        ]


def inline_allowed(rule_id: str, kind: str, *, is_inject: bool = False) -> bool:
    """Hard exclusions (spec §11.1): attacker-controlled content must not suppress itself."""
    if is_inject:
        return False
    return not (rule_id.startswith("WS-AGT-") and kind in ("agent-config", "doc"))


def _parse_kv(tail: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in KV.finditer(tail):
        val = m.group("q") if m.group("q") is not None else m.group("v")
        out.setdefault(m.group("k"), val.replace('\\"', '"'))
    return out


def _next_nonblank(ctx: FileCtx, after: int) -> int:
    n = ctx.line_count
    for ln in range(after + 1, n + 1):
        if ctx.line_text(ln).strip():
            return ln
    return n + 1  # nothing follows: covers nothing


def parse_markers(
    ctx: FileCtx,
    cfg: SuppressConfig | None = None,
    today: _dt.date | None = None,
) -> SuppressIndex:
    """Find and validate every ``whalescan:ignore`` marker in ``ctx``."""
    cfg = cfg or SuppressConfig()
    idx = SuppressIndex(allow_wildcard=cfg.allow_wildcard)
    text = ctx.text
    if "whalescan:ignore" not in text:
        return idx
    today = today or _dt.datetime.now(_dt.timezone.utc).date()
    open_starts: list[Marker] = []

    def invalid(line: int, why: str) -> None:
        idx.diagnostics.append(Diagnostic("warning", "suppression-invalid", why, ctx.path, line))

    for m in MARKER.finditer(text):
        start = m.start()
        line, _ = ctx.pos(start)
        raw_scope = (m.group("scope") or "").lstrip("-")
        scope = raw_scope or "line"
        ids = tuple(i for i in (s.strip() for s in (m.group("ids") or "").split(",")) if i) or ("*",)
        kv = _parse_kv(m.group("tail") or "")
        line_start = ctx.line_span(line)[0]
        alone = not text[line_start:start].strip()
        marker = Marker(line, scope, ids, kv.get("reason"), kv.get("until"), kv.get("ticket"))

        if scope == "end":
            if open_starts:
                open_starts.pop().last = line
            else:
                invalid(line, "whalescan:ignore-end without a matching ignore-start")
            continue

        # validity
        problem: str | None = None
        if cfg.require_reason and (
            marker.reason is None or len(marker.reason.strip()) < cfg.min_reason_chars
        ):
            problem = f'reason="..." of at least {cfg.min_reason_chars} characters is required'
        elif "*" in ids and not cfg.allow_wildcard:
            problem = "wildcard suppression is disabled (suppress.allow_wildcard)"
        elif scope == "file" and (not cfg.allow_file_level or line > _FILE_LEVEL_WINDOW):
            problem = f"file-level suppression must be in the first {_FILE_LEVEL_WINDOW} lines and be allowed"
        if problem is None and marker.until is not None:
            try:
                if _dt.date.fromisoformat(marker.until) < today:
                    marker.active = False
                    idx.diagnostics.append(
                        Diagnostic(
                            "warning",
                            "suppression-expired",
                            f"suppression expired on {marker.until}",
                            ctx.path,
                            line,
                        )
                    )
            except ValueError:
                problem = f"until={marker.until!r} is not an ISO date (YYYY-MM-DD)"
        if problem:
            invalid(line, problem)
            continue

        if scope == "line":
            marker.first = marker.last = _next_nonblank(ctx, line) if alone else line
        elif scope == "next-line":
            marker.first = marker.last = _next_nonblank(ctx, line)
        elif scope == "file":
            marker.first, marker.last = 1, ctx.line_count
        else:  # start
            marker.first, marker.last = line, line + cfg.max_block_lines
            open_starts.append(marker)
        idx.markers.append(marker)

    for om in open_starts:  # unterminated block: cap at max_block_lines
        idx.diagnostics.append(
            Diagnostic(
                "warning",
                "suppression-invalid",
                "ignore-start without ignore-end (block capped)",
                ctx.path,
                om.line,
            )
        )
    for mk in idx.markers:
        if mk.scope == "start" and mk.last > ctx.line_count:
            mk.last = ctx.line_count
    return idx


def marker_suppression(m: Marker) -> Suppression:
    return Suppression("inline", m.reason, m.until, m.ticket, m.line)


# --------------------------------------------------------------------------- baseline


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(slots=True)
class Baseline:
    entries: list[dict[str, Any]] = field(default_factory=list)
    tool_version: str = ""
    rules_hash: str = ""
    created_at: str = ""
    updated_at: str = ""

    # ---- io
    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> Baseline:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise ConfigError(f"baseline not found: {path}") from None
        except (OSError, ValueError) as e:
            raise ConfigError(f"unreadable baseline {path}: {e}") from None
        if not isinstance(data, dict) or data.get("schema") != BASELINE_SCHEMA:
            raise ConfigError(f"{path}: not a {BASELINE_SCHEMA} file")
        entries = data.get("entries", [])
        if not isinstance(entries, list) or not all(
            isinstance(e, dict) and isinstance(e.get("fingerprint"), str) and isinstance(e.get("path"), str)
            for e in entries
        ):
            raise ConfigError(f"{path}: malformed baseline entries")
        return cls(
            entries=entries,
            tool_version=str(data.get("tool_version", "")),
            rules_hash=str(data.get("rules_hash", "")),
            created_at=str(data.get("created_at", "")),
            updated_at=str(data.get("updated_at", "")),
        )

    def to_json(self) -> str:
        entries = sorted(self.entries, key=lambda e: (e["path"], e.get("rule_id", ""), e["fingerprint"]))
        doc = {
            "schema": BASELINE_SCHEMA,
            "tool_version": self.tool_version,
            "rules_hash": self.rules_hash,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "entries": entries,
        }
        return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"

    def save(self, path: str | os.PathLike[str]) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".tmp")
        tmp.write_text(self.to_json(), encoding="utf-8")
        os.replace(tmp, p)

    # ---- matching
    def classify(
        self,
        findings: Sequence[Finding],
        present_paths: Collection[str] = (),
        today: _dt.date | None = None,
    ) -> tuple[dict[int, Suppression], list[Diagnostic]]:
        """Map ``index in findings`` -> baseline Suppression, plus expiry diagnostics.

        Matching tries ``fingerprint`` first. If that fails and the entry's ``path`` is absent
        from ``present_paths`` (a moved/renamed file), it tries ``content_fingerprint``.
        """
        today = today or _dt.datetime.now(_dt.timezone.utc).date()
        by_fp = {e["fingerprint"]: e for e in self.entries}
        by_cfp = {
            e["content_fingerprint"]: e
            for e in self.entries
            if e.get("content_fingerprint") and e["path"] not in present_paths
        }
        out: dict[int, Suppression] = {}
        diags: list[Diagnostic] = []
        for i, f in enumerate(findings):
            e = by_fp.get(f.fingerprint) or by_cfp.get(f.content_fingerprint)
            if e is None:
                continue
            exp = e.get("expires")
            if exp:
                try:
                    if _dt.date.fromisoformat(exp) < today:
                        diags.append(
                            Diagnostic(
                                "warning",
                                "baseline-expired",
                                f"baseline entry expired on {exp}",
                                f.file,
                                f.line,
                                f.rule_id,
                            )
                        )
                        continue
                except ValueError:
                    diags.append(
                        Diagnostic(
                            "warning",
                            "baseline-invalid",
                            f"bad expires date {exp!r}",
                            f.file,
                            f.line,
                            f.rule_id,
                        )
                    )
                    continue
            out[i] = Suppression("baseline", e.get("reason"))
        return out, diags

    # ---- create / update
    @staticmethod
    def _entry(f: Finding, reason: str, today: str) -> dict[str, Any]:
        return {
            "fingerprint": f.fingerprint,
            "content_fingerprint": f.content_fingerprint,
            "rule_id": f.rule_id,
            "path": f.file,
            "line": f.line,
            "severity": f.severity.label,
            "reason": reason,
            "added_at": today,
            "expires": None,
        }

    @classmethod
    def create(
        cls,
        findings: Iterable[Finding],
        *,
        reason: str,
        tool_version: str = "",
        rules_hash: str = "",
        allow_critical: bool = False,
        now: str | None = None,
    ) -> Baseline:
        if not reason or not reason.strip():
            raise UsageError("baseline create requires --reason")
        findings = [f for f in findings if f.suppressed is None]
        crit = [f for f in findings if f.severity >= Severity.CRITICAL]
        if crit and not allow_critical:
            raise UsageError(f"{len(crit)} critical finding(s) cannot be baselined without --allow-critical")
        ts = now or _now()
        seen: set[str] = set()
        entries = []
        for f in findings:
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                entries.append(cls._entry(f, reason.strip(), ts[:10]))
        return cls(entries, tool_version, rules_hash, ts, ts)

    def update(
        self,
        findings: Iterable[Finding],
        in_scope: Callable[[str], bool],
        *,
        prune: bool = True,
        add_new: bool = False,
        reason: str | None = None,
        allow_critical: bool = False,
        now: str | None = None,
    ) -> tuple[int, int, int]:
        """Refresh in place; returns ``(kept, pruned, added)``.

        Only entries whose path was inside the scanned scope can be pruned, so a partial scan
        never deletes unrelated entries.
        """
        findings = [f for f in findings if f.suppressed is None]
        fps = {f.fingerprint for f in findings} | {f.content_fingerprint for f in findings}
        kept_entries: list[dict[str, Any]] = []
        pruned = 0
        for e in self.entries:
            found = e["fingerprint"] in fps or e.get("content_fingerprint") in fps
            if found or not in_scope(e["path"]) or not prune:
                kept_entries.append(e)
            else:
                pruned += 1
        known = {e["fingerprint"] for e in kept_entries}
        known_c = {e.get("content_fingerprint") for e in kept_entries}
        added = 0
        ts = now or _now()
        if add_new:
            if not reason or not reason.strip():
                raise UsageError("--add-new requires --reason")
            for f in findings:
                if f.fingerprint in known or f.content_fingerprint in known_c:
                    continue
                if f.severity >= Severity.CRITICAL and not allow_critical:
                    raise UsageError("critical finding(s) cannot be baselined without --allow-critical")
                kept_entries.append(self._entry(f, reason.strip(), ts[:10]))
                known.add(f.fingerprint)
                added += 1
        kept = len(kept_entries) - added
        self.entries = kept_entries
        self.updated_at = ts
        return kept, pruned, added
