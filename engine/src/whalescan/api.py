"""Public scanner pipeline (spec §8, §15–17). Every run owns its mutable state.

Workers return sanitized findings and span coordinates, never raw secret values.
"""

from __future__ import annotations

import copy
import os
import re
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields, replace
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

from . import __version__
from .config import Config, load_config
from .dedupe import Candidate as Identity
from .dedupe import dedupe, fingerprints, normalized_snippet
from .errors import InternalError, UsageError
from .ignore import IgnoreMatcher, any_glob_match
from .matchers.base import evaluate, leaf_kinds
from .matchers.regex import compile_pattern
from .model import Confidence, Diagnostic, Finding, Hit, Rule, RunInfo, ScanResult, Severity, Stats
from .redact import Redactor, redact_spans, redact_value
from .rules.cache import load_rules as cached_rules
from .rules.loader import KeywordTable, RuleSet
from .severity import effective_base, exposure_for, score
from .suppress import Baseline, SuppressIndex, inline_allowed, marker_suppression, parse_markers
from .walker import (
    Candidate,
    Loaded,
    Walker,
    ctx_from_bytes,
    ctx_from_text,
    git_changed_files,
    git_diff_hunks,
)
from .walker import load as load_file

__all__ = ["Scanner", "load_rules", "scan_injection", "scan_text"]

# Importing the implementation submodule installs `whalescan.redact` as a module. Restore
# the public function of that name (§16) after its first import, without eager startup imports.
sys.modules[__package__].__dict__["redact"] = redact_value


def load_rules(
    cfg: Config, *, packs: Sequence[str] | None = None, rule_ids: Sequence[str] | None = None
) -> RuleSet:
    rules = cached_rules(
        [cfg.resolve_path(p) for p in cfg.rules.extra_dirs],
        missing_dirs_ok=True,
        cache_dir=cfg.cache_path or None,
        use_cache=cfg.cache.enabled,
        config={"rules": cfg.to_dict()["rules"], "packs": list(packs or cfg.scan.packs)},
    )
    return rules.select(
        cfg.scan.packs if packs is None else packs,
        rule_ids,
        enable=cfg.rules.enable,
        disable=cfg.rules.disable,
    )


def _expired(deadline: float | None) -> bool:
    return deadline is not None and time.monotonic() >= deadline


def _deadline(budget: int) -> float | None:
    if budget < 0:
        raise UsageError("time_budget_ms must be non-negative")
    return time.monotonic() + budget / 1000 if budget else None


@lru_cache(maxsize=128)
def _keywords(words: tuple[str, ...]) -> re.Pattern[str] | None:
    return re.compile("(?=" + "|".join(re.escape(w) for w in words) + ")") if words else None


def _active_keywords(rules: Sequence[Rule], text: str) -> set[str]:
    table = KeywordTable.build(rules)
    ids = set(table.always)
    for mapping, haystack in ((table.sensitive, text), (table.insensitive, text.casefold())):
        words = tuple(sorted(mapping))
        rx = _keywords(words)
        if rx is None:
            continue
        first: dict[str, list[str]] = {}
        for word in words:
            first.setdefault(word[0], []).append(word)
        seen: set[str] = set()
        for match in rx.finditer(haystack):
            pos = match.start()
            for word in first[haystack[pos]]:
                if word not in seen and haystack.startswith(word, pos):
                    ids.update(mapping[word])
                    seen.add(word)
            if len(seen) == len(words):
                break
    return {rules[i].id for i in ids}


def _message(template: str, captures: Mapping[str, str], redactor: Redactor) -> str:
    return re.sub(r"\{\{(\w+)\}\}", lambda m: redactor.finalize(captures.get(m[1], "")), template)


def _clean(value: Any, redactor: Redactor) -> Any:
    if isinstance(value, str):
        return redactor.finalize(value)
    if isinstance(value, Mapping):
        return {_clean(k, redactor): _clean(v, redactor) for k, v in value.items()}
    if isinstance(value, tuple):
        return tuple(_clean(v, redactor) for v in value)
    if isinstance(value, list):
        return [_clean(v, redactor) for v in value]
    return value


def _clean_record(record: Any, redactor: Redactor) -> Any:
    updates = {f.name: _clean(getattr(record, f.name), redactor) for f in fields(record)}
    if isinstance(record, Finding) and record.suppressed is not None:
        updates["suppressed"] = _clean_record(record.suppressed, redactor)
    return replace(record, **updates)


@dataclass(slots=True)
class _FileResult:
    identities: list[Identity]
    markers: SuppressIndex
    diagnostics: list[Diagnostic]
    stats: Stats
    path: str
    spans: tuple[tuple[int, int], ...] = ()
    error_type: str | None = None
    timings: dict[str, tuple[float, int]] = field(default_factory=dict)


def _scan_file(
    loaded: Loaded,
    rules: RuleSet,
    cfg: Config,
    ignored: frozenset[str],
    deadline: float | None,
    line_ranges: Sequence[tuple[int, int]] | None = None,
    *,
    is_inject: bool = False,
) -> _FileResult:
    stats = Stats()
    ctx = loaded.ctx
    diagnostics = list(loaded.diagnostics)
    if ctx is None:
        if loaded.skip:
            stats.files_skipped[loaded.skip] = 1
        return _FileResult([], SuppressIndex(), diagnostics, stats, "")
    stats.files_scanned, stats.bytes_scanned = 1, ctx.size
    ctx.cache["secrets.entropy_delta"] = cfg.secrets.entropy_delta
    candidates = [
        r
        for r in rules.candidates(ctx.kind, ctx.lang, ctx.tags)
        if r.id not in ignored
        and (
            not r.applies_to.globs or (ctx.path != "<stdin>" and any_glob_match(r.applies_to.globs, ctx.path))
        )
        and not any_glob_match(r.applies_to.exclude_globs, ctx.path)
        and (r.applies_to.max_bytes is None or ctx.size <= r.applies_to.max_bytes)
        and (
            is_inject
            or not cfg.scan.skip_minified
            or "minified" not in ctx.tags
            or r.pack_root == "secrets"
            or r.applies_to.include_minified
        )
    ]
    active = _active_keywords(candidates, ctx.text)
    redactor = Redactor()
    items: list[tuple[Rule, Hit]] = []
    all_spans: set[tuple[int, int]] = set()
    error_type = None
    timings: dict[str, tuple[float, int]] = {}
    for rule in candidates:
        if _expired(deadline):
            stats.truncated = True
            break
        if rule.id not in active:
            continue
        if ctx.encoding_fallback and leaf_kinds(rule.match) == {"unicode"}:
            continue
        filters = rule.filters
        if filters.get("file_regex") and not compile_pattern(filters["file_regex"], re.M).search(ctx.text):
            continue
        if filters.get("file_not_regex") and compile_pattern(filters["file_not_regex"], re.M).search(
            ctx.text
        ):
            continue
        stats.rules_evaluated += 1
        began = time.monotonic()
        try:
            hits = evaluate(rule.match, ctx, replace(rule, max_hits_per_file=1000))
        except Exception as exc:
            from .errors import WhalescanError

            if isinstance(exc, WhalescanError):
                raise
            error_type = type(exc).__name__
            break
        timings[rule.id] = ((time.monotonic() - began) * 1000, len(hits))
        kept = []
        for hit in hits:
            spans = hit.secret_spans or ([(hit.start, hit.end)] if rule.is_secret_rule else [])
            for span in spans:
                all_spans.add(span)
                redactor.add_span(ctx.text, span)
            hit.secret_spans = list(spans)
            if rule.pack_root == "secrets" and any(
                compile_pattern(p).fullmatch(ctx.text[s:e])
                for p in cfg.secrets.allow_values
                for s, e in spans
            ):
                continue
            if filters.get("line_not_regex") and compile_pattern(filters["line_not_regex"]).search(
                ctx.line_text(hit.line)
            ):
                continue
            if any_glob_match(filters.get("path_not_glob", ()), ctx.path):
                continue
            if line_ranges is not None and not any(
                hit.end_line >= lo and hit.line <= hi for lo, hi in line_ranges
            ):
                continue
            kept.append(hit)
        excess = max(0, len(kept) - rule.max_hits_per_file) + ctx.cache.get("capped", {}).pop(rule.id, 0)
        if excess:
            stats.capped[rule.id] = excess
            diagnostics.append(
                Diagnostic("info", "rule-capped", f"{excess} hit(s) capped", ctx.path, rule_id=rule.id)
            )
        items.extend((rule, h) for h in kept[: rule.max_hits_per_file])
    diagnostics.extend(ctx.cache.get("diagnostics", ()))
    markers = parse_markers(ctx, cfg.suppress) if not is_inject else SuppressIndex()
    diagnostics.extend(markers.diagnostics)
    identities = []
    for rule, hit in items:
        base = effective_base(rule.id, rule.severity, cfg.severity.overrides)
        exposure = exposure_for(
            ctx.path, ctx.tags, cfg.severity.exposure, is_inject=is_inject, hint=hit.props.get("exposure")
        )
        value, severity = score(
            base, hit.reachability, exposure, exposure_sensitive=rule.exposure_sensitive and not is_inject
        )
        confidence = Confidence(max(0, min(2, int(rule.confidence) + hit.confidence_delta)))
        if rule.pack_root == "secrets" and "example" in ctx.tags:
            confidence = Confidence.LOW
        props = dict(hit.props)
        if ctx.source_label is not None:
            props["source_label"] = ctx.source_label
        start = ctx.line_span(hit.line)[0]
        stop = ctx.line_span(min(hit.end_line, hit.line + 2))[1]
        snippet = redact_spans(
            ctx.text[start:stop],
            [(max(s, start) - start, min(e, stop) - start) for s, e in all_spans if s < stop and e > start],
        )
        message = _message(rule.message, hit.captures, redactor)
        finding = Finding(
            rule.id,
            rule.title,
            severity,
            base,
            value,
            confidence,
            hit.reachability,
            exposure,
            rule.pack,
            ctx.path,
            ctx.kind,
            hit.line,
            hit.col,
            hit.end_line,
            hit.end_col,
            redactor.finalize(snippet)[: cfg.report.max_snippet_chars],
            rule.cwe,
            rule.owasp,
            message,
            rule.fix,
            rule.references,
            "",
            "",
            atlas=rule.atlas,
            properties=props,
        )
        finding = _clean_record(finding, redactor)
        identities.append(
            Identity(
                rule.id,
                ctx.path,
                hit.start,
                hit.end,
                hit.line,
                hit.col,
                hit.end_line,
                hit.end_col,
                normalized_snippet(ctx, hit, all_spans),
                value,
                confidence,
                "generic" in rule.tags,
                frozenset(rule.supersedes),
                tuple(hit.secret_spans),
                finding,
            )
        )
    for marker in markers.markers:
        marker.reason = _clean(marker.reason, redactor)
        marker.ticket = _clean(marker.ticket, redactor)
    return _FileResult(
        identities,
        markers,
        [_clean_record(d, redactor) for d in diagnostics],
        stats,
        ctx.path,
        tuple(sorted(all_spans)),
        error_type,
        timings,
    )


_WORKER_RULES: RuleSet | None = None
_WORKER_CFG: Config | None = None


def _init_worker(snapshot: Mapping[str, Any], cfg: Config) -> None:
    global _WORKER_RULES, _WORKER_CFG  # noqa: PLW0603 -- one initializer per process
    _WORKER_RULES = RuleSet.from_dict(snapshot)
    _WORKER_CFG = cfg


def _batch_worker(batch: Sequence[Candidate], deadline: float | None) -> list[_FileResult]:
    if _WORKER_RULES is None or _WORKER_CFG is None:
        raise RuntimeError("scanner worker not initialized")
    out = []
    for candidate in batch:
        if _expired(deadline):
            break
        out.append(
            _scan_file(
                load_file(candidate, _WORKER_CFG),
                _WORKER_RULES,
                _WORKER_CFG,
                candidate.ignored_rules,
                deadline,
            )
        )
    return out


def _batches(candidates: Sequence[Candidate]) -> list[list[Candidate]]:
    batches: list[list[Candidate]] = []
    batch: list[Candidate] = []
    size = 0
    for candidate in sorted(candidates, key=lambda c: (-c.size, c.path)):
        if batch and (len(batch) >= 64 or size + candidate.size > 2 << 20):
            batches.append(batch)
            batch, size = [], 0
        batch.append(candidate)
        size += candidate.size
    if batch:
        batches.append(batch)
    return batches


@dataclass(frozen=True, init=False)
class Scanner:
    rules: RuleSet
    cfg: Config
    adapters: tuple[str, ...]

    def __init__(self, rules: RuleSet, cfg: Config, *, adapters: Sequence[str] = ()) -> None:
        object.__setattr__(self, "rules", RuleSet.from_dict(rules.to_dict()))
        object.__setattr__(self, "cfg", copy.deepcopy(cfg))
        object.__setattr__(self, "adapters", tuple(adapters))

    def scan_paths(
        self,
        paths: Sequence[str | os.PathLike[str]],
        *,
        jobs: int | None = None,
        diff_ref: str | None = None,
        time_budget_ms: int | None = None,
    ) -> ScanResult:
        start = time.monotonic()
        deadline = _deadline(self.cfg.scan.time_budget_ms if time_budget_ms is None else time_budget_ms)
        count = self.cfg.scan.jobs if jobs is None else jobs
        if count < 0:
            raise UsageError("jobs must be non-negative")
        count = count or self.cfg.scan.effective_jobs
        only = git_changed_files(self.cfg.root, diff_ref) if diff_ref is not None else None
        hunks = (
            git_diff_hunks(self.cfg.root, diff_ref)
            if diff_ref is not None and self.cfg.scan.diff_lines_only
            else None
        )
        walker = Walker(self.cfg, rule_ids=self.rules.by_id, only=only)
        candidates = []
        for candidate in walker.walk(paths):
            if _expired(deadline):
                break
            candidates.append(candidate)
        results: list[_FileResult] = []
        parallel = count > 1 and len(candidates) >= 200 and sum(c.size for c in candidates) >= 4 << 20
        if parallel:
            from concurrent.futures import ProcessPoolExecutor
            from multiprocessing import get_context

            with ProcessPoolExecutor(
                max_workers=count,
                mp_context=get_context("forkserver" if sys.platform == "linux" else "spawn"),
                initializer=_init_worker,
                initargs=(self.rules.to_dict(), self.cfg),
            ) as pool:
                batches = _batches(candidates)
                for batch_result in pool.map(_batch_worker, batches, [deadline] * len(batches)):
                    results.extend(batch_result)
        else:
            for candidate in candidates:
                if _expired(deadline):
                    break
                results.append(
                    _scan_file(
                        load_file(candidate, self.cfg),
                        self.rules,
                        self.cfg,
                        candidate.ignored_rules,
                        deadline,
                    )
                )
        redactor = Redactor()
        by_path = {c.path: c for c in candidates}
        for result in results:
            if result.spans and result.path in by_path:
                loaded = load_file(by_path[result.path], self.cfg)
                if loaded.ctx is not None:
                    for span in result.spans:
                        redactor.add_span(loaded.ctx.text, span)
        stats = Stats(truncated=walker.truncated or _expired(deadline))
        walker.apply_stats(stats)
        return self._finish(
            results, stats, walker.diagnostics, {c.path for c in candidates}, start, redactor, hunks=hunks
        )

    def scan_text(
        self,
        text: str | bytes,
        *,
        filename: str = "<stdin>",
        line_ranges: Sequence[tuple[int, int]] | None = None,
        time_budget_ms: int | None = None,
    ) -> ScanResult:
        return self._text(text, filename, line_ranges, time_budget_ms)

    def _text(
        self,
        text: str | bytes,
        filename: str,
        ranges: Sequence[tuple[int, int]] | None,
        budget: int | None,
        *,
        is_inject: bool = False,
        source_label: str | None = None,
        truncated: bool = False,
        input_size: int | None = None,
    ) -> ScanResult:
        start = time.monotonic()
        deadline = _deadline(self.cfg.scan.time_budget_ms if budget is None else budget)
        filename = filename.replace(os.sep, "/")
        if os.path.isabs(filename):
            relative = os.path.relpath(filename, self.cfg.root or os.getcwd())
            if relative != ".." and not relative.startswith("../"):
                filename = relative
        matcher = IgnoreMatcher(self.cfg.root or os.getcwd(), extra=self.cfg.scan.exclude)
        if filename != "<stdin>" and matcher.is_ignored(filename):
            return self._finish([], Stats(files_skipped={"ignored": 1}), [], {filename}, start, Redactor())
        if isinstance(text, bytes) and is_inject:
            from .textio import decode

            decoded = decode(text, filename)
            loaded = Loaded(
                ctx_from_text(
                    decoded.text,
                    filename,
                    cfg=self.cfg,
                    size=len(text) if input_size is None else input_size,
                    encoding=decoded.encoding,
                    fallback=decoded.fallback,
                    source_label=source_label,
                ),
                diagnostics=decoded.diagnostics,
            )
        else:
            loaded = (
                ctx_from_bytes(text, filename, cfg=self.cfg, source_label=source_label)
                if isinstance(text, bytes)
                else Loaded(
                    ctx_from_text(text, filename, cfg=self.cfg, size=input_size, source_label=source_label)
                )
            )
        if is_inject and filename == "<stdin>" and loaded.ctx is not None:
            loaded.ctx.kind = "doc"
        result = _scan_file(
            loaded,
            self.rules,
            self.cfg,
            matcher.ignored_rules(filename, self.rules.by_id),
            deadline,
            ranges,
            is_inject=is_inject,
        )
        redactor = Redactor()
        if loaded.ctx is not None:
            for span in result.spans:
                redactor.add_span(loaded.ctx.text, span)
        diagnostics = list(matcher.diagnostics)
        if truncated:
            diagnostics.append(
                Diagnostic("warning", "input-truncated", "input scanned as its first and last bytes")
            )
        return self._finish(
            [result],
            Stats(truncated=truncated or _expired(deadline)),
            diagnostics,
            {filename},
            start,
            redactor,
            is_inject=is_inject,
        )

    def _finish(
        self,
        results: Sequence[_FileResult],
        stats: Stats,
        diagnostics: list[Diagnostic],
        present: set[str],
        start: float,
        redactor: Redactor,
        *,
        is_inject: bool = False,
        hunks: Mapping[str, Sequence[tuple[int, int]]] | None = None,
    ) -> ScanResult:
        diagnostics = [*self.cfg.diagnostics, *(w.to_diagnostic() for w in self.rules.warnings), *diagnostics]
        identities = []
        indexes = {}
        timings: dict[str, tuple[float, int]] = {}
        for result in sorted(results, key=lambda r: r.path):
            identities.extend(result.identities)
            indexes[result.path] = result.markers
            diagnostics.extend(result.diagnostics)
            for rule_id, (elapsed, hits) in result.timings.items():
                before = timings.get(rule_id, (0.0, 0))
                timings[rule_id] = (before[0] + elapsed, before[1] + hits)
            stats.files_scanned += result.stats.files_scanned
            stats.bytes_scanned += result.stats.bytes_scanned
            stats.rules_evaluated += result.stats.rules_evaluated
            stats.truncated |= result.stats.truncated
            for key, value in result.stats.files_skipped.items():
                stats.files_skipped[key] = stats.files_skipped.get(key, 0) + value
            for key, value in result.stats.capped.items():
                stats.capped[key] = stats.capped.get(key, 0) + value
        selected = dedupe(identities)
        findings = [
            replace(
                c.item,
                fingerprint=fp,
                content_fingerprint=cfp,
                properties={**c.item.properties, **({"related": sorted(c.related)} if c.related else {})},
            )
            for c, (fp, cfp) in zip(selected, fingerprints(selected), strict=True)
        ]
        baseline_path = self.cfg.resolve_path(self.cfg.scan.baseline) if self.cfg.scan.baseline else ""
        baseline = (
            Baseline.load(baseline_path) if baseline_path and os.path.exists(baseline_path) else Baseline()
        )
        matches, notes = baseline.classify(findings, present)
        diagnostics.extend(notes)
        kept = []
        for i, finding in enumerate(findings):
            suppression = None
            if inline_allowed(finding.rule_id, finding.file_kind, is_inject=is_inject):
                marker = indexes[finding.file].match(finding.line, finding.rule_id)
                if marker:
                    suppression = marker_suppression(marker)
            suppression = suppression or matches.get(i)
            if suppression:
                stats.suppressed[suppression.kind] += 1
            finding = replace(finding, suppressed=suppression)  # noqa: PLW2901
            if finding.confidence < Confidence.parse(self.cfg.scan.min_confidence):
                continue
            if hunks is not None and not any(
                finding.end_line >= lo and finding.line <= hi for lo, hi in hunks.get(finding.file, ())
            ):
                continue
            kept.append(_clean_record(finding, redactor))
        if self.cfg.suppress.report_unused:
            for path, index in indexes.items():
                diagnostics.extend(index.unused(path))
        if stats.truncated and not any(
            d.code == "input-truncated" or d.code.startswith("max-") for d in diagnostics
        ):
            diagnostics.append(
                Diagnostic(
                    "warning", "time-budget-exceeded", "time budget exceeded; partial scan (hooks fail open)"
                )
            )
        for adapter in self.adapters:
            diagnostics.append(
                Diagnostic(
                    "warning" if self.cfg.adapters.strict else "info",
                    "adapter-missing",
                    f"adapter {adapter} is not available in this engine build",
                )
            )
        run = RunInfo(
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            int((time.monotonic() - start) * 1000),
            self.cfg.root,
            packs=list(self.rules.packs),
            config_sources=list(self.cfg.sources),
            config_changes=list(self.cfg.changes),
            fail_on=self.cfg.scan.fail_on,
            truncated=stats.truncated,
            tool_version=__version__,
            rules_hash=self.rules.bundle_hash,
        )
        gate = tuple(sorted(kept, key=lambda f: f.sort_key))
        visible = tuple(f for f in gate if f.severity >= Severity.parse(self.cfg.scan.min_severity))
        for finding in visible:
            if finding.suppressed is None:
                stats.by_severity[finding.severity.label] = (
                    stats.by_severity.get(finding.severity.label, 0) + 1
                )
        scan_result = ScanResult(
            visible,
            tuple(
                sorted(
                    (_clean_record(d, redactor) for d in diagnostics),
                    key=lambda d: (d.file or "", d.line or 0, d.code, d.rule_id or ""),
                )
            ),
            stats,
            _clean_record(run, redactor),
            _gate_findings=gate,
        )
        scan_result.run.exit_code = scan_result.exit_code(self.cfg.scan.fail_on)
        scan_result.run._profile = timings
        scan_result.run._sweep = redactor.sweep
        error_type = next((r.error_type for r in results if r.error_type), None)
        if error_type:
            scan_result.run.error = {"type": error_type, "message": "matcher failed; partial scan"}
            scan_result.run.exit_code = 3
            error = InternalError("matcher failed; partial scan")
            error.partial_result = scan_result
            raise error
        return scan_result


@lru_cache(maxsize=16)
def _scanner(root: str | None, packs: tuple[str, ...]) -> Scanner:
    cfg = load_config(root)
    return Scanner(load_rules(cfg, packs=packs), cfg)


def scan_text(
    text: str | bytes,
    *,
    filename: str,
    packs: Sequence[str] = ("appsec", "secrets", "domain"),
    line_ranges: Sequence[tuple[int, int]] | None = None,
    time_budget_ms: int = 150,
    root: str | None = None,
) -> ScanResult:
    return _scanner(os.path.abspath(root or os.getcwd()), tuple(packs)).scan_text(
        text, filename=filename, line_ranges=line_ranges, time_budget_ms=time_budget_ms
    )


def _injection_input(data: bytes, limit: int) -> tuple[str | bytes, bool]:
    """First/last byte windows, without making valid Unicode look like a latin-1 file.

    A seam may cut UTF-8 or UTF-16/32 characters. Decode the windows independently with the
    original codec so such a cut cannot disable the Unicode matcher for the entire document.
    """
    from .textio import decode

    if limit < 1:
        raise UsageError("max_bytes must be positive")
    if len(data) <= limit:
        return data, False
    head, tail = data[: limit // 2], data[-(limit - limit // 2) :]
    decoded = decode(data)
    if decoded.fallback:
        return head + b"\n" + tail, True
    codec = decoded.encoding.replace("-sig", "")
    width = 4 if codec.startswith("utf-32") else (2 if codec.startswith("utf-16") else 1)
    if width > 1:
        tail = tail[len(tail) % width :]
    header = head.decode(decoded.encoding, errors="replace")
    if width > 1 and header.startswith("\ufeff"):
        header = header[1:]
    return header + "\n" + tail.decode(codec, errors="replace"), True


def scan_injection(
    text: str | bytes,
    *,
    source_label: str,
    reveal: bool = True,
    max_bytes: int | None = None,
    time_budget_ms: int = 150,
) -> ScanResult:
    scanner = _scanner(os.getcwd(), ("agentsec",))
    data = text.encode("utf-8", "surrogatepass") if isinstance(text, str) else text
    limit = scanner.cfg.inject.max_bytes if max_bytes is None else max_bytes
    scanned, truncated = _injection_input(data, limit)
    # Report fields always reveal (§13); reveal controls whole-input presentation, not findings.
    return scanner._text(
        scanned,
        "<stdin>",
        None,
        time_budget_ms,
        is_inject=True,
        source_label=source_label,
        truncated=truncated,
        input_size=min(len(data), limit),
    )
