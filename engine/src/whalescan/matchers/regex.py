"""`regex` leaf matcher (spec §8.2), plus helpers shared by the other text matchers.

Semantics:

- `finditer` over the whole text with `re.MULTILINE` and the rule's flags (`i`, `x`, `a`): every
  non-overlapping hit is reported, never just the first. `^`/`$` are line anchors and `.` never crosses a
  `\\n`; cross-line matching belongs to `multiline`.
- The hit span is `report_group` (default 0). A hit whose report span is empty, or whose report group did
  not participate, is skipped (R4 forbids zero-width patterns; this is the defensive half).
- `secret_group`, when it participated and is non-empty, becomes the hit's secret span.
- Patterns never pass through argv, so a leading `-` is literal (`-----BEGIN OPENSSH PRIVATE KEY-----`).

Compiled patterns are cached per `(pattern, flags)` in a module-level dict. Hits beyond
`rule.max_hits_per_file` are not built; they are counted (up to `OVERFLOW_COUNT_LIMIT`, so a hostile
file cannot make counting expensive) into `ctx.cache["capped"][rule.id]`.
"""

from __future__ import annotations

import re
import warnings
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Final, TypeVar

from ..errors import RuleError
from ..model import FileCtx, Hit, Rule
from .base import register

_T = TypeVar("_T")

CAPPED_KEY: Final = "capped"
"""`ctx.cache[CAPPED_KEY]` maps rule id -> hits a matcher dropped because of `max_hits_per_file`."""

OVERFLOW_COUNT_LIMIT: Final = 1000
"""Once a matcher is capped it keeps counting further hits, but saturates at this many (a lower bound)."""

FLAG_BITS: Final[Mapping[str, int]] = {"i": re.IGNORECASE, "x": re.VERBOSE, "a": re.ASCII, "s": re.DOTALL}

_CACHE: dict[tuple[str, int], re.Pattern[str]] = {}
_CACHE_MAX: Final = 4096


# --------------------------------------------------------------------------- shared helpers


def compile_pattern(pattern: str, flags: int = 0) -> re.Pattern[str]:
    """Compile once per `(pattern, flags)` and process. Raises `RuleError` for an invalid pattern."""
    key = (pattern, flags)
    rx = _CACHE.get(key)
    if rx is not None:
        return rx
    if not isinstance(pattern, str) or not pattern:
        raise RuleError(f"expected a non-empty regex pattern, got {type(pattern).__name__}")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # FutureWarning noise belongs to lint, not to every scan
            rx = re.compile(pattern, flags)
    except (re.error, RecursionError, OverflowError, ValueError) as exc:
        raise RuleError(f"invalid regex {pattern!r}: {exc}") from None
    if len(_CACHE) >= _CACHE_MAX:  # rules are finite; this only bounds a long-lived process
        _CACHE.clear()
    _CACHE[key] = rx
    return rx


def flag_bits(letters: object, allowed: str, *, where: str) -> int:
    """`re.MULTILINE` plus the bits of the rule's flag letters; letters outside `allowed` are rejected."""
    bits = re.MULTILINE
    if letters is None:
        return bits
    if isinstance(letters, (str, bytes)) or not isinstance(letters, Iterable):
        raise RuleError(f"{where}: flags must be a list of letters")
    for letter in letters:
        if not isinstance(letter, str) or letter not in allowed or letter not in FLAG_BITS:
            raise RuleError(f"{where}: unsupported flag {letter!r} (allowed: {', '.join(allowed)})")
        bits |= FLAG_BITS[letter]
    return bits


def record_capped(ctx: FileCtx, rule_id: str, excess: int) -> None:
    """Add `excess` dropped hits for `rule_id` to `ctx.cache["capped"]` (created on first use)."""
    if excess <= 0:
        return
    capped = ctx.cache.get(CAPPED_KEY)
    if not isinstance(capped, dict):
        capped = {}
        ctx.cache[CAPPED_KEY] = capped
    capped[rule_id] = int(capped.get(rule_id, 0)) + excess


def collect_capped(items: Iterable[_T], ctx: FileCtx, rule: Rule, build: Callable[[_T], Hit]) -> list[Hit]:
    """Build hits from `items` (already qualified, in position order) up to `rule.max_hits_per_file`.

    The overflow is counted without building hits and saturates at `OVERFLOW_COUNT_LIMIT`.
    """
    limit = max(0, int(rule.max_hits_per_file))
    hits: list[Hit] = []
    it = iter(items)
    for item in it:
        if len(hits) >= limit:
            excess = 1
            for _ in it:
                if excess >= OVERFLOW_COUNT_LIMIT:
                    break
                excess += 1
            record_capped(ctx, rule.id, excess)
            break
        hits.append(build(item))
    return hits


def captures_of(m: re.Match[str]) -> dict[str, str]:
    """Named groups of a match; a group that did not participate maps to ""."""
    return {k: ("" if v is None else v) for k, v in m.groupdict().items()}


# --------------------------------------------------------------------------- the regex leaf


@dataclass(frozen=True, slots=True)
class RegexSpec:
    pattern: str
    flags: int
    report_group: int | str = 0
    secret_group: str | None = None


def parse_spec(spec: Any) -> RegexSpec:
    """Normalize the `regex` leaf: a bare pattern string or `{pattern, flags, report_group, secret_group}`."""
    if isinstance(spec, str):
        return RegexSpec(spec, re.MULTILINE)
    if not isinstance(spec, Mapping):
        raise RuleError("regex: expected a pattern string or a mapping")
    pattern = spec.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        raise RuleError("regex: `pattern` must be a non-empty string")
    flags = flag_bits(spec.get("flags"), "ixa", where="regex")
    report = spec.get("report_group", 0)
    if isinstance(report, bool) or not isinstance(report, (int, str)):
        raise RuleError("regex: `report_group` must be a group number or name")
    if isinstance(report, int) and report < 0:
        raise RuleError("regex: `report_group` must be >= 0")
    secret = spec.get("secret_group")
    if secret is not None and not isinstance(secret, str):
        raise RuleError("regex: `secret_group` must be a group name")
    return RegexSpec(pattern, flags, report, secret)


def check_groups(rx: re.Pattern[str], report: int | str, secret: str | None, *, where: str) -> None:
    if isinstance(report, str):
        if report not in rx.groupindex:
            raise RuleError(f"{where}: report_group {report!r} is not a named group of the pattern")
    elif report > rx.groups:
        raise RuleError(f"{where}: report_group {report} exceeds the pattern's {rx.groups} group(s)")
    if secret is not None and secret not in rx.groupindex:
        raise RuleError(f"{where}: secret_group {secret!r} is not a named group of the pattern")


@register("regex")
def match_regex(spec: Any, ctx: FileCtx, rule: Rule) -> list[Hit]:
    rs = parse_spec(spec)
    rx = compile_pattern(rs.pattern, rs.flags)
    check_groups(rx, rs.report_group, rs.secret_group, where="regex")
    group, secret = rs.report_group, rs.secret_group

    def matches() -> Iterator[re.Match[str]]:
        for m in rx.finditer(ctx.text):
            s, e = m.span(group)
            if s != e:  # empty, or (-1, -1) for a report group that did not participate
                yield m

    def build(m: re.Match[str]) -> Hit:
        s, e = m.span(group)
        spans = [m.span(secret)] if secret is not None and m.group(secret) else []
        return Hit.at(ctx, s, e, captures=captures_of(m), secret_spans=spans)

    return collect_capped(matches(), ctx, rule, build)
