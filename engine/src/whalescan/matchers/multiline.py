"""`multiline` leaf matcher (spec §8.3).

**Pattern form** `{pattern, flags, max_span_lines, secret_group}`: `finditer` over the whole text with
`re.MULTILINE` (plus `re.DOTALL` for flag `s`). A hit is dropped when it spans more than `max_span_lines`
lines (default 30), counted from its first to its last character.

**Sequence form** `{sequence: [p1, ...], within_lines, flags}`: ordered line-proximity matching. For each
match of `p1`, the chain takes the earliest match of `p2` starting at or after the previous element's end,
then of `p3`, and so on; every element must start within `within_lines` lines of `p1`'s line. The hit spans
the first element's start to the last element's end. Each pattern runs once over the text (its matches are
kept as sorted start/end lists and searched with `bisect`), so the work is linear in the number of matches
and never depends on how patterns could overlap: ReDoS-safe by construction, given lint-clean patterns.
"""

from __future__ import annotations

import re
from bisect import bisect_left
from collections.abc import Iterator, Mapping, Sequence
from typing import Any, Final

from ..errors import RuleError
from ..model import FileCtx, Hit, Rule
from .base import register
from .regex import captures_of, check_groups, collect_capped, compile_pattern, flag_bits

DEFAULT_MAX_SPAN_LINES: Final = 30
MAX_SEQUENCE_MATCHES: Final = 250_000
"""Matches kept per later sequence pattern; a hostile file cannot make the index unbounded."""


def _int(spec: Mapping[str, Any], key: str, default: int | None, *, lo: int, where: str) -> int:
    value = spec.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < lo:
        raise RuleError(f"{where}: `{key}` must be an integer >= {lo}")
    return value


@register("multiline")
def match_multiline(spec: Any, ctx: FileCtx, rule: Rule) -> list[Hit]:
    if not isinstance(spec, Mapping):
        raise RuleError("multiline: expected a mapping with `pattern` or `sequence`")
    if "sequence" in spec:
        return _match_sequence(spec, ctx, rule)
    return _match_pattern(spec, ctx, rule)


# --------------------------------------------------------------------------- pattern form


def _match_pattern(spec: Mapping[str, Any], ctx: FileCtx, rule: Rule) -> list[Hit]:
    pattern = spec.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        raise RuleError("multiline: `pattern` must be a non-empty string")
    rx = compile_pattern(pattern, flag_bits(spec.get("flags"), "ixas", where="multiline"))
    max_span = _int(spec, "max_span_lines", DEFAULT_MAX_SPAN_LINES, lo=1, where="multiline")
    secret = spec.get("secret_group")
    if secret is not None and not isinstance(secret, str):
        raise RuleError("multiline: `secret_group` must be a group name")
    check_groups(rx, 0, secret, where="multiline")

    def matches() -> Iterator[re.Match[str]]:
        for m in rx.finditer(ctx.text):
            s, e = m.span()
            if s == e:
                continue
            if ctx.line_of(e - 1) - ctx.line_of(s) + 1 > max_span:
                continue
            yield m

    def build(m: re.Match[str]) -> Hit:
        s, e = m.span()
        spans = [m.span(secret)] if secret is not None and m.group(secret) else []
        return Hit.at(ctx, s, e, captures=captures_of(m), secret_spans=spans)

    return collect_capped(matches(), ctx, rule, build)


# --------------------------------------------------------------------------- sequence form


def _match_sequence(spec: Mapping[str, Any], ctx: FileCtx, rule: Rule) -> list[Hit]:
    seq = spec.get("sequence")
    if (
        isinstance(seq, (str, bytes))
        or not isinstance(seq, Sequence)
        or not 2 <= len(seq) <= 5
        or not all(isinstance(p, str) and p for p in seq)
    ):
        raise RuleError("multiline: `sequence` must be a list of 2 to 5 non-empty patterns")
    within = _int(spec, "within_lines", None, lo=0, where="multiline")
    flags = flag_bits(spec.get("flags"), "ixa", where="multiline.sequence")
    pats = [compile_pattern(p, flags) for p in seq]
    text = ctx.text
    later: list[tuple[list[int], list[int]] | None] = [None] * (len(pats) - 1)

    def index(j: int) -> tuple[list[int], list[int]]:
        """Sorted starts/ends of the non-empty matches of pattern j + 1, computed on first use."""
        got = later[j]
        if got is None:
            starts: list[int] = []
            ends: list[int] = []
            for m in pats[j + 1].finditer(text):
                s, e = m.span()
                if s != e:
                    starts.append(s)
                    ends.append(e)
                    if len(starts) >= MAX_SEQUENCE_MATCHES:
                        break
            got = later[j] = (starts, ends)
        return got

    def chains() -> Iterator[list[tuple[int, int]]]:
        for m0 in pats[0].finditer(text):
            s0, e0 = m0.span()
            if s0 == e0:
                continue
            limit = ctx.line_of(s0) + within
            chain = [(s0, e0)]
            for j in range(len(later)):
                starts, ends = index(j)
                k = bisect_left(starts, chain[-1][1])
                if k == len(starts):
                    # A later first element ends later, so its chain cannot find a match here either.
                    return
                if ctx.line_of(starts[k]) > limit:
                    break
                chain.append((starts[k], ends[k]))
            else:
                yield chain

    def build(chain: list[tuple[int, int]]) -> Hit:
        captures: dict[str, str] = {}
        for rx, (s, _) in zip(pats, chain, strict=True):
            m = rx.match(text, s)  # re-running at the recorded start reproduces the finditer match
            if m is None:
                continue
            for k, v in captures_of(m).items():
                if not captures.get(k):  # the first element that captured a name wins
                    captures[k] = v
        return Hit.at(
            ctx,
            chain[0][0],
            chain[-1][1],
            captures=captures,
            props={"sequence_lines": [ctx.line_of(s) for s, _ in chain]},
        )

    return collect_capped(chains(), ctx, rule, build)
