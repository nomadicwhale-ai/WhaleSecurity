"""Finding identity and de-duplication (spec §9).

Operates on :class:`Candidate` records so it stays independent of how findings are finally built.
Pipeline: :func:`dedupe` (exact, same-rule overlap, cross-rule secret overlap) then
:func:`fingerprints` (stable ids that survive line moves; ``content`` ids that survive renames).
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from .model import Confidence, FileCtx, Hit

_WS = re.compile(r"\s+")
_SEP = "\x1f"


def _sha(*parts: str) -> str:
    h = hashlib.sha256(_SEP.join(parts).encode("utf-8", "surrogatepass"))
    return "sha256:" + h.hexdigest()


def normalized_snippet(ctx: FileCtx, hit: Hit, secret_spans: Iterable[tuple[int, int]] = ()) -> str:
    """Lines ``hit.line .. min(hit.end_line, hit.line + 2)`` with secrets masked and whitespace collapsed.

    Unicode is deliberately *not* normalized: hidden code points are the finding.
    """
    last = min(hit.end_line, hit.line + 2)
    base = ctx.line_span(hit.line)[0]
    stop = ctx.line_span(last)[1]
    text = ctx.text[base:stop]
    for s, e in sorted({(s, e) for s, e in secret_spans if s < e}, reverse=True):
        s2, e2 = max(s, base) - base, min(e, stop) - base
        if s2 >= e2:
            continue
        secret = text[s2:e2]
        mask = (
            "<SECRET:" + hashlib.sha256(secret.encode("utf-8", "surrogatepass")).hexdigest() + ">"
            if len(secret) >= 16
            else f"<SECRET:len={len(secret)}>"
        )
        text = text[:s2] + mask + text[e2:]
    return _WS.sub(" ", text).strip()


@dataclass(slots=True)
class Candidate:
    rule_id: str
    path: str
    start: int
    end: int
    line: int
    col: int
    end_line: int
    end_col: int
    norm: str
    score: float = 0.0
    confidence: Confidence = Confidence.MEDIUM
    generic: bool = False
    supersedes: frozenset[str] = frozenset()
    secret_spans: tuple[tuple[int, int], ...] = ()
    item: Any = None  # caller payload (e.g. a partially built Finding)
    related: list[str] = field(default_factory=list)  # rule ids that lost to this candidate


def _exact(cands: Sequence[Candidate]) -> list[Candidate]:
    seen: set[tuple[str, str, int, int, int, int]] = set()
    out: list[Candidate] = []
    for c in cands:
        key = (c.rule_id, c.path, c.line, c.col, c.end_line, c.end_col)
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


def _same_rule_overlap(cands: Sequence[Candidate]) -> list[Candidate]:
    """Earliest start wins, then the longest span."""
    groups: dict[tuple[str, str], list[Candidate]] = defaultdict(list)
    for c in cands:
        groups[(c.path, c.rule_id)].append(c)
    keep: set[int] = set()
    for group in groups.values():
        last_end = -1
        for c in sorted(group, key=lambda c: (c.start, -c.end)):
            if c.start >= last_end:
                keep.add(id(c))
                last_end = c.end
    return [c for c in cands if id(c) in keep]


def _resolve_cluster(cluster: Sequence[Candidate], dropped: set[int]) -> None:
    """Keep every candidate of the best rule in an overlapping-secret cluster; drop the rest."""
    members: dict[str, list[Candidate]] = defaultdict(list)
    for c in cluster:
        members[c.rule_id].append(c)
    if len(members) < 2:
        return

    def rank(rid: str) -> tuple[float, ...]:
        first = members[rid][0]
        sup = sum(1 for o in members if o != rid and o in first.supersedes)
        best = max(x.score for x in members[rid])
        return (int(not first.generic), sup, best, int(first.confidence))

    winner = min(members, key=lambda r: (*(-v for v in rank(r)), r))
    for rid, group in members.items():
        if rid == winner:
            continue
        for c in group:
            dropped.add(id(c))
        for wc in members[winner]:
            if rid not in wc.related:
                wc.related.append(rid)


def _cross_rule_secret_overlap(cands: Sequence[Candidate]) -> list[Candidate]:
    """Among rules reporting overlapping secret spans, keep the best rule (spec §9 step 3).

    Preference: not ``generic`` > lists the others in ``supersedes`` > higher score > higher
    confidence > lexicographically smaller rule id (determinism). Losers are recorded in the
    winner's ``related``.
    """
    by_path: dict[str, list[tuple[int, int, Candidate]]] = defaultdict(list)
    for c in cands:
        for s, e in c.secret_spans:
            by_path[c.path].append((s, e, c))
    dropped: set[int] = set()
    for spans in by_path.values():
        spans.sort(key=lambda t: (t[0], t[1]))
        cluster: list[Candidate] = []
        reach = -1
        for s, e, c in spans:
            if cluster and s >= reach:
                _resolve_cluster(cluster, dropped)
                cluster, reach = [], -1
            cluster.append(c)
            reach = max(reach, e)
        _resolve_cluster(cluster, dropped)
    return [c for c in cands if id(c) not in dropped]


def dedupe(cands: Sequence[Candidate]) -> list[Candidate]:
    """Exact, same-rule overlap, then cross-rule secret overlap. Result is in input order."""
    return _cross_rule_secret_overlap(_same_rule_overlap(_exact(cands)))


def fingerprints(cands: Sequence[Candidate]) -> list[tuple[str, str]]:
    """``(fingerprint, content_fingerprint)`` per candidate, aligned with ``cands``.

    ``occ`` is the 0-based index among candidates in the same file with the same
    ``(rule_id, norm)``, in position order, so two identical lines stay distinct while line
    numbers never enter the hash.
    """
    order = sorted(range(len(cands)), key=lambda i: (cands[i].path, cands[i].start, cands[i].rule_id))
    seen: dict[tuple[str, str, str], int] = defaultdict(int)
    out: list[tuple[str, str]] = [("", "")] * len(cands)
    for i in order:
        c = cands[i]
        key = (c.path, c.rule_id, c.norm)
        occ = seen[key]
        seen[key] += 1
        out[i] = (_sha(c.rule_id, c.path, c.norm, str(occ)), _sha(c.rule_id, c.norm, str(occ)))
    return out
