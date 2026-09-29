"""Matcher contract, registry and combinators (spec §8.1).

A leaf matcher is a function `(spec, ctx, rule) -> Iterable[Hit]` registered under the key used
in a rule's `match` expression (`regex`, `multiline`, `unicode`, `entropy`, `yaml_path`, `py_ast`,
`hcl`, `builtin`). Leaf modules register themselves on import; `evaluate` imports them lazily so a
hook scanning one markdown file never imports `ast` or the YAML parser.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from ..model import FileCtx, Hit, Rule

LeafMatcher = Callable[[Any, FileCtx, Rule], Iterable[Hit]]

REGISTRY: dict[str, LeafMatcher] = {}

# matcher key -> module that registers it
_MODULES: dict[str, str] = {
    "regex": "whalescan.matchers.regex",
    "multiline": "whalescan.matchers.multiline",
    "unicode": "whalescan.matchers.unicode",
    "entropy": "whalescan.matchers.entropy",
    "yaml_path": "whalescan.matchers.yamlpath",
    "py_ast": "whalescan.matchers.pyast",
    "hcl": "whalescan.matchers.hcl",
    "builtin": "whalescan.matchers.builtin",
}

TEXT_MATCHERS = frozenset({"regex", "multiline", "unicode", "entropy"})
STRUCTURED_MATCHERS = frozenset({"yaml_path", "py_ast", "hcl", "builtin"})


def register(name: str) -> Callable[[LeafMatcher], LeafMatcher]:
    def deco(fn: LeafMatcher) -> LeafMatcher:
        REGISTRY[name] = fn
        return fn

    return deco


def leaf(name: str) -> LeafMatcher:
    fn = REGISTRY.get(name)
    if fn is None:
        importlib.import_module(_MODULES[name])
        fn = REGISTRY[name]
    return fn


def expr_kind(expr: Mapping[str, Any]) -> str:
    """The single key of a matcher expression: all|any|not|regex|..."""
    (key,) = (k for k in expr if k != "near_lines")
    return key


def leaf_kinds(expr: Mapping[str, Any]) -> set[str]:
    """Every leaf matcher type used anywhere in `expr`."""
    k = expr_kind(expr)
    if k in ("all", "any"):
        out: set[str] = set()
        for child in expr[k]:
            out |= leaf_kinds(child)
        return out
    if k == "not":
        return leaf_kinds(expr["not"])
    return {k}


def evaluate(expr: Mapping[str, Any], ctx: FileCtx, rule: Rule) -> list[Hit]:
    """Evaluate a matcher expression. Combinator semantics per spec §8.1:

    - `any`: union of children's hits.
    - `all`: every positive child must hit and every `not` child must produce nothing; reported
      hits are those of the first positive child. With `near_lines: N`, a first-child hit is kept
      only if every other positive child has a hit within N lines and no `not` child has one.
      Children evaluate in order and short-circuit on the first empty positive child.
    - `not`: only valid directly under `all` (enforced by the loader).
    """
    k = expr_kind(expr)
    if k == "any":
        hits: list[Hit] = []
        for child in expr["any"]:
            hits.extend(evaluate(child, ctx, rule))
        return hits
    if k == "all":
        return _evaluate_all(expr, ctx, rule)
    if k == "not":
        # Standalone `not` is rejected by the loader; treat as "no positive hits".
        return []
    return list(leaf(k)(expr[k], ctx, rule))


def _evaluate_all(expr: Mapping[str, Any], ctx: FileCtx, rule: Rule) -> list[Hit]:
    near = expr.get("near_lines")
    positives: list[list[Hit]] = []
    negatives: list[list[Hit]] = []
    for child in expr["all"]:
        if expr_kind(child) == "not":
            neg = evaluate(child["not"], ctx, rule)
            if neg and near is None:
                return []
            negatives.append(neg)
            continue
        hits = evaluate(child, ctx, rule)
        if not hits:
            return []
        positives.append(hits)
    if not positives:
        return []
    first, others = positives[0], positives[1:]
    if near is None:
        return first
    kept: list[Hit] = []
    for h in first:
        lo, hi = h.line - near, h.end_line + near
        if all(any(o.end_line >= lo and o.line <= hi for o in group) for group in others) and not any(
            any(n.end_line >= lo and n.line <= hi for n in group) for group in negatives
        ):
            kept.append(h)
    return kept
