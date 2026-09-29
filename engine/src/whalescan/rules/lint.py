"""Regex safety lint R1-R7 (spec §8.2), run at rule load time and in CI.

The analysis walks the parse tree produced by the stdlib regex parser (`re._parser` on 3.11+, `sre_parse` on
3.10; both produce identical trees for the constructs used here), so it sees exactly what the engine will run,
after the parser's own rewrites (single-character alternations become classes, common prefixes are factored
out of alternations).

- R1 (error): compiles, without parser warnings, portably to 3.10 (no atomic groups or possessive
  repeats), with ASCII-identifier group names.
- R2 (error): no unbounded repeat nested inside another unbounded repeat.
- R3 (error): the first element is not an unbounded repeat of `.`, `\\s`, `\\S` or a negated class.
- R4 (error): minimum width > 0.
- R5 (error): no DOTALL outside `multiline` patterns.
- R6 (warning): no unbounded (or > 4096) repeat of `.` or a negated class anywhere.
- R7 (error): no alternation inside an unbounded repeat whose branches can start with the same character.

Every walk is bounded: patterns longer than `MAX_PATTERN_CHARS` or nested deeper than `MAX_NESTING` are
rejected under R1 before any recursive analysis.
"""

from __future__ import annotations

import importlib
import re
import warnings
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal

Level = Literal["error", "warning"]
Context = Literal["regex", "multiline", "sequence", "search"]
"""Where a pattern runs: the `regex` matcher, a `multiline` pattern, a `multiline.sequence` item, or a
`re.search`-style check (filters, predicates, entropy excludes, py_ast argument regexes)."""

MAX_PATTERN_CHARS: Final = 16_384
MAX_NESTING: Final = 64
MAX_BOUND: Final = 4096
MAX_R7_ALTERNATIVES: Final = 256
MAX_R7_WORK: Final = 2_000_000       # candidate chars x class items examined for one alternation

FLAG_BITS: Final[Mapping[str, int]] = {
    "i": re.IGNORECASE, "x": re.VERBOSE, "a": re.ASCII, "s": re.DOTALL, "m": re.MULTILINE,
}


def _sre_modules() -> tuple[Any, Any]:
    try:
        return importlib.import_module("re._parser"), importlib.import_module("re._constants")
    except ImportError:  # Python 3.10: the parser is still the public (and already imported) sre_parse
        return importlib.import_module("sre_parse"), importlib.import_module("sre_constants")


_P, _C = _sre_modules()

_MAXREPEAT: Final[int] = int(_C.MAXREPEAT)
_POSSESSIVE = getattr(_C, "POSSESSIVE_REPEAT", None)
_ATOMIC = getattr(_C, "ATOMIC_GROUP", None)
_REPEATS: Final = frozenset(op for op in (_C.MAX_REPEAT, _C.MIN_REPEAT, _POSSESSIVE) if op is not None)
_ANCHORS: Final = frozenset(
    getattr(_C, name)
    for name in ("AT_BEGINNING", "AT_BEGINNING_STRING", "AT_BEGINNING_LINE")
    if hasattr(_C, name)
)
_IGNORECASE: Final = int(re.IGNORECASE)
_DOTALL: Final = int(re.DOTALL)
_GROUP_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


@dataclass(frozen=True, slots=True)
class LintIssue:
    code: str                  # R1 .. R7
    level: Level
    message: str
    where: str = ""            # location inside the rule, e.g. `match.all[0].regex.pattern`

    @property
    def is_error(self) -> bool:
        return self.level == "error"

    def __str__(self) -> str:
        loc = f"{self.where}: " if self.where else ""
        return f"{loc}{self.code} {self.message}"


@dataclass(frozen=True, slots=True)
class PatternRef:
    """One regex found in a rule, with the flags and context it runs under."""

    where: str
    pattern: str
    flags: tuple[str, ...] = ()
    context: Context = "search"


def compile_flags(letters: Iterable[str], context: Context = "regex") -> int:
    """`re` flags a pattern runs with: MULTILINE for matcher patterns, plus the rule's flag letters."""
    bits = re.MULTILINE if context != "search" else 0
    for letter in letters:
        bits |= FLAG_BITS.get(letter, 0)
    return bits


# --------------------------------------------------------------------------------------------- lint entry


def lint_pattern(
    pattern: str, flags: Iterable[str] = (), *, context: Context = "regex", where: str = ""
) -> list[LintIssue]:
    """All lint issues for one pattern. R1 failures stop the analysis (there is no tree to inspect)."""
    issues: list[LintIssue] = []

    def add(code: str, level: Level, message: str) -> None:
        issues.append(LintIssue(code, level, message, where))

    if len(pattern) > MAX_PATTERN_CHARS:
        add("R1", "error", f"pattern longer than {MAX_PATTERN_CHARS} characters")
        return issues
    letters = tuple(flags)
    bad = [f for f in letters if f not in FLAG_BITS]
    if bad:
        add("R1", "error", f"unknown flag(s): {', '.join(sorted(bad))}")
        return issues
    bits = compile_flags(letters, context)

    tree = _parse(pattern, bits, add)
    if tree is None:
        return issues
    if _nesting(tree) > MAX_NESTING:
        add("R1", "error", f"groups nested deeper than {MAX_NESTING} levels")
        return issues
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")        # already recorded by _parse
            compiled = re.compile(pattern, bits)
    except (re.error, RecursionError, OverflowError, ValueError) as exc:
        add("R1", "error", f"does not compile: {exc}")
        return issues
    for name in compiled.groupindex:
        if not _GROUP_NAME.match(name):
            add("R1", "error", f"group name {name!r} is not an ASCII identifier")
    if _uses(tree, {_ATOMIC, _POSSESSIVE} - {None}):
        add("R1", "error", "atomic groups and possessive repeats need Python 3.11+ (engine supports 3.10)")

    state_flags = int(getattr(tree.state, "flags", 0)) | bits
    icase = bool(state_flags & _IGNORECASE)

    if _has_nested_unbounded(tree):
        add("R2", "error", "nested unbounded repeats, e.g. (a+)+ or (?:\\w+\\s?)*: bound the inner or outer "
            "repeat with {0,N}")
    r3 = _r3_seq(tree)[0]
    if r3:
        add("R3", "error", "starts with an unbounded repeat of '.', '\\s', '\\S' or a negated class, "
            "which makes finditer quadratic on long lines: anchor on a literal or use {0,N}")
    try:
        min_width = int(tree.getwidth()[0])
    except (RecursionError, OverflowError):  # pragma: no cover - bounded by MAX_NESTING
        min_width = 1
    if min_width <= 0:
        add("R4", "error", "can match the empty string (minimum width 0)")
    if context != "multiline" and (state_flags & _DOTALL or _scoped_dotall(tree)):
        add("R5", "error", "DOTALL / (?s) is only allowed in `multiline` patterns")
    if not r3:
        wide = _wide_repeat(tree)
        if wide:
            add("R6", "warning", f"{wide} of '.' or a negated class: use {{0,N}} with N <= {MAX_BOUND}")
    r7 = _ambiguous_alternation(tree, icase)
    if r7:
        add("R7", "error", r7)
    return issues


def _parse(pattern: str, bits: int, add: Callable[[str, Level, str], None]) -> Any:
    """Parse with every parser warning captured: a warning today is an error on a newer Python."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            tree = _P.parse(pattern, bits)
        except re.error as exc:
            add("R1", "error", f"does not compile: {exc}")
            return None
        except (RecursionError, OverflowError, ValueError) as exc:
            add("R1", "error", f"does not compile: {type(exc).__name__}")
            return None
    for w in caught:
        add("R1", "error", f"{w.category.__name__}: {w.message}")
    return tree


def lint_patterns(refs: Iterable[PatternRef]) -> list[LintIssue]:
    out: list[LintIssue] = []
    for ref in refs:
        out += lint_pattern(ref.pattern, ref.flags, context=ref.context, where=ref.where)
    return out


def lint_rule(rule: Mapping[str, Any]) -> list[LintIssue]:
    """Lint every pattern of a (schema-valid) raw rule mapping, including filters and predicates."""
    return lint_patterns(iter_patterns(rule))


# --------------------------------------------------------------------------------------------- pattern walk


def iter_patterns(rule: Mapping[str, Any]) -> Iterator[PatternRef]:
    """Every regex in a raw rule: the matcher expression, then `filters`."""
    match = rule.get("match")
    if isinstance(match, Mapping):
        yield from iter_expr_patterns(match, "match")
    filters = rule.get("filters")
    if isinstance(filters, Mapping):
        for key in ("file_regex", "file_not_regex", "line_not_regex"):
            value = filters.get(key)
            if isinstance(value, str):
                yield PatternRef(f"filters.{key}", value, (), "search")


def iter_expr_patterns(expr: Mapping[str, Any], where: str, depth: int = 0) -> Iterator[PatternRef]:
    if depth > MAX_NESTING:
        return
    for key, spec in expr.items():
        here = f"{where}.{key}"
        if key in ("all", "any") and isinstance(spec, list):
            for i, child in enumerate(spec):
                if isinstance(child, Mapping):
                    yield from iter_expr_patterns(child, f"{here}[{i}]", depth + 1)
        elif key == "not" and isinstance(spec, Mapping):
            yield from iter_expr_patterns(spec, here, depth + 1)
        elif key == "regex":
            if isinstance(spec, str):
                yield PatternRef(here, spec, (), "regex")
            elif isinstance(spec, Mapping) and isinstance(spec.get("pattern"), str):
                yield PatternRef(f"{here}.pattern", spec["pattern"], _letters(spec), "regex")
        elif key == "multiline" and isinstance(spec, Mapping):
            if isinstance(spec.get("pattern"), str):
                yield PatternRef(f"{here}.pattern", spec["pattern"], _letters(spec), "multiline")
            seq = spec.get("sequence")
            if isinstance(seq, list):
                for i, pat in enumerate(seq):
                    if isinstance(pat, str):
                        yield PatternRef(f"{here}.sequence[{i}]", pat, _letters(spec), "sequence")
        elif key == "entropy" and isinstance(spec, Mapping):
            excludes = spec.get("exclude_regex")
            if isinstance(excludes, list):
                for i, pat in enumerate(excludes):
                    if isinstance(pat, str):
                        yield PatternRef(f"{here}.exclude_regex[{i}]", pat, (), "search")
        elif key in ("yaml_path", "hcl") and isinstance(spec, Mapping):
            for group in ("all", "any", "none"):
                conds = spec.get(group)
                if isinstance(conds, list):
                    for i, cond in enumerate(conds):
                        yield from _predicate_patterns(cond, f"{here}.{group}[{i}]")
        elif key == "py_ast" and isinstance(spec, Mapping):
            call = spec.get("call")
            if isinstance(call, Mapping):
                for group in ("args", "kwargs"):
                    conds = call.get(group)
                    if isinstance(conds, Mapping):
                        for name, cond in conds.items():
                            yield from _predicate_patterns(cond, f"{here}.call.{group}.{name}")
            route = spec.get("fastapi_route")
            if isinstance(route, Mapping):
                for name in ("auth_regex", "ignore_paths_regex"):
                    if isinstance(route.get(name), str):
                        yield PatternRef(f"{here}.fastapi_route.{name}", route[name], (), "search")


def _predicate_patterns(cond: Any, where: str) -> Iterator[PatternRef]:
    if not isinstance(cond, Mapping):
        return
    for name in ("regex", "not_regex"):
        if isinstance(cond.get(name), str):
            yield PatternRef(f"{where}.{name}", cond[name], (), "search")


def _letters(spec: Mapping[str, Any]) -> tuple[str, ...]:
    flags = spec.get("flags")
    return tuple(f for f in flags if isinstance(f, str)) if isinstance(flags, list) else ()


# --------------------------------------------------------------------------------------------- tree helpers


def _children(op: Any, av: Any) -> list[Any]:
    """Sub-sequences directly below one parse node."""
    if op is _C.SUBPATTERN:
        return [av[-1]]
    if op in _REPEATS:
        return [av[2]]
    if op is _C.BRANCH:
        return list(av[1])
    if op is _C.ASSERT or op is _C.ASSERT_NOT:
        return [av[1]]
    if _ATOMIC is not None and op is _ATOMIC:
        return [av]
    if op is _C.GROUPREF_EXISTS:
        return [s for s in (av[1], av[2]) if s is not None]
    return []


def _nesting(tree: Any) -> int:
    deepest = 0
    stack: list[tuple[Any, int]] = [(tree, 0)]
    while stack:
        seq, depth = stack.pop()
        deepest = max(deepest, depth)
        if depth > MAX_NESTING:
            break
        for op, av in seq:
            for child in _children(op, av):
                stack.append((child, depth + 1))
    return deepest


def _walk(seq: Any) -> Iterator[tuple[Any, Any]]:
    stack = [seq]
    while stack:
        for op, av in stack.pop():
            yield op, av
            stack.extend(_children(op, av))


def _uses(tree: Any, ops: set[Any]) -> bool:
    return bool(ops) and any(op in ops for op, _ in _walk(tree))


def _unbounded(op: Any, av: Any) -> bool:
    return op in _REPEATS and int(av[1]) == _MAXREPEAT


def _has_nested_unbounded(tree: Any) -> bool:
    for op, av in _walk(tree):
        if _unbounded(op, av) and any(_unbounded(o, a) for o, a in _walk(av[2])):
            return True
    return False


def _scoped_dotall(tree: Any) -> bool:
    return any(op is _C.SUBPATTERN and int(av[1]) & _DOTALL for op, av in _walk(tree))


def _is_wide(seq: Any, *, space: bool) -> bool:
    """True for a single atom matching '.', a negated class (incl. \\S \\D \\W), or with `space` also \\s."""
    nodes = list(seq)
    if len(nodes) != 1:
        return False
    op, av = nodes[0]
    if op is _C.ANY or op is _C.NOT_LITERAL:
        return True
    if op is _C.IN:
        if av and av[0][0] is _C.NEGATE:
            return True
        for item_op, item_av in av:
            if item_op is _C.CATEGORY:
                name = str(getattr(item_av, "name", ""))
                if name.startswith("CATEGORY_NOT_") or (space and name == "CATEGORY_SPACE"):
                    return True
        return False
    if op is _C.SUBPATTERN:
        return _is_wide(av[-1], space=space)
    if op is _C.BRANCH:
        return any(_is_wide(alt, space=space) for alt in av[1])
    return False


def _r3_seq(seq: Any) -> tuple[bool, bool]:
    """(an unbounded wide repeat can start a match, the sequence can match empty without a start anchor)."""
    for op, av in seq:
        offends, transparent = _r3_node(op, av)
        if offends:
            return True, False
        if not transparent:
            return False, False
    return False, True


def _r3_node(op: Any, av: Any) -> tuple[bool, bool]:
    if op is _C.AT:
        return False, av not in _ANCHORS           # ^ and \A anchor everything after them
    if op is _C.ASSERT or op is _C.ASSERT_NOT:
        return False, True
    if op in _REPEATS:
        lo, hi, item = av
        if int(hi) == _MAXREPEAT and _is_wide(item, space=True):
            return True, False
        offends, transparent = _r3_seq(item)
        return offends, (not offends) and (int(lo) == 0 or transparent)
    if op is _C.SUBPATTERN:
        return _r3_seq(av[-1])
    if _ATOMIC is not None and op is _ATOMIC:
        return _r3_seq(av)
    if op is _C.BRANCH or op is _C.GROUPREF_EXISTS:
        alts = list(av[1]) if op is _C.BRANCH else [s for s in (av[1], av[2]) if s is not None]
        results = [_r3_seq(alt) for alt in alts]
        empty_else = op is _C.GROUPREF_EXISTS and av[2] is None
        return any(o for o, _ in results), empty_else or any(t for _, t in results)
    if op is _C.GROUPREF:
        return False, True
    return False, False


def _wide_repeat(tree: Any) -> str:
    for op, av in _walk(tree):
        if op in _REPEATS and _is_wide(av[2], space=False):
            hi = int(av[1])
            if hi == _MAXREPEAT:
                return "unbounded repeat"
            if hi > MAX_BOUND:
                return f"repeat bound {hi} > {MAX_BOUND}"
    return ""


# --------------------------------------------------------------------------------------------- R7

# An atom is one character matcher that can start a branch: ("lit"|"notlit", codepoint, icase),
# ("in", items, icase) or ("any",).
_Atom = tuple[Any, ...]

_REPRESENTATIVES: Final = tuple(
    ord(c) for c in "09aAzZ_ \t\n\r!-./\\:@=\"'éÉ ٠一\x00\x7f￿\U0001f600"
)


def _ambiguous_alternation(tree: Any, icase: bool) -> str:
    """Message for the first alternation inside an unbounded repeat whose branches share a first character."""
    # (sequence, ignorecase, inside an unbounded repeat)
    stack: list[tuple[Any, bool, bool]] = [(tree, icase, False)]
    while stack:
        seq, ic, inside = stack.pop()
        for op, av in seq:
            if op is _C.BRANCH and inside:
                message = _branch_overlap(av[1], ic)
                if message:
                    return message
            if op is _C.SUBPATTERN:
                add, remove = int(av[1]), int(av[2])
                child_ic = (ic or bool(add & _IGNORECASE)) and not bool(remove & _IGNORECASE)
                stack.append((av[-1], child_ic, inside))
                continue
            child_inside = inside or _unbounded(op, av)
            for child in _children(op, av):
                stack.append((child, ic, child_inside))
    return ""


def _branch_overlap(alternatives: list[Any], icase: bool) -> str:
    if len(alternatives) > MAX_R7_ALTERNATIVES:
        return (f"alternation with more than {MAX_R7_ALTERNATIVES} branches inside an unbounded repeat "
                "is too large to analyze")
    firsts = [_first(alt, icase, 0)[0] for alt in alternatives]
    pool: set[int] = set(_REPRESENTATIVES)
    for atoms in firsts:
        pool |= _candidates(atoms)
    work = len(pool) * sum(len(a[1]) if a[0] == "in" else 1 for atoms in firsts for a in atoms)
    if work > MAX_R7_WORK:
        return ("alternation inside an unbounded repeat is too complex to analyze: simplify its branches or "
                "bound the repeat with {0,N}")
    owner: dict[int, int] = {}
    for idx, atoms in enumerate(firsts):
        if not atoms:
            continue
        for cp in pool:
            if any(_member(cp, atom) for atom in atoms):
                prev = owner.setdefault(cp, idx)
                if prev != idx:
                    shown = chr(cp) if chr(cp).isprintable() and not chr(cp).isspace() else f"U+{cp:04X}"
                    return (f"alternation inside an unbounded repeat has branches {prev + 1} and {idx + 1} "
                            f"that can both start with {shown!r} (exponential backtracking): make the "
                            "branches disjoint")
    return ""


def _first(seq: Any, icase: bool, depth: int) -> tuple[list[_Atom], bool]:
    """(atoms that can match the first character, whether the whole sequence can match empty)."""
    atoms: list[_Atom] = []
    if depth > MAX_NESTING:
        return [("any",)], False
    for op, av in seq:
        found, nullable = _first_node(op, av, icase, depth + 1)
        atoms += found
        if not nullable:
            return atoms, False
    return atoms, True


def _first_node(op: Any, av: Any, icase: bool, depth: int) -> tuple[list[_Atom], bool]:
    if op is _C.LITERAL:
        return [("lit", int(av), icase)], False
    if op is _C.NOT_LITERAL:
        return [("notlit", int(av), icase)], False
    if op is _C.ANY:
        return [("any",)], False
    if op is _C.IN:
        return [("in", av, icase)], False
    if op is _C.AT or op is _C.ASSERT or op is _C.ASSERT_NOT:
        return [], True
    if op in _REPEATS:
        atoms, nullable = _first(av[2], icase, depth)
        return atoms, nullable or int(av[0]) == 0
    if op is _C.SUBPATTERN:
        add, remove = int(av[1]), int(av[2])
        child_ic = (icase or bool(add & _IGNORECASE)) and not bool(remove & _IGNORECASE)
        return _first(av[-1], child_ic, depth)
    if _ATOMIC is not None and op is _ATOMIC:
        return _first(av, icase, depth)
    if op is _C.BRANCH or op is _C.GROUPREF_EXISTS:
        alts = list(av[1]) if op is _C.BRANCH else [s for s in (av[1], av[2]) if s is not None]
        merged: list[_Atom] = []
        nullable = op is _C.GROUPREF_EXISTS and av[2] is None
        for alt in alts:
            found, n = _first(alt, icase, depth)
            merged += found
            nullable = nullable or n
        return merged, nullable
    return [("any",)], op is _C.GROUPREF          # group references and anything unknown: conservative


def _candidates(atoms: list[_Atom]) -> set[int]:
    out: set[int] = set()
    for atom in atoms:
        if atom[0] in ("lit", "notlit"):
            c = atom[1]
            out.update((c - 1, c, c + 1))
        elif atom[0] == "in":
            for op, av in atom[1]:
                if op is _C.LITERAL:
                    out.update((av - 1, av, av + 1))
                elif op is _C.RANGE:
                    lo, hi = int(av[0]), int(av[1])
                    out.update((lo - 1, lo, hi, hi + 1))
    return {c for c in out if 0 <= c <= 0x10FFFF}


def _variants(cp: int) -> tuple[int, ...]:
    ch = chr(cp)
    out = {cp}
    for v in (ch.lower(), ch.upper(), ch.casefold()):
        if len(v) == 1:
            out.add(ord(v))
    return tuple(out)


def _member(cp: int, atom: _Atom) -> bool:
    kind = atom[0]
    if kind == "any":
        return True
    variants = _variants(cp) if atom[-1] else (cp,)
    if kind == "lit":
        return atom[1] in variants
    if kind == "notlit":
        return atom[1] not in variants
    items = atom[1]
    negate = bool(items) and items[0][0] is _C.NEGATE
    hit = any(_item_match(v, op, av) for v in variants for op, av in items if op is not _C.NEGATE)
    return hit != negate


def _item_match(cp: int, op: Any, av: Any) -> bool:
    if op is _C.LITERAL:
        return cp == int(av)
    if op is _C.RANGE:
        return int(av[0]) <= cp <= int(av[1])
    if op is _C.CATEGORY:
        ch = chr(cp)
        name = str(getattr(av, "name", ""))
        negated = "_NOT_" in name
        if name.endswith("DIGIT"):
            result = ch.isdecimal()
        elif name.endswith("SPACE"):
            result = ch.isspace()
        elif name.endswith("WORD"):
            result = ch.isalnum() or ch == "_"
        elif name.endswith("LINEBREAK"):
            result = ch == "\n"
        else:
            return True
        return result != negated
    return True
