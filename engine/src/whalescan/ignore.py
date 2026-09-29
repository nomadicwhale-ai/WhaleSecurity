"""gitignore-syntax compiler shared by the walker, ``.whalescanignore`` and path globs (spec §4).

Semantics follow git:

* ``#`` starts a comment (``\\#`` escapes it); trailing spaces are trimmed unless escaped;
  ``!`` negates (``\\!`` escapes it); a trailing ``/`` restricts the pattern to directories.
* A pattern with a leading or inner ``/`` is anchored to the directory of the file that defines
  it; otherwise it matches a basename at any depth below that directory.
* ``*`` matches any run of non-``/`` characters, ``?`` one non-``/`` character, ``[...]`` a
  character class (``!``/``^`` negation, ranges, ``[:alpha:]``-style classes). ``**/`` matches
  any leading directories, ``/**`` everything inside, ``/**/`` zero or more directories. Other
  runs of ``*`` act like a single ``*``.
* The last matching pattern wins; files are applied from the root down to the deepest
  directory; a path under an excluded directory cannot be re-included.

Extensions for ``.whalescanignore``: ``#!rules ID,GLOB,...`` starts a section whose patterns
apply only to those rule IDs (``#!rules *`` returns to all rules); ``.git`` is always excluded;
built-in excludes (:data:`BUILTIN_EXCLUDES`) sit below every file and can be negated.

Matching never uses backtracking regexes across path components: ``**`` is handled by a
component-level wildcard algorithm and components with many ``*`` by a linear-time greedy
matcher, so hostile ignore files cannot cause catastrophic backtracking.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Collection, Iterable, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase

from .model import Diagnostic

__all__ = [
    "BUILTIN_EXCLUDES",
    "IGNORE_FILENAME",
    "GlobSet",
    "IgnoreMatcher",
    "Pattern",
    "compile_glob",
    "compile_pattern",
    "glob_match",
    "normalize_relpath",
    "parse_patterns",
    "rule_glob_match",
]

IGNORE_FILENAME = ".whalescanignore"

#: Lowest-priority, negatable excludes (spec §4).
BUILTIN_EXCLUDES: tuple[str, ...] = (
    "node_modules/", ".venv/", "venv/", "__pycache__/", ".tox/", ".mypy_cache/", ".ruff_cache/",
    ".terraform/", ".terragrunt-cache/", "dist/", "build/", "target/", ".idea/", "*.min.js.map",
)  # fmt: skip

MAX_IGNORE_FILE_BYTES = 1 << 20  # larger ignore files are skipped with a warning
MAX_PATTERNS_PER_FILE = 20_000
MAX_PATTERN_CHARS = 4096
_MAX_CACHE = 200_000  # entries per decision cache before it is reset

SegMatch = Callable[[str], object]  # truthy when a single path component matches


class _StarStar:
    """Sentinel for a ``**`` path segment."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "**"


STARSTAR = _StarStar()
Seg = SegMatch | _StarStar


def _any_component(_: str) -> bool:
    return True


# --------------------------------------------------------------------------- component globs

_POSIX_CLASSES: dict[str, str] = {
    "alnum": "a-zA-Z0-9",
    "alpha": "a-zA-Z",
    "blank": " \\t",
    "cntrl": "\\x00-\\x1f\\x7f",
    "digit": "0-9",
    "graph": "\\x21-\\x7e",
    "lower": "a-z",
    "print": "\\x20-\\x7e",
    "punct": "!-/:-@\\[-`{-~",
    "space": " \\t\\n\\r\\f\\v",
    "upper": "A-Z",
    "xdigit": "0-9A-Fa-f",
}


class _Tok:
    """Wildcard token inside one component (distinct from any literal character)."""

    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return self.name


_STAR = _Tok("*")
_QMARK = _Tok("?")
Token = str | _Tok | tuple[str]


def _class_escape(c: str) -> str:
    return "\\" + c if c in "\\]^-[" else c


def _parse_class(pat: str, i: int) -> tuple[str, int] | None:
    """Parse a bracket expression starting at ``pat[i] == "["``.

    Returns ``(regex_class, index_after)`` or ``None`` when the bracket is not closed (the
    ``[`` is then a literal).
    """
    n = len(pat)
    j = i + 1
    negate = False
    if j < n and pat[j] in "!^":
        negate = True
        j += 1
    parts: list[str] = []
    first = True
    invalid = False
    while j < n:
        c = pat[j]
        if c == "]" and not first:
            break
        first = False
        if c == "[" and pat.startswith("[:", j):
            end = pat.find(":]", j + 2)
            if end != -1:
                cls = _POSIX_CLASSES.get(pat[j + 2 : end])
                if cls is None:
                    invalid = True
                else:
                    parts.append(cls)
                j = end + 2
                continue
        if c == "\\" and j + 1 < n:
            c = pat[j + 1]
            j += 2
        else:
            j += 1
        if j + 1 < n and pat[j] == "-" and pat[j + 1] != "]":
            hi = pat[j + 1]
            j += 2
            if hi == "\\" and j < n:
                hi = pat[j]
                j += 1
            if c <= hi:
                parts.append(f"{_class_escape(c)}-{_class_escape(hi)}")
            continue  # reversed ranges match nothing (git)
        parts.append(_class_escape(c))
    else:
        return None  # unterminated
    j += 1  # skip "]"
    if invalid:
        return ("[^\\s\\S]", j) if not negate else ("[\\s\\S]", j)
    body = "".join(parts)
    if not body:
        return ("[\\s\\S]", j) if negate else ("[^\\s\\S]", j)
    return ("[^" if negate else "[") + body + "]", j


def _tokenize(seg: str) -> list[Token]:
    """Split a component glob into literal chars, ``*``, ``?`` and ``(class_regex,)`` tokens."""
    toks: list[Token] = []
    i, n = 0, len(seg)
    while i < n:
        c = seg[i]
        if c == "\\":
            if i + 1 < n:
                toks.append(seg[i + 1])  # escaped literal (may be "*", "?", "[", "\\")
                i += 2
                continue
            toks.append("\\")  # a lone trailing backslash is kept literally
            i += 1
            continue
        if c == "*":
            if not (toks and toks[-1] is _STAR):
                toks.append(_STAR)
            i += 1
            continue
        if c == "?":
            toks.append(_QMARK)
            i += 1
            continue
        if c == "[":
            parsed = _parse_class(seg, i)
            if parsed is not None:
                toks.append((parsed[0],))
                i = parsed[1]
                continue
        toks.append(c)
        i += 1
    return toks


def _is_literal(tok: Token) -> bool:
    return isinstance(tok, str)


def _greedy(tokens: Sequence[Token]) -> SegMatch:
    """O(n*m) wildcard matcher for components with many ``*`` (backtracks to the last star)."""
    toks = tuple(re.compile(t[0], re.DOTALL) if isinstance(t, tuple) else t for t in tokens)
    m = len(toks)

    def one(tok: str | _Tok | re.Pattern[str], ch: str) -> bool:
        if isinstance(tok, _Tok):
            return tok is _QMARK
        if isinstance(tok, str):
            return tok == ch
        return tok.fullmatch(ch) is not None

    def match(s: str) -> bool:
        si = ti = 0
        star_ti = -1
        star_si = 0
        n = len(s)
        while si < n:
            if ti < m and toks[ti] is not _STAR and one(toks[ti], s[si]):
                si += 1
                ti += 1
            elif ti < m and toks[ti] is _STAR:
                star_ti = ti
                star_si = si
                ti += 1
            elif star_ti >= 0:
                ti = star_ti + 1
                star_si += 1
                si = star_si
            else:
                return False
        while ti < m and toks[ti] is _STAR:
            ti += 1
        return ti == m

    return match


def _compile_component(seg: str) -> SegMatch:
    toks = _tokenize(seg)
    stars = sum(1 for t in toks if t is _STAR)
    if all(_is_literal(t) for t in toks):
        lit = "".join(t for t in toks if isinstance(t, str))
        return lit.__eq__
    if toks == [_STAR]:
        return _any_component
    if stars == 1 and all(t is _STAR or _is_literal(t) for t in toks):
        k = toks.index(_STAR)
        pre = "".join(t for t in toks[:k] if isinstance(t, str))
        suf = "".join(t for t in toks[k + 1 :] if isinstance(t, str))
        if not pre:
            return lambda s: s.endswith(suf)
        if not suf:
            return lambda s: s.startswith(pre)
        need = len(pre) + len(suf)
        return lambda s: len(s) >= need and s.startswith(pre) and s.endswith(suf)
    if stars <= 2:
        # At most two unbounded runs: sre is O(n^2) worst case on a <= 255-char component.
        parts: list[str] = []
        for t in toks:
            if t is _STAR:
                parts.append(".*")
            elif isinstance(t, _Tok):
                parts.append(".")
            elif isinstance(t, tuple):
                parts.append(t[0])
            else:
                parts.append(re.escape(t))
        return re.compile("".join(parts), re.DOTALL).fullmatch
    return _greedy(toks)


def _match_parts(segs: Sequence[Seg], parts: Sequence[str]) -> bool:
    """Match path components against segments where ``**`` spans zero or more components.

    Greedy with a single backtrack point (the last ``**``): O(len(parts) * len(segs)).
    """
    pi = si = 0
    star_si = -1
    star_pi = 0
    np_, ns = len(parts), len(segs)
    while pi < np_:
        if si < ns:
            seg = segs[si]
            if isinstance(seg, _StarStar):
                star_si = si
                star_pi = pi
                si += 1
                continue
            if seg(parts[pi]):
                si += 1
                pi += 1
                continue
        if star_si >= 0:
            si = star_si + 1
            star_pi += 1
            pi = star_pi
            continue
        return False
    while si < ns and isinstance(segs[si], _StarStar):
        si += 1
    return si == ns


# --------------------------------------------------------------------------- patterns


@dataclass(frozen=True, slots=True, eq=False)
class Pattern:
    """One compiled gitignore line.

    Exactly one matching strategy is set: ``name`` (basename pattern), ``plain`` (anchored,
    no ``**``: one matcher per component), ``segs`` (anchored with ``**``) or ``alts``.
    """

    source: str  # the pattern as written (after trimming)
    negate: bool
    dir_only: bool
    name: SegMatch | None = None  # basename pattern: last component only
    plain: tuple[SegMatch, ...] | None = None  # anchored, fixed number of components
    segs: tuple[Seg, ...] | None = None  # anchored with ``**`` segments
    alts: tuple[Pattern, ...] | None = None  # alternatives (``X**/`` expansion), any may match
    base: tuple[str, ...] = ()  # directory (components) of the defining file
    scope: tuple[str, ...] | None = None  # rule-ID globs; None = every rule
    origin: str = ""  # "<file>:<line>" for debugging

    @property
    def basename(self) -> bool:
        return self.name is not None

    def matches(self, parts: Sequence[str], is_dir: bool) -> bool:
        """``parts`` are the path components *relative to* :attr:`base`."""
        if not parts or (self.dir_only and not is_dir):
            return False
        if self.name is not None:
            return bool(self.name(parts[-1]))
        if self.plain is not None:
            if len(parts) != len(self.plain):
                return False
            return all(seg(part) for seg, part in zip(self.plain, parts, strict=False))
        if self.segs is not None:
            return _match_parts(self.segs, parts)
        if self.alts is not None:
            return any(alt.matches(parts, is_dir) for alt in self.alts)
        return False


def _trim_trailing_spaces(line: str) -> str:
    end = len(line)
    while end > 0 and line[end - 1] == " ":
        # count backslashes before this space: odd => escaped, keep it
        k = end - 2
        bs = 0
        while k >= 0 and line[k] == "\\":
            bs += 1
            k -= 1
        if bs % 2 == 1:
            break
        end -= 1
    return line[:end]


def compile_pattern(
    line: str,
    base: Sequence[str] = (),
    scope: Sequence[str] | None = None,
    origin: str = "",
) -> Pattern | None:
    """Compile one gitignore line. Returns ``None`` for blanks, comments and no-op lines."""
    if line.endswith("\r"):
        line = line[:-1]
    if not line or line.startswith("#") or len(line) > MAX_PATTERN_CHARS:
        return None
    line = _trim_trailing_spaces(line)
    negate = False
    if line.startswith("!"):
        negate = True
        line = line[1:]
    dir_only = False
    while line.endswith("/") and not line.endswith("\\/"):
        dir_only = True
        line = line[:-1]
    if not line:
        return None
    anchored = "/" in line
    if line.startswith("/"):
        line = line.lstrip("/")
        if not line:
            return None
    raw_segs = [("**" if _pure_stars(s) else s) for s in line.split("/") if s]
    if not raw_segs:
        return None
    source = ("!" if negate else "") + line + ("/" if dir_only else "")
    base_t = tuple(base)
    scope_t = tuple(scope) if scope is not None else None
    if not anchored:
        first = raw_segs[0]
        name = _any_component if first == "**" else _compile_component(first)  # bare "**" acts as "*"
        return Pattern(source, negate, dir_only, name=name, base=base_t, scope=scope_t, origin=origin)
    variants = _expand_crossing_stars(raw_segs)
    built = [_anchored_segs(v) for v in variants]
    if len(built) == 1:
        segs = built[0]
        if not any(isinstance(x, _StarStar) for x in segs):
            plain = tuple(x for x in segs if not isinstance(x, _StarStar))
            return Pattern(source, negate, dir_only, plain=plain, base=base_t, scope=scope_t, origin=origin)
        return Pattern(source, negate, dir_only, segs=segs, base=base_t, scope=scope_t, origin=origin)
    alts = tuple(Pattern(source, negate, dir_only, segs=segs) for segs in built)
    return Pattern(source, negate, dir_only, alts=alts, base=base_t, scope=scope_t, origin=origin)


def _pure_stars(s: str) -> bool:
    return len(s) >= 2 and not s.strip("*")


_ANY_DEPTH = "\0**"  # internal marker: zero or more components, never the trailing one-or-more form


def _expand_crossing_stars(raw: list[str]) -> list[list[str]]:
    """Reproduce git's slash-crossing ``X**`` (anchored patterns only).

    git compares the literal prefix of a pattern (up to the first ``*?[\\``) with ``strncmp`` and
    wildmatches the remainder, so a ``**`` that is the *first* wildcard of the pattern becomes a
    leading ``**`` of that remainder and crosses ``/`` when it ends the pattern or precedes a
    ``/``, even after a non-slash character. With an earlier wildcard it is a plain ``*``.

    * trailing ``X**``: ``X*`` followed by zero or more components;
    * ``X**/rest`` (``X(?:.*/)?rest``): ``X`` glued to the next component, or ``X*`` followed by
      any number of components and then ``rest`` (two alternatives).
    """
    for i, seg in enumerate(raw):
        hit = next((k for k, ch in enumerate(seg) if ch in "*?[\\"), -1)
        if hit == -1:
            continue
        if seg == "**" or hit == 0 or seg[hit] != "*":
            return [raw]  # standard "**" segment, or the first wildcard is something else
        run = len(seg) - hit
        if run < 2 or seg[hit:] != "*" * run:
            return [raw]  # stars not at the end of the component: ordinary "*"
        x = seg[:hit]
        rest = raw[i + 1 :]
        while rest and rest[0] == "**":
            rest = rest[1:]
        if not rest:
            return [[*raw[:i], x + "*", _ANY_DEPTH]]
        return [[*raw[:i], x + rest[0], *rest[1:]], [*raw[:i], x + "*", "**", *rest]]
    return [raw]


def _anchored_segs(raw: list[str]) -> tuple[Seg, ...]:
    segs: list[Seg] = []
    for s in raw:
        if s in ("**", _ANY_DEPTH):
            if not (segs and isinstance(segs[-1], _StarStar)):
                segs.append(STARSTAR)
        else:
            segs.append(_compile_component(s))
    if raw[-1] == "**" and isinstance(segs[-1], _StarStar):
        # trailing "/**" matches everything *inside*: one or more components
        segs = [*segs[:-1], _any_component, STARSTAR]
    return tuple(segs)


def parse_patterns(
    text: str,
    base: Sequence[str] = (),
    *,
    rule_sections: bool = True,
    origin: str = "",
    diagnostics: list[Diagnostic] | None = None,
) -> list[Pattern]:
    """Parse an ignore file. ``#!rules`` sections are honored when ``rule_sections`` is true."""
    if text.startswith("\ufeff"):
        text = text[1:]
    out: list[Pattern] = []
    scope: tuple[str, ...] | None = None
    for lineno, raw in enumerate(text.split("\n"), 1):
        if rule_sections and raw.startswith("#!rules"):
            rest = raw[len("#!rules") :].rstrip("\r")
            if rest and not rest[0].isspace():
                continue  # e.g. "#!rulesfoo" is an ordinary comment
            ids = tuple(s.strip() for s in rest.split(",") if s.strip())
            scope = None if (not ids or "*" in ids) else ids
            continue
        if len(raw) > MAX_PATTERN_CHARS and not raw.startswith("#"):
            if diagnostics is not None:
                diagnostics.append(
                    Diagnostic(
                        "warning",
                        "ignore-pattern-too-long",
                        f"pattern longer than {MAX_PATTERN_CHARS} chars skipped",
                        file=origin or None,
                        line=lineno,
                    )
                )
            continue
        pat = compile_pattern(raw, base, scope, origin=f"{origin}:{lineno}" if origin else "")
        if pat is None:
            continue
        if len(out) >= MAX_PATTERNS_PER_FILE:
            if diagnostics is not None:
                diagnostics.append(
                    Diagnostic(
                        "warning",
                        "ignore-too-many-patterns",
                        f"only the first {MAX_PATTERNS_PER_FILE} patterns are used",
                        file=origin or None,
                        line=lineno,
                    )
                )
            break
        out.append(pat)
    return out


def rule_glob_match(pattern: str, rule_id: str) -> bool:
    """Case-sensitive shell-style match of a rule ID against an ID or glob (``WS-SEC-*``)."""
    return pattern in (rule_id, "*") or fnmatchcase(rule_id, pattern)


def normalize_relpath(path: str) -> str:
    """POSIX-normalize a root-relative path: ``\\`` → ``/``, no ``.`` or empty components, and
    ``a/../b`` collapsed (leading ``..`` are kept, so escaping paths stay recognizable)."""
    if os.sep != "/":  # pragma: no cover - Windows
        path = path.replace(os.sep, "/")
    lead = "/" if path.startswith("/") else ""
    out: list[str] = []
    for p in path.split("/"):
        if not p or p == ".":
            continue
        if p == ".." and out and out[-1] != "..":
            out.pop()
        elif p == ".." and lead:
            continue  # "/.." is "/"
        else:
            out.append(p)
    return lead + "/".join(out)


def _split(relpath: str) -> tuple[str, ...]:
    # Only the platform separator splits: on POSIX a file may be named "tests\\fixtures\\x.md",
    # and treating that as a path would let it hide under an ignored directory.
    if os.sep != "/" and os.sep in relpath:  # pragma: no cover - Windows
        relpath = relpath.replace(os.sep, "/")
    parts = relpath.split("/")
    if "" in parts or "." in parts:
        return tuple(p for p in parts if p and p != ".")
    return tuple(parts)


# --------------------------------------------------------------------------- matcher


def _compile_list(lines: Iterable[str], origin: str) -> tuple[Pattern, ...]:
    out: list[Pattern] = []
    for x in lines:
        pat = compile_pattern(x, (), None, origin)
        if pat is not None:
            out.append(pat)
    return tuple(out)


@dataclass(frozen=True, slots=True)
class _Level:
    base: tuple[str, ...]
    patterns: tuple[Pattern, ...]
    scopes: frozenset[tuple[str, ...]] = frozenset()  # distinct `#!rules` scopes used here

    @property
    def scoped(self) -> bool:
        return bool(self.scopes)


def _level(base: tuple[str, ...], pats: Iterable[Pattern]) -> _Level:
    pt = tuple(pats)
    return _Level(base, pt, frozenset(p.scope for p in pt if p.scope is not None))


class IgnoreMatcher:
    """Evaluates a stack of gitignore pattern lists for root-relative POSIX paths.

    Priority, lowest to highest: built-in excludes, ``pre`` patterns (e.g. ``.git/info/exclude``),
    per-directory ignore files from the root down to the path's directory, then ``extra``
    patterns (config and CLI ``exclude``). Per-directory files are loaded lazily from ``root``
    (never through a symlinked ignore file) and cached.

    Paths that are absolute or start with ``..`` are outside the root: per-directory files are
    not consulted for them, but built-in, ``pre`` and ``extra`` patterns still apply.
    """

    def __init__(
        self,
        root: str | os.PathLike[str] | None = None,
        *,
        filename: str | None = IGNORE_FILENAME,
        builtin: bool = True,
        pre: Iterable[str] = (),
        extra: Iterable[str] = (),
        rule_sections: bool = True,
        always_exclude_git: bool = True,
        max_file_bytes: int = MAX_IGNORE_FILE_BYTES,
    ) -> None:
        self.root = os.path.abspath(os.fspath(root)) if root is not None else None
        self.filename = filename
        self.rule_sections = rule_sections
        self.always_exclude_git = always_exclude_git
        self.max_file_bytes = max_file_bytes
        self.diagnostics: list[Diagnostic] = []
        low: list[_Level] = []
        if builtin:
            low.append(_level((), _compile_list(BUILTIN_EXCLUDES, "<builtin>")))
        pre_pats = _compile_list(pre, "<pre>")
        if pre_pats:
            low.append(_level((), pre_pats))
        self._low = tuple(low)
        extra_pats = _compile_list(extra, "<exclude>")
        self._high: tuple[_Level, ...] = (_level((), extra_pats),) if extra_pats else ()
        self._file_levels: dict[tuple[str, ...], _Level | None] = {}
        self._chain_cache: dict[tuple[str, ...], tuple[_Level, ...]] = {}
        self._dir_cache: dict[tuple[tuple[str, ...], str | None], bool] = {}
        self._scope_cache: dict[tuple[tuple[str, ...], str], bool] = {}
        self._rev_cache: dict[tuple[str, ...], tuple[_Level, ...]] = {}
        self._group_cache: dict[
            tuple[frozenset[tuple[str, ...]], tuple[str, ...]], tuple[tuple[str, tuple[str, ...]], ...]
        ] = {}

    # ------------------------------------------------------------------ construction helpers

    @classmethod
    def from_text(
        cls,
        text: str,
        *,
        builtin: bool = False,
        extra: Iterable[str] = (),
        rule_sections: bool = True,
    ) -> IgnoreMatcher:
        """A matcher for one in-memory ignore file located at the root (tests, stdin)."""
        m = cls(None, filename=None, builtin=builtin, extra=extra, rule_sections=rule_sections)
        pats = parse_patterns(
            text, (), rule_sections=rule_sections, origin="<text>", diagnostics=m.diagnostics
        )
        m._file_levels[()] = _level((), pats)
        return m

    # ------------------------------------------------------------------ loading

    def _load_level(self, dir_parts: tuple[str, ...]) -> _Level | None:
        if dir_parts in self._file_levels:
            return self._file_levels[dir_parts]
        level: _Level | None = None
        if self.root is not None and self.filename is not None:
            from . import textio

            path = os.path.join(self.root, *dir_parts, self.filename)
            rel = "/".join((*dir_parts, self.filename))
            data: bytes | None = None
            try:
                data = textio.read_file(path, self.max_file_bytes)
            except (FileNotFoundError, NotADirectoryError):
                data = None
            except textio.FileTooLargeError:
                self.diagnostics.append(
                    Diagnostic(
                        "warning",
                        "ignore-file-too-large",
                        f"{self.filename} larger than {self.max_file_bytes} bytes ignored",
                        file=rel,
                    )
                )
            except textio.NotRegularFileError:
                data = None
            except OSError as exc:
                self.diagnostics.append(
                    Diagnostic(
                        "warning",
                        "ignore-file-unreadable",
                        f"{self.filename} not read: {exc.strerror or type(exc).__name__}",
                        file=rel,
                    )
                )
            if data is not None:
                text = data.decode("utf-8", "surrogateescape")
                pats = parse_patterns(
                    text,
                    dir_parts,
                    rule_sections=self.rule_sections,
                    origin=rel,
                    diagnostics=self.diagnostics,
                )
                if pats:
                    level = _level(dir_parts, pats)
        if len(self._file_levels) > _MAX_CACHE:
            self._file_levels.clear()
        self._file_levels[dir_parts] = level
        return level

    def _chain(self, dir_parts: tuple[str, ...]) -> tuple[_Level, ...]:
        """File levels from the root down to ``dir_parts`` (inclusive), in priority order.

        Iterative (paths can be thousands of components deep) and cached per directory.
        """
        hit = self._chain_cache.get(dir_parts)
        if hit is not None:
            return hit
        if dir_parts and (dir_parts[0].startswith("/") or ".." in dir_parts):
            return ()  # outside (or escaping) the root: per-directory files are never consulted
        if len(self._chain_cache) > _MAX_CACHE:
            self._chain_cache.clear()
        k = len(dir_parts) - 1
        while k >= 0 and dir_parts[:k] not in self._chain_cache:
            k -= 1
        if k < 0:
            lvl = self._load_level(())
            chain: tuple[_Level, ...] = (lvl,) if lvl else ()
            self._chain_cache[()] = chain
            k = 0
        else:
            chain = self._chain_cache[dir_parts[:k]]
        for i in range(k + 1, len(dir_parts) + 1):
            lvl = self._load_level(dir_parts[:i])
            if lvl:
                chain = (*chain, lvl)
            self._chain_cache[dir_parts[:i]] = chain
        return chain

    # ------------------------------------------------------------------ evaluation

    def _scope_ok(self, scope: tuple[str, ...] | None, rule_id: str | None) -> bool:
        if scope is None:
            return True
        if rule_id is None:
            return False
        key = (scope, rule_id)
        hit = self._scope_cache.get(key)
        if hit is None:
            hit = any(rule_glob_match(g, rule_id) for g in scope)
            if len(self._scope_cache) > _MAX_CACHE:
                self._scope_cache.clear()
            self._scope_cache[key] = hit
        return hit

    def _levels_for(self, parent: tuple[str, ...]) -> tuple[_Level, ...]:
        """All levels for entries of ``parent``, highest priority first (cached)."""
        hit = self._rev_cache.get(parent)
        if hit is None:
            hit = tuple(reversed((*self._low, *self._chain(parent), *self._high)))
            if len(self._rev_cache) > _MAX_CACHE:
                self._rev_cache.clear()
            self._rev_cache[parent] = hit
        return hit

    def _decide(self, parts: tuple[str, ...], is_dir: bool, rule_id: str | None) -> bool | None:
        """Last-match decision for one entry, ignoring its ancestors. ``None`` = no match."""
        for level in self._levels_for(parts[:-1]):
            nb = len(level.base)
            if nb:
                if len(parts) <= nb or parts[:nb] != level.base:
                    continue
                sub = parts[nb:]
            else:
                sub = parts
            for pat in reversed(level.patterns):
                if pat.scope is not None and not self._scope_ok(pat.scope, rule_id):
                    continue
                if pat.matches(sub, is_dir):
                    return not pat.negate
        return None

    def _dir_excluded(self, dir_parts: tuple[str, ...], rule_id: str | None) -> bool:
        """True when ``dir_parts`` or any ancestor directory is excluded."""
        key = (dir_parts, rule_id)
        hit = self._dir_cache.get(key)
        if hit is not None:
            return hit
        # find the deepest cached ancestor, then walk down (iterative: paths can be deep)
        k = len(dir_parts) - 1
        while k > 0 and (dir_parts[:k], rule_id) not in self._dir_cache:
            k -= 1
        excluded = self._dir_cache.get((dir_parts[:k], rule_id), False) if k > 0 else False
        if len(self._dir_cache) > _MAX_CACHE:
            self._dir_cache.clear()
        start = k + 1 if k > 0 else 1
        for i in range(start, len(dir_parts) + 1):
            prefix = dir_parts[:i]
            if not excluded:
                excluded = self._decide(prefix, True, rule_id) is True
            self._dir_cache[(prefix, rule_id)] = excluded
        return excluded

    def is_ignored(
        self,
        relpath: str,
        is_dir: bool = False,
        rule_id: str | None = None,
        *,
        check_parents: bool = True,
    ) -> bool:
        """Is ``relpath`` (root-relative POSIX) excluded, optionally for one rule only?

        ``rule_id=None`` asks whether the path is excluded for every rule (patterns inside
        ``#!rules`` sections are skipped). With a rule ID, global and matching scoped patterns
        are evaluated together, last match wins. ``check_parents=False`` skips ancestor checks
        (the directory walker already pruned excluded directories).
        """
        parts = _split(relpath)
        if relpath.startswith("/"):
            parts = ("/" + parts[0], *parts[1:]) if parts else ("/",)
        if not parts:
            return False
        if self.always_exclude_git and ".git" in parts:
            return True
        if check_parents and len(parts) > 1 and self._dir_excluded(parts[:-1], rule_id):
            return True
        return self._decide(parts, is_dir, rule_id) is True

    def has_rule_sections(self, relpath: str) -> bool:
        """Whether any ``#!rules`` section could apply to ``relpath`` (cheap pre-check)."""
        parts = _split(relpath)
        if relpath.startswith("/") and parts:
            parts = ("/" + parts[0], *parts[1:])
        return any(level.scoped for level in self._chain(parts[:-1]))

    def ignored_rules(self, relpath: str, rule_ids: Iterable[str], is_dir: bool = False) -> frozenset[str]:
        """Rule IDs for which ``relpath`` is excluded by rule-scoped sections.

        Assumes the path is not excluded for every rule (the walker already checked). Returns
        an empty set quickly when no rule-scoped section exists along the path.
        """
        parts = _split(relpath)
        if relpath.startswith("/") and parts:
            parts = ("/" + parts[0], *parts[1:])
        scopes: frozenset[tuple[str, ...]] = frozenset().union(*(lv.scopes for lv in self._chain(parts[:-1])))
        if not scopes:
            return frozenset()
        # Rules matching the same set of scopes get the same answer: evaluate once per group.
        ids = tuple(rule_ids)
        key = (scopes, ids)
        groups = self._group_cache.get(key)
        if groups is None:
            by_sig: dict[frozenset[tuple[str, ...]], list[str]] = {}
            for rid in ids:
                sig = frozenset(sc for sc in scopes if self._scope_ok(sc, rid))
                if sig:  # no matching scope: same answer as for "all rules" (not excluded)
                    by_sig.setdefault(sig, []).append(rid)
            groups = tuple((members[0], tuple(members)) for members in by_sig.values())
            if len(self._group_cache) > 1024:
                self._group_cache.clear()
            self._group_cache[key] = groups
        out: list[str] = []
        for rep, members in groups:
            if self.is_ignored(relpath, is_dir, rep):
                out.extend(members)
        return frozenset(out)


class GlobSet:
    """A list of gitignore-syntax globs evaluated with last-match-wins and ancestor semantics.

    Used for ``scan.include``/``--include``: a file is selected when it, or one of its parent
    directories, is matched by a non-negated pattern that is not overridden later. An empty
    set matches everything.
    """

    def __init__(self, patterns: Iterable[str]) -> None:
        self.patterns = tuple(patterns)
        self._m = IgnoreMatcher(
            None, filename=None, builtin=False, extra=self.patterns, always_exclude_git=False
        )
        self._empty = not self._m._high

    def __bool__(self) -> bool:
        return not self._empty

    def matches(self, relpath: str, is_dir: bool = False) -> bool:
        if self._empty:
            return True
        return self._m.is_ignored(relpath, is_dir)


_GLOB_CACHE: dict[str, Pattern | None] = {}


def compile_glob(glob: str) -> Pattern | None:
    """Compile a gitignore-syntax path glob (``tests/**``, ``**/*.py``, ``*.env``). Cached."""
    hit = _GLOB_CACHE.get(glob)
    if hit is None and glob not in _GLOB_CACHE:
        hit = compile_pattern(glob)
        if len(_GLOB_CACHE) > 4096:
            _GLOB_CACHE.clear()
        _GLOB_CACHE[glob] = hit
    return hit


def glob_match(glob: str, relpath: str, is_dir: bool = False) -> bool:
    """Does the path itself match ``glob`` (gitignore syntax, no ancestor semantics)?

    A leading ``!`` is not interpreted (use :class:`GlobSet` for lists with negations).
    """
    pat = compile_glob(glob)
    if pat is None:
        return False
    parts = _split(relpath)
    return bool(parts) and pat.matches(parts, is_dir)


def any_glob_match(globs: Collection[str], relpath: str, is_dir: bool = False) -> bool:
    """Whether any of ``globs`` matches the path itself."""
    parts = _split(relpath)
    if not parts:
        return False
    for g in globs:
        pat = compile_glob(g)
        if pat is not None and pat.matches(parts, is_dir):
            return True
    return False
