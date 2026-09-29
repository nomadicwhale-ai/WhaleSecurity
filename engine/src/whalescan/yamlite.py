"""YAML subset parser with source positions and raw keys (spec §8.6 "Parser", limits §5.3).

``yamlite`` is the stdlib-only YAML reader behind ``yaml_path`` rules and YAML rule packs. It favors
what a security scanner needs over round-tripping:

* **Positions.** Every node and every mapping key carries code-point offsets into the original text
  (``start``, exclusive ``end``) and lazily computed 1-based ``line``/``col``/``end_line``/``end_col``.
  Only ``"\\n"`` breaks lines for positions (spec §5.5-§5.6), whatever the YAML line breaks are.
* **Raw keys.** Keys are never type-resolved: ``on``, ``"on"`` and ``'on'`` are all the key ``on`` and
  ``true:`` is the key ``true`` (the GitHub Actions ``on:`` pitfall). Only scalar *values* are resolved,
  lazily, with the ``yaml12`` (core) or ``yaml11`` table of the spec.
* **Supported:** block and flow collections, plain/single/double-quoted scalars (all escapes),
  literal and folded block scalars with chomping and indentation indicators, comments, ``---``/``...``
  multi-document streams, ``%YAML`` directives, anchors and aliases (shared nodes), ``<<`` merge keys
  (expanded at parse time; explicit keys win) and tags (kept verbatim on nodes). JSON parses through
  the same code as flow YAML (tabs are accepted as separators there).
* **Unsupported, a ``YamlError`` for that document only:** complex ``?`` keys, collections used as
  keys, ``%TAG`` directives and named tag handles, and recursive aliases.
* **Limits (spec §5.3):** 2 MiB of text, nesting depth 64, 200 000 nodes and 10 000 alias
  expansions per stream. An alias adds the aliased subtree to the node count and its height to the
  nesting depth, so "billion laughs" input fails fast and every returned tree can be traversed
  (``descendants``, ``to_python``) in bounded time and recursion depth. A failed document gives its
  budget back, so one bad document never starves the others.
* **Helm lenient mode:** lines that are pure template control are blanked (and are invisible inside
  block scalars), a line holding only ``{{ ... }}`` output between entries is skipped, and inline
  ``{{ ... }}`` is an opaque run inside a plain (string) scalar.

Error messages never quote document text, which may hold secrets; they carry positions only.
"""

from __future__ import annotations

import gc
import re
from bisect import bisect_right
from collections.abc import Iterator
from itertools import accumulate, repeat
from operator import add
from typing import Any, ClassVar, Final, NoReturn

__all__ = [
    "DOUBLE",
    "FOLDED",
    "LITERAL",
    "MAX_ALIASES",
    "MAX_BYTES",
    "MAX_DEPTH",
    "MAX_NODES",
    "PLAIN",
    "SCHEMAS",
    "SINGLE",
    "Document",
    "KeyNode",
    "MapNode",
    "Node",
    "ScalarNode",
    "SeqNode",
    "YamlError",
    "load",
    "load_all",
    "resolve_scalar",
    "to_python",
]

#: Parse limits (spec §5.3). Text over MAX_BYTES (UTF-8) is rejected before parsing.
MAX_BYTES: Final = 2 * 1024 * 1024
MAX_DEPTH: Final = 64
MAX_NODES: Final = 200_000
MAX_ALIASES: Final = 10_000
#: Numeric-looking plain scalars longer than this stay strings (int() of huge digit runs is slow).
_MAX_NUMBER_CHARS: Final = 1000
#: Texts longer than this are parsed with the cyclic garbage collector paused.
_GC_PAUSE_CHARS: Final = 32 * 1024

SCHEMAS: Final = ("yaml11", "yaml12")

PLAIN: Final = "plain"
SINGLE: Final = "single"
DOUBLE: Final = "double"
LITERAL: Final = "literal"
FOLDED: Final = "folded"

# ------------------------------------------------------------------------------------------ errors


class YamlError(ValueError):
    """A syntax or limit error. ``line``/``col`` are 1-based code-point positions (0 when unknown)."""

    def __init__(self, message: str, line: int = 0, col: int = 0, offset: int = -1) -> None:
        super().__init__(message)
        self.message = message
        self.line = line
        self.col = col
        self.offset = offset

    def __str__(self) -> str:
        if self.line:
            return f"{self.message} (line {self.line}, column {self.col})"
        return self.message

    def __reduce__(self) -> tuple[Any, ...]:
        return (YamlError, (self.message, self.line, self.col, self.offset))


class _BadEscape(Exception):
    """Raised by ``_unescape``; carries the index of the bad escape inside the scalar body."""

    def __init__(self, index: int) -> None:
        super().__init__(index)
        self.index = index


# ------------------------------------------------------------------------------------------ source


class _Source:
    """Text, value schema and a lazily built newline index shared by every node of one parse."""

    __slots__ = ("_nl", "schema", "text")

    def __init__(self, text: str, schema: str) -> None:
        self.text = text
        self.schema = schema
        self._nl: list[int] | None = None

    def pos(self, off: int) -> tuple[int, int]:
        nl = self._nl
        if nl is None:
            nl = [0]
            find = self.text.find
            k = find("\n")
            while k != -1:
                nl.append(k + 1)
                k = find("\n", k + 1)
            self._nl = nl
        i = bisect_right(nl, off) - 1
        return i + 1, off - nl[i] + 1

    def end_pos(self, start: int, end: int) -> tuple[int, int]:
        if end <= start:
            return self.pos(start)
        line, col = self.pos(end - 1)
        return line, col + 1


# ------------------------------------------------------------------------------------------ nodes


class _Spanned:
    """Position API shared by nodes and mapping keys (offsets are code points, ``end`` exclusive)."""

    __slots__ = ("_src", "anchor", "end", "start", "tag")

    start: int
    end: int
    tag: str | None
    anchor: str | None
    _src: _Source

    @property
    def line(self) -> int:
        return self._src.pos(self.start)[0]

    @property
    def col(self) -> int:
        return self._src.pos(self.start)[1]

    @property
    def end_line(self) -> int:
        return self._src.end_pos(self.start, self.end)[0]

    @property
    def end_col(self) -> int:
        return self._src.end_pos(self.start, self.end)[1]

    @property
    def span(self) -> tuple[int, int]:
        return self.start, self.end

    @property
    def source(self) -> str:
        """The exact source text of the span (quotes and block indicators included)."""
        return self._src.text[self.start : self.end]

    def _where(self) -> str:
        line, col = self._src.pos(self.start)
        return f"{line}:{col}"


class Node(_Spanned):
    """Base class of ``MapNode``, ``SeqNode`` and ``ScalarNode``.

    Aliases are resolved to the anchored node itself, so a tree may share subtrees (it is a DAG,
    never cyclic). ``anchor`` and ``tag`` are the properties written on the node, tags verbatim
    (``!Ref``, ``!!str``; ``!<tag:yaml.org,2002:x>`` is normalized to ``!!x``).
    """

    __slots__ = ()

    kind: ClassVar[str] = "node"
    is_map: ClassVar[bool] = False
    is_seq: ClassVar[bool] = False
    is_scalar: ClassVar[bool] = False

    def values(self) -> list[Node]:
        """Child value nodes (mapping values or sequence items); empty for scalars."""
        return []

    def descendants(self) -> Iterator[Node]:
        """Every value node below this one, pre-order (keys are not nodes). Bounded by MAX_NODES."""
        stack = self.values()
        stack.reverse()
        while stack:
            n = stack.pop()
            yield n
            children = n.values()
            if children:
                children.reverse()
                stack.extend(children)

    def type_name(self, schema: str | None = None) -> str:
        """``map``, ``seq``, or the resolved scalar type: ``str int float bool null``."""
        return self.kind


class ScalarNode(Node):
    """A scalar. ``raw`` is its string content after unquoting, escapes and folding.

    ``value`` resolves ``raw`` lazily with the schema given to ``load_all``; ``resolve(schema)``
    uses another one. Quoted and block scalars always resolve to ``str`` unless tagged.
    """

    __slots__ = ("_v", "raw", "style")

    kind: ClassVar[str] = "scalar"
    is_scalar: ClassVar[bool] = True

    raw: str
    style: str
    _v: Any

    def __init__(
        self, raw: str, style: str, tag: str | None, anchor: str | None, start: int, end: int, src: _Source
    ) -> None:
        self.raw = raw
        self.style = style
        self.tag = tag
        self.anchor = anchor
        self.start = start
        self.end = end
        self._src = src

    @property
    def value(self) -> Any:
        try:
            return self._v
        except AttributeError:
            v = self._v = resolve_scalar(self.raw, self._src.schema, self.style, self.tag)
            return v

    def resolve(self, schema: str | None = None) -> Any:
        if schema is None or schema == self._src.schema:
            return self.value
        return resolve_scalar(self.raw, schema, self.style, self.tag)

    def type_name(self, schema: str | None = None) -> str:
        return _type_name(self.resolve(schema))

    def __repr__(self) -> str:
        return f"<ScalarNode {self.style} len={len(self.raw)} at {self._where()}>"


class SeqNode(Node):
    """A block or flow sequence; ``items`` are its nodes."""

    __slots__ = ("items",)

    kind: ClassVar[str] = "seq"
    is_seq: ClassVar[bool] = True

    items: list[Node]

    def __init__(
        self, items: list[Node], tag: str | None, anchor: str | None, start: int, end: int, src: _Source
    ) -> None:
        self.items = items
        self.tag = tag
        self.anchor = anchor
        self.start = start
        self.end = end
        self._src = src

    def values(self) -> list[Node]:
        return list(self.items)

    def __repr__(self) -> str:
        return f"<SeqNode items={len(self.items)} at {self._where()}>"


class MapNode(Node):
    """A block or flow mapping; ``items`` is a list of ``(KeyNode, Node)`` pairs in source order.

    Duplicate keys are all kept (a scanner should see every value); ``get`` returns the last one,
    like most YAML loaders. ``<<`` merges are already expanded: merged pairs come first and explicit
    keys win.
    """

    __slots__ = ("items",)

    kind: ClassVar[str] = "map"
    is_map: ClassVar[bool] = True

    items: list[tuple[KeyNode, Node]]

    def __init__(
        self,
        items: list[tuple[KeyNode, Node]],
        tag: str | None,
        anchor: str | None,
        start: int,
        end: int,
        src: _Source,
    ) -> None:
        self.items = items
        self.tag = tag
        self.anchor = anchor
        self.start = start
        self.end = end
        self._src = src

    def values(self) -> list[Node]:
        return [v for _, v in self.items]

    def keys(self) -> list[str]:
        return [k.raw for k, _ in self.items]

    def get(self, key: str, default: Node | None = None) -> Node | None:
        found = default
        for k, v in self.items:
            if k.raw == key:
                found = v
        return found

    def get_all(self, key: str) -> list[Node]:
        return [v for k, v in self.items if k.raw == key]

    def key_node(self, key: str) -> KeyNode | None:
        found: KeyNode | None = None
        for k, _ in self.items:
            if k.raw == key:
                found = k
        return found

    def __repr__(self) -> str:
        return f"<MapNode items={len(self.items)} at {self._where()}>"


class KeyNode(_Spanned):
    """A mapping key. ``raw`` is the unquoted source text, never type-resolved."""

    __slots__ = ("raw", "style")

    raw: str
    style: str

    def __init__(
        self, raw: str, style: str, tag: str | None, anchor: str | None, start: int, end: int, src: _Source
    ) -> None:
        self.raw = raw
        self.style = style
        self.tag = tag
        self.anchor = anchor
        self.start = start
        self.end = end
        self._src = src

    @property
    def value(self) -> str:
        return self.raw

    @property
    def is_merge(self) -> bool:
        return self.raw == "<<" and self.style == PLAIN and self.tag in (None, "!!merge")

    def __repr__(self) -> str:
        return f"<KeyNode {self.style} len={len(self.raw)} at {self._where()}>"


class Document:
    """One document of a stream: ``root`` (``None`` iff ``error`` is set) plus its span.

    An empty document (``---`` alone) has an empty plain scalar (null) root.
    """

    __slots__ = ("_src", "end", "error", "explicit_end", "explicit_start", "index", "root", "start", "version")

    def __init__(
        self,
        root: Node | None,
        error: YamlError | None,
        index: int,
        start: int,
        end: int,
        explicit_start: bool,
        explicit_end: bool,
        version: str | None,
        src: _Source,
    ) -> None:
        self.root = root
        self.error = error
        self.index = index
        self.start = start
        self.end = end
        self.explicit_start = explicit_start
        self.explicit_end = explicit_end
        self.version = version
        self._src = src

    @property
    def schema(self) -> str:
        return self._src.schema

    @property
    def line(self) -> int:
        return self._src.pos(self.start)[0]

    def to_python(self, schema: str | None = None) -> Any:
        """Plain Python values (keys are raw strings); raises the document's ``YamlError``."""
        return to_python(self, schema)

    def __repr__(self) -> str:
        state = "error" if self.error is not None else type(self.root).__name__
        return f"<Document #{self.index} {state} at line {self.line}>"


# ------------------------------------------------------------------------------------------ values

_MISS: Final = object()

_Y12_CONST: Final[dict[str, Any]] = {
    "true": True, "True": True, "TRUE": True,
    "false": False, "False": False, "FALSE": False,
    "null": None, "Null": None, "NULL": None, "~": None, "": None,
}  # fmt: skip
_Y11_CONST: Final[dict[str, Any]] = {
    **_Y12_CONST,
    "yes": True, "Yes": True, "YES": True, "on": True, "On": True, "ON": True, "y": True, "Y": True,
    "no": False, "No": False, "NO": False, "off": False, "Off": False, "OFF": False, "n": False, "N": False,
}  # fmt: skip
_BOOLS: Final[dict[str, dict[str, bool]]] = {
    "yaml12": {k: v for k, v in _Y12_CONST.items() if isinstance(v, bool)},
    "yaml11": {k: v for k, v in _Y11_CONST.items() if isinstance(v, bool)},
}
_NUM_START: Final = frozenset("+-.0123456789")
_INF: Final = float("inf")
_NAN: Final = float("nan")

_Y12_INT = re.compile(r"[-+]?[0-9]+\Z")
_Y12_OCT = re.compile(r"0o[0-7]+\Z")
_Y12_HEX = re.compile(r"0x[0-9a-fA-F]+\Z")
_Y12_FLOAT = re.compile(r"[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?\Z")
_Y12_INFNAN = re.compile(r"(?:[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))\Z")
# YAML 1.1 as PyYAML implements it (the spec adds y/Y/n/N bools and keeps timestamps as strings).
_Y11_INT = re.compile(
    r"[-+]?(?:0b[0-1_]+|0[0-7_]+|(?:0|[1-9][0-9_]*)|0x[0-9a-fA-F_]+|[1-9][0-9_]*(?::[0-5]?[0-9])+)\Z"
)
_Y11_FLOAT = re.compile(
    r"(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?"
    r"|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))\Z"
)


def _y12_number(raw: str) -> Any:
    try:
        if _Y12_INT.match(raw):
            return int(raw, 10)
        if raw[0] == "0" and len(raw) > 2:
            if _Y12_OCT.match(raw):
                return int(raw[2:], 8)
            if _Y12_HEX.match(raw):
                return int(raw[2:], 16)
        if _Y12_FLOAT.match(raw):
            return float(raw)
        if _Y12_INFNAN.match(raw):
            if raw[-3:].lower() == "nan":
                return _NAN
            return -_INF if raw[0] == "-" else _INF
    except (ValueError, OverflowError):
        pass
    return _MISS


def _y11_int(raw: str) -> Any:
    v = raw.replace("_", "")
    sign = -1 if v[:1] == "-" else 1
    if v[:1] in ("-", "+"):
        v = v[1:]
    try:
        if v == "0":
            return 0
        if v.startswith("0b"):
            return sign * int(v[2:], 2)
        if v.startswith("0x"):
            return sign * int(v[2:], 16)
        if v[:1] == "0":
            return sign * int(v, 8)
        if ":" in v:
            total = 0
            for part in v.split(":"):
                total = total * 60 + int(part)
            return sign * total
        return sign * int(v)
    except (ValueError, OverflowError):
        return _MISS


def _y11_float(raw: str) -> Any:
    v = raw.replace("_", "").lower()
    sign = -1.0 if v[:1] == "-" else 1.0
    if v[:1] in ("-", "+"):
        v = v[1:]
    try:
        if v == ".inf":
            return sign * _INF
        if v == ".nan":
            return _NAN
        if ":" in v:
            total = 0.0
            for part in v.split(":"):
                total = total * 60 + float(part)
            return sign * total
        return sign * float(v)
    except (ValueError, OverflowError):
        return _MISS


def _y11_number(raw: str) -> Any:
    if _Y11_FLOAT.match(raw):
        return _y11_float(raw)
    if _Y11_INT.match(raw):
        return _y11_int(raw)
    return _MISS


def _resolve_plain(raw: str, schema: str) -> Any:
    v = (_Y12_CONST if schema == "yaml12" else _Y11_CONST).get(raw, _MISS)
    if v is not _MISS:
        return v
    if raw[0] in _NUM_START and len(raw) <= _MAX_NUMBER_CHARS:
        v = _y12_number(raw) if schema == "yaml12" else _y11_number(raw)
        if v is not _MISS:
            return v
    return raw


def resolve_scalar(raw: str, schema: str = "yaml12", style: str = PLAIN, tag: str | None = None) -> Any:
    """Resolve a scalar's string content to a Python value (spec §8.6 value tables).

    Untagged plain scalars follow ``schema``; quoted and block scalars are strings. ``!!str``,
    ``!!int``, ``!!float``, ``!!bool`` and ``!!null`` tags convert when the text allows it and fall
    back to the string otherwise; every other tag (``!Ref``, ``!vault``, ``!!binary``) yields the
    string content. Never raises for any input text.
    """
    if schema not in SCHEMAS:
        raise ValueError(f"unknown YAML schema {schema!r}; expected one of {SCHEMAS}")
    if tag is None:
        if style != PLAIN:
            return raw
        return _resolve_plain(raw, schema)
    if tag == "!!str" or tag == "!":
        return raw
    if tag == "!!null":
        return None
    if tag == "!!bool":
        b = _BOOLS[schema].get(raw)
        return raw if b is None else b
    if tag in ("!!int", "!!float") and raw and raw[0] in _NUM_START and len(raw) <= _MAX_NUMBER_CHARS:
        num = _y12_number(raw) if schema == "yaml12" else _y11_number(raw)
        if num is _MISS or isinstance(num, bool):
            return raw
        if tag == "!!int":
            return num if isinstance(num, int) else raw
        return float(num)
    return raw


def _type_name(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "float"
    return "str"


# ------------------------------------------------------------------------------------------ lexing

# Plain scalars, one line at a time (lines never contain break characters). Whitespace is only
# space and tab, as in YAML: NBSP and other Unicode spaces are ordinary characters. All repeated
# groups are linear: their alternatives start with disjoint characters, and runs are forced to be
# maximal with a negative lookahead (Python 3.10 has no possessive quantifiers), so a failed match
# backtracks at most once per run instead of trying every split of it.
_FIRST_B = r"""[^ \t\-?:,\[\]{}#&*!|>'"%@`]|[-?:](?=[^ \t])"""
_BODY_B = r"""[^ \t:#]+(?![^ \t:#])|:(?=[^ \t])|(?<=[^ \t])\#|[ \t]+(?=[^ \t\#:]|:[^ \t])"""
_FIRST_F = r"""[^ \t\-?:,\[\]{}#&*!|>'"%@`]|-(?=[^ \t])"""
_BODY_F = (
    r"""[^ \t:#,\[\]{}]+(?![^ \t:#,\[\]{}])|:(?=[^ \t,\[\]{}])|(?<=[^ \t])\#"""
    r"""|[ \t]+(?=[^ \t\#:,\[\]{}]|:[^ \t,\[\]{}])"""
)
# Helm lenient mode: `{{ ... }}` (to the line end if unclosed) is one opaque run of a plain scalar.
_TPL = r"""\{\{(?:[^}]+(?![^}])|\}(?!\}))*(?:\}\}|\Z)"""
_FIRST_BH = _TPL + "|" + _FIRST_B
_BODY_BH = (
    _TPL + r"""|[^ \t:#{]+(?![^ \t:#{])|\{(?!\{)|:(?=[^ \t])|(?<=[^ \t])\#"""
    r"""|[ \t]+(?=[^ \t\#:]|:[^ \t])"""
)
_FIRST_FH = _TPL + "|" + _FIRST_F
_BODY_FH = (
    _TPL + r"""|[^ \t:#,\[\]{}]+(?![^ \t:#,\[\]{}])|:(?=[^ \t,\[\]{}])|(?<=[^ \t])\#"""
    r"""|[ \t]+(?=[^ \t\#:,\[\]{}]|:[^ \t,\[\]{}]|\{\{)"""
)
_ANCH = r"[^ \t,\[\]{}:#]+"
_KEY_TAIL = r"[ \t]*:(?:[ \t]+|\Z)"


def _key_re(first: str, body: str) -> re.Pattern[str]:
    # Groups: 1 plain key, 2 double-quoted body, 3 single-quoted body, 4 alias name.
    return re.compile(
        rf"""(?:((?:{first})(?:{body})*)|"([^"\\]*(?:\\.[^"\\]*)*)"|'([^']*(?:''[^']*)*)'|\*({_ANCH})){_KEY_TAIL}"""
    )


class _Lex:
    __slots__ = ("cont_b", "cont_f", "entry", "item", "key", "plain_b", "plain_f")

    def __init__(self, fb: str, bb: str, ff: str, bf: str) -> None:
        plain = f"(?:{fb})(?:{bb})*"
        self.key = _key_re(fb, bb)
        self.plain_b = re.compile(plain)
        self.cont_b = re.compile(f"(?:{bb})*")
        self.plain_f = re.compile(f"(?:{ff})(?:{bf})*")
        self.cont_f = re.compile(f"(?:{bf})*")
        # Fast path for mapping entries with a plain key: one match classifies the whole line.
        # Groups: 1 key; 2 plain value (3: a comment follows it); 4 double-quoted body without
        # escapes; 5 single-quoted body without ''; 6 (empty) where any other value starts. No
        # value group set: nothing but a comment after the colon.
        self.entry = re.compile(
            rf"""({plain})[ \t]*:(?:(?:[ \t]+\#.*)?\Z|[ \t]+(?:({plain})[ \t]*(\#.*)?\Z"""
            rf"""|"([^"\\]*)"[ \t]*(?:\#.*)?\Z|'([^']*)'[ \t]*(?:\#.*)?\Z|()))"""
        )
        # Fast path for a whole sequence item: plain (2: a comment follows), or simple quoted.
        self.item = re.compile(
            rf"""({plain})[ \t]*(\#.*)?\Z|"([^"\\]*)"[ \t]*(?:\#.*)?\Z|'([^']*)'[ \t]*(?:\#.*)?\Z"""
        )


_LEX: dict[bool, _Lex] = {}


def _lex(helm: bool) -> _Lex:
    lx = _LEX.get(helm)
    if lx is None:
        lx = _LEX[helm] = (
            _Lex(_FIRST_BH, _BODY_BH, _FIRST_FH, _BODY_FH) if helm else _Lex(_FIRST_B, _BODY_B, _FIRST_F, _BODY_F)
        )
    return lx


_WS = re.compile(r"[ \t]*")
_FWS = re.compile(r"[ \t]*(?:#.*)?")
_DQ_LINE = re.compile(r'([^"\\]*(?:\\.[^"\\]*)*)"')
_DQ_BODY = re.compile(r'[^"\\]*(?:\\.[^"\\]*)*')
_SQ_LINE = re.compile(r"([^']*(?:''[^']*)*)'")
_SQ_BODY = re.compile(r"[^']*(?:''[^']*)*")
_ANCHOR = re.compile(r"&(" + _ANCH + ")")
_ALIAS = re.compile(r"\*(" + _ANCH + ")")
_TAG = re.compile(r"!(?:<([^>]*)>|(!?)([^ \t,\[\]{}!<]*))")
_BLOCK_HEAD = re.compile(r"[|>]([0-9+-]*)[ \t]*(?:#.*)?\Z")
_YAML_DIRECTIVE = re.compile(r"%YAML[ \t]+([0-9]+)\.([0-9]+)[ \t]*(?:#.*)?\Z")
_MARKER = re.compile(r"^(?:---|\.\.\.)(?=[ \t\r\n]|\Z)", re.M)
_BREAK_SPLIT = re.compile("(\r\n|[\r\n\x85  ])")
_SURROGATE = re.compile("[\ud800-\udfff]")
_ESCAPE = re.compile(r"\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|.)")
_ESCAPES: Final[dict[str, str]] = {
    "0": "\0", "a": "\x07", "b": "\b", "t": "\t", "\t": "\t", "n": "\n", "v": "\x0b", "f": "\x0c",
    "r": "\r", "e": "\x1b", " ": " ", '"': '"', "/": "/", "\\": "\\", "N": "\x85", "_": "\xa0",
    "L": " ", "P": " ",
}  # fmt: skip
# Helm: pure template control lines (spec §8.6), plus comment lines written `{{/* ... */}}` and
# `{{ $var := ... }}` assignments, which render nothing either.
_HELM_CONTROL = re.compile(
    r"^[ \t]*\{\{-?[ \t]*(?:(?:if|else|end|range|with|define|template|include)\b|/\*"
    r"|\$[A-Za-z0-9_]*[ \t]*:?=).*\}\}[ \t]*(?=\r?$)",
    re.M,
)
_TPL_LINE = re.compile(r"(?:\{\{(?:[^}]+(?![^}])|\}(?!\}))*\}\}[ \t]*)+(?:#.*)?\Z")

_TAB_MSG: Final = "tab character used for indentation"
_DEPTH_MSG: Final = f"nesting deeper than {MAX_DEPTH} levels"
_NODES_MSG: Final = f"more than {MAX_NODES} nodes"


def _unescape(body: str) -> str:
    """Process double-quoted escapes. Surrogate pairs from ``\\u`` escapes are combined (JSON)."""

    def rep(m: re.Match[str]) -> str:
        g = m.group(1)
        if len(g) > 1:
            cp = int(g[1:], 16)
            if cp > 0x10FFFF:
                raise _BadEscape(m.start())
            return chr(cp)
        r = _ESCAPES.get(g)
        if r is None:
            raise _BadEscape(m.start())
        return r

    out = _ESCAPE.sub(rep, body)
    if _SURROGATE.search(out):
        out = out.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace")
    return out


def _norm_tag(m: re.Match[str]) -> str | None:
    """Normalize a tag match; ``None`` for an unsupported named handle or empty verbatim tag."""
    verbatim = m.group(1)
    if verbatim is not None:
        if not verbatim:
            return None
        if verbatim.startswith("tag:yaml.org,2002:"):
            return "!!" + verbatim[18:]
        return verbatim if verbatim.startswith("!") else f"!<{verbatim}>"
    if m.group(2):
        return "!!" + m.group(3) if m.group(3) else None
    return "!" + m.group(3)


def _split_lines(text: str) -> tuple[list[str], list[int], list[str] | None]:
    """Split on YAML line breaks. Returns lines (no break chars), their start offsets, and the break
    string after each line when some break is not a plain ``\\n``/``\\r\\n`` (else ``None``)."""
    special = "\x85" in text or " " in text or " " in text
    if not special:
        if "\r" not in text:
            lines = text.split("\n")
            starts = list(accumulate(map(add, map(len, lines), repeat(1)), initial=0))
            starts.pop()
            return lines, starts, None
        if text.count("\r") == text.count("\r\n"):
            raw = text.split("\n")
            starts = list(accumulate(map(add, map(len, raw), repeat(1)), initial=0))
            starts.pop()
            return [s[:-1] if s.endswith("\r") else s for s in raw], starts, None
    parts = _BREAK_SPLIT.split(text)
    lines = parts[0::2]
    brks = parts[1::2]
    starts = list(accumulate(map(add, map(len, lines), map(len, brks)), initial=0))
    starts = starts[: len(lines)]
    return lines, starts, brks


def _marker_kind(s: str) -> str | None:
    if s[:3] in ("---", "...") and (len(s) == 3 or s[3] in " \t"):
        return s[:3]
    if s[:1] == "%":
        return "%"
    return None


def _utf8_len_exceeds(text: str, limit: int) -> bool:
    if len(text) * 4 <= limit:
        return False
    if len(text) > limit:
        return True
    return len(text.encode("utf-8", "surrogatepass")) > limit


# ------------------------------------------------------------------------------------------ parser


class _Chunk:
    """One document's line range, found by the marker pre-pass."""

    __slots__ = ("col0", "error", "explicit", "explicit_end", "hi", "lo", "version")

    def __init__(self, lo: int, col0: int, explicit: bool) -> None:
        self.lo = lo
        self.hi = lo
        self.col0 = col0
        self.explicit = explicit
        self.explicit_end = False
        self.version: str | None = None
        self.error: YamlError | None = None


class _Parser:
    def __init__(self, text: str, src: _Source, helm: bool) -> None:
        self.src = src
        self.helm = helm
        work = text
        blanked: list[int] = []
        if helm and "{{" in text:

            def blank(m: re.Match[str]) -> str:
                blanked.append(m.start())
                return " " * (m.end() - m.start())

            work = _HELM_CONTROL.sub(blank, text)
        lines, starts, brk = _split_lines(work)
        self.bom = bool(lines[0]) and lines[0][0] == "﻿"
        if self.bom:
            lines[0] = lines[0][1:]
            starts[0] += 1
        self.work = work
        self.lines = lines
        self.starts = starts
        self.brk = brk
        if "\t" in work:
            self.ind = [len(s) - len(s.lstrip(" ")) for s in lines]
            self.cc = [len(s) - len(s.lstrip(" \t")) for s in lines]
        else:
            self.ind = self.cc = [len(s) - len(s.lstrip(" ")) for s in lines]
        self.skip: frozenset[int] = frozenset(bisect_right(starts, off) - 1 for off in blanked)
        self.last = len(lines) - 1
        lx = _lex(helm)
        self.key_match = lx.key.match
        self.entry_match = lx.entry.match
        self.item_match = lx.item.match
        self.plain_b = lx.plain_b.match
        self.cont_b = lx.cont_b.match
        self.plain_f = lx.plain_f.match
        self.cont_f = lx.cont_f.match
        self.hi = 0
        self.i = 0
        self.c = 0
        self.count = 0
        self.aliases = 0
        self.maxd = 0
        self.anchors: dict[str, tuple[Node, int, int]] = {}

    # -------------------------------------------------------------------- helpers

    def _fail(self, msg: str, i: int, c: int) -> NoReturn:
        lines = self.lines
        if i >= len(lines):
            off = len(self.src.text)
        else:
            off = self.starts[i] + max(0, min(c, len(lines[i])))
        line, col = self.src.pos(off)
        raise YamlError(msg, line, col, off)

    def _fail_at(self, msg: str, off: int) -> NoReturn:
        line, col = self.src.pos(off)
        raise YamlError(msg, line, col, off)

    def _bump(self, i: int, c: int) -> None:
        self.count += 1
        if self.count > MAX_NODES:
            self._fail(_NODES_MSG, i, c)

    def _open(self, depth: int, i: int, c: int) -> int:
        lvl = depth + 1
        if lvl > MAX_DEPTH:
            self._fail(_DEPTH_MSG, i, c)
        if lvl > self.maxd:
            self.maxd = lvl
        self._bump(i, c)
        return lvl

    def _anchor_begin(self, depth: int) -> tuple[int, int]:
        n0, d0 = self.count, self.maxd
        self.maxd = depth
        return n0, d0

    def _anchor_end(self, name: str, node: Node, n0: int, d0: int, depth: int) -> None:
        height = self.maxd - depth
        if d0 > self.maxd:
            self.maxd = d0
        self.anchors[name] = (node, self.count - n0, height)

    def _next_content(self, i: int) -> int:
        """First line >= i with content other than a comment (or ``hi``)."""
        lines = self.lines
        cc = self.cc
        hi = self.hi
        while i < hi:
            s = lines[i]
            k = cc[i]
            if k < len(s) and s[k] != "#":
                return i
            i += 1
        return hi

    def _next_entry(self, i: int) -> int:
        """Like ``_next_content``; in Helm mode it also skips lines holding only ``{{ ... }}``."""
        i = self._next_content(i)
        if self.helm:
            while i < self.hi and self._is_tpl(i):
                i = self._next_content(i + 1)
        return i

    def _is_tpl(self, i: int) -> bool:
        return _TPL_LINE.match(self.lines[i], self.cc[i]) is not None

    def _is_dash(self, i: int, k: int) -> bool:
        s = self.lines[i]
        return s[k] == "-" and (k + 1 == len(s) or s[k + 1] in " \t")

    def _brk(self, i: int) -> str:
        """The line break after line ``i`` as scalars see it: ``\\n``, U+2028/U+2029, or '' at EOF."""
        if i >= self.last:
            return ""
        brk = self.brk
        if brk is None:
            return "\n"
        b = brk[i]
        return b if b in (" ", " ") else "\n"

    def _fold(self, li: int, empties: int) -> str:
        """Flow-scalar line folding after line ``li`` followed by ``empties`` empty lines."""
        if self.brk is None:
            return " " if empties == 0 else "\n" * empties
        first = self._brk(li)
        rest = "".join(self._brk(li + 1 + t) or "\n" for t in range(empties))
        if first not in ("\n", ""):
            return first + rest
        return rest if empties else " "

    def _finish_line(self, i: int, c: int) -> None:
        """After a node that ended mid-line in block context, only a comment may follow."""
        s = self.lines[i]
        k = _WS.match(s, c).end()
        if k < len(s) and s[k] != "#":
            if s[k] == ":":
                self._fail("mapping values are not allowed here (complex or multi-line key?)", i, k)
            self._fail("unexpected content after a node", i, k)
        self.i = i + 1

    def _props(self, i: int, c: int, flow: bool) -> tuple[str | None, str | None, int, int]:
        """Parse ``&anchor``/``!tag`` properties at (i, c). Returns (anchor, tag, end, next)."""
        s = self.lines[i]
        n = len(s)
        anchor: str | None = None
        tag: str | None = None
        end = c
        while c < n and s[c] in "&!":
            if s[c] == "&":
                if anchor is not None:
                    self._fail("a node can have only one anchor", i, c)
                m = _ANCHOR.match(s, c)
                if m is None:
                    self._fail("anchor name expected", i, c)
                anchor = m.group(1)
            else:
                if tag is not None:
                    self._fail("a node can have only one tag", i, c)
                m = _TAG.match(s, c)
                t = _norm_tag(m) if m is not None else None
                if m is None or t is None or (m.end() < n and s[m.end()] == "!"):
                    self._fail("unsupported tag (named tag handles and %TAG are not supported)", i, c)
                tag = t
            c = end = m.end()
            if c < n and s[c] not in " \t" and not (flow and s[c] in ",[]{}"):
                self._fail("a node property must be followed by a space", i, c)
            c = _WS.match(s, c).end()
        return anchor, tag, end, c

    def _merge_prop(self, outer: str | None, inner: str | None, what: str, i: int, c: int) -> str | None:
        if outer is not None and inner is not None:
            self._fail(f"a node can have only one {what}", i, c)
        return inner if inner is not None else outer

    # -------------------------------------------------------------------- stream

    def _markers(self) -> list[int]:
        """Ascending indices of ``---`` and ``...`` marker lines (the only hard document boundaries)."""
        lines = self.lines
        if self.brk is None and not self.bom:
            cand = [bisect_right(self.starts, m.start()) - 1 for m in _MARKER.finditer(self.work)]
        else:
            cand = [k for k, s in enumerate(lines) if s[:3] in ("---", "...")]
        return [k for k in cand if _marker_kind(lines[k]) in ("---", "...")]

    def _err_line(self, msg: str, i: int, c: int = 0) -> YamlError:
        off = self.starts[i] + c
        line, col = self.src.pos(off)
        return YamlError(msg, line, col, off)

    def _directives(self, ch: _Chunk, dirs: list[int]) -> None:
        for k in dirs:
            s = self.lines[k]
            if s.startswith("%TAG") and (len(s) == 4 or s[4] in " \t"):
                ch.error = self._err_line("%TAG directives are not supported", k)
                return
            if s.startswith("%YAML") and (len(s) == 5 or s[5] in " \t"):
                m = _YAML_DIRECTIVE.match(s)
                if m is None or ch.version is not None:
                    ch.error = self._err_line("invalid or repeated %YAML directive", k)
                    return
                if m.group(1) != "1":
                    ch.error = self._err_line("unsupported YAML version (1.x is required)", k)
                    return
                ch.version = f"{m.group(1)}.{m.group(2)}"
            # other (reserved) directives are ignored, as YAML prescribes

    def run(self, strict: bool) -> list[Document]:
        """Split the stream and parse each document.

        ``---`` and ``...`` lines always separate documents. A ``%`` line is a directive in the
        prologue (stream start, after ``...``, or after a document it ended); inside a document it
        ends the document only where a new token would start at column 0 (as in PyYAML), so a
        multi-line root scalar may still continue over it.
        """
        lines = self.lines
        cc = self.cc
        n = len(lines)
        marks = self._markers()
        docs: list[Document] = []
        directives: list[int] = []
        pos = 0
        mi = 0
        while True:
            while mi < len(marks) and marks[mi] < pos:
                mi += 1
            k = marks[mi] if mi < len(marks) else n
            j = pos
            while j < k:
                s = lines[j]
                if s[:1] == "%":
                    directives.append(j)
                elif cc[j] < len(s) and s[cc[j]] != "#":
                    break
                j += 1
            if j < k:  # a bare document (no '---')
                ch = _Chunk(j, 0, False)
                ch.hi = k
                if directives:
                    ch.error = self._err_line("directives must be followed by a '---' marker", directives[0])
                    directives = []
                pos = self._emit(ch, docs, strict)
                continue
            if k >= n:
                break
            s = lines[k]
            if s[:3] == "...":
                rest = _WS.match(s, 3).end()
                if rest < len(s) and s[rest] != "#":
                    bad = _Chunk(k, 3, False)
                    bad.hi = k + 1
                    bad.error = self._err_line("content after the '...' document end marker", k, rest)
                    self._emit(bad, docs, strict)
                pos = k + 1
                continue
            ch = _Chunk(k, 3, True)
            ch.hi = marks[mi + 1] if mi + 1 < len(marks) else n
            self._directives(ch, directives)
            directives = []
            pos = self._emit(ch, docs, strict)
        if directives:
            bad = _Chunk(directives[0], 0, False)
            bad.hi = n
            bad.error = self._err_line("directives must be followed by a '---' marker", directives[0])
            self._emit(bad, docs, strict)
        self.anchors = {}
        return docs

    def _emit(self, ch: _Chunk, docs: list[Document], strict: bool) -> int:
        """Parse one document into ``docs``; return the line where the next one may start."""
        n0, a0 = self.count, self.aliases
        root: Node | None = None
        err = ch.error
        resume = ch.hi
        if err is None:
            try:
                root, resume = self._document(ch)
            except YamlError as exc:
                err = exc.with_traceback(None)
            except RecursionError:  # defensive: the depth limit keeps recursion far below this
                err = self._err_line(_DEPTH_MSG, ch.lo)
        if err is not None:
            if strict:
                raise err
            root = None
            resume = ch.hi
            self.count, self.aliases = n0, a0
        starts = self.starts
        lines = self.lines
        explicit_end = resume == ch.hi and ch.hi < len(lines) and lines[ch.hi][:3] == "..."
        end = starts[resume] if resume < len(starts) else len(self.src.text)
        docs.append(
            Document(root, err, len(docs), starts[ch.lo], end, ch.explicit, explicit_end, ch.version, self.src)
        )
        return resume

    def _document(self, ch: _Chunk) -> tuple[Node, int]:
        self.hi = ch.hi
        self.anchors = {}
        self.maxd = 0
        i = ch.lo
        empty_off = self.starts[i]
        if ch.explicit:
            s = self.lines[i]
            k = _WS.match(s, 3).end()
            empty_off += 3
            if k < len(s) and s[k] != "#":
                node = self._block_node(i, k, -1, 0, False, False, None, None)
                return node, self._doc_end(self.i)
        else:
            i -= 1
        node = self._below(i, -1, 0, empty_off, None, None, False)
        return node, self._doc_end(self.i)

    def _doc_end(self, i: int) -> int:
        j = self._next_entry(i)
        if j >= self.hi:
            return self.hi
        if self.lines[j][:1] == "%":
            return j  # a directive line at a token boundary ends the document
        self._fail("unexpected content after the document root (bad indentation?)", j, self.cc[j])

    # -------------------------------------------------------------------- block context

    def _below(
        self, i: int, parent: int, depth: int, empty_off: int, anchor: str | None, tag: str | None, seq_ok: bool
    ) -> Node:
        """The node whose content starts on a line after ``i`` (more indented than ``parent``), an
        indentless sequence (``seq_ok``), or an empty (null) scalar at ``empty_off``."""
        hi = self.hi
        j = self._next_content(i + 1)
        if self.helm and j < hi and self._is_tpl(j):
            k = j
            while True:
                k = self._next_content(k + 1)
                if k >= hi or not self._is_tpl(k):
                    break
            if k < hi and (self.ind[k] > parent or (seq_ok and self.ind[k] == parent and self._is_dash(k, parent))):
                j = k
        if j < hi and parent < 0 and self.lines[j][:1] == "%":
            j = hi  # a directive line: the (empty) root ends here
        if j < hi:
            ind = self.ind[j]
            if ind > parent:
                if self.cc[j] != ind:
                    self._fail(_TAB_MSG, j, ind)
                return self._block_node(j, ind, parent, depth, True, seq_ok, anchor, tag)
            if seq_ok and ind == parent and self._is_dash(j, ind):
                return self._block_seq(j, ind, depth, anchor, tag)
        if anchor is not None:
            n0, d0 = self._anchor_begin(depth)
        self._bump(i + 1, 0)
        node = ScalarNode("", PLAIN, tag, anchor, empty_off, empty_off, self.src)
        if anchor is not None:
            self._anchor_end(anchor, node, n0, d0, depth)
        self.i = i + 1
        return node

    def _block_node(
        self,
        i: int,
        c: int,
        parent: int,
        depth: int,
        block_ok: bool,
        seq_ok: bool,
        anchor: str | None,
        tag: str | None,
    ) -> Node:
        """A node whose first character is at (i, c) in block context. ``block_ok`` allows a block
        collection to start here (line start or after ``- ``); ``parent`` is the enclosing block
        indentation (-1 at the root); ``depth`` is the enclosing collection level."""
        s = self.lines[i]
        ch = s[c]
        if ch == "&" or ch == "!":
            pc = c
            a2, t2, pend, c = self._props(i, c, False)
            if c >= len(s) or s[c] == "#":
                anchor = self._merge_prop(anchor, a2, "anchor", i, pc)
                tag = self._merge_prop(tag, t2, "tag", i, pc)
                return self._below(i, parent, depth, self.starts[i] + pend, anchor, tag, seq_ok)
            if block_ok and self.key_match(s, c) is not None:
                # `&a key: v`: the properties belong to the first key, the map starts at them.
                return self._block_map(i, pc, depth, anchor, tag)
            anchor = self._merge_prop(anchor, a2, "anchor", i, pc)
            tag = self._merge_prop(tag, t2, "tag", i, pc)
            ch = s[c]
            block_ok = False
        n = len(s)
        if ch == "-" and (c + 1 == n or s[c + 1] in " \t"):
            if not block_ok:
                self._fail("block sequence entries are not allowed here", i, c)
            return self._block_seq(i, c, depth, anchor, tag)
        if ch == "?" and (c + 1 == n or s[c + 1] in " \t"):
            self._fail("complex mapping keys ('?') are not supported", i, c)
        if ch == "|" or ch == ">":
            return self._block_scalar(i, c, parent, depth, anchor, tag)
        if block_ok:
            fm = self.entry_match(s, c)
            if fm is not None or (ch in "\"'*" and self.key_match(s, c) is not None):
                return self._block_map(i, c, depth, anchor, tag, fm)
        if ch == "*":
            if anchor is not None or tag is not None:
                self._fail("an alias cannot have properties", i, c)
            node = self._alias(i, c, depth)
            self._finish_line(self.i, self.c)
            return node
        if ch == "[" or (ch == "{" and not (self.helm and s.startswith("{{", c))):
            fnode = self._flow(i, c, depth, anchor, tag)
            self._finish_line(self.i, self.c)
            return fnode
        if anchor is not None:
            n0, d0 = self._anchor_begin(depth)
        if ch == '"' or ch == "'":
            raw = self._dquoted(i, c) if ch == '"' else self._squoted(i, c)
            self._bump(i, c)
            node: ScalarNode = ScalarNode(
                raw, DOUBLE if ch == '"' else SINGLE, tag, anchor, self.starts[i] + c,
                self.starts[self.i] + self.c, self.src,
            )  # fmt: skip
            self._finish_line(self.i, self.c)
        else:
            node = self._plain_block(i, c, parent, tag, anchor)
        if anchor is not None:
            self._anchor_end(anchor, node, n0, d0, depth)
        return node

    def _block_seq(self, i: int, c: int, depth: int, anchor: str | None, tag: str | None) -> SeqNode:
        if anchor is not None:
            n0, d0 = self._anchor_begin(depth)
        lvl = self._open(depth, i, c)
        lines = self.lines
        starts = self.starts
        ind = self.ind
        hi = self.hi
        indent = c
        start = starts[i] + c
        cc = self.cc
        item_match = self.item_match
        src = self.src
        helm = self.helm
        items: list[Node] = []
        while True:
            s = lines[i]
            n = len(s)
            k = c + 1
            while k < n and (s[k] == " " or s[k] == "\t"):
                k += 1
            if k >= n or s[k] == "#":
                item = self._below(i, indent, lvl, starts[i] + c + 1, None, None, False)
            else:
                fm = item_match(s, k) if s[k] not in "&!*[{|>" else None
                if fm is not None:
                    # fast path: `- scalar [# comment]` (a key would have stopped the match)
                    self.count += 1
                    if self.count > MAX_NODES:
                        self._fail(_NODES_MSG, i, k)
                    base = starts[i]
                    pv, com, dv, sv = fm.groups()
                    j = i + 1
                    if pv is not None:
                        ve = fm.end(1)
                        if com is None and j < hi:
                            t = lines[j]
                            kk = cc[j]
                            if kk >= len(t) or (t[kk] != "#" and ind[j] > indent):
                                pv, vend = self._plain_more(i, k, ve, indent)
                            else:
                                vend = base + ve
                                self.i = j
                        else:
                            vend = base + ve
                            self.i = j
                        item = ScalarNode(pv, PLAIN, None, None, base + k, vend, src)
                    else:
                        self.i = j
                        if dv is not None:
                            item = ScalarNode(dv, DOUBLE, None, None, base + k, base + fm.end(3) + 1, src)
                        else:
                            item = ScalarNode(sv, SINGLE, None, None, base + k, base + fm.end(4) + 1, src)
                else:
                    item = self._block_node(i, k, indent, lvl, True, False, None, None)
            items.append(item)
            j = self.i
            while j < hi:
                t = lines[j]
                kk = cc[j]
                if kk < len(t) and t[kk] != "#":
                    break
                j += 1
            if helm:
                j = self._next_entry(j)
            if j >= hi:
                break
            ji = ind[j]
            if ji != indent:
                if ji > indent:
                    self._fail("bad indentation of a sequence entry", j, ji)
                break
            if not self._is_dash(j, ji):
                break
            i = j
        self.i = j
        end = max(items[-1].end, start + 1)
        node = SeqNode(items, tag, anchor, start, end, self.src)
        if anchor is not None:
            self._anchor_end(anchor, node, n0, d0, depth)
        return node

    def _block_map(
        self, i: int, c: int, depth: int, anchor: str | None, tag: str | None, first: re.Match[str] | None = None
    ) -> MapNode:
        if anchor is not None:
            n0, d0 = self._anchor_begin(depth)
        lvl = self._open(depth, i, c)
        lines = self.lines
        starts = self.starts
        ind = self.ind
        cc = self.cc
        hi = self.hi
        key_match = self.key_match
        indent = c
        start = starts[i] + c
        entry_match = self.entry_match
        src = self.src
        helm = self.helm
        items: list[tuple[KeyNode, Node]] = []
        merge = False
        while True:
            s = lines[i]
            base = starts[i]
            if first is not None:
                fm: re.Match[str] | None = first
                first = None
            else:
                fm = entry_match(s, c)
            if fm is not None:
                # fast path: a plain key (and a simple one-line value, or none)
                kraw, pv, com, dv, sv, cx = fm.groups()
                self.count += 2
                if self.count > MAX_NODES:
                    self._fail(_NODES_MSG, i, c)
                key = KeyNode(kraw, PLAIN, None, None, base + c, base + fm.end(1), src)
                if kraw == "<<":
                    merge = True
                if cx is not None:
                    self.count -= 1  # the value is counted where it is parsed
                    v = fm.start(6)
                    if v >= len(s):
                        colon = s.index(":", fm.end(1))
                        value = self._below(i, indent, lvl, base + colon + 1, None, None, True)
                    else:
                        value = self._block_node(i, v, indent, lvl, False, True, None, None)
                elif pv is not None:
                    vs = fm.start(2)
                    ve = fm.end(2)
                    j = i + 1
                    if com is None and j < hi:
                        t = lines[j]
                        k = cc[j]
                        if k >= len(t) or (t[k] != "#" and ind[j] > indent):
                            pv, vend = self._plain_more(i, vs, ve, indent)
                        else:
                            vend = base + ve
                            self.i = j
                    else:
                        vend = base + ve
                        self.i = j
                    value: Node = ScalarNode(pv, PLAIN, None, None, base + vs, vend, src)
                elif dv is not None:
                    value = ScalarNode(dv, DOUBLE, None, None, base + fm.start(4) - 1, base + fm.end(4) + 1, src)
                    self.i = i + 1
                elif sv is not None:
                    value = ScalarNode(sv, SINGLE, None, None, base + fm.start(5) - 1, base + fm.end(5) + 1, src)
                    self.i = i + 1
                else:
                    self.count -= 1  # the value is parsed (and counted) below
                    colon = s.index(":", fm.end(1))
                    value = self._below(i, indent, lvl, base + colon + 1, None, None, True)
            else:
                m = key_match(s, c)
                if m is not None:
                    key = self._key(m, i, c, lvl, None, None)
                else:
                    key, m = self._key_with_props(i, c, lvl)
                if key.style == PLAIN and key.raw == "<<":
                    merge = True
                v = m.end()
                if v >= len(s) or s[v] == "#":
                    colon = s.rfind(":", c, v)
                    value = self._below(i, indent, lvl, base + colon + 1, None, None, True)
                else:
                    value = self._block_node(i, v, indent, lvl, False, True, None, None)
            items.append((key, value))
            j = self.i
            while j < hi:
                t = lines[j]
                k = cc[j]
                if k < len(t) and t[k] != "#":
                    break
                j += 1
            if helm:
                j = self._next_entry(j)
            if j >= hi:
                break
            ji = ind[j]
            if ji != indent:
                if ji > indent:
                    self._fail("bad indentation of a mapping entry", j, ji)
                break
            if cc[j] != ji:
                self._fail(_TAB_MSG, j, ji)
            if ji == 0 and lines[j][0] == "%":
                break  # a directive line ends the root mapping and the document
            i = j
            c = ji
        self.i = j
        lk, lv = items[-1]
        end = lv.end if lv.end > lk.end else lk.end
        if merge:
            items = self._merge(items)
        node = MapNode(items, tag, anchor, start, end, self.src)
        if anchor is not None:
            self._anchor_end(anchor, node, n0, d0, depth)
        return node

    def _key(
        self, m: re.Match[str], i: int, c: int, depth: int, anchor: str | None, tag: str | None
    ) -> KeyNode:
        g = m.lastindex
        base = self.starts[i]
        if g == 1:
            raw = m.group(1)
            style = PLAIN
            end = m.end(1)
        elif g == 2:
            body = m.group(2)
            raw = self._unescape(body, i, m.start(2)) if "\\" in body else body
            style = DOUBLE
            end = m.end(2) + 1
        elif g == 3:
            raw = m.group(3).replace("''", "'")
            style = SINGLE
            end = m.end(3) + 1
        else:
            if anchor is not None or tag is not None:
                self._fail("an alias cannot have properties", i, c)
            target = self._alias_target(m.group(4), i, c, depth)
            if not isinstance(target, ScalarNode):
                self._fail("complex mapping keys are not supported", i, c)
            return KeyNode(target.raw, target.style, target.tag, None, base + c, base + m.end(4), self.src)
        self._bump(i, c)
        key = KeyNode(raw, style, tag, anchor, base + c, base + end, self.src)
        if anchor is not None:
            self.anchors[anchor] = (ScalarNode(raw, style, tag, anchor, base + c, base + end, self.src), 1, 0)
        return key

    def _key_with_props(self, i: int, c: int, depth: int) -> tuple[KeyNode, re.Match[str]]:
        s = self.lines[i]
        ch = s[c]
        if ch == "&" or ch == "!":
            anchor, tag, _, k = self._props(i, c, False)
            m = self.key_match(s, k) if k < len(s) else None
            if m is not None:
                return self._key(m, i, k, depth, anchor, tag), m
            self._fail("could not find the ':' of a mapping key", i, k)
        if ch == "?" and (c + 1 == len(s) or s[c + 1] in " \t"):
            self._fail("complex mapping keys ('?') are not supported", i, c)
        if self._is_dash(i, c):
            self._fail("block sequence entries are not allowed here (expected a mapping key)", i, c)
        if ch in "[{":
            self._fail("complex mapping keys are not supported", i, c)
        self._fail("could not find the ':' of a mapping key", i, c)

    def _merge(self, items: list[tuple[KeyNode, Node]]) -> list[tuple[KeyNode, Node]]:
        """Expand ``<<`` merge keys like PyYAML: explicit keys win; within ``<<: [a, b]`` the earlier
        mapping wins; with repeated ``<<`` keys the later one wins."""
        merged: list[tuple[KeyNode, Node]] = []
        explicit: list[tuple[KeyNode, Node]] = []
        for k, v in items:
            if not k.is_merge:
                explicit.append((k, v))
                continue
            if isinstance(v, MapNode):
                merged.extend(v.items)
            elif isinstance(v, SeqNode):
                subs: list[list[tuple[KeyNode, Node]]] = []
                for s in v.items:
                    if not isinstance(s, MapNode):
                        self._fail_at("a merge key needs a mapping or a sequence of mappings", k.start)
                    subs.append(s.items)
                for sub in reversed(subs):
                    merged.extend(sub)
            else:
                self._fail_at("a merge key needs a mapping or a sequence of mappings", k.start)
        if not merged:
            return explicit
        later = {k.raw for k, _ in explicit}
        kept: list[tuple[KeyNode, Node]] = []
        for k, v in reversed(merged):
            if k.raw not in later:
                later.add(k.raw)
                kept.append((k, v))
        kept.reverse()
        return kept + explicit

    def _alias_target(self, name: str, i: int, c: int, depth: int) -> Node:
        entry = self.anchors.get(name)
        if entry is None:
            self._fail("undefined alias (anchors must be defined before use; recursion is not allowed)", i, c)
        node, size, height = entry
        self.aliases += 1
        if self.aliases > MAX_ALIASES:
            self._fail(f"more than {MAX_ALIASES} alias expansions", i, c)
        self.count += size
        if self.count > MAX_NODES:
            self._fail(_NODES_MSG + " (alias expansion)", i, c)
        if depth + height > MAX_DEPTH:
            self._fail(_DEPTH_MSG + " (alias expansion)", i, c)
        if depth + height > self.maxd:
            self.maxd = depth + height
        return node

    def _alias(self, i: int, c: int, depth: int) -> Node:
        m = _ALIAS.match(self.lines[i], c)
        if m is None:
            self._fail("alias name expected", i, c)
        node = self._alias_target(m.group(1), i, c, depth)
        self.i = i
        self.c = m.end()
        return node

    def _plain_block(self, i: int, c: int, parent: int, tag: str | None, anchor: str | None) -> ScalarNode:
        s = self.lines[i]
        m = self.plain_b(s, c)
        if m is None:
            self._fail("a plain scalar cannot start with this character", i, c)
        e = m.end()
        base = self.starts[i]
        k = _WS.match(s, e).end()
        if k < len(s):
            if s[k] == ":":
                self._fail("mapping values are not allowed here", i, k)
            raw = s[c:e]
            end = base + e
            self.i = i + 1
        else:
            raw, end = self._plain_more(i, c, e, parent)
        self._bump(i, c)
        return ScalarNode(raw, PLAIN, tag, anchor, base + c, end, self.src)

    def _plain_more(self, i: int, c: int, e: int, parent: int) -> tuple[str, int]:
        """Continuation lines of a block plain scalar ending at (i, e) at the end of its line."""
        lines = self.lines
        ind = self.ind
        cc = self.cc
        hi = self.hi
        cont = self.cont_b
        chunks: list[str] | None = None
        end_i, end_e = i, e
        j = i + 1
        empties = 0
        while j < hi:
            s = lines[j]
            k = cc[j]
            if k >= len(s):
                empties += 1
                j += 1
                continue
            if s[k] == "#" or ind[j] <= parent:
                break
            e2 = cont(s, k).end()
            if e2 == k:
                break
            if chunks is None:
                chunks = [lines[i][c:e]]
            chunks.append(self._fold(end_i, empties))
            chunks.append(s[k:e2])
            empties = 0
            end_i, end_e = j, e2
            t = _WS.match(s, e2).end()
            if t < len(s):
                if s[t] == ":":
                    self._fail("mapping values are not allowed here (implicit keys must be one line)", j, t)
                break
            j += 1
        self.i = end_i + 1
        raw = lines[i][c:e] if chunks is None else "".join(chunks)
        return raw, self.starts[end_i] + end_e

    def _block_scalar(self, i: int, c: int, parent: int, depth: int, anchor: str | None, tag: str | None) -> Node:
        lines = self.lines
        s = lines[i]
        m = _BLOCK_HEAD.match(s, c)
        if m is None:
            self._fail("invalid block scalar header", i, c)
        chomp = ""
        incr = 0
        flags = m.group(1)
        for f in flags:
            if f in "+-":
                if chomp:
                    self._fail("invalid block scalar header", i, c)
                chomp = f
            else:
                if incr or f == "0":
                    self._fail("block scalar indentation indicator must be 1-9", i, c)
                incr = int(f)
        if anchor is not None:
            n0, d0 = self._anchor_begin(depth)
        folded = s[c] == ">"
        min_ind = max(parent + 1, 1)
        ind = self.ind
        hi = self.hi
        skip = self.skip
        k = i + 1
        if incr:
            indent = min_ind + incr - 1
        else:
            max_ind = 0
            while k < hi:
                if k in skip:
                    k += 1
                    continue
                sp = ind[k]
                if sp > max_ind:
                    max_ind = sp
                if sp < len(lines[k]):
                    break
                k += 1
            indent = max(min_ind, max_ind)
            k = i + 1
        chunks: list[str] = []
        breaks: list[str] = []
        line_break = ""
        last_content = -1
        started = False
        leading_ns = False
        while k < hi:
            if k in skip:
                k += 1
                continue
            t = lines[k]
            sp = ind[k]
            if sp >= indent and len(t) > indent:
                content = t[indent:]
                if started:
                    if folded and line_break == "\n" and leading_ns and content[0] not in " \t":
                        if not breaks:
                            chunks.append(" ")
                    else:
                        chunks.append(line_break)
                chunks.extend(breaks)
                breaks = []
                leading_ns = content[0] not in " \t"
                chunks.append(content)
                line_break = self._brk(k)
                last_content = k
                started = True
            elif sp == len(t) or (sp >= indent and len(t) == indent):
                breaks.append(self._brk(k) or "")
            else:
                break
            k += 1
        if chomp != "-":
            chunks.append(line_break)
        if chomp == "+":
            chunks.extend(breaks)
        self.i = k
        start = self.starts[i] + c
        end = self.starts[last_content] + len(lines[last_content]) if last_content >= 0 else start + 1 + len(flags)
        self._bump(i, c)
        node = ScalarNode("".join(chunks), FOLDED if folded else LITERAL, tag, anchor, start, end, self.src)
        if anchor is not None:
            self._anchor_end(anchor, node, n0, d0, depth)
        return node

    # -------------------------------------------------------------------- scalars

    def _unescape(self, body: str, i: int, c: int) -> str:
        try:
            return _unescape(body)
        except _BadEscape as exc:
            self._fail("invalid escape sequence in a double-quoted scalar", i, c + exc.index)

    def _dquoted(self, i: int, c: int) -> str:
        s = self.lines[i]
        m = _DQ_LINE.match(s, c + 1)
        if m is not None:
            self.i = i
            self.c = m.end()
            body = m.group(1)
            return self._unescape(body, i, c + 1) if "\\" in body else body
        lines = self.lines
        cc = self.cc
        hi = self.hi
        chunks: list[str] = []
        k = i
        b = c + 1
        while True:
            s = lines[k]
            e = _DQ_BODY.match(s, b).end()
            if e < len(s) and s[e] == '"':
                chunks.append(self._unescape(s[b:e], k, b))
                self.i = k
                self.c = e + 1
                return "".join(chunks)
            escaped_break = e < len(s)  # only a trailing backslash can stop the body short
            if escaped_break:
                chunks.append(self._unescape(s[b:e], k, b))
            else:
                t = len(s)
                while t > b and s[t - 1] in " \t":
                    t -= 1
                if t < len(s):
                    q = t
                    while q > b and s[q - 1] == "\\":
                        q -= 1
                    if (t - q) % 2 == 1:
                        t += 1
                chunks.append(self._unescape(s[b:t], k, b))
            k0 = k
            k += 1
            empties = 0
            while k < hi and cc[k] >= len(lines[k]):
                empties += 1
                k += 1
            if k >= hi:
                self._fail("unterminated double-quoted scalar", i, c)
            chunks.append("\n" * empties if escaped_break else self._fold(k0, empties))
            b = cc[k]

    def _squoted(self, i: int, c: int) -> str:
        s = self.lines[i]
        m = _SQ_LINE.match(s, c + 1)
        if m is not None:
            self.i = i
            self.c = m.end()
            return m.group(1).replace("''", "'")
        lines = self.lines
        cc = self.cc
        hi = self.hi
        chunks: list[str] = []
        k = i
        b = c + 1
        while True:
            s = lines[k]
            e = _SQ_BODY.match(s, b).end()
            if e < len(s):
                chunks.append(s[b:e].replace("''", "'"))
                self.i = k
                self.c = e + 1
                return "".join(chunks)
            chunks.append(s[b:].rstrip(" \t").replace("''", "'"))
            k0 = k
            k += 1
            empties = 0
            while k < hi and cc[k] >= len(lines[k]):
                empties += 1
                k += 1
            if k >= hi:
                self._fail("unterminated single-quoted scalar", i, c)
            chunks.append(self._fold(k0, empties))
            b = cc[k]

    # -------------------------------------------------------------------- flow context

    def _fws(self, i: int, c: int) -> tuple[int, int]:
        """Skip spaces, tabs, comments and line breaks inside a flow collection."""
        lines = self.lines
        hi = self.hi
        while True:
            s = lines[i]
            k = _FWS.match(s, c).end()
            if k < len(s):
                return i, k
            i += 1
            c = 0
            if i >= hi:
                self._fail("unexpected end of document inside a flow collection", i - 1, len(lines[i - 1]))

    def _empty(self, off: int, anchor: str | None, tag: str | None, depth: int, i: int, c: int) -> ScalarNode:
        if anchor is not None:
            n0, d0 = self._anchor_begin(depth)
        self._bump(i, c)
        node = ScalarNode("", PLAIN, tag, anchor, off, off, self.src)
        if anchor is not None:
            self._anchor_end(anchor, node, n0, d0, depth)
        return node

    def _as_key(self, node: Node) -> KeyNode:
        if not isinstance(node, ScalarNode):
            self._fail_at("complex mapping keys are not supported", node.start)
        return KeyNode(node.raw, node.style, node.tag, node.anchor, node.start, node.end, self.src)

    def _flow(self, i: int, c: int, depth: int, anchor: str | None, tag: str | None) -> Node:
        """A flow collection starting at the bracket at (i, c); leaves (self.i, self.c) after it.

        A ``:`` is a value indicator when followed by a space, a flow indicator or the line end, or
        right after a JSON-like node (quoted scalar or collection), as in ``{"a":1}``.
        """
        if anchor is not None:
            n0, d0 = self._anchor_begin(depth)
        lvl = self._open(depth, i, c)
        lines = self.lines
        starts = self.starts
        start = starts[i] + c
        fws = self._fws
        fnode = self._fnode
        node: Node
        if lines[i][c] == "[":
            items: list[Node] = []
            i, c = fws(i, c + 1)
            while True:
                s = lines[i]
                ch = s[c]
                if ch == "]":
                    break
                if ch == ",":
                    self._fail("expected a node, found ','", i, c)
                item = fnode(i, c, lvl)
                i = self.i
                c = self.c
                s = lines[i]
                if c >= len(s) or s[c] in " \t#":
                    i, c = fws(i, c)
                    s = lines[i]
                ch = s[c]
                if ch == ":" and (
                    c + 1 == len(s)
                    or s[c + 1] in " \t,[]{}"
                    or not isinstance(item, ScalarNode)
                    or item.style != PLAIN
                ):
                    item = self._flow_pair(item, i, c, lvl)
                    i = self.i
                    c = self.c
                    s = lines[i]
                    ch = s[c]
                items.append(item)
                if ch == ",":
                    c += 1
                    if c >= len(s) or s[c] in " \t#":
                        i, c = fws(i, c)
                elif ch != "]":
                    self._fail("expected ',' or ']' in a flow sequence", i, c)
            node = SeqNode(items, tag, anchor, start, starts[i] + c + 1, self.src)
        else:
            src = self.src
            pairs: list[tuple[KeyNode, Node]] = []
            merge = False
            i, c = fws(i, c + 1)
            while True:
                s = lines[i]
                ch = s[c]
                if ch == "}":
                    break
                if ch == ",":
                    self._fail("expected a mapping key, found ','", i, c)
                if ch in "?:" and (c + 1 == len(s) or s[c + 1] in " \t,[]{}"):
                    if ch == "?":
                        self._fail("complex mapping keys ('?') are not supported", i, c)
                    self._fail("expected a mapping key before ':'", i, c)
                m = _DQ_LINE.match(s, c + 1) if ch == '"' else None
                if m is not None:  # fast path: one-line double-quoted key (all JSON keys)
                    body = m.group(1)
                    self.count += 1
                    if self.count > MAX_NODES:
                        self._fail(_NODES_MSG, i, c)
                    key = KeyNode(
                        self._unescape(body, i, c + 1) if "\\" in body else body,
                        DOUBLE, None, None, starts[i] + c, starts[i] + m.end(), src,
                    )  # fmt: skip
                    c = m.end()
                    json_like = True
                else:
                    knode = fnode(i, c, lvl)
                    key = self._as_key(knode)
                    i = self.i
                    c = self.c
                    s = lines[i]
                    json_like = key.style != PLAIN or not isinstance(knode, ScalarNode)
                if c >= len(s) or s[c] in " \t#":
                    i, c = fws(i, c)
                    s = lines[i]
                if s[c] == ":" and (json_like or c + 1 == len(s) or s[c + 1] in " \t,[]{}"):
                    colon_end = starts[i] + c + 1
                    c += 1
                    if c >= len(s) or s[c] in " \t#":
                        i, c = fws(i, c)
                        s = lines[i]
                    if s[c] in ",}":
                        value: Node = self._empty(colon_end, None, None, lvl, i, c)
                    else:
                        value = fnode(i, c, lvl)
                        i = self.i
                        c = self.c
                        s = lines[i]
                        if c >= len(s) or s[c] in " \t#":
                            i, c = fws(i, c)
                            s = lines[i]
                else:
                    value = self._empty(key.end, None, None, lvl, i, c)
                if key.style == PLAIN and key.raw == "<<":
                    merge = True
                pairs.append((key, value))
                ch = s[c]
                if ch == ",":
                    c += 1
                    if c >= len(s) or s[c] in " \t#":
                        i, c = fws(i, c)
                elif ch != "}":
                    self._fail("expected ',' or '}' in a flow mapping", i, c)
            if merge:
                pairs = self._merge(pairs)
            node = MapNode(pairs, tag, anchor, start, starts[i] + c + 1, self.src)
        self.i = i
        self.c = c + 1
        if anchor is not None:
            self._anchor_end(anchor, node, n0, d0, depth)
        return node

    def _flow_pair(self, knode: Node, i: int, c: int, depth: int) -> MapNode:
        """``[a: b]``: a single-pair mapping inside a flow sequence; (i, c) is at the ':'."""
        key = self._as_key(knode)
        lvl = self._open(depth, i, c)
        lines = self.lines
        colon_end = self.starts[i] + c + 1
        i, c = self._fws(i, c + 1)
        s = lines[i]
        if s[c] in ",]":
            value: Node = self._empty(colon_end, None, None, lvl, i, c)
        else:
            value = self._fnode(i, c, lvl)
            i, c = self._fws(self.i, self.c)
        items = [(key, value)]
        if key.is_merge:
            items = self._merge(items)
        self.i = i
        self.c = c
        return MapNode(items, None, None, key.start, max(value.end, colon_end), self.src)

    def _fnode(self, i: int, c: int, depth: int) -> Node:
        """A node inside a flow collection at (i, c); leaves (self.i, self.c) right after it."""
        s = self.lines[i]
        ch = s[c]
        if ch == '"':
            m = _DQ_LINE.match(s, c + 1)
            if m is not None:  # fast path: one-line double-quoted scalar
                body = m.group(1)
                raw = self._unescape(body, i, c + 1) if "\\" in body else body
                e = m.end()
                self.count += 1
                if self.count > MAX_NODES:
                    self._fail(_NODES_MSG, i, c)
                self.i = i
                self.c = e
                base = self.starts[i]
                return ScalarNode(raw, DOUBLE, None, None, base + c, base + e, self.src)
        elif ch not in "&!*[{'|>?":
            m = self.plain_f(s, c)
            if m is not None:
                e = m.end()
                if e < len(s) and s[e] != " " and s[e] != "\t":  # fast path: cannot continue
                    self.count += 1
                    if self.count > MAX_NODES:
                        self._fail(_NODES_MSG, i, c)
                    self.i = i
                    self.c = e
                    base = self.starts[i]
                    return ScalarNode(s[c:e], PLAIN, None, None, base + c, base + e, self.src)
        return self._fnode_slow(i, c, depth)

    def _fnode_slow(self, i: int, c: int, depth: int) -> Node:
        s = self.lines[i]
        ch = s[c]
        anchor: str | None = None
        tag: str | None = None
        if ch == "&" or ch == "!":
            anchor, tag, pend, c2 = self._props(i, c, True)
            pend_off = self.starts[i] + pend
            i, c = self._fws(i, c2)
            s = self.lines[i]
            ch = s[c]
            if ch in ",]}" or (ch == ":" and (c + 1 == len(s) or s[c + 1] in " \t,[]{}")):
                self.i = i
                self.c = c
                return self._empty(pend_off, anchor, tag, depth, i, c)
        if ch == "*":
            if anchor is not None or tag is not None:
                self._fail("an alias cannot have properties", i, c)
            return self._alias(i, c, depth)
        if ch == "[" or (ch == "{" and not (self.helm and s.startswith("{{", c))):
            return self._flow(i, c, depth, anchor, tag)
        if anchor is not None:
            n0, d0 = self._anchor_begin(depth)
        base = self.starts[i]
        if ch == '"' or ch == "'":
            raw = self._dquoted(i, c) if ch == '"' else self._squoted(i, c)
            style = DOUBLE if ch == '"' else SINGLE
            end = self.starts[self.i] + self.c
        elif ch in "|>":
            self._fail("block scalars are not allowed inside flow collections", i, c)
        elif ch == "?":
            self._fail("complex mapping keys ('?') are not supported", i, c)
        else:
            m = self.plain_f(s, c)
            if m is None:
                self._fail("unexpected character in a flow collection", i, c)
            raw, end = self._plain_flow(i, c, m.end())
            style = PLAIN
        self._bump(i, c)
        node = ScalarNode(raw, style, tag, anchor, base + c, end, self.src)
        if anchor is not None:
            self._anchor_end(anchor, node, n0, d0, depth)
        return node

    def _plain_flow(self, i: int, c: int, e: int) -> tuple[str, int]:
        lines = self.lines
        s = lines[i]
        base = self.starts[i]
        if _WS.match(s, e).end() < len(s):
            self.i = i
            self.c = e
            return s[c:e], base + e
        cc = self.cc
        hi = self.hi
        cont = self.cont_f
        chunks: list[str] | None = None
        end_i, end_e = i, e
        j = i + 1
        empties = 0
        while j < hi:
            t = lines[j]
            k = cc[j]
            if k >= len(t):
                empties += 1
                j += 1
                continue
            if t[k] == "#":
                break
            e2 = cont(t, k).end()
            if e2 == k:
                break
            if chunks is None:
                chunks = [s[c:e]]
            chunks.append(self._fold(end_i, empties))
            chunks.append(t[k:e2])
            empties = 0
            end_i, end_e = j, e2
            if _WS.match(t, e2).end() < len(t):
                break
            j += 1
        self.i = end_i
        self.c = end_e
        raw = s[c:e] if chunks is None else "".join(chunks)
        return raw, self.starts[end_i] + end_e


# ------------------------------------------------------------------------------------------ API


def load_all(
    text: str, schema: str = "yaml12", lenient_helm: bool = False, *, strict: bool = False
) -> list[Document]:
    """Parse a YAML (or JSON) stream into documents.

    A syntax or limit error affects only its own document: that ``Document`` has ``root=None`` and
    ``error`` set, and parsing resumes at the next ``---``/``...``/``%`` line. With ``strict=True`` the
    first error is raised instead. ``schema`` (``yaml12`` or ``yaml11``) is the default for
    ``ScalarNode.value``; ``lenient_helm`` enables the Helm template leniency of spec §8.6.
    """
    if not isinstance(text, str):
        raise TypeError("yamlite.load_all expects str")
    if schema not in SCHEMAS:
        raise ValueError(f"unknown YAML schema {schema!r}; expected one of {SCHEMAS}")
    src = _Source(text, schema)
    if _utf8_len_exceeds(text, MAX_BYTES):
        err = YamlError(f"YAML text larger than {MAX_BYTES} bytes", 1, 1, 0)
        if strict:
            raise err
        return [Document(None, err, 0, 0, len(text), False, False, None, src)]
    if not text:
        return []
    # Node graphs are acyclic, so pausing the cyclic collector during a large parse is safe; it
    # saves the repeated full-heap passes that tens of thousands of fresh nodes would trigger.
    pause = len(text) > _GC_PAUSE_CHARS and gc.isenabled()
    if pause:
        gc.disable()
    try:
        return _Parser(text, src, lenient_helm).run(strict)
    finally:
        if pause:
            gc.enable()


def load(text: str, schema: str = "yaml12", lenient_helm: bool = False) -> Node | None:
    """Parse a single-document stream; ``None`` for an empty stream. Raises ``YamlError``."""
    docs = load_all(text, schema, lenient_helm, strict=True)
    if not docs:
        return None
    if len(docs) > 1:
        d = docs[1]
        line, col = d._src.pos(d.start)
        raise YamlError("expected a single document in the stream", line, col, d.start)
    return docs[0].root


def to_python(node: Node | Document | None, schema: str | None = None) -> Any:
    """Convert a node tree (or document) to plain Python values: dict (raw string keys; the last
    duplicate wins), list, str, int, float, bool, None. Aliased subtrees become shared objects.
    A ``Document`` with an error raises it."""
    if schema is not None and schema not in SCHEMAS:
        raise ValueError(f"unknown YAML schema {schema!r}; expected one of {SCHEMAS}")
    if isinstance(node, Document):
        if node.error is not None:
            raise node.error
        node = node.root
    if node is None:
        return None
    return _py(node, schema, {})


def _py(n: Node, schema: str | None, memo: dict[int, Any]) -> Any:
    if isinstance(n, ScalarNode):
        return n.resolve(schema)
    got = memo.get(id(n))
    if got is not None:
        return got
    if isinstance(n, MapNode):
        d: dict[str, Any] = {}
        memo[id(n)] = d
        for k, v in n.items:
            d[k.raw] = _py(v, schema, memo)
        return d
    if isinstance(n, SeqNode):
        out: list[Any] = []
        memo[id(n)] = out
        for v in n.items:
            out.append(_py(v, schema, memo))
        return out
    raise TypeError(f"not a yamlite node: {type(n).__name__}")
