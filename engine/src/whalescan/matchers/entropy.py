"""`entropy` leaf matcher (spec §8.5): high-entropy tokens gated by charset, context and FP filters.

Shannon entropy in bits per character, `H(s) = -Σ (n_c/L)·log2(n_c/L)`, `0 <= H <= log2(min(L, |charset|))`.

**Candidates.** `scope: values` (default) runs the charset's token regex only inside quoted string literals
(`"…"`, `'…'`, `` `…` `` on one line, backslash escapes honored) and inside the `val` group of the
key/value regex below; `scope: anywhere` runs it over the whole text. Candidate regions and tokens are
cached in `ctx.cache` and shared by every entropy rule on the file.

**A token is a hit iff** (1) `min_len <= L <= max_len`; (2) `H >= threshold(L)`, where the rule's
`threshold` replaces the per-charset length buckets and `secrets.entropy_delta` is added to either; (3) it
has `min_classes` of {upper, lower, digit} (hex: a digit and a letter); (4) neither the token nor its
enclosing value is a placeholder; (5) it has no run of one character repeated six times; (6) it holds no
sequential run of six (`012345`, `abcdef`, `FEDCBA`); (7) it is not a UUID, unless keyword context
matched; (8) it is not a 40/64-hex digest whose key or line names a digest (`sha256`, `commit`, `rev`,
`ref`, `digest`, `checksum`, `integrity`, `uses`); (9) the file is not tagged `lockfile`; (10) no
`exclude_regex` pattern matches it. With `context.required`, a token without keyword context is dropped.

**Context and confidence.** Keywords are searched case-insensitively, ignoring `_` and `-` (so
`access_key`, `accessKey` and `ACCESS-KEY` agree), in the `key` group and in the `window_chars` before
the token on its line. Confidence is high with a keyword and `H >= threshold + 0.3`, medium with a
keyword, low without; the hit's `confidence_delta` moves the rule's confidence to that level.
`props = {entropy: round(H, 2), charset, length}`; the token is the hit's secret span.

**Configuration.** The matcher API carries no config object, so the pipeline passes
`secrets.entropy_delta` as `ctx.cache[ENTROPY_DELTA_KEY]` (a float; absent means 0.0).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping
from functools import lru_cache
from typing import Any, Final, NamedTuple

from ..errors import RuleError
from ..model import Confidence, FileCtx, Hit, Rule
from .base import register
from .regex import collect_capped, compile_pattern

__all__ = ["CHARSETS", "DEFAULT_KEYWORDS", "ENTROPY_DELTA_KEY", "match_entropy", "shannon", "threshold_for"]

ENTROPY_DELTA_KEY: Final = "secrets.entropy_delta"
DEFAULT_KEYWORDS: Final = (
    "secret", "token", "passwd", "password", "pwd", "api_key", "apikey", "access_key", "private",
    "credential", "auth", "bearer", "signature", "client_secret", "dsn", "conn", "webhook", "hmac",
)
DEFAULT_MIN_LEN: Final = 20
DEFAULT_MAX_LEN: Final = 200
DEFAULT_MIN_CLASSES: Final = 2
DEFAULT_WINDOW: Final = 80
HIGH_MARGIN: Final = 0.3
MAX_LITERAL: Final = 4096      # chars per literal segment between escapes
MAX_ESCAPES: Final = 256       # escapes per literal
_MIN_TOKEN: Final = 16         # the shortest token any charset regex yields
_CHUNK: Final = 72             # scope anywhere: context kept around a token for the placeholder check


class Charset(NamedTuple):
    name: str
    token: str                                  # token regex (the spec's, first character hoisted)
    max_entropy: float
    thresholds: tuple[float, float, float]      # L = 16-23 / 24-39 / >= 40


# The spec's token regexes, rewritten to start with a plain class so `re` can skip ahead in C:
# `(?<!C)C{16,128}(?!C)` is matched as `C(?<!CC)C{15,127}(?!C)`.
CHARSETS: Final[Mapping[str, Charset]] = {
    "hex": Charset(
        "hex", r"[0-9A-Fa-f](?<![0-9A-Fa-f]{2})[0-9A-Fa-f]{15,127}(?![0-9A-Fa-f])", 4.0, (3.0, 3.2, 3.4)
    ),
    "base64": Charset(
        "base64",
        r"[A-Za-z0-9+/](?<![A-Za-z0-9+/]{2})[A-Za-z0-9+/]{15,199}={0,2}(?![A-Za-z0-9+/=])",
        6.0,
        (3.8, 4.2, 4.5),
    ),
    "base64url": Charset(
        "base64url",
        r"[A-Za-z0-9_-](?<![A-Za-z0-9_-]{2})[A-Za-z0-9_-]{15,199}(?![A-Za-z0-9_-])",
        6.0,
        (3.8, 4.2, 4.5),
    ),
    "alnum": Charset(
        "alnum", r"[A-Za-z0-9](?<![A-Za-z0-9]{2})[A-Za-z0-9]{15,199}(?![A-Za-z0-9])", 5.95, (3.6, 4.0, 4.3)
    ),
}

# The spec's key/value candidate regex (lookbehind moved after the first key character, same language).
_KV_SRC: Final = (
    r"(?P<key>[A-Za-z_](?<![A-Za-z0-9_.\-][A-Za-z_])[A-Za-z0-9_.\-]{0,63})[\"']?[ \t]{0,8}"
    r"(?::=|=>|[:=])[ \t]{0,8}(?P<q>[\"'`]?)(?P<val>[^\s\"'`,;]{8,256})"
)


def _literal_src(quote: str) -> str:
    # `"` not preceded by a backslash opens; the unrolled loop keeps every step deterministic (linear).
    seg = rf"[^{quote}\\\n]{{0,{MAX_LITERAL}}}"
    return rf"{quote}(?<!\\{quote})({seg}(?:\\.{seg}){{0,{MAX_ESCAPES}}}){quote}"


_LITERAL_SRC: Final = "|".join(_literal_src(q) for q in ('"', "'", "`"))

_PLACEHOLDER: Final = re.compile(
    r"x{6,}|\*{4,}|<[^>]{1,64}>|\$\{[^}]{1,64}\}|\{\{[^}]{1,64}\}\}"
    r"|(?:your|my|example|sample|dummy|fake|test|changeme|placeholder|redacted|replace)[_-]?[a-z0-9_-]{0,40}",
    re.IGNORECASE,
)
_REPEAT: Final = re.compile(r"(.)\1{5,}")
_UUID: Final = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")
_HEX: Final = re.compile(r"[0-9a-fA-F]+")
# The spec's digest words; `sha` also covers `sha1`/`sha256`/… since `\b` never splits `sha256`.
_DIGEST_CONTEXT: Final = re.compile(
    r"\b(?:sha(?:1|224|256|384|512)?|commit|rev|ref|digest|checksum|integrity|uses)\b", re.IGNORECASE
)
_CAMEL: Final = re.compile(r"(?<=[a-z])(?=[A-Z])")
_UPPER: Final = re.compile(r"[A-Z]")
_LOWER: Final = re.compile(r"[a-z]")
_DIGIT: Final = re.compile(r"[0-9]")
_HEX_LETTER: Final = re.compile(r"[A-Fa-f]")
_QUOTES: Final = frozenset("\"'`")

_REGIONS_KEY: Final = "entropy.regions"


def _sequential_windows() -> frozenset[str]:
    out: set[str] = set()
    for alphabet in ("0123456789", "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        for seq in (alphabet, alphabet[::-1]):
            out.update(seq[i : i + 6] for i in range(len(seq) - 5))
    return frozenset(out)


_SEQUENTIAL: Final = _sequential_windows()


# --------------------------------------------------------------------------- entropy


@lru_cache(maxsize=1)
def _nlog2n() -> tuple[float, ...]:
    return (0.0, *(n * math.log2(n) for n in range(1, 1025)))


def shannon(s: str) -> float:
    """Shannon entropy of `s` in bits per character (0.0 for an empty string)."""
    size = len(s)
    if size == 0:
        return 0.0
    table = _nlog2n()
    total = 0.0
    for n in Counter(s).values():
        total += table[n] if n < len(table) else n * math.log2(n)
    return max(0.0, math.log2(size) - total / size)


def threshold_for(charset: str, length: int, override: float | None = None, delta: float = 0.0) -> float:
    """Entropy a token of `length` needs: the rule's `threshold`, else the charset's bucket, plus delta."""
    if override is not None:
        return override + delta
    buckets = CHARSETS[charset].thresholds
    return buckets[0 if length < 24 else 1 if length < 40 else 2] + delta


# --------------------------------------------------------------------------- parameters


class _Params(NamedTuple):
    charset: Charset
    min_len: int
    max_len: int
    threshold: float | None
    delta: float
    scope: str
    min_classes: int
    keywords: re.Pattern[str] | None
    required: bool
    window: int
    excludes: tuple[re.Pattern[str], ...]


def _norm(s: str) -> str:
    return s.casefold().replace("_", "").replace("-", "")


@lru_cache(maxsize=64)
def _keyword_regex(keywords: tuple[str, ...]) -> re.Pattern[str] | None:
    words = sorted({w for w in (_norm(k) for k in keywords) if w}, key=len, reverse=True)
    return re.compile("|".join(map(re.escape, words))) if words else None


def _int(spec: Mapping[str, Any], key: str, default: int, lo: int, hi: int) -> int:
    value = spec.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise RuleError(f"entropy: `{key}` must be an integer in [{lo}, {hi}]")
    return value


def _strs(value: Any, what: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise RuleError(f"entropy: `{what}` must be a list of strings")
    out = tuple(value)
    if not all(isinstance(v, str) for v in out):
        raise RuleError(f"entropy: `{what}` must be a list of strings")
    return out


def _params(spec: Any, ctx: FileCtx) -> _Params:
    if not isinstance(spec, Mapping):
        raise RuleError("entropy: expected a mapping with `charset`")
    name = spec.get("charset")
    charset = CHARSETS.get(name) if isinstance(name, str) else None
    if charset is None:
        raise RuleError(f"entropy: `charset` must be one of {', '.join(CHARSETS)}")
    threshold = spec.get("threshold")
    if threshold is not None and (isinstance(threshold, bool) or not isinstance(threshold, (int, float))):
        raise RuleError("entropy: `threshold` must be a number")
    scope = spec.get("scope", "values")
    if scope not in ("values", "anywhere"):
        raise RuleError("entropy: `scope` must be `values` or `anywhere`")
    context = spec.get("context") or {}
    if not isinstance(context, Mapping):
        raise RuleError("entropy: `context` must be a mapping")
    keywords = _strs(context.get("keywords", DEFAULT_KEYWORDS), "context.keywords")
    required = context.get("required", False)
    if not isinstance(required, bool):
        raise RuleError("entropy: `context.required` must be a boolean")
    delta = ctx.cache.get(ENTROPY_DELTA_KEY, 0.0)
    if isinstance(delta, bool) or not isinstance(delta, (int, float)) or not math.isfinite(delta):
        delta = 0.0
    return _Params(
        charset=charset,
        min_len=_int(spec, "min_len", DEFAULT_MIN_LEN, 1, 1 << 20),
        max_len=_int(spec, "max_len", DEFAULT_MAX_LEN, 1, 1 << 20),
        threshold=None if threshold is None else float(threshold),
        delta=float(delta),
        scope=scope,
        min_classes=_int(spec, "min_classes", DEFAULT_MIN_CLASSES, 1, 3),
        keywords=_keyword_regex(keywords),
        required=required,
        window=_int(context, "window_chars", DEFAULT_WINDOW, 0, 1 << 16),
        excludes=tuple(compile_pattern(p, 0) for p in _strs(spec.get("exclude_regex", ()), "exclude_regex")),
    )


# --------------------------------------------------------------------------- candidates


class _Token(NamedTuple):
    start: int
    end: int
    key: str | None      # key group of the key/value match that yielded it
    vstart: int          # enclosing value (literal content or `val` group); -1 for scope anywhere
    vend: int


@lru_cache(maxsize=1)
def _region_regexes() -> tuple[re.Pattern[str], re.Pattern[str]]:
    return re.compile(_KV_SRC), re.compile(_LITERAL_SRC)


@lru_cache(maxsize=8)
def _token_regex(charset: str) -> re.Pattern[str]:
    return re.compile(CHARSETS[charset].token)


def _regions(ctx: FileCtx) -> list[tuple[int, int, str | None]]:
    """Value regions of scope `values`: key/value `val` groups first (they carry a key), then literals."""
    cached = ctx.cache.get(_REGIONS_KEY)
    if isinstance(cached, list):
        return cached
    kv, literal = _region_regexes()
    text = ctx.text
    out: list[tuple[int, int, str | None]] = []
    for m in kv.finditer(text):
        s, e = m.span("val")
        if e - s >= _MIN_TOKEN:
            out.append((s, e, m.group("key")))
    for m in literal.finditer(text):
        s, e = m.span(m.lastindex or 0)
        if e - s >= _MIN_TOKEN:
            out.append((s, e, None))
    ctx.cache[_REGIONS_KEY] = out
    return out


def _tokens(ctx: FileCtx, charset: str, scope: str) -> list[_Token]:
    key = f"entropy.tokens.{charset}.{scope}"
    cached = ctx.cache.get(key)
    if isinstance(cached, list):
        return cached
    rx = _token_regex(charset)
    text = ctx.text
    toks: list[_Token]
    if scope == "anywhere":
        toks = [_Token(m.start(), m.end(), None, -1, -1) for m in rx.finditer(text)]
    else:
        seen: dict[tuple[int, int], _Token] = {}
        size = len(text)
        for rs, re_, k in _regions(ctx):
            # endpos one past the region lets the token regex's lookahead see the real next character.
            for m in rx.finditer(text, rs, min(size, re_ + 1)):
                s, e = m.span()
                if e > re_:
                    break
                seen.setdefault((s, e), _Token(s, e, k, rs, re_))
        toks = sorted(seen.values(), key=lambda t: (t.start, t.end))
    ctx.cache[key] = toks
    return toks


# --------------------------------------------------------------------------- hit conditions


def _classes_ok(tok: str, min_classes: int, is_hex: bool) -> bool:
    digit = _DIGIT.search(tok) is not None
    if is_hex:
        return digit + (_HEX_LETTER.search(tok) is not None) >= min(min_classes, 2)
    return digit + (_UPPER.search(tok) is not None) + (_LOWER.search(tok) is not None) >= min_classes


def _is_sequential(tok: str) -> bool:
    return any(tok[i : i + 6] in _SEQUENTIAL for i in range(len(tok) - 5))


def _is_placeholder(s: str) -> bool:
    return _PLACEHOLDER.fullmatch(s) is not None


def _enclosing(text: str, tok: _Token) -> str:
    """The value a token sits in: its literal or `val` group, else (scope anywhere) the surrounding run of
    non-space, non-quote characters, at most `_CHUNK` on each side."""
    if tok.vstart >= 0:
        return text[tok.vstart : tok.vend].strip()
    lo = tok.start
    floor = max(0, tok.start - _CHUNK)
    while lo > floor and not text[lo - 1].isspace() and text[lo - 1] not in _QUOTES:
        lo -= 1
    hi = tok.end
    ceiling = min(len(text), tok.end + _CHUNK)
    while hi < ceiling and not text[hi].isspace() and text[hi] not in _QUOTES:
        hi += 1
    return text[lo:hi]


def _words(s: str) -> str:
    """`commitSha`, `git_commit`, `image.sha256` -> space-separated words for `\\b` matching."""
    return _CAMEL.sub(" ", s).replace("_", " ").replace(".", " ")


class _Scorer:
    """Evaluates tokens of one file for one rule; caches per-line lookups."""

    __slots__ = ("_digest_lines", "ctx", "p")

    def __init__(self, ctx: FileCtx, p: _Params) -> None:
        self.ctx = ctx
        self.p = p
        self._digest_lines: dict[int, bool] = {}

    def _has_keyword(self, tok: _Token) -> bool:
        rx = self.p.keywords
        if rx is None:
            return False
        if tok.key and rx.search(_norm(tok.key)):
            return True
        if self.p.window <= 0:
            return False
        ctx = self.ctx
        line_start = ctx.line_starts[ctx.line_of(tok.start) - 1]
        window = ctx.text[max(line_start, tok.start - self.p.window) : tok.start]
        return rx.search(_norm(window)) is not None

    def _digest_context(self, tok: _Token) -> bool:
        if tok.key and _DIGEST_CONTEXT.search(_words(tok.key)):
            return True
        line = self.ctx.line_of(tok.start)
        got = self._digest_lines.get(line)
        if got is None:
            got = self._digest_lines[line] = (
                _DIGEST_CONTEXT.search(_words(self.ctx.line_text(line))) is not None
            )
        return got

    def score(self, tok: _Token) -> tuple[float, Confidence] | None:
        p = self.p
        size = tok.end - tok.start
        if size < p.min_len or size > p.max_len:
            return None
        text = self.ctx.text
        s = text[tok.start : tok.end]
        if not _classes_ok(s, p.min_classes, p.charset.name == "hex"):
            return None
        h = shannon(s)
        thr = threshold_for(p.charset.name, size, p.threshold, p.delta)
        if h < thr:
            return None
        if _REPEAT.search(s) is not None or _is_sequential(s):
            return None
        if _is_placeholder(s):
            return None
        value = _enclosing(text, tok)
        if value != s and _is_placeholder(value):
            return None
        keyword = self._has_keyword(tok)
        if not keyword and _UUID.fullmatch(s) is not None:
            return None
        if size in (40, 64) and _HEX.fullmatch(s) is not None and self._digest_context(tok):
            return None
        if any(rx.search(s) is not None for rx in p.excludes):
            return None
        if not keyword:
            return None if p.required else (h, Confidence.LOW)
        return h, (Confidence.HIGH if h >= thr + HIGH_MARGIN else Confidence.MEDIUM)


@register("entropy")
def match_entropy(spec: Any, ctx: FileCtx, rule: Rule) -> list[Hit]:
    p = _params(spec, ctx)
    if "lockfile" in ctx.tags or not ctx.text:
        return []
    scorer = _Scorer(ctx, p)
    base = int(rule.confidence)
    name = p.charset.name

    def scored() -> Iterator[tuple[_Token, float, Confidence]]:
        for tok in _tokens(ctx, name, p.scope):
            got = scorer.score(tok)
            if got is not None:
                yield tok, got[0], got[1]

    def build(item: tuple[_Token, float, Confidence]) -> Hit:
        tok, h, conf = item
        return Hit.at(
            ctx,
            tok.start,
            tok.end,
            secret_spans=[(tok.start, tok.end)],
            confidence_delta=int(conf) - base,
            props={"entropy": round(h, 2), "charset": name, "length": tok.end - tok.start},
        )

    return collect_capped(scored(), ctx, rule, build)
