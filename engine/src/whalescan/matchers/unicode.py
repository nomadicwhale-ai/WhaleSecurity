"""`unicode` leaf matcher (spec §8.4) and the public `reveal` / `decode_tags` helpers.

Classes and what one hit is:

- **ZW, BIDI, TAG, VS**: one hit per run of consecutive flagged code points of the selected classes. The
  precision exemptions are part of the run regex, so exempt characters never start or extend a run and
  emoji- or Persian-heavy text is skipped at C speed:
  ZWJ between Extended_Pictographic characters (an emoji element may end in U+FE0F or a skin tone);
  ZWNJ between two Arabic (U+0600-06FF) or two Indic (U+0900-0DFF) characters; U+FEFF at offset 0;
  a lone U+FE0F after an emoji or inside a keycap (`1` VS16 U+20E3); a lone U+FE00-FE0E. Variation selectors
  in runs of two or more are never exempt and are decoded as bytes (`props.decoded_bytes_hex`).
  TAG characters are always flagged and decoded to ASCII (`props.decoded`). A hit with BIDI controls
  carries `props.bidi_unbalanced` (an embedding/override or isolate left open at the end of its line).
- **PUA, CTRL**: one hit per run, from their own scanners. PUA is exempt in files tagged `font`/`icons`;
  CTRL excludes TAB, LF, FF and CR.
- **HOMOGLYPH**: one hit per word (`[^\\W_]+`) that mixes an ASCII letter with a Cyrillic/Greek confusable
  (`props.skeleton` is its ASCII look-alike). A word made only of confusables (and ASCII digits, at least
  two characters, so lone math symbols such as rho stay quiet) is reported with `confidence_delta = -1`
  when every other non-ASCII letter or digit on its line is a confusable too; other all-Cyrillic or
  all-Greek words are exempt.

`min_run` applies per class; `bidi_unbalanced_only` keeps only BIDI hits on unbalanced lines. Nothing runs
for latin-1 fallback files, whose code points are meaningless. Pure-ASCII text (the `isascii()` C fast
path) can only hold CTRL characters, so only the CTRL scanner can run there: the terminal-escape vector
(ESC) is ASCII.

`reveal(text)` replaces every hidden code point with its marker (`[ZWSP]`, `[BIDI:RLO]`, `[TAG:"…"]`,
`[VS:17]`, `[PUA:U+E123]`, `[CTRL:U+001B]`, `[U+0430→a]`) using the same exemptions, except that U+FEFF is
revealed everywhere, so reporters never echo a hidden payload into an agent's context.
"""

from __future__ import annotations

import heapq
import re
from bisect import bisect_right
from collections.abc import Iterable, Iterator, Mapping
from functools import lru_cache
from typing import Any, Final, NamedTuple

from ..errors import RuleError
from ..model import FileCtx, Hit, Rule
from . import unicode_data as ud
from .base import register
from .regex import collect_capped

__all__ = ["DECODE_MAX", "bidi_line_unbalanced", "decode_tags", "match_unicode", "reveal"]

DECODE_MAX: Final = 4096
"""`props.decoded` keeps at most this many characters, `props.decoded_bytes_hex` this many bytes."""
SKELETON_MAX: Final = 256

RUN_CLASSES: Final = frozenset({"ZW", "BIDI", "TAG", "VS"})
_ICON_TAGS: Final = frozenset({"font", "icons"})
_LETTERS: Final = (("Z", "ZW"), ("B", "BIDI"), ("T", "TAG"), ("V", "VS"))
_SEP: Final = "\U00000100"  # outside 0-255: separates variation-selector sub-runs in a translated run

# ctx.cache keys (shared by every unicode rule on the same file)
_BIDI_CACHE: Final = "unicode.bidi_unbalanced"
_ASCII_LINE_CACHE: Final = "unicode.otherwise_ascii"


# --------------------------------------------------------------------------- regex sources


def _esc(cp: int) -> str:
    return f"\\u{cp:04x}" if cp <= 0xFFFF else f"\\U{cp:08x}"


def _cls(ranges: Iterable[tuple[int, int]]) -> str:
    return "[" + "".join(_esc(a) if a == b else f"{_esc(a)}-{_esc(b)}" for a, b in sorted(ranges)) + "]"


_EP: Final = _cls(ud.EXTENDED_PICTOGRAPHIC)
_SKIN: Final = _cls([ud.EMOJI_MODIFIERS])
_VS: Final = _cls(ud.VS_RANGES)
_VS_TEXT: Final = _cls([ud.VS_TEXT_SINGLES])
_ARABIC: Final = _cls([ud.ARABIC_RANGE])
_INDIC: Final = _cls([ud.INDIC_RANGE])
_ZWJ: Final = _esc(ud.ZWJ)
_ZWNJ: Final = _esc(ud.ZWNJ)
_BOM: Final = _esc(ud.ZWNBSP)
_VS16: Final = _esc(ud.VS16)
_KEYCAP: Final = _esc(ud.COMBINING_ENCLOSING_KEYCAP)
_KEYCAP_BASE: Final = "[0-9#*]"

# Validators run right after the candidate character was consumed; each accepts it only when no
# exemption applies. Lookbehinds therefore end with the character itself.
_ZWJ_OK: Final = (
    rf"(?<={_ZWJ})(?!(?:(?<={_EP}{_ZWJ})|(?<={_EP}{_VS16}{_ZWJ})|(?<={_EP}{_SKIN}{_ZWJ})){_EP})"
)
_ZWNJ_OK: Final = rf"(?<={_ZWNJ})(?!(?<={_ARABIC}{_ZWNJ}){_ARABIC})(?!(?<={_INDIC}{_ZWNJ}){_INDIC})"
_BOM_OK: Final = rf"(?<={_BOM})(?<!^{_BOM})"
_VS_OK_EMOJI: Final = (
    rf"(?<={_VS})(?:(?={_VS})|(?<={_VS}{_VS})"
    rf"|(?<!{_VS_TEXT})(?<!{_EP}{_VS16})(?!(?<={_KEYCAP_BASE}{_VS16}){_KEYCAP}))"
)
_VS_OK_PLAIN: Final = rf"(?<={_VS})(?:(?={_VS})|(?<={_VS}{_VS})|(?<!{_VS_TEXT}))"

_CONF_BODY: Final = "".join(_esc(ord(c)) for c in sorted(ud.CONFUSABLES))
_CONF: Final = f"[{_CONF_BODY}]"
_W: Final = r"[^\W_]"


def _run_source(
    plain: list[tuple[int, int]], special: list[tuple[int, int]], checks: list[str], min_run: int
) -> str:
    """Runs of flagged characters. The pattern starts with a plain class so `re` can skip ahead in C."""
    any_cls = _cls(plain + special)
    branches = ([f"(?<={_cls(plain)})"] if plain else []) + checks
    ok = "(?:" + "|".join(branches) + ")"
    unit = any_cls + ok
    if min_run <= 1:
        return f"{unit}(?:{unit})*"
    # Only try run starts: a run shorter than min_run fails once instead of once per character.
    anchor = f"(?<!{_cls(plain)}{any_cls})" if plain else ""
    return f"{any_cls}{anchor}{ok}(?:{unit}){{{min_run - 1},}}"


def _class_parts(
    classes: frozenset[str], allow_emoji: bool, file_mode: bool
) -> tuple[list[tuple[int, int]], list[tuple[int, int]], list[str]]:
    plain: list[tuple[int, int]] = []
    special: list[tuple[int, int]] = []
    checks: list[str] = []
    if "ZW" in classes:
        plain += ud.ZW_PLAIN
        special.append((ud.ZWNJ, ud.ZWNJ))
        checks.append(_ZWNJ_OK)
        if allow_emoji:
            special.append((ud.ZWJ, ud.ZWJ))
            checks.append(_ZWJ_OK)
        else:
            plain.append((ud.ZWJ, ud.ZWJ))
        if file_mode:
            special.append((ud.ZWNBSP, ud.ZWNBSP))
            checks.append(_BOM_OK)
        else:
            plain.append((ud.ZWNBSP, ud.ZWNBSP))
    if "BIDI" in classes:
        plain += ud.BIDI_RANGES
    if "TAG" in classes:
        plain.append(ud.TAG_RANGE)
    if "VS" in classes:
        special += ud.VS_RANGES
        checks.append(_VS_OK_EMOJI if allow_emoji else _VS_OK_PLAIN)
    return plain, special, checks


@lru_cache(maxsize=64)
def _run_regex(classes: frozenset[str], allow_emoji: bool, min_run: int) -> re.Pattern[str]:
    plain, special, checks = _class_parts(classes, allow_emoji, file_mode=True)
    return re.compile(_run_source(plain, special, checks, min_run))


@lru_cache(maxsize=32)
def _class_regex(kind: str, min_run: int) -> re.Pattern[str]:
    cls = _cls(ud.PUA_RANGES if kind == "PUA" else ud.CTRL_RANGES)
    tail = "*" if min_run <= 1 else f"{{{min_run - 1},}}"
    return re.compile(f"{cls}(?<!{cls}{cls}){cls}{tail}")


class _HomoglyphRes(NamedTuple):
    conf: re.Pattern[str]         # any confusable
    mixed: re.Pattern[str]        # a word with >= 1 ASCII letter and >= 1 confusable
    all_conf: re.Pattern[str]     # a word of >= 2 chars made only of confusables and ASCII digits
    other_alnum: re.Pattern[str]  # a non-ASCII letter/digit that is not a confusable


@lru_cache(maxsize=1)
def _homoglyph_res() -> _HomoglyphRes:
    # Word-start anchored and lookahead-checked, so every word is scanned a bounded number of times.
    word_start = f"(?<!{_W}{_W})"
    return _HomoglyphRes(
        conf=re.compile(_CONF),
        mixed=re.compile(
            rf"{_W}{word_start}(?:(?<=[A-Za-z])|(?={_W}*?[A-Za-z]))(?:(?<={_CONF})|(?={_W}*?{_CONF})){_W}*"
        ),
        all_conf=re.compile(
            rf"[0-9{_CONF_BODY}](?<!{_W}[0-9{_CONF_BODY}])(?:(?<={_CONF})|(?=[0-9]*{_CONF}))"
            rf"[0-9{_CONF_BODY}]+(?!{_W})"
        ),
        other_alnum=re.compile(rf"[^\W_\x00-\x7f](?<!{_CONF})"),
    )


@lru_cache(maxsize=1)
def _reveal_regex() -> re.Pattern[str]:
    plain, special, checks = _class_parts(RUN_CLASSES, allow_emoji=True, file_mode=False)
    plain += ud.PUA_RANGES
    plain += ud.CTRL_RANGES
    return re.compile(_run_source(plain, special, checks, 1))


@lru_cache(maxsize=1)
def _misc_res() -> tuple[re.Pattern[str], re.Pattern[str], re.Pattern[str], re.Pattern[str]]:
    tag = _cls([ud.TAG_RANGE])
    return (
        re.compile(f"({tag}+)"),                                  # TAG runs (split keeps them)
        re.compile(_cls(ud.PUA_RANGES)),                          # one PUA char
        re.compile(_cls(r for r in ud.CTRL_RANGES if r[0] < 0x80)),  # ASCII control chars
        re.compile(_cls(ud.BIDI_RANGES)),                         # BIDI controls
    )


# --------------------------------------------------------------------------- translate tables


class _Tables(NamedTuple):
    letters: dict[int, str]              # run char -> class letter
    tag_decode: dict[int, str | None]    # run char -> decoded ASCII, or deleted
    vs_bytes: dict[int, str]             # run char -> chr(byte), or the sub-run separator
    markers: dict[int, str]              # ZW/BIDI/VS/CTRL char -> reveal marker
    conf_markers: dict[int, str]         # confusable -> [U+0430→a]
    skeleton: dict[int, str]             # confusable -> ASCII look-alike


@lru_cache(maxsize=1)
def _tables() -> _Tables:
    zw = list(ud.ZW_MARKERS)
    bidi = list(ud.BIDI_NAMES)
    tag = list(ud.codepoints([ud.TAG_RANGE]))
    vs = list(ud.codepoints(ud.VS_RANGES))
    lo, hi = ud.TAG_PRINTABLE
    letters = {cp: "Z" for cp in zw} | {cp: "B" for cp in bidi}
    letters |= {cp: "T" for cp in tag} | {cp: "V" for cp in vs}
    tag_decode: dict[int, str | None] = {cp: None for cp in zw + bidi + vs}
    tag_decode |= {cp: (chr(cp - ud.TAG_RANGE[0]) if lo <= cp <= hi else None) for cp in tag}
    vs_bytes = {cp: _SEP for cp in zw + bidi + tag} | {cp: chr(ud.vs_byte(cp)) for cp in vs}
    markers: dict[int, str] = {}
    for cp in [*zw, *bidi, *vs, *ud.codepoints(ud.CTRL_RANGES)]:
        m = ud.marker(cp)
        if m is not None:
            markers[cp] = m
    return _Tables(
        letters=letters,
        tag_decode=tag_decode,
        vs_bytes=vs_bytes,
        markers=markers,
        conf_markers={ord(c): ud.confusable_marker(c) for c in ud.CONFUSABLES},
        skeleton={ord(c): a for c, a in ud.CONFUSABLES.items()},
    )


# --------------------------------------------------------------------------- public helpers


def decode_tags(text: str) -> str:
    """The ASCII smuggled in TAG characters: `chr(cp - 0xE0000)` for each of U+E0020-E007E, in order.

    Every other character, including the non-printable TAG characters, is ignored.
    """
    if text.isascii():
        return ""
    tag_runs = _misc_res()[0]
    return "".join(tag_runs.findall(text)).translate(_tables().tag_decode)


def bidi_line_unbalanced(line: str) -> bool:
    """Whether an embedding/override (closed by PDF) or an isolate (closed by PDI) is still open at the end
    of `line`. Closers only close what is open, so `PDF RLO` is unbalanced although the counts match."""
    emb_open = sum(map(line.count, ud.BIDI_EMBEDDING_OPENERS))
    iso_open = sum(map(line.count, ud.BIDI_ISOLATE_OPENERS))
    if not emb_open and not iso_open:
        return False
    if emb_open > line.count(ud.BIDI_PDF) or iso_open > line.count(ud.BIDI_PDI):
        return True
    emb = iso = 0
    for ch in _misc_res()[3].findall(line):
        if ch in ud.BIDI_EMBEDDING_OPENERS:
            emb += 1
        elif ch in ud.BIDI_ISOLATE_OPENERS:
            iso += 1
        elif ch == ud.BIDI_PDF:
            emb = max(0, emb - 1)
        elif ch == ud.BIDI_PDI:
            iso = max(0, iso - 1)
    return emb > 0 or iso > 0


def reveal(text: str) -> str:
    """Replace every hidden code point (§8.4) with its reveal marker; see the module docstring."""
    if not text:
        return text
    tables = _tables()
    if text.isascii():
        if _misc_res()[2].search(text) is None:
            return text
        return text.translate(tables.markers)
    return _reveal_regex().sub(_reveal_run, _reveal_homoglyphs(text))


def _tag_marker(run: str, tables: _Tables) -> str:
    decoded = run.translate(tables.tag_decode).replace("\\", "\\\\").replace('"', '\\"')
    return f'[TAG:"{decoded}"]'


def _plain_markers(run: str, tables: _Tables) -> str:
    out = run.translate(tables.markers)
    if not out.isascii():  # only PUA characters are left untranslated (the table would be huge)
        out = _misc_res()[1].sub(lambda m: f"[PUA:U+{ord(m.group()):04X}]", out)
    return out


def _reveal_run(m: re.Match[str]) -> str:
    run = m.group()
    tables = _tables()
    tag_runs = _misc_res()[0]
    if tag_runs.search(run) is None:
        return _plain_markers(run, tables)
    parts = tag_runs.split(run)  # odd indexes are TAG runs
    return "".join(
        _tag_marker(p, tables) if i % 2 else _plain_markers(p, tables) for i, p in enumerate(parts) if p
    )


def _reveal_homoglyphs(text: str) -> str:
    res = _homoglyph_res()
    if res.conf.search(text) is None:
        return text
    spans = [m.span() for m in res.mixed.finditer(text)]
    line_starts: list[int] | None = None
    verdicts: dict[int, bool] = {}
    for m in res.all_conf.finditer(text):
        if line_starts is None:
            line_starts = _line_starts(text)
        i = bisect_right(line_starts, m.start()) - 1
        ok = verdicts.get(i)
        if ok is None:
            end = line_starts[i + 1] - 1 if i + 1 < len(line_starts) else len(text)
            ok = verdicts[i] = res.other_alnum.search(text, line_starts[i], end) is None
        if ok:
            spans.append(m.span())
    if not spans:
        return text
    spans.sort()
    markers = _tables().conf_markers
    out: list[str] = []
    prev = 0
    for s, e in spans:
        out.append(text[prev:s])
        out.append(text[s:e].translate(markers))
        prev = e
    out.append(text[prev:])
    return "".join(out)


def _line_starts(text: str) -> list[int]:
    starts = [0]
    find = text.find
    i = find("\n")
    while i != -1:
        starts.append(i + 1)
        i = find("\n", i + 1)
    return starts


# --------------------------------------------------------------------------- the matcher


class _Options(NamedTuple):
    classes: frozenset[str]
    min_run: int
    bidi_only: bool
    allow_emoji: bool


class _Cand(NamedTuple):
    start: int
    end: int
    props: dict[str, Any]
    delta: int = 0


def _cand_start(c: _Cand) -> int:
    return c.start


def _options(spec: Any) -> _Options:
    if not isinstance(spec, Mapping):
        raise RuleError("unicode: expected a mapping with `classes`")
    raw = spec.get("classes")
    if isinstance(raw, (str, bytes)) or not isinstance(raw, Iterable):
        raise RuleError("unicode: `classes` must be a list")
    classes = frozenset(raw)
    unknown = classes - frozenset(ud.CLASSES)
    if not classes or unknown:
        raise RuleError(f"unicode: unknown or empty classes {sorted(map(str, unknown))}")
    min_run = spec.get("min_run", 1)
    if isinstance(min_run, bool) or not isinstance(min_run, int) or min_run < 1:
        raise RuleError("unicode: `min_run` must be an integer >= 1")
    bidi_only = spec.get("bidi_unbalanced_only", False)
    allow_emoji = spec.get("allow_emoji_sequences", True)
    if not isinstance(bidi_only, bool) or not isinstance(allow_emoji, bool):
        raise RuleError("unicode: `bidi_unbalanced_only` and `allow_emoji_sequences` must be booleans")
    return _Options(classes, min_run, bidi_only, allow_emoji)


def _cache(ctx: FileCtx, key: str) -> dict[int, bool]:
    got = ctx.cache.get(key)
    if not isinstance(got, dict):
        got = {}
        ctx.cache[key] = got
    return got


def _bidi_unbalanced(ctx: FileCtx, line: int) -> bool:
    cache = _cache(ctx, _BIDI_CACHE)
    got = cache.get(line)
    if got is None:
        got = cache[line] = bidi_line_unbalanced(ctx.line_text(line))
    return got


def _otherwise_ascii(ctx: FileCtx, line: int) -> bool:
    """Every non-ASCII letter or digit on `line` is a confusable."""
    cache = _cache(ctx, _ASCII_LINE_CACHE)
    got = cache.get(line)
    if got is None:
        s, e = ctx.line_span(line)
        got = cache[line] = _homoglyph_res().other_alnum.search(ctx.text, s, e) is None
    return got


def _scan_runs(ctx: FileCtx, classes: frozenset[str], opt: _Options) -> Iterator[_Cand]:
    rx = _run_regex(classes, opt.allow_emoji, opt.min_run)
    tables = _tables()
    per_class = opt.min_run > 1 and len(classes) > 1
    for m in rx.finditer(ctx.text):
        run = m.group()
        codes = run.translate(tables.letters)
        present = [(letter, name) for letter, name in _LETTERS if letter in codes]
        if per_class and max(codes.count(letter) for letter, _ in present) < opt.min_run:
            continue
        start = m.start()
        props: dict[str, Any] = {"classes": [name for _, name in present], "count": len(run)}
        if "B" in codes:
            unbalanced = props["bidi_unbalanced"] = _bidi_unbalanced(ctx, ctx.line_of(start))
            if opt.bidi_only and not unbalanced:
                continue
        elif opt.bidi_only:
            continue
        if "T" in codes:
            decoded = run.translate(tables.tag_decode)
            props["decoded"] = decoded[:DECODE_MAX]
            if len(decoded) > DECODE_MAX:
                props["decoded_truncated"] = True
        if codes.count("V") >= 2:
            parts = run.translate(tables.vs_bytes).split(_SEP)
            data = "".join(p for p in parts if len(p) >= 2).encode("latin-1")
            if data:
                props["decoded_bytes_hex"] = data[:DECODE_MAX].hex()
                if len(data) > DECODE_MAX:
                    props["decoded_truncated"] = True
        yield _Cand(start, m.end(), props)


def _scan_class(ctx: FileCtx, kind: str, min_run: int) -> Iterator[_Cand]:
    for m in _class_regex(kind, min_run).finditer(ctx.text):
        s, e = m.span()
        yield _Cand(s, e, {"classes": [kind], "count": e - s})


def _homoglyph_cand(word: str, start: int, end: int, count: int, delta: int) -> _Cand:
    skeleton = word.translate(_tables().skeleton)[:SKELETON_MAX]
    return _Cand(start, end, {"classes": ["HOMOGLYPH"], "count": count, "skeleton": skeleton}, delta)


def _scan_mixed_words(ctx: FileCtx, min_run: int) -> Iterator[_Cand]:
    res = _homoglyph_res()
    for m in res.mixed.finditer(ctx.text):
        word = m.group()
        n = len(res.conf.findall(word))
        if n >= min_run:
            yield _homoglyph_cand(word, m.start(), m.end(), n, 0)


def _scan_all_confusable_words(ctx: FileCtx, min_run: int) -> Iterator[_Cand]:
    res = _homoglyph_res()
    text = ctx.text
    pos, size = 0, len(text)
    while pos < size:
        m = res.all_conf.search(text, pos)
        if m is None:
            return
        s, e = m.span()
        line = ctx.line_of(s)
        if not _otherwise_ascii(ctx, line):
            pos = ctx.line_span(line)[1] + 1  # nothing else on this line can qualify
            continue
        pos = e
        word = m.group()
        n = len(res.conf.findall(word))
        if n >= min_run:
            yield _homoglyph_cand(word, s, e, n, -1)


def _scan_homoglyphs(ctx: FileCtx, min_run: int) -> Iterator[_Cand]:
    if _homoglyph_res().conf.search(ctx.text) is None:
        return iter(())
    return heapq.merge(
        _scan_mixed_words(ctx, min_run), _scan_all_confusable_words(ctx, min_run), key=_cand_start
    )


@register("unicode")
def match_unicode(spec: Any, ctx: FileCtx, rule: Rule) -> list[Hit]:
    opt = _options(spec)
    text = ctx.text
    if ctx.encoding_fallback or not text:
        return []
    streams: list[Iterator[_Cand]] = []
    if text.isascii():
        if "CTRL" in opt.classes and not opt.bidi_only:
            streams.append(_scan_class(ctx, "CTRL", opt.min_run))
    else:
        run_classes = opt.classes & (frozenset({"BIDI"}) if opt.bidi_only else RUN_CLASSES)
        if run_classes:
            streams.append(_scan_runs(ctx, run_classes, opt))
        if not opt.bidi_only:
            if "PUA" in opt.classes and not ctx.tags & _ICON_TAGS:
                streams.append(_scan_class(ctx, "PUA", opt.min_run))
            if "CTRL" in opt.classes:
                streams.append(_scan_class(ctx, "CTRL", opt.min_run))
            if "HOMOGLYPH" in opt.classes:
                streams.append(_scan_homoglyphs(ctx, opt.min_run))
    if not streams:
        return []
    items = streams[0] if len(streams) == 1 else heapq.merge(*streams, key=_cand_start)

    def build(c: _Cand) -> Hit:
        return Hit.at(ctx, c.start, c.end, confidence_delta=c.delta, props=c.props)

    return collect_capped(items, ctx, rule, build)
