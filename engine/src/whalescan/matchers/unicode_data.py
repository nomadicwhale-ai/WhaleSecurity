"""Code-point tables for the `unicode` matcher and `reveal` (spec §8.4).

Data only: nothing here compiles a regex or touches `unicodedata`, so importing it is cheap. Ranges are
inclusive `(first, last)` code-point pairs, sorted and non-overlapping.
"""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Iterable, Mapping
from typing import Final

Ranges = tuple[tuple[int, int], ...]

# --------------------------------------------------------------------------- classes

CLASSES: Final = ("ZW", "BIDI", "TAG", "VS", "PUA", "CTRL", "HOMOGLYPH")

# ZW. U+2061-2064 and U+180E have no short name; their marker is the generic `[U+XXXX]` form.
ZW_MARKERS: Final[Mapping[int, str]] = {
    0x00AD: "SHY",
    0x180E: "U+180E",
    0x200B: "ZWSP",
    0x200C: "ZWNJ",
    0x200D: "ZWJ",
    0x2060: "WJ",
    0x2061: "U+2061",
    0x2062: "U+2062",
    0x2063: "U+2063",
    0x2064: "U+2064",
    0xFEFF: "ZWNBSP",
}
ZWNJ: Final = 0x200C
ZWJ: Final = 0x200D
ZWNBSP: Final = 0xFEFF
# ZW code points that are flagged wherever they occur (no precision exemption applies to them).
ZW_PLAIN: Final[Ranges] = ((0x00AD, 0x00AD), (0x180E, 0x180E), (0x200B, 0x200B), (0x2060, 0x2064))

# BIDI. Embedding/override initiators are closed by PDF; isolate initiators by PDI.
BIDI_NAMES: Final[Mapping[int, str]] = {
    0x061C: "ALM",
    0x200E: "LRM",
    0x200F: "RLM",
    0x202A: "LRE",
    0x202B: "RLE",
    0x202C: "PDF",
    0x202D: "LRO",
    0x202E: "RLO",
    0x2066: "LRI",
    0x2067: "RLI",
    0x2068: "FSI",
    0x2069: "PDI",
}
BIDI_RANGES: Final[Ranges] = (
    (0x061C, 0x061C), (0x200E, 0x200F), (0x202A, 0x202E), (0x2066, 0x2069),
)
BIDI_EMBEDDING_OPENERS: Final = "\U0000202A\U0000202B\U0000202D\U0000202E"
BIDI_ISOLATE_OPENERS: Final = "\U00002066\U00002067\U00002068"
BIDI_PDF: Final = "\U0000202C"
BIDI_PDI: Final = "\U00002069"

# TAG. Only U+E0020-E007E decode to printable ASCII (`chr(cp - 0xE0000)`).
TAG_RANGE: Final = (0xE0000, 0xE007F)
TAG_PRINTABLE: Final = (0xE0020, 0xE007E)

# VS. VS1-VS16 then VS17-VS256; the selector number n is also the decoded byte + 1.
VS_BMP: Final = (0xFE00, 0xFE0F)
VS_SUPPLEMENT: Final = (0xE0100, 0xE01EF)
VS_RANGES: Final[Ranges] = (VS_BMP, VS_SUPPLEMENT)
VS16: Final = 0xFE0F                                  # emoji presentation selector
VS_TEXT_SINGLES: Final = (0xFE00, 0xFE0E)             # exempt when they occur alone

# PUA: the BMP area and planes 15-16 (their last two code points are noncharacters).
PUA_RANGES: Final[Ranges] = ((0xE000, 0xF8FF), (0xF0000, 0xFFFFD), (0x100000, 0x10FFFD))

# CTRL: C0 minus TAB, LF, FF, CR; DEL; C1.
CTRL_RANGES: Final[Ranges] = ((0x00, 0x08), (0x0B, 0x0B), (0x0E, 0x1F), (0x7F, 0x9F))

# Context used by the precision exemptions.
ARABIC_RANGE: Final = (0x0600, 0x06FF)
INDIC_RANGE: Final = (0x0900, 0x0DFF)
EMOJI_MODIFIERS: Final = (0x1F3FB, 0x1F3FF)           # skin tones may sit between an emoji and a ZWJ
KEYCAP_BASES: Final = "0123456789#*"
COMBINING_ENCLOSING_KEYCAP: Final = 0x20E3

# Extended_Pictographic (UTS #51 emoji-data.txt, Unicode 13-15.1: 3537 code points, including the blocks
# reserved for future emoji). A superset of newer releases, which only matters for the ZWJ/VS16
# exemptions, where "treat as emoji" is the precise choice.
EXTENDED_PICTOGRAPHIC: Final[Ranges] = (
    (0x00A9, 0x00A9), (0x00AE, 0x00AE), (0x203C, 0x203C), (0x2049, 0x2049), (0x2122, 0x2122),
    (0x2139, 0x2139), (0x2194, 0x2199), (0x21A9, 0x21AA), (0x231A, 0x231B), (0x2328, 0x2328),
    (0x2388, 0x2388), (0x23CF, 0x23CF), (0x23E9, 0x23F3), (0x23F8, 0x23FA), (0x24C2, 0x24C2),
    (0x25AA, 0x25AB), (0x25B6, 0x25B6), (0x25C0, 0x25C0), (0x25FB, 0x25FE), (0x2600, 0x2605),
    (0x2607, 0x2612), (0x2614, 0x2685), (0x2690, 0x2705), (0x2708, 0x2712), (0x2714, 0x2714),
    (0x2716, 0x2716), (0x271D, 0x271D), (0x2721, 0x2721), (0x2728, 0x2728), (0x2733, 0x2734),
    (0x2744, 0x2744), (0x2747, 0x2747), (0x274C, 0x274C), (0x274E, 0x274E), (0x2753, 0x2755),
    (0x2757, 0x2757), (0x2763, 0x2767), (0x2795, 0x2797), (0x27A1, 0x27A1), (0x27B0, 0x27B0),
    (0x27BF, 0x27BF), (0x2934, 0x2935), (0x2B05, 0x2B07), (0x2B1B, 0x2B1C), (0x2B50, 0x2B50),
    (0x2B55, 0x2B55), (0x3030, 0x3030), (0x303D, 0x303D), (0x3297, 0x3297), (0x3299, 0x3299),
    (0x1F000, 0x1F0FF), (0x1F10D, 0x1F10F), (0x1F12F, 0x1F12F), (0x1F16C, 0x1F171),
    (0x1F17E, 0x1F17F), (0x1F18E, 0x1F18E), (0x1F191, 0x1F19A), (0x1F1AD, 0x1F1E5),
    (0x1F201, 0x1F20F), (0x1F21A, 0x1F21A), (0x1F22F, 0x1F22F), (0x1F232, 0x1F23A),
    (0x1F23C, 0x1F23F), (0x1F249, 0x1F3FA), (0x1F400, 0x1F53D), (0x1F546, 0x1F64F),
    (0x1F680, 0x1F6FF), (0x1F774, 0x1F77F), (0x1F7D5, 0x1F7FF), (0x1F80C, 0x1F80F),
    (0x1F848, 0x1F84F), (0x1F85A, 0x1F85F), (0x1F888, 0x1F88F), (0x1F8AE, 0x1F8FF),
    (0x1F90C, 0x1F93A), (0x1F93C, 0x1F945), (0x1F947, 0x1FAFF), (0x1FC00, 0x1FFFD),
)

# HOMOGLYPH: Cyrillic and Greek letters that render like an ASCII letter in common fonts (a curated
# subset of the Unicode confusables data). Greek iota and gamma are left out: they read as symbols.
_CONFUSABLE_CODEPOINTS: Final[Mapping[int, str]] = {
    # Cyrillic lowercase
    0x0430: "a", 0x0435: "e", 0x043E: "o", 0x0440: "p", 0x0441: "c", 0x0443: "y",
    0x0445: "x", 0x0455: "s", 0x0456: "i", 0x0458: "j", 0x04BB: "h", 0x04CF: "l",
    0x0501: "d", 0x051B: "q", 0x051D: "w",
    # Cyrillic uppercase
    0x0405: "S", 0x0406: "I", 0x0408: "J", 0x0410: "A", 0x0412: "B", 0x0415: "E",
    0x041A: "K", 0x041C: "M", 0x041D: "H", 0x041E: "O", 0x0420: "P", 0x0421: "C",
    0x0422: "T", 0x0425: "X", 0x04AE: "Y", 0x04C0: "I", 0x051A: "Q", 0x051C: "W",
    # Greek lowercase
    0x03B1: "a", 0x03BD: "v", 0x03BF: "o", 0x03C1: "p",
    # Greek uppercase
    0x0391: "A", 0x0392: "B", 0x0395: "E", 0x0396: "Z", 0x0397: "H", 0x0399: "I",
    0x039A: "K", 0x039C: "M", 0x039D: "N", 0x039F: "O", 0x03A1: "P", 0x03A4: "T",
    0x03A5: "Y", 0x03A7: "X",
}
CONFUSABLES: Final[Mapping[str, str]] = {chr(cp): a for cp, a in _CONFUSABLE_CODEPOINTS.items()}

# --------------------------------------------------------------------------- helpers


def _starts(ranges: Ranges) -> tuple[int, ...]:
    return tuple(a for a, _ in ranges)


_EP_STARTS: Final = _starts(EXTENDED_PICTOGRAPHIC)


def in_ranges(cp: int, ranges: Ranges, starts: tuple[int, ...] | None = None) -> bool:
    """Whether `cp` falls inside one of the sorted, inclusive `ranges`."""
    i = bisect_right(starts if starts is not None else _starts(ranges), cp) - 1
    return i >= 0 and cp <= ranges[i][1]


def is_extended_pictographic(cp: int) -> bool:
    return in_ranges(cp, EXTENDED_PICTOGRAPHIC, _EP_STARTS)


def is_vs(cp: int) -> bool:
    return VS_BMP[0] <= cp <= VS_BMP[1] or VS_SUPPLEMENT[0] <= cp <= VS_SUPPLEMENT[1]


def vs_number(cp: int) -> int:
    """Variation selector number: U+FE00 is VS1, U+FE0F VS16, U+E0100 VS17, U+E01EF VS256."""
    if VS_BMP[0] <= cp <= VS_BMP[1]:
        return cp - VS_BMP[0] + 1
    if VS_SUPPLEMENT[0] <= cp <= VS_SUPPLEMENT[1]:
        return cp - VS_SUPPLEMENT[0] + 17
    raise ValueError(f"U+{cp:04X} is not a variation selector")


def vs_byte(cp: int) -> int:
    """Byte smuggled by one selector (FE00-FE0F -> 0-15, E0100-E01EF -> 16-255)."""
    return vs_number(cp) - 1


def codepoints(ranges: Iterable[tuple[int, int]]) -> Iterable[int]:
    for a, b in ranges:
        yield from range(a, b + 1)


def marker(cp: int) -> str | None:
    """Reveal marker for one hidden code point, or None when `cp` is in no hidden class.

    TAG characters are revealed per run (`[TAG:"…"]`) and homoglyphs per word, so neither is handled here.
    """
    name = ZW_MARKERS.get(cp)
    if name is not None:
        return f"[{name}]"
    name = BIDI_NAMES.get(cp)
    if name is not None:
        return f"[BIDI:{name}]"
    if is_vs(cp):
        return f"[VS:{vs_number(cp)}]"
    if in_ranges(cp, CTRL_RANGES):
        return f"[CTRL:U+{cp:04X}]"
    if in_ranges(cp, PUA_RANGES):
        return f"[PUA:U+{cp:04X}]"
    return None


def confusable_marker(ch: str) -> str:
    """`[U+0430→a]` for a confusable letter."""
    return f"[U+{ord(ch):04X}\N{RIGHTWARDS ARROW}{CONFUSABLES[ch]}]"
