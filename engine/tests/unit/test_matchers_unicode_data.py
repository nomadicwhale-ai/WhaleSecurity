"""Tests for whalescan.matchers.unicode_data (spec §8.4 tables)."""

from __future__ import annotations

import unicodedata

import pytest

from whalescan.matchers import unicode_data as ud


def _check_sorted_disjoint(ranges: ud.Ranges) -> None:
    prev = -1
    for a, b in ranges:
        assert a <= b
        assert a > prev
        prev = b


@pytest.mark.parametrize(
    "ranges",
    [ud.EXTENDED_PICTOGRAPHIC, ud.PUA_RANGES, ud.CTRL_RANGES, ud.BIDI_RANGES, ud.ZW_PLAIN, ud.VS_RANGES],
)
def test_ranges_are_sorted_and_disjoint(ranges: ud.Ranges) -> None:
    _check_sorted_disjoint(ranges)


def test_extended_pictographic_is_the_emoji_data_set() -> None:
    assert sum(b - a + 1 for a, b in ud.EXTENDED_PICTOGRAPHIC) == 3537  # emoji-data.txt, Unicode 13-15.1


@pytest.mark.parametrize(
    ("cp", "expected"),
    [
        (0x00A9, True),     # copyright
        (0x2764, True),     # heavy black heart
        (0x1F600, True),    # grinning face
        (0x1F468, True),    # man
        (0x1F9B0, True),    # emoji component red hair
        (0x2B1B, True),     # black large square (black cat sequence)
        (0x1FFFD, True),    # reserved for future emoji
        (0x1F3FB, False),   # skin tone modifiers are not pictographs
        (0x1F1E6, False),   # regional indicator A
        (0x0023, False),    # keycap base '#'
        (0x0041, False),
        (0x200D, False),
    ],
)
def test_is_extended_pictographic(cp: int, expected: bool) -> None:
    assert ud.is_extended_pictographic(cp) is expected


def test_in_ranges_edges() -> None:
    ranges = ((10, 20), (30, 30))
    assert [x for x in range(0, 40) if ud.in_ranges(x, ranges)] == [*range(10, 21), 30]


def test_confusables_are_cyrillic_or_greek_letters_mapping_to_ascii() -> None:
    assert 45 <= len(ud.CONFUSABLES) <= 60
    for ch, ascii_ in ud.CONFUSABLES.items():
        name = unicodedata.name(ch)
        assert name.startswith(("CYRILLIC", "GREEK")), name
        assert unicodedata.category(ch) in ("Ll", "Lu"), name
        assert len(ascii_) == 1 and ascii_.isascii() and ascii_.isalpha()
        # Case agrees: a lowercase look-alike maps to a lowercase ASCII letter.
        assert ch.islower() == ascii_.islower(), name


@pytest.mark.parametrize("cp", [0x0430, 0x0435, 0x043E, 0x0440, 0x0441, 0x0445, 0x0456, 0x03BF, 0x0391])
def test_spec_listed_confusables_present(cp: int) -> None:
    assert chr(cp) in ud.CONFUSABLES


def test_confusable_marker() -> None:
    assert ud.confusable_marker("\N{CYRILLIC SMALL LETTER A}") == "[U+0430\N{RIGHTWARDS ARROW}a]"
    assert ud.confusable_marker("\N{GREEK CAPITAL LETTER ALPHA}") == "[U+0391\N{RIGHTWARDS ARROW}A]"


@pytest.mark.parametrize(
    ("cp", "number", "byte"),
    [(0xFE00, 1, 0), (0xFE0F, 16, 15), (0xE0100, 17, 16), (0xE01EF, 256, 255)],
)
def test_variation_selector_numbering(cp: int, number: int, byte: int) -> None:
    assert ud.is_vs(cp)
    assert ud.vs_number(cp) == number
    assert ud.vs_byte(cp) == byte


@pytest.mark.parametrize("cp", [0xFDFF, 0xFE10, 0xE00FF, 0xE01F0, 0x41])
def test_vs_number_rejects_other_code_points(cp: int) -> None:
    assert not ud.is_vs(cp)
    with pytest.raises(ValueError, match="not a variation selector"):
        ud.vs_number(cp)


@pytest.mark.parametrize(
    ("cp", "expected"),
    [
        (0x200B, "[ZWSP]"),
        (0x200C, "[ZWNJ]"),
        (0x200D, "[ZWJ]"),
        (0x2060, "[WJ]"),
        (0xFEFF, "[ZWNBSP]"),
        (0x00AD, "[SHY]"),
        (0x2061, "[U+2061]"),
        (0x2064, "[U+2064]"),
        (0x180E, "[U+180E]"),
        (0x202E, "[BIDI:RLO]"),
        (0x202A, "[BIDI:LRE]"),
        (0x202B, "[BIDI:RLE]"),
        (0x202C, "[BIDI:PDF]"),
        (0x202D, "[BIDI:LRO]"),
        (0x2066, "[BIDI:LRI]"),
        (0x2067, "[BIDI:RLI]"),
        (0x2068, "[BIDI:FSI]"),
        (0x2069, "[BIDI:PDI]"),
        (0x200E, "[BIDI:LRM]"),
        (0x200F, "[BIDI:RLM]"),
        (0x061C, "[BIDI:ALM]"),
        (0xFE00, "[VS:1]"),
        (0xE01EF, "[VS:256]"),
        (0x1B, "[CTRL:U+001B]"),
        (0x00, "[CTRL:U+0000]"),
        (0x7F, "[CTRL:U+007F]"),
        (0x85, "[CTRL:U+0085]"),
        (0xE123, "[PUA:U+E123]"),
        (0xF0000, "[PUA:U+F0000]"),
        (0x10FFFD, "[PUA:U+10FFFD]"),
    ],
)
def test_marker(cp: int, expected: str) -> None:
    assert ud.marker(cp) == expected


@pytest.mark.parametrize("cp", [0x41, 0x09, 0x0A, 0x0C, 0x0D, 0x20, 0xE0041, 0x10FFFE, 0x1F600])
def test_marker_none_outside_classes(cp: int) -> None:
    assert ud.marker(cp) is None  # TAG is revealed per run, not per code point


def test_ctrl_class_excludes_tab_lf_ff_cr() -> None:
    ctrl = set(ud.codepoints(ud.CTRL_RANGES))
    assert not {0x09, 0x0A, 0x0C, 0x0D} & ctrl
    assert {0x00, 0x08, 0x0B, 0x0E, 0x1B, 0x1F, 0x7F, 0x80, 0x9F} <= ctrl
    assert len(ctrl) == 9 + 1 + 18 + 33


def test_bidi_tables_agree() -> None:
    names = ud.BIDI_NAMES
    assert set(names) == set(ud.codepoints(ud.BIDI_RANGES))
    openers = ud.BIDI_EMBEDDING_OPENERS + ud.BIDI_ISOLATE_OPENERS
    assert sorted(names[ord(c)] for c in openers) == ["FSI", "LRE", "LRI", "LRO", "RLE", "RLI", "RLO"]
    assert names[ord(ud.BIDI_PDF)] == "PDF"
    assert names[ord(ud.BIDI_PDI)] == "PDI"


def test_zw_plain_is_zw_minus_context_dependent_points() -> None:
    plain = set(ud.codepoints(ud.ZW_PLAIN))
    assert plain | {ud.ZWJ, ud.ZWNJ, ud.ZWNBSP} == set(ud.ZW_MARKERS)
    assert not plain & {ud.ZWJ, ud.ZWNJ, ud.ZWNBSP}


def test_every_class_member_is_invisible_or_control() -> None:
    for cp in [*ud.ZW_MARKERS, *ud.BIDI_NAMES, *ud.codepoints(ud.VS_RANGES), *ud.codepoints([ud.TAG_RANGE])]:
        assert unicodedata.category(chr(cp)) in ("Cf", "Mn", "Cn"), hex(cp)
