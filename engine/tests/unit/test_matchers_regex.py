"""Tests for whalescan.matchers.regex (spec §8.1, §8.2) and the helpers the text matchers share."""

from __future__ import annotations

import re
import time
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from whalescan.errors import RuleError
from whalescan.matchers import regex as rx_mod
from whalescan.matchers.base import REGISTRY, evaluate, leaf
from whalescan.matchers.regex import (
    CAPPED_KEY,
    OVERFLOW_COUNT_LIMIT,
    collect_capped,
    compile_pattern,
    flag_bits,
    match_regex,
    parse_spec,
    record_capped,
)
from whalescan.model import AppliesTo, Confidence, FileCtx, Hit, Rule, Severity


def make_rule(match: Any = None, *, max_hits: int = 50, rule_id: str = "WS-SEC-TST-001") -> Rule:
    return Rule(
        id=rule_id,
        title="test rule title",
        pack="secrets/test",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        owner="@whalesecurity/test",
        applies_to=AppliesTo(),
        match=match if match is not None else {"regex": "x"},
        message="test message here",
        references=("https://example.com/ref",),
        max_hits_per_file=max_hits,
    )


def run(spec: Any, text: str, **rule_kw: Any) -> tuple[list[Hit], FileCtx]:
    ctx = FileCtx(path="f.txt", text=text)
    return match_regex(spec, ctx, make_rule({"regex": spec}, **rule_kw)), ctx


def spans(hits: list[Hit]) -> list[tuple[int, int]]:
    return [(h.start, h.end) for h in hits]


# --------------------------------------------------------------------------- registry & spec forms


def test_registered_under_regex() -> None:
    assert REGISTRY["regex"] is match_regex
    assert leaf("regex") is match_regex


def test_bare_string_spec() -> None:
    hits, _ = run(r"tok_[0-9]+", "a tok_1 b tok_22")
    assert spans(hits) == [(2, 7), (10, 16)]


def test_mapping_spec_defaults() -> None:
    spec = parse_spec({"pattern": "abc"})
    assert spec.pattern == "abc"
    assert spec.flags == re.MULTILINE
    assert spec.report_group == 0
    assert spec.secret_group is None


@pytest.mark.parametrize(
    "bad",
    [
        None,
        42,
        ["abc"],
        {},
        {"pattern": ""},
        {"pattern": 5},
        {"pattern": "a", "report_group": True},
        {"pattern": "a", "report_group": -1},
        {"pattern": "a", "report_group": 1.5},
        {"pattern": "a", "secret_group": 3},
        {"pattern": "a", "flags": "i"},
        {"pattern": "a", "flags": ["s"]},  # DOTALL is multiline-only (R5)
        {"pattern": "a", "flags": ["m"]},
        {"pattern": "a", "flags": [1]},
    ],
)
def test_invalid_specs_raise_rule_error(bad: Any) -> None:
    with pytest.raises(RuleError):
        match_regex(bad, FileCtx(path="f", text="a"), make_rule())


def test_invalid_pattern_raises_rule_error() -> None:
    with pytest.raises(RuleError, match="invalid regex"):
        run("(unclosed", "text")


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ({"pattern": "(a)", "report_group": 2}, "exceeds"),
        ({"pattern": "(?P<x>a)", "report_group": "y"}, "not a named group"),
        ({"pattern": "(?P<x>a)", "secret_group": "y"}, "not a named group"),
    ],
)
def test_group_references_are_checked(spec: dict[str, Any], message: str) -> None:
    with pytest.raises(RuleError, match=message):
        run(spec, "a")


# --------------------------------------------------------------------------- all hits, positions


def test_reports_every_non_overlapping_hit_not_just_the_first() -> None:
    text = "privileged: true\nx: 1\nprivileged: true\nprivileged: true\n"
    hits, _ = run(r"privileged:\s*true", text)
    assert [h.line for h in hits] == [1, 3, 4]
    assert all(h.col == 1 and h.end_col == 17 for h in hits)


def test_positions_are_one_based_and_end_exclusive() -> None:
    hits, _ = run("needle", "hay\n  needle hay")
    (h,) = hits
    assert (h.start, h.end) == (6, 12)
    assert (h.line, h.col, h.end_line, h.end_col) == (2, 3, 2, 9)


def test_columns_count_code_points_not_utf16_units() -> None:
    # U+1F600 is one code point (two UTF-16 units); columns must count it once.
    hits, _ = run("key", "\U0001F600\U000000E9 key")
    (h,) = hits
    assert (h.col, h.end_col) == (4, 7)


def test_caret_and_dollar_are_line_anchors() -> None:
    hits, _ = run(r"^debug = true$", "a = 1\ndebug = true\nx debug = true\ndebug = true")
    assert [h.line for h in hits] == [2, 4]


def test_dot_never_crosses_a_newline() -> None:
    hits, _ = run(r"BEGIN.{0,20}END", "BEGIN\nEND BEGIN x END")
    assert [(h.line, h.col) for h in hits] == [(2, 5)]


def test_crlf_text_keeps_carriage_returns() -> None:
    # Text is never newline-normalized (§5.5): `$` only sits before `\n`, so `\r` is still in front of it.
    text = "a = 1\r\nb = 2\r\n"
    assert spans(run(r"= \d$", text)[0]) == []
    assert [h.line for h in run(r"= \d\r?$", text)[0]] == [1, 2]


def test_dash_leading_pattern_is_literal_regression() -> None:
    # DESIGN "-- semantics": patterns never pass through argv, so a leading dash is literal.
    text = "key:\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n"
    hits, _ = run("-----BEGIN OPENSSH PRIVATE KEY-----", text)
    assert [(h.line, h.col, h.end_col) for h in hits] == [(2, 1, 36)]


def test_multi_hit_on_one_line() -> None:
    hits, _ = run(r"\bAKIA[0-9A-Z]{4}\b", "AKIA1234 AKIA5678,AKIA9ABC")
    assert [h.col for h in hits] == [1, 10, 19]


def test_hits_across_a_large_file_all_reported() -> None:
    text = "".join(f"line {i} token_{i}\n" if i % 100 == 0 else f"line {i}\n" for i in range(5000))
    hits, _ = run(r"token_\d+", text, max_hits=1000)
    assert [h.line for h in hits] == list(range(1, 5001, 100))


# --------------------------------------------------------------------------- flags


def test_flag_i() -> None:
    assert len(run({"pattern": "secret", "flags": ["i"]}, "SECRET Secret secret")[0]) == 3
    assert len(run({"pattern": "secret"}, "SECRET Secret secret")[0]) == 1


def test_flag_x_verbose() -> None:
    hits, _ = run({"pattern": r"tok \d+   # a comment", "flags": ["x"]}, "tok123")
    assert spans(hits) == [(0, 6)]


def test_flag_a_ascii() -> None:
    text = "\U00000661\U00000662\U00000663 123"  # Arabic-Indic digits, then ASCII digits
    assert spans(run({"pattern": r"\d+"}, text)[0]) == [(0, 3), (4, 7)]
    assert spans(run({"pattern": r"\d+", "flags": ["a"]}, text)[0]) == [(4, 7)]


def test_flag_bits() -> None:
    assert flag_bits(None, "ixa", where="t") == re.MULTILINE
    assert flag_bits(["i", "a"], "ixa", where="t") == re.MULTILINE | re.IGNORECASE | re.ASCII
    assert flag_bits(("s",), "ixas", where="t") & re.DOTALL
    with pytest.raises(RuleError, match="unsupported flag"):
        flag_bits(["s"], "ixa", where="t")


# --------------------------------------------------------------------------- report / secret groups


def test_report_group_by_name_and_number() -> None:
    text = "password=hunter2"
    by_name, _ = run({"pattern": r"(?P<k>password)=(?P<v>\w+)", "report_group": "v"}, text)
    by_num, _ = run({"pattern": r"(password)=(\w+)", "report_group": 2}, text)
    assert spans(by_name) == spans(by_num) == [(9, 16)]
    assert by_name[0].col == 10


def test_empty_or_missing_report_group_is_skipped() -> None:
    spec = {"pattern": r"key=(?P<v>\w*)|token", "report_group": "v"}
    hits, _ = run(spec, "key= key=abc token")
    assert spans(hits) == [(9, 12)]  # empty `v`, and `token` (v did not participate), are skipped


def test_secret_group_becomes_secret_span() -> None:
    spec = {
        "pattern": r"(?P<scheme>postgres)://(?P<user>[^:\s]{1,32}):(?P<secret>[^@\s]{1,64})@",
        "secret_group": "secret",
    }
    text = 'URI = "postgres://etl:s3cr3t@db:5432/x"'
    (h,) = run(spec, text)[0]
    assert h.secret_spans == [(text.index("s3cr3t"), text.index("s3cr3t") + 6)]
    assert h.captures == {"scheme": "postgres", "user": "etl", "secret": "s3cr3t"}


def test_secret_group_empty_or_absent_gives_no_span() -> None:
    spec = {"pattern": r"pw=(?P<secret>\w*)(?P<tail>;)?", "secret_group": "secret"}
    hits, _ = run(spec, "pw=; pw=x")
    assert [h.secret_spans for h in hits] == [[], [(8, 9)]]


def test_captures_map_non_participating_groups_to_empty_string() -> None:
    (h,) = run(r"(?P<a>x)|(?P<b>y)", "y")[0]
    assert h.captures == {"a": "", "b": "y"}


# --------------------------------------------------------------------------- max_hits_per_file


def test_cap_truncates_and_counts_exact_overflow() -> None:
    hits, ctx = run("x", "x" * 60, max_hits=50)
    assert len(hits) == 50
    assert ctx.cache[CAPPED_KEY] == {"WS-SEC-TST-001": 10}


def test_no_capped_entry_when_under_the_cap() -> None:
    _, ctx = run("x", "x" * 50, max_hits=50)
    assert CAPPED_KEY not in ctx.cache


def test_overflow_count_saturates() -> None:
    hits, ctx = run("x", "x" * (OVERFLOW_COUNT_LIMIT + 500), max_hits=1)
    assert len(hits) == 1
    assert ctx.cache[CAPPED_KEY]["WS-SEC-TST-001"] == OVERFLOW_COUNT_LIMIT


def test_capped_counts_accumulate_across_calls_and_rules() -> None:
    ctx = FileCtx(path="f", text="ab" * 5)
    match_regex("a", ctx, make_rule(max_hits=2))
    match_regex("b", ctx, make_rule(max_hits=4))
    match_regex("a", ctx, make_rule(max_hits=1, rule_id="WS-SEC-TST-002"))
    assert ctx.cache[CAPPED_KEY] == {"WS-SEC-TST-001": 3 + 1, "WS-SEC-TST-002": 4}


def test_record_capped_replaces_a_foreign_value() -> None:
    ctx = FileCtx(path="f", text="")
    ctx.cache[CAPPED_KEY] = "garbage"
    record_capped(ctx, "R", 2)
    record_capped(ctx, "R", 0)
    assert ctx.cache[CAPPED_KEY] == {"R": 2}


def test_collect_capped_with_zero_limit() -> None:
    ctx = FileCtx(path="f", text="abc")
    hits = collect_capped(range(3), ctx, make_rule(max_hits=0), lambda i: Hit.at(ctx, i, i + 1))
    assert hits == []
    assert ctx.cache[CAPPED_KEY] == {"WS-SEC-TST-001": 3}


def test_capped_scan_stays_fast_on_a_hostile_file() -> None:
    text = "a" * 1_000_000
    start = time.perf_counter()
    hits, ctx = run("a", text, max_hits=50)
    assert len(hits) == 50 and ctx.cache[CAPPED_KEY]["WS-SEC-TST-001"] == OVERFLOW_COUNT_LIMIT
    assert time.perf_counter() - start < 1.0


# --------------------------------------------------------------------------- compile cache


def test_compile_cache_reuses_patterns() -> None:
    a = compile_pattern("abc+", re.MULTILINE)
    assert compile_pattern("abc+", re.MULTILINE) is a
    assert compile_pattern("abc+", re.MULTILINE | re.IGNORECASE) is not a
    assert ("abc+", re.MULTILINE) in rx_mod._CACHE


def test_compile_cache_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rx_mod, "_CACHE", {})
    monkeypatch.setattr(rx_mod, "_CACHE_MAX", 3)
    for i in range(10):
        compile_pattern(f"p{i}", 0)
        assert len(rx_mod._CACHE) <= 3


def test_compile_pattern_rejects_empty_and_non_strings() -> None:
    with pytest.raises(RuleError):
        compile_pattern("", 0)
    with pytest.raises(RuleError):
        compile_pattern(b"abc", 0)  # type: ignore[arg-type]


def test_compile_pattern_silences_future_warnings() -> None:
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        compile_pattern("[[a]", 0)  # "Possible nested set" would be a FutureWarning


# --------------------------------------------------------------------------- combinators (§8.1)


def test_any_and_all_with_near_lines() -> None:
    text = "subprocess.run(cmd, shell=True)\n\n\nshell=True\n"
    rule = make_rule()
    ctx = FileCtx(path="f.py", text=text)
    any_hits = evaluate({"any": [{"regex": r"subprocess\.run"}, {"regex": r"shell=True"}]}, ctx, rule)
    assert len(any_hits) == 3
    near = {"all": [{"regex": r"shell=True"}, {"regex": r"subprocess"}], "near_lines": 0}
    assert [h.line for h in evaluate(near, ctx, rule)] == [1]
    negated = {"all": [{"regex": r"shell=True"}, {"not": {"regex": r"nosec"}}]}
    assert len(evaluate(negated, ctx, rule)) == 2


# --------------------------------------------------------------------------- properties


_TEXT = st.text(alphabet="ab\n\U000000E9\U0001F600x", max_size=200)


@settings(max_examples=300, deadline=None)
@given(text=_TEXT, pattern=st.sampled_from(["a", "ab", "a+", r"b\n?a", "x|\U0001F600", "^a", "b$"]))
def test_hits_are_exactly_the_non_empty_finditer_spans(text: str, pattern: str) -> None:
    hits, ctx = run(pattern, text, max_hits=1000)
    expected = [m.span() for m in re.finditer(pattern, text, re.MULTILINE) if m.end() > m.start()]
    assert spans(hits) == expected
    for h in hits:
        assert (h.line, h.col) == ctx.pos(h.start)
        assert (h.end_line, h.end_col) == ctx.end_pos(h.end)
        assert ctx.line_text(h.line)[h.col - 1] == text[h.start]


@settings(max_examples=200, deadline=None)
@given(n=st.integers(min_value=0, max_value=200), cap=st.integers(min_value=0, max_value=60))
def test_cap_invariant(n: int, cap: int) -> None:
    hits, ctx = run("q", "q" * n, max_hits=cap)
    assert len(hits) == min(n, cap)
    assert ctx.cache.get(CAPPED_KEY, {}).get("WS-SEC-TST-001", 0) == max(0, n - cap)
