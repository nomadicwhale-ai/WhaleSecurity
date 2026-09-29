"""Tests for whalescan.matchers.multiline (spec §8.3)."""

from __future__ import annotations

import re
import time
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from whalescan.errors import RuleError
from whalescan.matchers.base import REGISTRY, evaluate
from whalescan.matchers.multiline import MAX_SEQUENCE_MATCHES, match_multiline
from whalescan.matchers.regex import CAPPED_KEY
from whalescan.model import AppliesTo, Confidence, FileCtx, Hit, Rule, Severity


def make_rule(match: Any = None, *, max_hits: int = 50) -> Rule:
    return Rule(
        id="WS-AIR-TST-001",
        title="test rule title",
        pack="domain/airflow",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        owner="@whalesecurity/test",
        applies_to=AppliesTo(),
        match=match if match is not None else {"multiline": {"pattern": "x"}},
        message="test message here",
        references=("https://example.com/ref",),
        max_hits_per_file=max_hits,
    )


def run(spec: Any, text: str, **rule_kw: Any) -> tuple[list[Hit], FileCtx]:
    ctx = FileCtx(path="f.txt", text=text)
    return match_multiline(spec, ctx, make_rule({"multiline": spec}, **rule_kw)), ctx


def spans(hits: list[Hit]) -> list[tuple[int, int]]:
    return [(h.start, h.end) for h in hits]


PRIVATE_KEY = "-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[A-Za-z0-9+/=\\s]{64,8192}-----END"
KEY_BODY = "\n".join(["MIIEowIBAAKCAQEA7nq3Zr9m1kQ2vX8w0cT4yJ5uHh6LdPq9sR2tF3gB4nV5c6x7"] * 5)
PEM = f"-----BEGIN RSA PRIVATE KEY-----\n{KEY_BODY}\n-----END RSA PRIVATE KEY-----\n"

AIRFLOW = {
    "sequence": [r"\bBashOperator\(", r"""bash_command\s*=\s*f?["']""", r"\{\{\s*(?:dag_run\.conf|params)\b"],
    "within_lines": 12,
}


def test_registered_under_multiline() -> None:
    assert REGISTRY["multiline"] is match_multiline


# --------------------------------------------------------------------------- pattern form


def test_private_key_spans_lines() -> None:
    text = "key = '''\n" + PEM + "'''\n"
    (h,) = run({"pattern": PRIVATE_KEY}, text)[0]
    assert (h.line, h.col) == (2, 1)
    assert h.end_line == 8 and text[h.start : h.end].endswith("c6x7\n-----END")
    assert h.secret_spans == []  # no secret_group: redaction uses the whole match for secrets rules


def test_max_span_lines_drops_long_hits() -> None:
    text = "BEGIN\n" + "x\n" * 40 + "END\n"
    spec = {"pattern": r"BEGIN[\s\S]{0,4096}?END"}
    assert run(spec, text)[0] == []  # 42 lines > default 30
    assert len(run({**spec, "max_span_lines": 42}, text)[0]) == 1
    assert run({**spec, "max_span_lines": 41}, text)[0] == []


def test_max_span_counts_first_to_last_character() -> None:
    # A match ending with "\n" still ends on its last line: A\nB\n spans 2 lines.
    assert len(run({"pattern": r"A\nB\n", "max_span_lines": 2}, "A\nB\n")[0]) == 1
    assert run({"pattern": r"A\nB\nC", "max_span_lines": 2}, "A\nB\nC")[0] == []


def test_flag_s_lets_dot_cross_lines() -> None:
    text = "on:\n  pull_request_target:\njobs: x"
    assert run({"pattern": r"on:.{0,40}pull_request_target"}, text)[0] == []
    (h,) = run({"pattern": r"on:.{0,40}pull_request_target", "flags": ["s"]}, text)[0]
    assert (h.line, h.end_line) == (1, 2)


def test_multiline_anchor_semantics() -> None:
    text = "jobs:\n  build:\n    runs-on: x\non:\n  push:\n"
    (h,) = run({"pattern": r"^on:\n[ \t]{2}push:"}, text)[0]
    assert h.line == 4


def test_pattern_secret_group() -> None:
    text = "password:\n  hunter22\n"
    (h,) = run({"pattern": r"password:\n[ \t]+(?P<secret>\S+)", "secret_group": "secret"}, text)[0]
    assert h.secret_spans == [(text.index("hunter22"), text.index("hunter22") + 8)]
    assert h.captures == {"secret": "hunter22"}


def test_pattern_reports_all_hits_and_skips_zero_width() -> None:
    hits, _ = run({"pattern": r"a\nb|(?=zzz)"}, "a\nb a\nb zzz")
    assert spans(hits) == [(0, 3), (4, 7)]


@pytest.mark.parametrize(
    "bad",
    [
        None,
        "pattern",
        {},
        {"pattern": ""},
        {"pattern": "a", "flags": ["q"]},
        {"pattern": "a", "max_span_lines": 0},
        {"pattern": "a", "max_span_lines": True},
        {"pattern": "a", "secret_group": "nope"},
        {"pattern": "a", "secret_group": 1},
        {"sequence": ["a"], "within_lines": 3},
        {"sequence": "ab", "within_lines": 3},
        {"sequence": ["a", "b", "c", "d", "e", "f"], "within_lines": 3},
        {"sequence": ["a", ""], "within_lines": 3},
        {"sequence": ["a", "b"]},
        {"sequence": ["a", "b"], "within_lines": -1},
        {"sequence": ["a", "b"], "within_lines": 2, "flags": ["s"]},
        {"sequence": ["a", "(b"], "within_lines": 2},
    ],
)
def test_invalid_specs_raise_rule_error(bad: Any) -> None:
    with pytest.raises(RuleError):
        match_multiline(bad, FileCtx(path="f", text="a\nb"), make_rule())


# --------------------------------------------------------------------------- sequence form


def test_airflow_template_injection_example() -> None:
    text = (
        "from airflow.operators.bash import BashOperator\n"
        "\n"
        "run = BashOperator(\n"
        "    task_id='run',\n"
        "    bash_command=f'echo {{ dag_run.conf[\"cmd\"] }}',\n"
        ")\n"
    )
    (h,) = run(AIRFLOW, text)[0]
    assert (h.line, h.col) == (3, 7)
    assert h.end_line == 5
    assert text[h.start : h.end].startswith("BashOperator(")
    assert text[h.start : h.end].endswith("{{ dag_run.conf")
    assert h.props == {"sequence_lines": [3, 5, 5]}


def test_airflow_negative_constant_command() -> None:
    text = "run = BashOperator(\n    task_id='run',\n    bash_command='echo hello',\n)\n"
    assert run(AIRFLOW, text)[0] == []


def test_elements_must_appear_in_order() -> None:
    text = "C\nB\nA\n"
    assert run({"sequence": ["A", "B", "C"], "within_lines": 5}, text)[0] == []
    assert len(run({"sequence": ["C", "B", "A"], "within_lines": 5}, text)[0]) == 1


def test_later_element_must_start_after_previous_end() -> None:
    # "ab" overlaps the first element "abc"; the chain needs a separate later occurrence.
    assert run({"sequence": ["abc", "bc"], "within_lines": 3}, "abc")[0] == []
    assert spans(run({"sequence": ["abc", "bc"], "within_lines": 3}, "abcbc")[0]) == [(0, 5)]


def test_within_lines_boundary() -> None:
    text = "A\n" + "x\n" * 11 + "B\n"  # B is 12 lines after A
    assert len(run({"sequence": ["A", "B"], "within_lines": 12}, text)[0]) == 1
    assert run({"sequence": ["A", "B"], "within_lines": 11}, text)[0] == []


def test_within_lines_zero_means_same_line() -> None:
    assert len(run({"sequence": ["A", "B"], "within_lines": 0}, "A B\n")[0]) == 1
    assert run({"sequence": ["A", "B"], "within_lines": 0}, "A\nB\n")[0] == []


def test_limit_is_measured_from_the_first_element() -> None:
    text = "A\nB\n" + "x\n" * 4 + "C\n"  # C is 6 lines after A, 5 after B
    assert run({"sequence": ["A", "B", "C"], "within_lines": 5}, text)[0] == []
    assert len(run({"sequence": ["A", "B", "C"], "within_lines": 6}, text)[0]) == 1


def test_every_first_element_starts_its_own_chain() -> None:
    text = "A\nA\nB\n" + "x\n" * 10 + "A\nB\n"
    hits, _ = run({"sequence": ["A", "B"], "within_lines": 2}, text)
    assert [(h.line, h.end_line) for h in hits] == [(1, 3), (2, 3), (14, 15)]


def test_flags_apply_to_every_element() -> None:
    text = "bashoperator(\nBASH_COMMAND = 'x'\n"
    spec = {"sequence": [r"bashoperator\(", r"bash_command\s*="], "within_lines": 3}
    assert run(spec, text)[0] == []
    assert len(run({**spec, "flags": ["i"]}, text)[0]) == 1


def test_sequence_captures_merge_first_wins() -> None:
    spec = {"sequence": [r"(?P<op>\w+Operator)\(", r"(?P<arg>\w+)=(?P<op>\w+)"], "within_lines": 2}
    (h,) = run(spec, "BashOperator(\n cmd=x\n")[0]
    assert h.captures == {"op": "BashOperator", "arg": "cmd"}


def test_sequence_skips_zero_width_elements() -> None:
    assert run({"sequence": ["A", "(?=B)"], "within_lines": 2}, "A\nB")[0] == []


def test_sequence_early_exit_keeps_earlier_hits() -> None:
    # After the last B there is no B for later A's: those chains stop, earlier hits stay.
    text = "A\nB\nA\nA\n"
    assert [h.line for h in run({"sequence": ["A", "B"], "within_lines": 5}, text)[0]] == [1]


def test_sequence_cap() -> None:
    text = "A B\n" * 70
    hits, ctx = run({"sequence": ["A", "B"], "within_lines": 0}, text, max_hits=50)
    assert len(hits) == 50
    assert ctx.cache[CAPPED_KEY] == {"WS-AIR-TST-001": 20}


def test_sequence_index_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    import whalescan.matchers.multiline as ml

    monkeypatch.setattr(ml, "MAX_SEQUENCE_MATCHES", 3)
    text = "A " + "B " * 10 + "\n" + "A B\n"
    hits, _ = run({"sequence": ["A", "B"], "within_lines": 5}, text)
    assert [h.line for h in hits] == [1]  # the index holds 3 Bs, all on line 1
    assert MAX_SEQUENCE_MATCHES >= 100_000


def test_sequence_is_linear_on_hostile_input() -> None:
    text = ("A " * 50_000 + "\n") * 4 + "B"
    start = time.perf_counter()
    hits, _ = run({"sequence": ["A", "B"], "within_lines": 0}, text, max_hits=1000)
    assert hits == []
    assert time.perf_counter() - start < 2.0


def test_multiline_through_evaluate() -> None:
    ctx = FileCtx(path="dags/x.py", text="BashOperator(\n bash_command='{{ params.x }}')\n")
    hits = evaluate({"multiline": AIRFLOW}, ctx, make_rule())
    assert len(hits) == 1


# --------------------------------------------------------------------------- properties


def reference_sequence(text: str, patterns: list[str], within: int) -> list[tuple[int, int]]:
    """The spec's pseudo-code, transcribed literally (linear scans instead of bisect)."""
    ctx = FileCtx(path="ref", text=text)
    lists = [[m for m in re.finditer(p, text, re.MULTILINE) if m.end() > m.start()] for p in patterns]
    out = []
    for h0 in lists[0]:
        prev, limit = h0, ctx.line_of(h0.start()) + within
        for later in lists[1:]:
            nxt = next((m for m in later if m.start() >= prev.end()), None)
            if nxt is None or ctx.line_of(nxt.start()) > limit:
                break
            prev = nxt
        else:
            out.append((h0.start(), prev.end()))
    return out


@settings(max_examples=400, deadline=None)
@given(
    text=st.text(alphabet="abc\n ", max_size=120),
    patterns=st.lists(st.sampled_from(["a", "b", "c", "ab", "b+", "c\n?a", "^a", "b$"]), min_size=2, max_size=4),
    within=st.integers(min_value=0, max_value=6),
)
def test_sequence_matches_spec_reference(text: str, patterns: list[str], within: int) -> None:
    hits, _ = run({"sequence": patterns, "within_lines": within}, text, max_hits=1000)
    assert spans(hits) == reference_sequence(text, patterns, within)


@settings(max_examples=200, deadline=None)
@given(text=st.text(alphabet="ab\n", max_size=80), max_span=st.integers(min_value=1, max_value=5))
def test_pattern_form_respects_max_span(text: str, max_span: int) -> None:
    pattern = r"a[ab\n]{0,20}?b"
    hits, ctx = run({"pattern": pattern, "max_span_lines": max_span}, text, max_hits=1000)
    expected = [
        m.span()
        for m in re.finditer(pattern, text, re.MULTILINE)
        if ctx.line_of(m.end() - 1) - ctx.line_of(m.start()) + 1 <= max_span
    ]
    assert spans(hits) == expected
    assert all(h.end_line - h.line + 1 <= max_span for h in hits)
