"""Tests for whalescan.rules.lint: regex safety lint R1-R7 (spec §8.2)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from whalescan.rules import lint as L

SRC = os.path.join(os.path.dirname(__file__), "..", "..", "src")


def codes(pattern: str, flags: tuple[str, ...] = (), context: L.Context = "regex") -> set[str]:
    return {i.code for i in L.lint_pattern(pattern, flags, context=context)}


def errors(pattern: str, flags: tuple[str, ...] = (), context: L.Context = "regex") -> set[str]:
    return {i.code for i in L.lint_pattern(pattern, flags, context=context) if i.level == "error"}


# ------------------------------------------------------------------------------------------ clean patterns

CLEAN = [
    # §7.1 secrets example and its filter
    r"(?P<scheme>postgres(?:ql)?|mysql|mariadb|singlestore|memsql|mongodb(?:\+srv)?|rediss?|amqps?)://"
    r"(?P<user>[^:/\s@]{1,128}):(?P<secret>[^@\s/]{1,256})@",
    r"://[^:\s]{1,128}:(?:\$\{[^}]{1,64}\}|\{\{[^}]{1,64}\}\}|<[^>]{1,64}>|\*{3,})@",
    # dash-leading literal (DESIGN "--" semantics regression)
    r"-----BEGIN OPENSSH PRIVATE KEY-----",
    # §8.5 entropy token and placeholder regexes
    r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{16,128}(?![0-9A-Fa-f])",
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,200}={0,2}(?![A-Za-z0-9+/=])",
    r"(?i)^(?:x{6,}|\*{4,}|<[^>]{1,64}>|\$\{[^}]{1,64}\}|\{\{[^}]{1,64}\}\}|(?:your|my|example|sample|dummy|fake|test"
    r"|changeme|placeholder|redacted|replace)[_-]?[a-z0-9_-]{0,40})$",
    r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$",
    # §8.6 / §8.7 examples
    r"^(?:@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$",
    r"github\.event\.pull_request\.head\.(sha|ref)",
    r"(?i)(auth|current_?user|verify|token|jwt|oauth|api_?key|security|permission|require|login|principal|session)",
    r"^/(?:health|healthz|livez|readyz|metrics)$",
    r"\bBashOperator\(",
    r"AKIA[0-9A-Z]{16}",
    r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}",
    r"(?:a|b.)*c",
    r"(?:ab|cd)+",
    r"(?i)(?:a|A)+b",  # the parser folds single-char alternations into a class
    r"(?P<name>a)(?P=name)",
    r"(a)?(?(1)b|c)",
    r"\d+(?:\.\d+)?",
    r"[\t ]*#[^\n]{0,200}",
]


@pytest.mark.parametrize("pattern", CLEAN)
def test_clean_patterns_have_no_issues(pattern: str) -> None:
    assert L.lint_pattern(pattern) == []


def test_multiline_examples_are_clean_in_their_context() -> None:
    pem = r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[A-Za-z0-9+/=\s]{64,8192}-----END"
    assert L.lint_pattern(pem, context="multiline") == []
    for item in (r"\bBashOperator\(", r"bash_command\s*=\s*f?[\"']", r"\{\{\s*(?:dag_run\.conf|params)\b"):
        assert L.lint_pattern(item, context="sequence") == []


# ------------------------------------------------------------------------------------------ table

TABLE: list[tuple[str, set[str]]] = [
    # R1
    (r"(unclosed", {"R1"}),
    (r"\q", {"R1"}),
    (r"[[a]", {"R1"}),  # FutureWarning: possible nested set
    (r"(?P<nämé>a)", {"R1"}),
    ("(" * 80 + "a" + ")" * 80, {"R1"}),
    # R2
    (r"(a+)+", {"R2"}),
    (r"(?:\w+\s?)*", {"R2", "R4"}),
    (r"x(?:[a-z]+,)*y", {"R2"}),
    (r"x(?:a{2,}b)+", {"R2"}),
    (r"x(?:a*?b)+?", {"R2"}),
    # R3
    (r".*foo", {"R3"}),
    (r".+?foo", {"R3"}),
    (r"\s+foo", {"R3"}),
    (r"\S+@x", {"R3"}),
    (r"[^a]+x", {"R3"}),
    (r"[^ab]*x", {"R3"}),
    (r"\bx?.+y", {"R3"}),
    (r"(?:foo)?\s*bar", {"R3"}),
    (r"(?=a).*b", {"R3"}),
    (r"(?:.*)x", {"R3"}),
    (r"(?:a|.*b)", {"R3"}),
    (r"[\s\S]+x", {"R3"}),
    (r"\D+1", {"R3"}),
    (r".{3,}x", {"R3"}),
    # R3 does not fire: anchored, literal first, bounded
    (r"^.*foo", {"R6"}),
    (r"\A.*foo", {"R6"}),
    (r"(?:^|\s)\S+", {"R6"}),
    (r"foo.*bar", {"R6"}),
    (r".{0,40}foo", set()),
    (r"\s{0,5}x", set()),
    # R4
    (r"a*", {"R4"}),
    (r"(?:x)?", {"R4"}),
    (r"\b", {"R4"}),
    (r"(?=x)", {"R4"}),
    # R5
    (r"(?s)abc", {"R5"}),
    (r"(?s:a.)b", {"R5"}),
    # R6
    (r"x[^y]*z", {"R6"}),
    (r"x\S+", {"R6"}),
    (r"foo[^x]{0,5000}bar", {"R6"}),
    (r"foo[^x]{0,4096}bar", set()),
    (r"x\s+y", set()),  # \s is not a negated class; only R3 treats it specially
    # R7
    (r"(?:\d\w|\w\d)+", {"R7"}),
    (r"(?:x|[^y]z)+", {"R7"}),
    (r"(?:foo|f\w+)*", {"R2", "R4", "R7"}),
    (r"a(?:b|c)+", set()),
    (r"a(?:bc|bd){1,5}", set()),  # bounded repeat: not R7
    (r"(?i)x(?:ab|Ac)+", {"R7"}),  # case-insensitive overlap
    (r"x(?:ab|Ac)+", set()),
    (r"x(?:(?i:ab)|Ac)+", {"R7"}),  # scoped ignorecase
]


@pytest.mark.parametrize(("pattern", "expected"), TABLE, ids=[p[:40] for p, _ in TABLE])
def test_lint_table(pattern: str, expected: set[str]) -> None:
    assert codes(pattern) == expected


def test_levels() -> None:
    by_code = {i.code: i.level for p, _ in TABLE for i in L.lint_pattern(p)}
    assert by_code["R6"] == "warning"
    for code in ("R1", "R2", "R3", "R4", "R5", "R7"):
        assert by_code[code] == "error"


def test_r1_stops_analysis() -> None:
    issues = L.lint_pattern(r"(.*")
    assert [i.code for i in issues] == ["R1"]


@pytest.mark.skipif(sys.version_info < (3, 11), reason="3.10 rejects the syntax at compile time (also R1)")
def test_atomic_and_possessive_are_not_portable_to_310() -> None:
    assert "R1" in codes(r"(?>a+)b")
    assert "R1" in codes(r"a*+b")
    assert "R1" in codes(r"a++b")


def test_atomic_and_possessive_fail_everywhere() -> None:
    assert "R1" in codes(r"(?>a+)b")
    assert "R1" in codes(r"x[a-z]++y")


def test_unknown_flag_letters() -> None:
    assert codes("abc", ("q",)) == {"R1"}
    assert codes("abc", ("m",)) == set()


def test_dotall_rules_by_context() -> None:
    assert codes("a.b", ("s",), "multiline") == set()
    assert codes("(?s)a.b", (), "multiline") == set()
    assert codes("a.b", ("s",), "regex") == {"R5"}
    assert codes("a.b", ("s",), "sequence") == {"R5"}
    assert codes("(?s:a.)b", (), "search") == {"R5"}


def test_verbose_flag_is_honored_when_parsing() -> None:
    assert codes(r"foo   # comment", ("x",)) == set()
    assert codes(r"(?x) \s+ foo", ()) == {"R3"}


def test_too_long_pattern() -> None:
    assert codes("a" * (L.MAX_PATTERN_CHARS + 1)) == {"R1"}


def test_huge_alternation_in_unbounded_repeat_is_bounded() -> None:
    alts = "|".join(f"k{i:04d}x" for i in range(400))
    pattern = f"z(?:{alts})+"
    start = time.perf_counter()
    issues = L.lint_pattern(pattern)
    assert time.perf_counter() - start < 2.0
    assert "R7" in {i.code for i in issues}


def test_alternation_with_huge_classes_is_bounded() -> None:
    cls = "".join(chr(0x3400 + 2 * i) for i in range(600))
    pattern = "z(?:" + "|".join(f"[{cls}]{i}" for i in range(12)) + ")+"
    start = time.perf_counter()
    issues = L.lint_pattern(pattern)
    assert time.perf_counter() - start < 3.0
    assert "R7" in {i.code for i in issues}


def test_extremely_deep_nesting_is_rejected_without_crashing() -> None:
    for depth in (500, 3000):
        issues = L.lint_pattern("(" * depth + "a" + ")" * depth)
        assert [i.code for i in issues] == ["R1"]


def test_large_disjoint_alternation_is_fast_and_clean() -> None:
    alts = "|".join(f"{chr(0x4E00 + i)}q" for i in range(200))
    pattern = f"z(?:{alts})+"
    start = time.perf_counter()
    assert L.lint_pattern(pattern) == []
    assert time.perf_counter() - start < 2.0


def test_issue_str_and_where() -> None:
    (issue,) = L.lint_pattern("a*", where="match.regex")
    assert issue.where == "match.regex"
    assert str(issue).startswith("match.regex: R4 ")
    assert issue.is_error


def test_compile_flags() -> None:
    import re

    assert L.compile_flags(("i", "x"), "regex") == re.M | re.I | re.X
    assert L.compile_flags((), "search") == 0
    assert L.compile_flags(("s",), "multiline") == re.M | re.S


# ------------------------------------------------------------------------------------------ rule walking


def full_rule() -> dict[str, Any]:
    return {
        "id": "WS-INJ-001",
        "match": {
            "all": [
                {"regex": "a1"},
                {"regex": {"pattern": "a2", "flags": ["i"]}},
                {"not": {"multiline": {"pattern": "a3", "flags": ["s"]}}},
                {
                    "any": [
                        {"multiline": {"sequence": ["a4", "a5"], "within_lines": 3, "flags": ["x"]}},
                        {"entropy": {"charset": "hex", "exclude_regex": ["a6"]}},
                    ]
                },
                {
                    "yaml_path": {
                        "all": [{"path": "p", "regex": "a7"}],
                        "none": [{"path": "q", "not_regex": "a8"}],
                    }
                },
                {
                    "py_ast": {
                        "call": {
                            "callee": "f",
                            "args": {"0": {"regex": "a9"}},
                            "kwargs": {"k": {"regex": "a10"}},
                        }
                    }
                },
                {"py_ast": {"fastapi_route": {"auth_regex": "a11", "ignore_paths_regex": "a12"}}},
                {"hcl": {"block": "b", "any": [{"attr": "x", "regex": "a13", "not_regex": "a14"}]}},
                {"unicode": {"classes": ["ZW"]}},
                {"builtin": "mcp_drift"},
            ]
        },
        "filters": {
            "file_regex": "a15",
            "file_not_regex": "a16",
            "line_not_regex": "a17",
            "path_not_glob": ["x"],
        },
    }


def test_iter_patterns_finds_every_pattern_with_context() -> None:
    refs = list(L.iter_patterns(full_rule()))
    assert sorted(int(r.pattern[1:]) for r in refs) == list(range(1, 18))
    by_pattern = {r.pattern: r for r in refs}
    assert by_pattern["a1"].context == "regex" and by_pattern["a1"].where == "match.all[0].regex"
    assert by_pattern["a2"].flags == ("i",) and by_pattern["a2"].where == "match.all[1].regex.pattern"
    assert (
        by_pattern["a3"].context == "multiline"
        and by_pattern["a3"].where == "match.all[2].not.multiline.pattern"
    )
    assert by_pattern["a5"].context == "sequence" and by_pattern["a5"].flags == ("x",)
    assert by_pattern["a5"].where == "match.all[3].any[0].multiline.sequence[1]"
    assert by_pattern["a6"].where == "match.all[3].any[1].entropy.exclude_regex[0]"
    assert by_pattern["a8"].where == "match.all[4].yaml_path.none[0].not_regex"
    assert by_pattern["a9"].where == "match.all[5].py_ast.call.args.0.regex"
    assert by_pattern["a12"].where == "match.all[6].py_ast.fastapi_route.ignore_paths_regex"
    assert by_pattern["a14"].where == "match.all[7].hcl.any[0].not_regex"
    assert by_pattern["a17"].where == "filters.line_not_regex" and by_pattern["a17"].context == "search"


def test_lint_rule_reports_locations() -> None:
    rule = {"match": {"any": [{"regex": ".*x"}, {"regex": "(a+)+"}]}, "filters": {"line_not_regex": "(?s)y"}}
    issues = L.lint_rule(rule)
    assert {(i.where, i.code) for i in issues} == {
        ("match.any[0].regex", "R3"),
        ("match.any[1].regex", "R2"),
        ("filters.line_not_regex", "R5"),
    }


def test_iter_patterns_tolerates_malformed_rules() -> None:
    assert list(L.iter_patterns({})) == []
    assert list(L.iter_patterns({"match": {"regex": 5}, "filters": "x"})) == []
    assert list(L.iter_patterns({"match": {"all": "x", "yaml_path": {"all": [1]}}})) == []


# ------------------------------------------------------------------------------------------ robustness


@settings(max_examples=300, deadline=None)
@given(st.text(alphabet=st.sampled_from(list("ab.*+?|()[]^$\\{},0123-sSdDwWbB:<>=!P#x ")), max_size=40))
def test_lint_never_raises_on_regex_like_input(pattern: str) -> None:
    for issue in L.lint_pattern(pattern):
        assert issue.code in {"R1", "R2", "R3", "R4", "R5", "R6", "R7"}


@settings(max_examples=200, deadline=None)
@given(st.text(max_size=60))
def test_lint_never_raises_on_arbitrary_text(pattern: str) -> None:
    L.lint_pattern(pattern, context="search")


@settings(max_examples=150, deadline=None)
@given(st.text(alphabet=st.sampled_from(list("ab.*+?|()[]^\\sdw")), min_size=1, max_size=24))
def test_r4_agrees_with_the_regex_engine(pattern: str) -> None:
    """R4 fires exactly when the compiled pattern can match the empty string at the end of input."""
    import re
    import warnings

    issues = L.lint_pattern(pattern)
    if any(i.code == "R1" for i in issues):
        return
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        rx = re.compile(pattern, re.M)
    can_be_empty = rx.fullmatch("") is not None
    if can_be_empty:
        assert "R4" in {i.code for i in issues}


# ------------------------------------------------------------------------------------------ versions

VERSION_PROBE = [p for p, _ in TABLE if not p.startswith("(?P<n")] + CLEAN


def _results_here() -> dict[str, list[str]]:
    return {p: sorted({i.code for i in L.lint_pattern(p)}) for p in VERSION_PROBE}


@pytest.mark.parametrize("version", ["3.10", "3.12", "3.13"])
def test_same_results_on_other_interpreters(version: str) -> None:
    exe = shutil.which(f"python{version}")
    if exe is None:
        pytest.skip(f"python{version} not installed")
    if f"{sys.version_info[0]}.{sys.version_info[1]}" == version:
        pytest.skip("same interpreter")
    script = (
        "import json, sys\n"
        "from whalescan.rules import lint as L\n"
        "pats = json.loads(sys.stdin.read())\n"
        "print(json.dumps({p: sorted({i.code for i in L.lint_pattern(p)}) for p in pats}))\n"
    )
    env = {**os.environ, "PYTHONPATH": os.path.abspath(SRC), "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.run(
        [exe, "-c", script],
        input=json.dumps(VERSION_PROBE),
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    theirs = json.loads(proc.stdout)
    assert theirs == _results_here()
