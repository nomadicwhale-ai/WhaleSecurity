"""Bounded, deterministic fuzzing of the engine's untrusted-input boundaries.

Keep inputs small and structured so CI explores syntax, not just invalid byte streams.
Adversarial resource tests run separately in killable subprocesses.
"""

from __future__ import annotations

import json
import math
import os
import tempfile
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
import yaml
from hypothesis import example, given, settings
from hypothesis import strategies as st

from whalescan import config, textio, yamlite
from whalescan._vendor import tomli
from whalescan.config import load_config
from whalescan.errors import ConfigError, RuleError
from whalescan.ignore import compile_pattern, parse_patterns
from whalescan.matchers.entropy import match_entropy, shannon
from whalescan.matchers.multiline import match_multiline
from whalescan.matchers.regex import match_regex
from whalescan.matchers.unicode import decode_tags, match_unicode, reveal
from whalescan.model import AppliesTo, Confidence, FileCtx, Rule, Severity
from whalescan.rules import loader
from whalescan.rules.lint import lint_pattern

# Only the killable subprocess campaign opts out of timing individual examples: Windows
# filesystem/scheduler overhead is not a parser hang. Its enclosing 45s process limit remains.
FUZZ = settings(
    max_examples=150,
    deadline=None if os.environ.get("WHALESCAN_FUZZ_PROCESS_BOUNDED") == "1" else 500,
    derandomize=True, database=None,
)
SCALARS = st.none() | st.booleans() | st.integers(-1_000_000, 1_000_000) | st.text(max_size=64)
VALUES = st.recursive(
    SCALARS,
    lambda children: st.lists(children, max_size=6)
    | st.dictionaries(st.text(alphabet="abcdef_", min_size=1, max_size=8), children, max_size=6),
    max_leaves=25,
)
YAMLISH = st.text(alphabet="abc0129 :,-[]{}&*!#%|>\"'\\\n\r\t", max_size=512)


def raw_rule(match: Any) -> dict[str, Any]:
    return {
        "id": "WS-INJ-001",
        "title": "Untrusted input test",
        "pack": "appsec/injection",
        "severity": "high",
        "confidence": "medium",
        "owner": "@whalesecurity/test",
        "applies_to": {"kind": "code", "lang": "python"},
        "match": match,
        "message": "Untrusted input test.",
        "references": ["https://example.com/rule"],
    }


def rule() -> Rule:
    return Rule(
        id="WS-INJ-001", title="fuzz", pack="appsec/injection", severity=Severity.HIGH,
        confidence=Confidence.MEDIUM, owner="test", applies_to=AppliesTo(), match={},
        message="fuzz", references=(), max_hits_per_file=10,
    )


@FUZZ
@given(text=YAMLISH | st.text(max_size=512), schema=st.sampled_from(yamlite.SCHEMAS), helm=st.booleans())
@example(text='["\\U00110000"]', schema="yaml12", helm=False)
@example(text="a: &a [*a]", schema="yaml12", helm=False)
@example(text="a: [1\n---\nb: 2", schema="yaml12", helm=False)
def test_yaml_parser_only_reports_yaml_errors(text: str, schema: str, helm: bool) -> None:
    docs = yamlite.load_all(text, schema=schema, lenient_helm=helm)
    for doc in docs:
        if doc.error is not None:
            assert isinstance(doc.error, yamlite.YamlError)
        else:
            yamlite.to_python(doc)
            if doc.root is not None:
                for node in [doc.root, *doc.root.descendants()]:
                    assert 0 <= node.start <= node.end <= len(text)
    try:
        strict = yamlite.load_all(text, schema=schema, lenient_helm=helm, strict=True)
    except yamlite.YamlError:
        assert any(doc.error is not None for doc in docs)
    else:
        assert len(strict) == len(docs)


@FUZZ
@given(digits=st.text(alphabet="0123456789", min_size=1, max_size=1000), schema=st.sampled_from(yamlite.SCHEMAS))
@example(digits="9" * 400, schema="yaml12")
def test_explicit_numeric_tags_never_raise(digits: str, schema: str) -> None:
    for tag in ("!!int", "!!float"):
        yamlite.resolve_scalar(digits, schema, tag=tag)
        yamlite.to_python(yamlite.load(f"value: {tag} {digits}", schema=schema))


@FUZZ
@given(value=VALUES, flow=st.booleans())
def test_safe_yaml_roundtrip_agrees_with_pyyaml(value: Any, flow: bool) -> None:
    # PyYAML quotes ambiguous strings. String keys avoid yamlite's intentional raw-key deviation.
    text = yaml.safe_dump(value, default_flow_style=flow, allow_unicode=False, width=80)
    expected = yaml.safe_load(text)
    for schema in yamlite.SCHEMAS:
        assert yamlite.to_python(yamlite.load(text, schema=schema)) == expected == value


@FUZZ
@given(data=st.binary(max_size=1024), bom=st.sampled_from([b"", *(b for b, _ in textio.BOMS)]))
def test_decoding_is_total_lossless_or_explicitly_replaced(data: bytes, bom: bytes) -> None:
    source = bom + data
    decoded = textio.decode(source, "untrusted.txt")
    detected = textio.detect_bom(source)
    if detected is not None:
        prefix, codec = detected
        expected = source[len(prefix):].decode(codec, errors="replace")
        assert decoded.text == expected
        assert not decoded.fallback
    elif decoded.fallback:
        assert decoded.text.encode("latin-1") == source
        assert [d.code for d in decoded.diagnostics] == ["decode-fallback-latin1"]
    else:
        assert decoded.text.encode("utf-8") == source
    starts = textio.line_starts(decoded.text)
    ctx = FileCtx("untrusted.txt", decoded.text)
    assert starts == ctx.line_starts
    for off in (0, len(decoded.text) // 2, len(decoded.text)):
        assert textio.pos(starts, off) == ctx.pos(off)


@FUZZ
@given(text=st.text(alphabet="ab[]!^*?\\-:/#, \n\r\t", max_size=512), path=st.text(max_size=128))
@example(text="[a-\\]", path="a")
def test_ignore_parser_and_matcher_are_total(text: str, path: str) -> None:
    diagnostics = []
    patterns = parse_patterns(text, diagnostics=diagnostics)
    parts = tuple(path.split("/"))
    for pattern in patterns:
        assert isinstance(pattern.matches(parts, False), bool)
        assert isinstance(pattern.matches(parts, True), bool)
    single = compile_pattern(text)
    if single is not None:
        assert isinstance(single.matches(parts, False), bool)


@FUZZ
@given(
    glob=st.text(alphabet="ab*?", min_size=1, max_size=32),
    name=st.text(alphabet="ab", min_size=1, max_size=64),
)
def test_simple_ignore_globs_agree_with_fnmatch(glob: str, name: str) -> None:
    import fnmatch

    pattern = compile_pattern(glob)
    assert pattern is not None
    assert pattern.matches((name,), False) == fnmatch.fnmatchcase(name, glob)


@FUZZ
@given(data=st.binary(max_size=512) | YAMLISH.map(str.encode), suffix=st.sampled_from(["yaml", "json"]))
@example(data=b"[", suffix="yaml")
def test_rule_source_only_raises_rule_error(data: bytes, suffix: str) -> None:
    source = loader.SourceFile("extra", f"untrusted.{suffix}", f"untrusted.{suffix}", "fuzz")
    try:
        raws = loader.parse_source(source, data)
        assert loader.build(raws).bundle_hash.startswith("sha256:")
    except RuleError:
        pass


@FUZZ
@given(codepoint=st.integers(0xD800, 0xDFFF))
@example(codepoint=0xD800)
def test_json_rule_surrogates_raise_rule_error_before_hashing(codepoint: int) -> None:
    raw = raw_rule({"regex": {"pattern": "literal"}})
    raw["message"] += chr(codepoint)
    source = loader.SourceFile("extra", "rules.json", "rules.json", "fuzz")
    with pytest.raises(RuleError, match="unpaired Unicode surrogate"):
        _ = loader.build(loader.parse_source(source, json.dumps([raw]).encode())).bundle_hash


@FUZZ
@given(value=VALUES, match=VALUES)
def test_rule_schema_mutations_never_escape_rule_errors(value: Any, match: Any) -> None:
    for raw in (value, raw_rule(match)):
        with suppress(RuleError):
            loader.build([loader.RawRule(raw, "untrusted.yaml", "extra", 0)])


@FUZZ
@given(literal=st.text(alphabet="abc012 .:-", min_size=1, max_size=64))
def test_valid_rule_packs_roundtrip_through_yaml_json_and_normalization(literal: str) -> None:
    import re

    raw = raw_rule({"regex": {"pattern": re.escape(literal)}})
    expected = loader.rule_to_dict(loader.normalize(raw))
    for suffix, text in (
        ("yaml", yaml.safe_dump([raw], allow_unicode=False)),
        ("json", json.dumps([raw])),
    ):
        source = loader.SourceFile("extra", f"rules.{suffix}", "<memory>", "fuzz")
        (loaded,) = loader.build(loader.parse_source(source, text.encode())).rules
        assert loader.rule_to_dict(loaded, with_source=False) == {
            key: value for key, value in expected.items() if key != "source_file"
        }
        assert loader.rule_to_dict(loader.rule_from_dict(loader.rule_to_dict(loaded))) == loader.rule_to_dict(loaded)


@FUZZ
@given(pattern=st.text(alphabet="ab01[]{}()+*?|^$\\.:=!<>-", max_size=128))
def test_rule_pattern_lint_is_total(pattern: str) -> None:
    for context in ("regex", "multiline", "sequence", "search"):
        lint_pattern(pattern, context=context)
    loader.check_rule(raw_rule({"regex": {"pattern": pattern}}))


@FUZZ
@given(data=st.binary(max_size=512) | YAMLISH.map(str.encode))
@example(data=b'schema=1\nrules.extra_dirs=["\\u0000"]')
@example(data=b'schema=1\nscan.baseline="\\u0000"')
@example(data=b'schema=1\nhooks.' + b'a.' * 599 + b'a=1')
@example(data=b'schema=1\nsecrets.allow_values=["' + b'(' * 600 + b'a' + b')' * 600 + b'"]')
def test_project_config_only_raises_config_error(data: bytes) -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "config.toml"
        path.write_bytes(data)
        with suppress(ConfigError):
            load_config(directory, path=path, env={}, user=False)
        # Exercise the Python 3.10 fallback even on newer CI interpreters without replacing
        # global sys.version_info (which would affect Hypothesis and unrelated modules).
        with patch.object(config, "sys", SimpleNamespace(version_info=(3, 10))), suppress(ConfigError):
            load_config(directory, path=path, env={}, user=False)


@FUZZ
@given(value=st.integers(-1_000_000, 1_000_000) | st.booleans() | st.text(max_size=64))
def test_vendored_tomli_agrees_on_scalar_subset(value: Any) -> None:
    # TOML shares JSON's quoted-string escapes except slash and surrogate escapes (not generated here).
    text = "value = " + json.dumps(value, ensure_ascii=False)
    try:
        expected = tomli.loads(text)
    except tomli.TOMLDecodeError:
        return
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "config.toml"
        path.write_text(text, encoding="utf-8")
        from whalescan.config import _load_toml

        assert _load_toml(str(path), "project") == expected


@FUZZ
@given(char=st.sampled_from(["a", "b", "0", "\u0130", "\u0131", "\u017f", "\u212a"]), copies=st.integers(2, 8))
def test_ambiguous_repeated_prefixes_are_rejected(char: str, copies: int) -> None:
    import re

    short = re.escape(char)
    for body in (f"{short}|{short * copies}", f"{short}{{1,{copies}}}"):
        issues = lint_pattern(f"(?:{body})+!")
        assert any(issue.is_error for issue in issues)


@FUZZ
@given(char=st.characters(categories=("Lu", "Ll", "Lt")))
@example(char="\u0130")
@example(char="\ufb05")
def test_repeated_case_equivalents_use_native_regex_semantics(char: str) -> None:
    import re

    for other in (char.lower(), char.upper(), char.casefold(), "\ufb06", "i", "\u0131", "\u017f", "\u212a"):
        if other != char and len(other) == 1 and re.fullmatch(re.escape(char), other, re.IGNORECASE) is not None:
            pattern = f"(?i)(?:{re.escape(char)}a|{re.escape(other)}b)+!"
            assert any(i.code == "R7" and i.is_error for i in lint_pattern(pattern))


@FUZZ
@given(data=YAMLISH | st.text(max_size=512))
def test_vendored_tomli_only_raises_decode_error(data: str) -> None:
    with suppress(tomli.TOMLDecodeError):
        tomli.loads(data)


@FUZZ
@given(
    text=st.text(max_size=1024) | st.lists(
        st.sampled_from(["a", "\n", "\r", "\u202e", "\u2066", "\u200b", "\U000e0041", "\ufe00", "\U000e0110", "\ue001", "\x1b", "\u0430"]),
        max_size=256,
    ).map("".join),
    charset=st.sampled_from(["hex", "base64", "base64url", "alnum"]),
)
def test_text_matchers_return_bounded_valid_spans(text: str, charset: str) -> None:
    ctx = FileCtx("untrusted.py", text, lang="python", kind="code")
    hits = [
        *match_regex(r"[A-Za-z0-9]{1,64}", ctx, rule()),
        *match_multiline({"pattern": r"a[^b]{0,64}b", "max_span_lines": 3}, ctx, rule()),
        *match_multiline({"sequence": ["a", "b"], "within_lines": 3}, ctx, rule()),
        *match_entropy({"charset": charset}, ctx, rule()),
        *match_unicode({"classes": ["ZW", "BIDI", "TAG", "VS", "PUA", "CTRL", "HOMOGLYPH"]}, ctx, rule()),
    ]
    for hit in hits:
        assert 0 <= hit.start < hit.end <= len(text)
        assert (hit.line, hit.col) == ctx.pos(hit.start)
        assert (hit.end_line, hit.end_col) == ctx.end_pos(hit.end)
        assert all(0 <= s < e <= len(text) for s, e in hit.secret_spans)
    assert len(hits) <= 5 * rule().max_hits_per_file
    entropy = shannon(text)
    assert 0 <= entropy <= math.log2(max(1, len(text))) + 1e-12
    assert isinstance(decode_tags(text), str)
    assert isinstance(reveal(text), str)
