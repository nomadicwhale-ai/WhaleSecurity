"""Concrete parser regressions and killable adversarial tests for spec §5.3 / §8.2.

Subprocess deadlines are deliberately generous, not microbenchmarks: a regression must fail
rather than stall CI inside Python's non-timeout-capable regex engine.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from whalescan import textio, yamlite
from whalescan.config import MAX_CONFIG_BYTES, load_config
from whalescan.errors import ConfigError, RuleError
from whalescan.ignore import MAX_PATTERN_CHARS, MAX_PATTERNS_PER_FILE, parse_patterns
from whalescan.rules import loader
from whalescan.rules.lint import lint_pattern


def run_bounded(program: str) -> None:
    result = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("schema", yamlite.SCHEMAS)
@pytest.mark.parametrize("number", ["9" * 400, "0x" + "f" * 400])
def test_tagged_huge_integer_float_overflow_stays_string(schema: str, number: str) -> None:
    assert yamlite.resolve_scalar(number, schema, tag="!!float") == number
    assert yamlite.to_python(yamlite.load(f"value: !!float {number}", schema)) == {"value": number}


@pytest.mark.parametrize("text", ["[", "a: &a [*a]", "a: *undefined", 'a: "\\q"'])
def test_deferred_yaml_rule_errors_are_wrapped(text: str) -> None:
    with pytest.raises(RuleError, match="YAML parse error"):
        loader.default_yaml_loader(text)


@pytest.mark.parametrize("suffix", ["yaml", "json"])
def test_in_memory_rule_sources_obey_file_byte_limit(suffix: str) -> None:
    src = loader.SourceFile("extra", f"rules.{suffix}", f"rules.{suffix}", "test")
    data = b"[]" + b" " * (loader.MAX_RULE_FILE_BYTES - 2)
    assert loader.parse_source(src, data) == []
    with pytest.raises(RuleError, match="larger than"):
        loader.parse_source(src, data + b" ")


def test_text_reader_byte_limit_and_long_line(tmp_path: Path) -> None:
    path = tmp_path / "long.txt"
    path.write_bytes(b"x" * (1 << 20))
    assert len(textio.read_file(path, 1 << 20)) == 1 << 20
    with pytest.raises(textio.FileTooLargeError):
        textio.read_file(path, (1 << 20) - 1)
    # No invented line-length cutoff: §5.3 caps the file, §5.5 preserves all decoded text.
    decoded = textio.decode(textio.read_file(path, 1 << 20), "long.txt")
    assert textio.line_starts(decoded.text) == [0]
    assert textio.pos([0], len(decoded.text)) == (1, (1 << 20) + 1)


def test_toml_file_limit(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_bytes(b"schema=1\n#" + b"x" * (MAX_CONFIG_BYTES - 10))
    load_config(tmp_path, path=path, user=False, env={})
    with path.open("ab") as stream:
        stream.write(b"x")
    with pytest.raises(ConfigError, match="larger than"):
        load_config(tmp_path, path=path, user=False, env={})


@pytest.mark.parametrize("section", ["hooks", "secrets.allow_values"])
def test_deep_config_only_raises_config_error(tmp_path: Path, section: str) -> None:
    path = tmp_path / "config.toml"
    if section == "hooks":
        body = "hooks." + ".".join(["a"] * 600) + "=1"
    else:
        body = 'secrets.allow_values=["' + "(" * 600 + "a" + ")" * 600 + '"]'
    path.write_text("schema=1\n" + body)
    with pytest.raises(ConfigError):
        load_config(tmp_path, path=path, user=False, env={})


@pytest.mark.parametrize("pattern", ["a*", ".*example", "(?s).*example"])
def test_safe_fullmatch_exclusions_keep_their_semantics(tmp_path: Path, pattern: str) -> None:
    path = tmp_path / "config.toml"
    path.write_text('schema=1\nsecrets.allow_values=["' + pattern + '"]')
    assert load_config(tmp_path, path=path, user=False, env={}).secrets.allow_values == (pattern,)


@pytest.mark.parametrize("pattern", ["(?:a|aa)+!", "(?:a{1,2})+!", "(?:a?b?)+!", "(a+)+!"])
def test_project_exclusion_regexes_cannot_bypass_lint(tmp_path: Path, pattern: str) -> None:
    path = tmp_path / "config.toml"
    path.write_text('schema=1\nsecrets.allow_values=["' + pattern + '"]')
    with pytest.raises(ConfigError, match="invalid regular expression"):
        load_config(tmp_path, path=path, user=False, env={})


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX special files")
def test_config_fifo_does_not_block(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    os.mkfifo(path)
    run_bounded(
        "from whalescan.config import load_config\n"
        "from whalescan.errors import ConfigError\n"
        "try:\n"
        f"    load_config({str(tmp_path)!r}, path={str(path)!r}, user=False, env={{}})\n"
        "except ConfigError:\n"
        "    pass\n"
        "else:\n"
        "    raise AssertionError('FIFO accepted')\n"
    )


@pytest.mark.parametrize("pattern", [
    "(?:a|aa)+!", "(?:aa|a)+!", "(?:a{1,2})+!", "(?:a?b?)+!",
    "(?i)(?:\u0130a|ib)+!", r"(?i)(?:\ufb05a|\ufb06b)+!",
    r"(?i)(?:[\u2100-\u2200]a|[J-L]b)+!", r"(?:[\u1ba0-\u1bc0]a|\db)+!",
    r"(?:[\u0100-\uffff]a|\db)+!",
])
def test_r7_guards_cover_rewritten_and_unicode_branches(pattern: str) -> None:
    for context in ("regex", "multiline", "sequence", "search"):
        assert any(i.code == "R7" and i.is_error for i in lint_pattern(pattern, context=context))


@pytest.mark.parametrize("pattern", ["(?:ab|abc)+!", "(?:ab?)+!", "(?:a{1,2}b)+!", r"(?:[a-z]a|\db)+!"])
def test_provably_disjoint_repeated_bodies_still_load(pattern: str) -> None:
    assert not any(i.is_error for i in lint_pattern(pattern))


def test_ignore_limits_preserve_diagnostics() -> None:
    diagnostics = []
    assert parse_patterns("x" * (MAX_PATTERN_CHARS + 1), diagnostics=diagnostics) == []
    assert [d.code for d in diagnostics] == ["ignore-pattern-too-long"]
    diagnostics.clear()
    assert len(parse_patterns("x\n" * (MAX_PATTERNS_PER_FILE + 1), diagnostics=diagnostics)) == MAX_PATTERNS_PER_FILE
    assert [d.code for d in diagnostics] == ["ignore-too-many-patterns"]


def test_ignore_two_star_virtual_path_does_not_backtrack_quadratically() -> None:
    run_bounded(
        "from whalescan.ignore import compile_pattern\n"
        "p = compile_pattern('*a*a?b')\n"
        "assert p is not None\n"
        "assert not p.matches(('a' * 65536,), False)\n"
        "assert p.matches(('a' * 65536 + 'b',), False)\n"
    )


def test_yaml_bombs_fail_within_deadline() -> None:
    run_bounded(
        "from whalescan import yamlite as Y\n"
        "texts = ['[' * 5000 + '0' + ']' * 5000, 'x' * (Y.MAX_BYTES + 1)]\n"
        "texts.append('a: &a x\\nb: [' + ','.join(['*a'] * (Y.MAX_ALIASES + 1)) + ']')\n"
        "texts.append('a: &a [1]\\n' + '\\n'.join(\n"
        "    f'{chr(98+i)}: &{chr(98+i)} [' + ','.join(['*'+chr(97+i)]*10) + ']'\n"
        "    for i in range(8)))\n"
        "for text in texts:\n"
        "    docs = Y.load_all(text)\n"
        "    assert any(d.error is not None for d in docs)\n"
        "text = '[' + ','.join(['0'] * Y.MAX_NODES) + ']'\n"
        "assert Y.load_all(text)[0].error is not None\n"
    )


def test_max_size_line_text_matchers_finish_within_deadline() -> None:
    run_bounded(
        "from whalescan.model import FileCtx, Rule, Severity, Confidence, AppliesTo\n"
        "from whalescan.matchers.regex import match_regex\n"
        "from whalescan.matchers.multiline import match_multiline\n"
        "from whalescan.matchers.entropy import match_entropy\n"
        "from whalescan.matchers.unicode import match_unicode\n"
        "r = Rule('WS-INJ-001','t','appsec',Severity.HIGH,Confidence.MEDIUM,'t',AppliesTo(),{},'t',())\n"
        "texts = ('a' * (1<<20), chr(34) + ((chr(92)+'a') * ((1<<19)-1)), chr(0x202e) * (1<<19))\n"
        "for text in texts:\n"
        "    c = FileCtx('untrusted.txt',text)\n"
        "    match_regex('needle[^x]{0,64}end',c,r)\n"
        "    match_multiline({'sequence':['needle','end'], 'within_lines':3},c,r)\n"
        "    match_multiline({'pattern':'needle.{0,64}end', 'flags':['s']},c,r)\n"
        "    match_entropy({'charset':'alnum'},c,r)\n"
        "    match_unicode({'classes':['ZW','BIDI','TAG','VS','CTRL']},c,r)\n"
    )


def test_fuzz_campaign_has_a_hard_process_deadline() -> None:
    # Hypothesis deadlines detect slow examples but cannot kill a stuck C regex. The complete
    # deterministic campaign also runs under a process deadline to enforce a real no-hang gate.
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/security/test_untrusted_inputs.py", "-q"],
        cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True, timeout=45, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
