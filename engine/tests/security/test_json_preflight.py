"""Reject native-stack exhaustion before decoding any untrusted JSON document."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from whalescan import jsonio, suppress
from whalescan.errors import ConfigError, RuleError
from whalescan.rules import cache, fixtures, loader

KINDS = ("rule", "bundle", "baseline", "cache", "sidecar")


def assert_rejected(kind: str, text: str, root: Path, message: str | None = None) -> None:
    data = text.encode()
    if kind in ("rule", "bundle"):
        source = loader.SourceFile("bundle" if kind == "bundle" else "extra", "p.json", "p.json", "test")
        with pytest.raises(RuleError, match=message):
            loader.parse_source(source, data)
    elif kind == "baseline":
        path = root / "baseline.json"
        path.write_bytes(data)
        with pytest.raises(ConfigError, match=message):
            suppress.Baseline.load(path)
    elif kind == "sidecar":
        (root / "expect.json").write_bytes(data)
        with pytest.raises(fixtures.FixtureError, match=message):
            fixtures.load_sidecar(str(root), str(root))
    else:
        store = cache.RuleCache(root / "cache")
        key = "0" * 64
        path = store.store(key, loader.RuleSet(()))
        assert path is not None
        Path(path).write_bytes(data)
        assert store.load(key) is None
        if message is not None:
            assert not Path(path).exists()  # existing decoded-corrupt-cache policy


def decoder_must_not_run(*args, **kwargs):
    raise AssertionError("unsafe input reached json.loads")


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("opening,closing", [("[", "]"), ('{"x":', "}"), ('[{"x":', "}]")])
def test_all_json_readers_preflight_deep_input(kind, opening, closing, tmp_path, monkeypatch):
    monkeypatch.setattr(json, "loads", decoder_must_not_run)
    text = opening * (jsonio.MAX_JSON_DEPTH + 1) + "0" + closing * (jsonio.MAX_JSON_DEPTH + 1)
    assert_rejected(kind, text, tmp_path, "JSON nested too deeply")


@pytest.mark.parametrize("kind", KINDS)
def test_all_json_readers_reject_size_before_decoder(kind, tmp_path, monkeypatch):
    monkeypatch.setattr(json, "loads", decoder_must_not_run)
    monkeypatch.setattr(loader, "MAX_RULE_FILE_BYTES", 64)
    monkeypatch.setattr(loader, "MAX_BUNDLE_BYTES", 64)
    monkeypatch.setattr(cache, "MAX_CACHE_BYTES", 64)
    monkeypatch.setattr(fixtures, "MAX_SIDECAR_BYTES", 64)
    monkeypatch.setattr(suppress, "MAX_BASELINE_BYTES", 64)
    assert_rejected(kind, " " * 65, tmp_path)


@pytest.mark.parametrize("depth", [1, jsonio.MAX_JSON_DEPTH])
@pytest.mark.parametrize("opening,closing", [("[", "]"), ('{"x":', "}")])
def test_exact_depth_boundary_is_accepted(depth, opening, closing):
    text = opening * depth + "0" + closing * depth
    jsonio.preflight(text, max_bytes=len(text.encode()))
    json.loads(text)


@pytest.mark.parametrize("text", [json.dumps("é" * 4096, ensure_ascii=False), '"ascii"'])
def test_utf8_byte_size_boundary_is_exact(text):
    size = len(text.encode())
    jsonio.preflight(text, max_bytes=size)
    with pytest.raises(ValueError, match="larger than"):
        jsonio.preflight(text, max_bytes=size - 1)


@pytest.mark.parametrize("text", [
    "]" + "[" * 100_000, "[}" + "[" * 100_000,
    '{"x":"escaped\\\"[' + "[" * 100_000 + '","y":' + "[" * 100_000,
])
def test_malformed_prefixes_cannot_hide_nesting(text):
    with pytest.raises(ValueError, match="JSON"):
        jsonio.preflight(text, max_bytes=2 << 20)


@settings(max_examples=100, derandomize=True, deadline=200)
@given(value=st.text(max_size=200))
def test_string_escaping_preserves_decoder_semantics(value):
    # All syntax-like characters, including surrogate escapes, remain inside the string.
    value += '[{}]"\\' * 100
    text = json.dumps({"value": value})
    jsonio.preflight(text, max_bytes=len(text))
    assert json.loads(text) == {"value": value}


def test_hundred_thousand_nested_containers_fail_in_killable_process():
    # Python 3.14 can segfault in the native decoder before RecursionError. A subprocess
    # turns any bypass into a bounded test failure, not a crash of the whole test runner.
    program = (
        "import tempfile\n"
        "from pathlib import Path\n"
        "from tests.security.test_json_preflight import KINDS, assert_rejected\n"
        "with tempfile.TemporaryDirectory() as root:\n"
        "    for opening, closing in (('[', ']'), ('{\"x\":', '}')):\n"
        "        text = opening * 100_000 + '0' + closing * 100_000\n"
        "        for kind in KINDS:\n"
        "            assert_rejected(kind, text, Path(root))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", program], cwd=Path(__file__).resolve().parents[2],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode == 0, result.stderr
