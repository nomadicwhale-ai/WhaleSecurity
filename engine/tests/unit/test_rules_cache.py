"""Tests for whalescan.rules.cache: the JSON rule cache (spec §15.2)."""

from __future__ import annotations

import json
import os
import stat
import time
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from whalescan.rules import cache as C
from whalescan.rules import loader as LD
from whalescan.rules.loader import RuleSet

POSIX = hasattr(os, "getuid")


def base_rule(i: int = 1, **over: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": f"WS-INJ-{i:03d}",
        "title": "Shell command built from input",
        "pack": "appsec/injection",
        "severity": "high",
        "confidence": "medium",
        "owner": "@whalesecurity/appsec",
        "applies_to": {"kind": "code", "lang": "python"},
        "match": {"regex": {"pattern": r"os\.system\((?P<arg>[^)\n]{1,200})\)"}},
        "message": "os.system called with {{arg}}.",
        "keywords": ["os.system"],
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    }
    rule.update(over)
    return rule


def ruleset() -> RuleSet:
    return LD.load_raw_rules(
        [base_rule(1), base_rule(2, match={"regex": r"popen\([^)]*\)"}, message="popen is called here.")]
    )


KEY = "a" * 64
KEY2 = "b" * 64


# ------------------------------------------------------------------------------------------ keys


def test_compute_key_is_deterministic_and_order_independent() -> None:
    a = C.compute_key("1.0.0", [("x", b"1"), ("y", b"2")], {"packs": ["appsec"]})
    b = C.compute_key("1.0.0", [("y", b"2"), ("x", b"1")], {"packs": ["appsec"]})
    assert a == b and len(a) == 64 and int(a, 16) >= 0


@pytest.mark.parametrize(
    "variant",
    [
        ("1.0.1", [("x", b"1"), ("y", b"2")], {"packs": ["appsec"]}),
        ("1.0.0", [("x", b"1"), ("y", b"3")], {"packs": ["appsec"]}),
        ("1.0.0", [("x", b"1"), ("z", b"2")], {"packs": ["appsec"]}),
        ("1.0.0", [("x", b"1")], {"packs": ["appsec"]}),
        ("1.0.0", [("x", b"1"), ("y", b"2")], {"packs": ["secrets"]}),
        ("1.0.0", [("x", b"1"), ("y", b"2")], None),
    ],
)
def test_compute_key_changes_with_every_input(variant: tuple[str, list[tuple[str, bytes]], Any]) -> None:
    base = C.compute_key("1.0.0", [("x", b"1"), ("y", b"2")], {"packs": ["appsec"]})
    assert C.compute_key(*variant) != base


@settings(max_examples=100)
@given(
    st.dictionaries(st.text(max_size=5), st.binary(max_size=8), max_size=4),
    st.dictionaries(st.text(max_size=5), st.integers(), max_size=3),
)
def test_compute_key_property(files: dict[str, bytes], config: dict[str, int]) -> None:
    pairs = list(files.items())
    assert C.compute_key("v", pairs, config) == C.compute_key("v", list(reversed(pairs)), dict(config))


def test_path_for_uses_key_prefix_and_validates_keys(tmp_path: Any) -> None:
    cache = C.RuleCache(tmp_path)
    assert cache.path_for(KEY) == os.path.join(str(tmp_path), "rules-" + "a" * 16 + ".json")
    for bad in ("", "A" * 64, "a" * 63, "../" + "a" * 61):
        with pytest.raises(ValueError):
            cache.path_for(bad)


# ------------------------------------------------------------------------------------------ store / load


def test_store_and_load_roundtrip(tmp_path: Any) -> None:
    rs = ruleset()
    cache = C.RuleCache(tmp_path / "cache")
    path = cache.store(KEY, rs)
    assert path is not None and os.path.exists(path)
    back = cache.load(KEY)
    assert back is not None
    assert back.rules == rs.rules and back.bundle_hash == rs.bundle_hash
    assert back.index == rs.index and back.keyword_table == rs.keyword_table
    assert cache.load(KEY2) is None
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    assert doc["schema"] == C.CACHE_SCHEMA and doc["key"] == KEY


@pytest.mark.skipif(not POSIX, reason="POSIX permissions")
def test_permissions(tmp_path: Any) -> None:
    cache = C.RuleCache(tmp_path / "cache")
    path = cache.store(KEY, ruleset())
    assert path is not None
    assert stat.S_IMODE(os.stat(tmp_path / "cache").st_mode) == 0o700
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


@pytest.mark.skipif(not POSIX, reason="POSIX permissions")
def test_loose_directory_permissions_are_tightened(tmp_path: Any) -> None:
    d = tmp_path / "cache"
    d.mkdir(mode=0o777)
    os.chmod(d, 0o777)  # noqa: S103 - the test needs a loose directory
    assert C.RuleCache(d).store(KEY, ruleset()) is not None
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700


def test_key_mismatch_is_a_miss(tmp_path: Any) -> None:
    cache = C.RuleCache(tmp_path)
    colliding = "a" * 16 + "f" * 48  # same file name, different full key
    assert cache.store(colliding, ruleset()) is not None
    assert cache.load(KEY) is None


@pytest.mark.parametrize(
    "content",
    [
        b"{not json",
        b"[]",
        b'{"schema": "other"}',
        b"\xff\xfe",
        json.dumps({"schema": C.CACHE_SCHEMA, "key": KEY, "ruleset": {"rules": 5}}).encode(),
    ],
)
def test_corrupt_entries_are_misses_and_removed(tmp_path: Any, content: bytes) -> None:
    cache = C.RuleCache(tmp_path)
    path = cache.path_for(KEY)
    with open(path, "wb") as fh:
        fh.write(content)
    os.chmod(path, 0o600)
    assert cache.load(KEY) is None
    assert not os.path.exists(path)


@pytest.mark.skipif(not POSIX, reason="POSIX permissions")
def test_group_writable_entry_is_ignored(tmp_path: Any) -> None:
    cache = C.RuleCache(tmp_path)
    path = cache.store(KEY, ruleset())
    assert path is not None
    os.chmod(path, 0o666)  # noqa: S103 - the test needs a foreign-writable entry
    assert cache.load(KEY) is None
    assert os.path.exists(path)  # not ours to trust, but not deleted either


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_symlinked_entry_is_ignored(tmp_path: Any) -> None:
    real = C.RuleCache(tmp_path / "real")
    target = real.store(KEY, ruleset())
    assert target is not None
    cache = C.RuleCache(tmp_path / "other")
    os.makedirs(cache.directory, mode=0o700)
    os.symlink(target, cache.path_for(KEY))
    assert cache.load(KEY) is None


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_symlinked_cache_directory_is_unusable(tmp_path: Any) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    os.symlink(real, tmp_path / "link")
    cache = C.RuleCache(tmp_path / "link")
    assert cache.store(KEY, ruleset()) is None
    assert cache.load(KEY) is None
    assert os.listdir(real) == []


def test_store_into_an_unwritable_location_fails_softly(tmp_path: Any) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x")
    cache = C.RuleCache(blocker / "cache")
    assert cache.store(KEY, ruleset()) is None
    assert cache.load(KEY) is None


def test_prune_keeps_the_newest_entries(tmp_path: Any) -> None:
    cache = C.RuleCache(tmp_path, keep=5)
    rs = ruleset()
    keys = [f"{i:x}" * 64 for i in range(1, 8)]
    now = time.time()
    for n, key in enumerate(keys):
        path = cache.store(key[:64], rs)
        assert path is not None
        os.utime(path, (now - 100 + n, now - 100 + n))
    stale_tmp = tmp_path / ".rules-leftover.tmp"
    stale_tmp.write_text("x")
    os.utime(stale_tmp, (now - 7200, now - 7200))
    fresh_tmp = tmp_path / ".rules-inflight.tmp"
    fresh_tmp.write_text("x")
    cache.prune()
    left = sorted(p for p in os.listdir(tmp_path) if p.startswith("rules-"))
    assert left == sorted(f"rules-{k[:16]}.json" for k in keys[2:])
    assert not stale_tmp.exists() and fresh_tmp.exists()


def test_hit_refreshes_mtime(tmp_path: Any) -> None:
    cache = C.RuleCache(tmp_path)
    path = cache.store(KEY, ruleset())
    assert path is not None
    os.utime(path, (1000, 1000))
    assert cache.load(KEY) is not None
    assert os.stat(path).st_mtime > 1000


def test_load_or_build(tmp_path: Any) -> None:
    cache = C.RuleCache(tmp_path)
    calls: list[int] = []

    def builder() -> RuleSet:
        calls.append(1)
        return ruleset()

    first = cache.load_or_build(KEY, builder)
    second = cache.load_or_build(KEY, builder)
    assert calls == [1] and first.rules == second.rules


# ------------------------------------------------------------------------------------------ env


def test_default_cache_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    home = str(tmp_path / "home")
    monkeypatch.setenv("HOME", home)
    assert C.default_cache_dir({}) == os.path.join(home, ".cache", "whalescan")
    assert C.default_cache_dir({"XDG_CACHE_HOME": "/xdg"}) == "/xdg/whalescan"
    assert C.default_cache_dir({"XDG_CACHE_HOME": "relative"}) == os.path.join(home, ".cache", "whalescan")
    assert C.default_cache_dir({"WHALESCAN_CACHE_DIR": "/explicit", "XDG_CACHE_HOME": "/xdg"}) == "/explicit"
    monkeypatch.setenv("WHALESCAN_CACHE_DIR", "/from-env")
    assert C.default_cache_dir() == "/from-env"


def test_cache_disabled() -> None:
    assert C.cache_disabled({"WHALESCAN_NO_CACHE": "1"})
    assert C.cache_disabled({"WHALESCAN_NO_CACHE": "true"})
    assert not C.cache_disabled({"WHALESCAN_NO_CACHE": "0"})
    assert not C.cache_disabled({})


# ------------------------------------------------------------------------------------------ load_rules


def write_pack(directory: Any, rules: list[dict[str, Any]], name: str = "pack.json") -> None:
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, name), "w", encoding="utf-8") as fh:
        json.dump(rules, fh)


def test_load_rules_builds_once_then_hits(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    rules_dir = tmp_path / "rules"
    write_pack(rules_dir, [base_rule(1)])
    cache_dir = tmp_path / "cache"
    monkeypatch.delenv("WHALESCAN_NO_CACHE", raising=False)
    first = C.load_rules([rules_dir], builtin=False, cache_dir=cache_dir, engine_version="1.0.0")
    assert [r.id for r in first] == ["WS-INJ-001"]
    assert len([p for p in os.listdir(cache_dir) if p.startswith("rules-")]) == 1

    def boom(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("a cache hit must not parse rule files")

    monkeypatch.setattr(C, "parse_source", boom)
    second = C.load_rules([rules_dir], builtin=False, cache_dir=cache_dir, engine_version="1.0.0")
    assert second.rules == first.rules
    monkeypatch.undo()

    write_pack(rules_dir, [base_rule(1), base_rule(2)])  # content change -> new key -> rebuild
    third = C.load_rules([rules_dir], builtin=False, cache_dir=cache_dir, engine_version="1.0.0")
    assert [r.id for r in third] == ["WS-INJ-001", "WS-INJ-002"]
    assert len([p for p in os.listdir(cache_dir) if p.startswith("rules-")]) == 2


def test_load_rules_config_and_version_are_part_of_the_key(tmp_path: Any) -> None:
    rules_dir = tmp_path / "rules"
    write_pack(rules_dir, [base_rule(1)])
    cache_dir = tmp_path / "cache"
    C.load_rules([rules_dir], builtin=False, cache_dir=cache_dir, engine_version="1", use_cache=True)
    C.load_rules([rules_dir], builtin=False, cache_dir=cache_dir, engine_version="2")
    C.load_rules([rules_dir], builtin=False, cache_dir=cache_dir, engine_version="2", config={"packs": ["x"]})
    assert len(os.listdir(cache_dir)) == 3


def test_load_rules_without_cache(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    rules_dir = tmp_path / "rules"
    write_pack(rules_dir, [base_rule(1)])
    cache_dir = tmp_path / "cache"
    C.load_rules([rules_dir], builtin=False, cache_dir=cache_dir, use_cache=False)
    monkeypatch.setenv("WHALESCAN_NO_CACHE", "1")
    C.load_rules([rules_dir], builtin=False, cache_dir=cache_dir)
    assert not cache_dir.exists()


def test_load_rules_errors_are_not_cached(tmp_path: Any) -> None:
    rules_dir = tmp_path / "rules"
    write_pack(rules_dir, [base_rule(1, severity="bogus")])
    cache_dir = tmp_path / "cache"
    with pytest.raises(LD.RuleLoadError):
        C.load_rules([rules_dir], builtin=False, cache_dir=cache_dir)
    assert not cache_dir.exists() or not os.listdir(cache_dir)


def test_load_rules_keeps_warnings_through_the_cache(tmp_path: Any) -> None:
    rules_dir = tmp_path / "rules"
    write_pack(
        rules_dir, [base_rule(1, match={"regex": r"os\.system\([^)]*\)"}, message="os.system is used.")]
    )
    cache_dir = tmp_path / "cache"
    first = C.load_rules([rules_dir], builtin=False, cache_dir=cache_dir, engine_version="1")
    second = C.load_rules([rules_dir], builtin=False, cache_dir=cache_dir, engine_version="1")
    assert [w.code for w in first.warnings] == [w.code for w in second.warnings] == ["lint-R6"]


def test_load_rules_default_engine_version(tmp_path: Any) -> None:
    rules_dir = tmp_path / "rules"
    write_pack(rules_dir, [base_rule(1)])
    rs = C.load_rules([rules_dir], builtin=False, cache_dir=tmp_path / "cache")
    assert len(rs) == 1


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_fifo_in_place_of_an_entry_does_not_hang(tmp_path: Any) -> None:
    cache = C.RuleCache(tmp_path)
    os.mkfifo(cache.path_for(KEY), 0o600)
    assert cache.load(KEY) is None
