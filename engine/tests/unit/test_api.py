"""Integration coverage of the real Scanner, with in-test rule packs only."""

from __future__ import annotations

import json
import pickle
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from whalescan import api
from whalescan.config import Config
from whalescan.errors import UsageError
from whalescan.model import Diagnostic, Hit, Severity
from whalescan.rules.loader import RuleSet, load_raw_rules
from whalescan.suppress import Baseline
from whalescan.walker import Candidate, Loaded


def rule(**changes: object) -> dict[str, object]:
    raw: dict[str, object] = {
        "id": "WS-INJ-001",
        "title": "Unsafe fixture operation",
        "pack": "appsec/python",
        "severity": "high",
        "confidence": "high",
        "owner": "@whalesecurity",
        "applies_to": {"kind": ["code", "doc", "data", "agent-config"]},
        "match": {"regex": "DANGER"},
        "message": "Unsafe fixture operation found.",
        "references": ["https://example.com/security"],
    }
    raw.update(changes)
    return raw


def scanner(tmp_path: Path, *raws: dict[str, object], **overrides: object) -> api.Scanner:
    cfg = Config.default(tmp_path).with_overrides({"scan.baseline": "", **overrides})
    return api.Scanner(load_raw_rules(raws or [rule()]), cfg)


def test_public_exports_and_immutable(tmp_path: Path) -> None:
    import whalescan

    for name in whalescan.__all__:
        assert getattr(whalescan, name) is not None
    with pytest.raises(AttributeError):
        _ = whalescan.missing
    s = scanner(tmp_path)
    with pytest.raises(FrozenInstanceError):
        s.cfg = Config.default()  # type: ignore[misc]
    assert s.scan_text("DANGER", filename="app.py").exit_code() == 1
    assert callable(whalescan.redact)
    assert "REDACTED" in whalescan.redact("fixture")


def test_pipeline_deterministic_threadsafe(tmp_path: Path) -> None:
    s = scanner(tmp_path)
    (tmp_path / "b.py").write_text("DANGER\nDANGER", encoding="utf-8")
    (tmp_path / "a.py").write_text("DANGER", encoding="utf-8")
    result = s.scan_paths([tmp_path], jobs=1)
    assert [f.file for f in result.findings] == ["a.py", "b.py", "b.py"]
    assert len({f.fingerprint for f in result.findings}) == 3
    assert result.stats.files_scanned == 2
    assert result.stats.rules_evaluated == 2
    assert result.stats.by_severity == {"high": 3}
    with ThreadPoolExecutor(max_workers=4) as pool:
        outputs = list(pool.map(lambda _: s.scan_text("DANGER", filename="app.py").findings, range(20)))
    assert all(o == outputs[0] for o in outputs)


@pytest.mark.parametrize(
    "applies,filename,text,expected",
    [
        ({"kind": "iac"}, "app.py", "DANGER", 0),
        ({"lang": "python"}, "doc.md", "DANGER", 0),
        ({"tags_any": ["fastapi"]}, "app.py", "DANGER", 0),
        ({"tags_none": ["fastapi"]}, "app.py", "import fastapi\nDANGER", 0),
        ({"glob": ["*.py"]}, "<stdin>", "DANGER", 0),
        ({"glob": ["*.py"]}, "app.py", "DANGER", 1),
        ({"exclude_glob": ["*.py"]}, "app.py", "DANGER", 0),
        ({"max_bytes": 2}, "app.py", "DANGER", 0),
        ({"kind": "code"}, "app.min.js", "DANGER", 0),
        ({"include_minified": True}, "app.min.js", "DANGER", 1),
    ],
)
def test_applicability(
    tmp_path: Path, applies: dict[str, object], filename: str, text: str, expected: int
) -> None:
    assert (
        len(scanner(tmp_path, rule(applies_to=applies)).scan_text(text, filename=filename).findings)
        == expected
    )


def test_keyword_overlap_casefold_and_literal(tmp_path: Path) -> None:
    raws = [
        rule(id=f"WS-INJ-{i:03}", keywords=[kw], keywords_case=case)
        for i, (kw, case) in enumerate(
            [("abc", "sensitive"), ("bcd", "sensitive"), ("STRASSE", "insensitive"), ("a+b", "sensitive")],
            start=1,
        )
    ]
    s = scanner(tmp_path, *raws)
    assert len(s.scan_text("abcd Straße a+b DANGER", filename="app.py").findings) == 4
    assert not s.scan_text("aab DANGER", filename="app.py").findings


@pytest.mark.parametrize(
    "filters,text,expected",
    [
        ({"file_regex": "NEEDED"}, "DANGER", 0),
        ({"file_not_regex": "DANGER"}, "DANGER", 0),
        ({"line_not_regex": "SAFE"}, "DANGER SAFE\nDANGER", 1),
        ({"path_not_glob": ["*.py"]}, "DANGER", 0),
        ({"file_regex": "NEEDED"}, "NEEDED DANGER", 1),
    ],
)
def test_filters(tmp_path: Path, filters: dict[str, object], text: str, expected: int) -> None:
    assert (
        len(scanner(tmp_path, rule(filters=filters)).scan_text(text, filename="app.py").findings) == expected
    )


def test_cap_after_line_filters_and_ranges(tmp_path: Path) -> None:
    s = scanner(tmp_path, rule(max_hits_per_file=1, filters={"line_not_regex": "SAFE"}))
    r = s.scan_text("DANGER SAFE\nDANGER\nDANGER", filename="app.py")
    assert [f.line for f in r.findings] == [2]
    assert r.stats.capped == {"WS-INJ-001": 1}
    assert r.diagnostics[0].code == "rule-capped"
    assert s.scan_text("DANGER\nDANGER", filename="app.py", line_ranges=[(2, 2)]).findings[0].line == 2
    assert not s.scan_text("DANGER", filename="app.py", line_ranges=[]).findings


def test_output_threshold_does_not_change_fail_on(tmp_path: Path) -> None:
    r = scanner(tmp_path, **{"scan.min_severity": "critical"}).scan_text("DANGER", filename="app.py")
    assert not r.findings
    assert r.exit_code("high") == 1
    assert r.run.exit_code == 1
    assert r.exit_code("never") == 0
    assert (
        not scanner(tmp_path, rule(confidence="low"), **{"scan.min_confidence": "high"})
        .scan_text("DANGER", filename="app.py")
        .findings
    )


def test_suppressions_baseline_and_hard_exclusion(tmp_path: Path) -> None:
    s = scanner(tmp_path, **{"suppress.report_unused": True})
    r = s.scan_text(
        'DANGER # whalescan:ignore[WS-INJ-001] reason="intentional fixture risk"', filename="app.py"
    )
    assert r.stats.suppressed["inline"] == 1
    assert r.exit_code() == 0
    unused = s.scan_text(
        '# whalescan:ignore[WS-INJ-001] reason="intentional fixture risk"', filename="app.py"
    )
    assert any(d.code == "suppression-unused" for d in unused.diagnostics)
    base = Baseline.create(s.scan_text("DANGER", filename="old.py").findings, reason="accepted fixture risk")
    base.save(tmp_path / "baseline.json")
    with_base = scanner(tmp_path, **{"scan.baseline": "baseline.json"})
    assert with_base.scan_text("DANGER", filename="new.py").stats.suppressed["baseline"] == 1
    agt = scanner(tmp_path, rule(id="WS-AGT-001", pack="agentsec/injection"))
    assert (
        agt.scan_text(
            'DANGER # whalescan:ignore[WS-AGT-001] reason="attacker authored marker"', filename="AGENTS.md"
        ).exit_code()
        == 1
    )


def test_ignore_rules_and_binary_decode(tmp_path: Path) -> None:
    (tmp_path / ".whalescanignore").write_text("ignore.py\n#!rules WS-INJ-*\nscoped.py\n", encoding="utf-8")
    s = scanner(tmp_path)
    assert s.scan_text("DANGER", filename="ignore.py").stats.files_skipped["ignored"] == 1
    assert not s.scan_text("DANGER", filename="scoped.py").findings
    assert s.scan_text(b"\0", filename="image.png").stats.files_skipped["binary"] == 1
    r = s.scan_text(b"DANGER\xff", filename="app.py")
    assert r.findings and any(d.code == "decode-fallback-latin1" for d in r.diagnostics)
    uni = scanner(tmp_path, rule(match={"unicode": {"classes": ["ZW"]}}))
    assert uni.scan_text(b"\xff", filename="app.py").stats.rules_evaluated == 0
    assert s.scan_text("DANGER", filename=str(tmp_path / "app.py")).findings[0].file == "app.py"


def secret_rule(**changes: object) -> dict[str, object]:
    data = rule(
        id="WS-SEC-001",
        pack="secrets/generic",
        exposure_sensitive=False,
        match={"regex": {"pattern": "TOKEN=(?P<secret>[A-Za-z0-9]{12,32})", "secret_group": "secret"}},
        message="Fixture contains {{secret}} credential.",
    )
    data.update(changes)
    return data


def test_redaction_dedupe_metadata_and_cross_file(tmp_path: Path) -> None:
    value = "FixtureCredential123456"
    s = scanner(tmp_path, secret_rule(), secret_rule(id="WS-SEC-002", tags=["generic"]))
    (tmp_path / "a.env").write_text("TOKEN=" + value, encoding="utf-8")
    (tmp_path / "b.py").write_text("TOKEN=" + value, encoding="utf-8")
    r = s.scan_paths([tmp_path])
    assert len(r.findings) == 2
    assert r.findings[0].properties["related"] == ["WS-SEC-002"]
    for output in (r.to_json(), r.to_jsonl(), r.to_sarif(), r.to_markdown(), r.to_text()):
        assert value not in output
    assert "sha256:" in r.findings[0].snippet
    assert r.run._sweep is not None
    assert value not in r.run._sweep("reason includes " + value)
    assert "_sweep" not in r.to_json()
    example = s.scan_text("TOKEN=" + value, filename=".env.example")
    assert str(example.findings[0].confidence) == "low"
    allowed = scanner(tmp_path, secret_rule(), **{"secrets.allow_values": [value]})
    assert not allowed.scan_text("TOKEN=" + value, filename="app.py").findings


def test_secret_rule_without_group_and_reveal(tmp_path: Path) -> None:
    s = scanner(tmp_path, rule(id="WS-SEC-001", pack="secrets/generic", exposure_sensitive=False))
    assert "DANGER" not in s.scan_text("DANGER", filename="app.py").findings[0].snippet
    uni = scanner(tmp_path, rule(match={"unicode": {"classes": ["ZW"]}}))
    assert "[ZWSP]" in uni.scan_text("hello\u200bworld", filename="app.py").findings[0].snippet


def test_matcher_props_parse_diagnostics_severity_and_unused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def evaluate(expr: object, ctx: object, rule: object) -> list[Hit]:
        ctx.cache["diagnostics"] = [Diagnostic("warning", "parse-error", "fixture parse failed")]  # type: ignore[attr-defined]
        return [
            Hit.at(ctx, 0, 6, reachability="tainted", props={"exposure": "internet", "trace": [{"line": 1}]})
        ]  # type: ignore[arg-type]

    monkeypatch.setattr(api, "evaluate", evaluate)
    r = scanner(tmp_path).scan_text("DANGER", filename="app.py")
    assert r.findings[0].severity == Severity.CRITICAL
    assert any(d.code == "parse-error" for d in r.diagnostics)
    assert r.findings[0].properties["trace"] == [{"line": 1}]


def test_budget_between_rules_and_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ticks = iter([False, True])
    monkeypatch.setattr(api, "_expired", lambda _: next(ticks, True))
    r = scanner(tmp_path, rule(), rule(id="WS-INJ-002")).scan_text("DANGER", filename="app.py")
    assert len(r.findings) == 1
    assert r.run.truncated and r.stats.truncated
    assert any(d.code == "time-budget-exceeded" for d in r.diagnostics)
    assert r.exit_code() == 1  # callers inspect truncation and fail open, not a false clean result
    (tmp_path / "app.py").write_text("DANGER", encoding="utf-8")
    assert scanner(tmp_path).scan_paths([tmp_path]).run.truncated


def test_invalid_limits_and_missing_path(tmp_path: Path) -> None:
    s = scanner(tmp_path)
    with pytest.raises(UsageError):
        s.scan_text("DANGER", time_budget_ms=-1)
    with pytest.raises(UsageError):
        s.scan_paths([tmp_path], jobs=-1)
    with pytest.raises(UsageError):
        s.scan_paths([tmp_path / "missing"])
    assert api._deadline(1) is not None


def test_process_pool_real_and_deterministic(tmp_path: Path) -> None:
    s = scanner(tmp_path)
    for n in range(201):
        (tmp_path / f"file-{n:03}.py").write_text("DANGER\n" + "# padded\n" * 2400, encoding="utf-8")
    serial = s.scan_paths([tmp_path], jobs=1)
    parallel = s.scan_paths([tmp_path], jobs=2)
    assert serial.findings == parallel.findings
    assert serial.stats.to_dict() == parallel.stats.to_dict()
    assert serial.diagnostics == parallel.diagnostics


def test_batches_and_worker_guard(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    batches = api._batches([Candidate(str(n), None, 1) for n in range(130)])
    assert [len(b) for b in batches] == [64, 64, 2]
    assert len(api._batches([Candidate("a", None, 2 << 20), Candidate("b", None, 1)])) == 2
    assert not api._batches([])
    monkeypatch.setattr(api, "_WORKER_RULES", None)
    with pytest.raises(RuntimeError):
        api._batch_worker([], None)
    api._init_worker(RuleSet([]).to_dict(), Config.default(tmp_path))
    monkeypatch.setattr(api, "_expired", lambda _: True)
    assert not api._batch_worker([Candidate("a", None, 1)], 1)


def test_load_rules_and_hook_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from whalescan.rules import loader

    empty_bundle = tmp_path / "bundle.json"
    empty_bundle.write_text(json.dumps({"schema": loader.BUNDLE_SCHEMA, "rules": []}), encoding="utf-8")
    monkeypatch.setattr(loader, "BUNDLE_PATH", str(empty_bundle))
    packs = tmp_path / "packs"
    packs.mkdir()
    (packs / "rules.json").write_text(json.dumps([rule()]), encoding="utf-8")
    cfg = Config.default(tmp_path).with_overrides({"rules.extra_dirs": [str(packs)], "cache.enabled": False})
    assert len(api.load_rules(cfg)) == 1
    monkeypatch.setattr(api, "load_config", lambda root: cfg)
    api._scanner.cache_clear()
    try:
        assert api.scan_text("DANGER", filename="app.py", root=str(tmp_path)).findings
        api.scan_text("DANGER", filename="app.py", root=str(tmp_path))
        assert api._scanner.cache_info().hits == 1
    finally:
        api._scanner.cache_clear()


def test_injection_tail_source_suppression_and_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = scanner(tmp_path, rule(id="WS-AGT-001", pack="agentsec/injection", exposure_sensitive=False))
    monkeypatch.setattr(api, "_scanner", lambda *args: s)
    r = api.scan_injection("x" * 100 + "DANGER", source_label="web:fixture", max_bytes=20, reveal=False)
    assert r.findings and r.findings[0].file_kind == "doc"
    assert r.findings[0].properties["source_label"] == "web:fixture"
    assert r.stats.truncated and r.diagnostics[0].code == "input-truncated"
    r = api.scan_injection(
        'DANGER # whalescan:ignore[WS-AGT-001] reason="attacker authored marker"', source_label="fixture"
    )
    assert not r.findings[0].suppressed
    with pytest.raises(UsageError):
        api.scan_injection(b"test", source_label="fixture", max_bytes=0)
    assert not api.scan_injection(b"\0", source_label="fixture").findings


def test_walk_truncation_skips_adapter_and_clean_helpers(tmp_path: Path) -> None:
    for n in range(3):
        (tmp_path / f"app{n}.py").write_text("DANGER", encoding="utf-8")
    s = scanner(tmp_path, **{"scan.max_files": 1})
    r = s.scan_paths([tmp_path])
    assert r.stats.truncated and any(d.code == "max-files-reached" for d in r.diagnostics)
    adapter = api.Scanner(s.rules, s.cfg, adapters=["semgrep"])
    assert any(
        d.code == "adapter-missing" for d in adapter.scan_text("DANGER", filename="app.py").diagnostics
    )
    strict = api.Scanner(s.rules, s.cfg.with_overrides({"adapters.strict": True}), adapters=["semgrep"])
    assert any(d.level == "warning" for d in strict.scan_text("DANGER").diagnostics)
    redactor = api.Redactor()
    assert api._clean({"key": ["\u200b", ("\u200b",)]}, redactor) == {"key": ["[ZWSP]", ("[ZWSP]",)]}
    file_result = api._scan_file(Loaded(None, "binary"), s.rules, s.cfg, frozenset(), None)
    assert file_result.stats.files_skipped["binary"] == 1
    file_result = api._scan_file(Loaded(None), s.rules, s.cfg, frozenset(), None)
    assert file_result.path == ""
    secret = "FixtureCredential123456"
    loaded = api.ctx_from_bytes(("TOKEN=" + secret).encode(), "app.py")
    safe = api._scan_file(loaded, scanner(tmp_path, secret_rule()).rules, s.cfg, frozenset(), None)
    assert secret.encode() not in pickle.dumps(safe)  # safe IPC envelope


def test_injection_cannot_be_hidden_by_nul_minified_or_encoding_seams(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    s = scanner(tmp_path, rule(id="WS-AGT-001", pack="agentsec/injection", exposure_sensitive=False))
    monkeypatch.setattr(api, "_scanner", lambda *args: s)
    assert api.scan_injection(b"\0DANGER", source_label="fixture").findings
    assert api.scan_injection("x" * 30000 + "DANGER", source_label="fixture", max_bytes=40000).findings
    data = ("padding" * 30 + "DANGER").encode("utf-16")
    result = api.scan_injection(data, source_label="fixture", max_bytes=30)
    assert result.findings and result.stats.truncated and result.stats.bytes_scanned == 30
    unicode_scanner = scanner(
        tmp_path,
        rule(
            id="WS-AGT-002",
            pack="agentsec/injection",
            applies_to={"kind": "doc", "max_bytes": 18},
            match={"unicode": {"classes": ["ZW"]}},
        ),
    )
    monkeypatch.setattr(api, "_scanner", lambda *args: unicode_scanner)
    result = api.scan_injection("é" * 100 + "payload\u200b", source_label="fixture", max_bytes=18)
    assert result.findings and result.stats.bytes_scanned == 18
    assert "[ZWSP]" in result.findings[0].snippet
    assert api._injection_input(b"\xff" * 40, 10)[1]
    union = scanner(tmp_path, rule(match={"any": [{"regex": "DANGER"}, {"unicode": {"classes": ["ZW"]}}]}))
    assert union.scan_text(b"\xffDANGER", filename="app.py").findings


def test_partial_internal_result_and_private_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from whalescan.errors import InternalError, RuleError

    real = api.evaluate

    def fail(expr: object, ctx: object, rule: object) -> object:
        if rule.id == "WS-INJ-002":
            raise RuntimeError("sensitive exception text")
        return real(expr, ctx, rule)

    monkeypatch.setattr(api, "evaluate", fail)
    with pytest.raises(InternalError) as raised:
        scanner(tmp_path, rule(), rule(id="WS-INJ-002")).scan_text("DANGER", filename="app.py")
    result = raised.value.partial_result
    assert result is not None and len(result.findings) == 1
    assert result.run.error["type"] == "RuntimeError"
    assert result.run.exit_code == 3
    assert "WS-INJ-001" in result.run._profile
    assert "_profile" not in result.to_json()
    assert "sensitive exception text" not in result.to_json()

    def invalid(*args: object) -> object:
        raise RuleError("invalid rule")

    monkeypatch.setattr(api, "evaluate", invalid)
    with pytest.raises(RuleError):
        scanner(tmp_path).scan_text("DANGER", filename="app.py")


def test_diff_filter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "a.py").write_text("DANGER\nDANGER", encoding="utf-8")
    (tmp_path / "b.py").write_text("DANGER", encoding="utf-8")
    monkeypatch.setattr(api, "git_changed_files", lambda root, ref: ["a.py"])
    monkeypatch.setattr(api, "git_diff_hunks", lambda root, ref: {"a.py": [(2, 2)]})
    r = scanner(tmp_path, **{"scan.diff_lines_only": True}).scan_paths([tmp_path], diff_ref="HEAD")
    assert [(f.file, f.line) for f in r.findings] == [("a.py", 2)]
