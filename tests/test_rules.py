"""Seed contracts: exact public positions, schema oracle, precision guards and redaction."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
from whalescan.api import Scanner
from whalescan.config import Config
from whalescan.matchers.base import evaluate
from whalescan.model import FileCtx
from whalescan.rules import fixtures
from whalescan.rules.loader import RuleSet, default_yaml_loader, load
from whalescan.rules.schema import RULE_SCHEMA

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures"
RULES = load(bundle_path=ROOT / "rules/bundle.json")
CASES = [(r, fx) for r in RULES for fx in fixtures.discover(FIXTURES, r.id).all]
POSITIONS = {
    "WS-INJ-001/pos.py": [(2, 8), (3, 8), (4, 8), (5, 8)],
    "WS-INJ-003/pos.py": [(2, 1), (3, 1), (4, 1)],
    "WS-INJ-009/pos.py": [(2, 1), (3, 1)],
    "WS-DES-001/pos.py": [(2, 1), (3, 1), (4, 1)],
    "WS-DES-002/pos.py": [(2, 1), (3, 1), (4, 1)],
    "WS-CRY-005/pos.py": [(2, 45), (3, 1)],
    "WS-SEC-AWS-001/pos.env": [(2, 19)],
    "WS-SEC-GH-001/pos.env": [(2, 14)],
    "WS-SEC-DB-002/pos.env": [(2, 14), (3, 14)],
    "WS-SEC-GEN-001/pos.env": [(2, 10), (3, 16)],
    "WS-SEC-PK-001/pos.pem": [(2, 1)],
    "WS-SEC-PK-001/pos_escaped.py": [(2, 8)],
    "WS-SEC-PK-001/pos_encrypted.pem": [(2, 1)],
    "WS-SEC-PK-001/pos_putty.ppk": [(2, 1)],
    "WS-AGT-UNI-001/pos.txt": [(2, 8)],
    "WS-AGT-UNI-001/pos_emoji.txt": [(2, 7)],
    "WS-AGT-UNI-002/pos.txt": [(2, 3), (3, 5), (4, 3)],
    "WS-AGT-UNI-002/pos_run.txt": [(2, 5)],
    "WS-AGT-UNI-003/pos.txt": [(2, 7), (2, 17), (3, 5)],
    "WS-AGT-UNI-003/pos_marks.txt": [(2, 6), (2, 11)],
    "WS-AGT-OVR-001/pos.txt": [(2, 1), (3, 1), (4, 1)],
    "WS-AGT-OVR-001/pos_wrapped.txt": [(2, 1)],
    "WS-SEC-GEN-001/pos_json.json": [(2, 10)],
}


@pytest.mark.parametrize(("rule", "fixture"), CASES, ids=[fx.name for _, fx in CASES])
def test_rule_fixture(rule, fixture) -> None:
    cfg = Config.default(ROOT).with_overrides(
        {
            "scan.baseline": "",
            "scan.min_severity": "info",
            "scan.min_confidence": "low",
        }
    )
    scanner = Scanner(RuleSet([rule]), cfg)
    result = scanner.scan_text(fixture.data, filename=fixture.virtual_path)
    assert not result.diagnostics
    assert fixtures.evaluate(fixture, [f.line for f in result.findings]).ok
    actual = [(f.line, f.col) for f in result.findings]
    assert actual == POSITIONS.get(fixture.name, [])
    assert all(f.rule_id == rule.id and f.suppressed is None for f in result.findings)
    if fixture.polarity == "pos":
        assert fixture.annotated and fixture.name in POSITIONS
    # Every positive must remain correct with Windows line endings too.
    if fixture.polarity == "pos":
        crlf = scanner.scan_text(fixture.data.replace(b"\n", b"\r\n"), filename=fixture.virtual_path)
        assert [(f.line, f.col) for f in crlf.findings] == actual


def test_pack_schema_agrees_with_reference_validator() -> None:
    for path in sorted((ROOT / "rules").rglob("*.yaml")):
        for doc in default_yaml_loader(path.read_text(encoding="utf-8")):
            for raw in doc:
                jsonschema.Draft202012Validator(RULE_SCHEMA).validate(raw)


def test_fixture_sets_are_complete_and_bundles_identical() -> None:
    assert len(RULES) == 15
    for rule in RULES:
        discovered = fixtures.discover(FIXTURES, rule.id)
        assert discovered.complete and not discovered.problems
        assert rule.fix and rule.owner and rule.references
    data = (ROOT / "rules/bundle.json").read_bytes()
    assert data == (ROOT / "engine/src/whalescan/rules/bundle.json").read_bytes()
    assert b"\r" not in data and data.endswith(b"\n")
    doc = json.loads(data)
    assert doc["bundle_hash"] == RULES.bundle_hash
    assert [r["id"] for r in doc["rules"]] == sorted(r.id for r in RULES)


@pytest.mark.parametrize(
    ("rule", "fixture"),
    [c for c in CASES if c[0].pack.startswith("secrets/") and c[1].polarity == "pos"],
    ids=lambda x: getattr(x, "name", getattr(x, "id", "case")),
)
def test_no_secret_fragments_in_any_public_surface(rule, fixture) -> None:
    ctx = FileCtx(fixture.virtual_path, fixture.text)
    hits = evaluate(rule.match, ctx, rule)
    spans = [span for hit in hits for span in (hit.secret_spans or [(hit.start, hit.end)])]
    values = [ctx.text[start:end] for start, end in spans]
    assert values
    if rule.id == "WS-SEC-PK-001":
        values = [
            line.strip()
            for value in values
            for line in value.replace(r"\n", "\n").split("\n")
            if line.strip() and not line.strip().startswith("-----")
        ]
    # Public rule text describes the format; common words such as 'password' are not leaks.
    public_text = " ".join((rule.title, rule.message, rule.fix))
    bad = {
        value[i : i + 8]
        for value in values
        for i in range(len(value) - 7)
        if len(set(value[i : i + 8])) >= 4 and value[i : i + 8] not in public_text
    }
    result = Scanner(RULES, Config.default(ROOT).with_overrides({"scan.min_severity": "info"})).scan_text(
        fixture.data,
        filename=fixture.virtual_path,
    )
    outputs = [
        result.to_text(),
        result.to_json(),
        result.to_jsonl(),
        result.to_sarif(),
        result.to_markdown(),
        repr(result.findings),
    ]
    for output in outputs:
        if any(output[i : i + 8] in bad for i in range(len(output) - 7)):
            pytest.fail("raw fixture secret fragment leaked (value intentionally not printed)")
