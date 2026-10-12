"""Release compiler gates and byte determinism use minimal synthetic packs."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from whalescan.errors import RuleError
from whalescan.rules.loader import default_yaml_loader
from whalescan.rules.testing import redos_check

from tools import build_bundle as builder

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    rules = tmp_path / "rules"
    rules.mkdir()
    # JSON-shaped YAML exercises the stdlib parser without a YAML emitter dependency.
    raw = {
        "id": "WS-INJ-900",
        "title": "Synthetic unsafe operation",
        "pack": "appsec/injection",
        "severity": "high",
        "confidence": "high",
        "owner": "@whalesecurity/appsec",
        "applies_to": {"kind": "code", "lang": "python"},
        "match": {"regex": "DANGER"},
        "message": "Synthetic unsafe operation found.",
        "references": ["https://example.com/security"],
    }
    (rules / "pack.yaml").write_text(json.dumps([raw]), encoding="utf-8")
    fixtures = tmp_path / "tests/fixtures/WS-INJ-900"
    fixtures.mkdir(parents=True)
    (fixtures / "pos.py").write_text("DANGER # expect: WS-INJ-900\n", encoding="utf-8")
    (fixtures / "neg.py").write_text("safe\n", encoding="utf-8")
    return tmp_path


def test_determinism_stale_detection_and_both_committed_copies(tree: Path, capsys) -> None:
    assert builder.main(["--root", str(tree), "--check"]) == 1
    assert not (tree / builder.TARGETS[0]).exists()
    first = builder.compile_bundle(tree)
    assert builder.main(["--root", str(tree)]) == 0
    assert first == builder.compile_bundle(tree)
    assert builder.main(["--root", str(tree), "--check"]) == 0
    for target in builder.TARGETS:
        path = tree / target
        path.write_bytes(path.read_bytes() + b" ")
        assert builder.main(["--root", str(tree), "--check"]) == 1
        assert path.read_bytes().endswith(b" ")  # --check never repairs it
        assert builder.main(["--root", str(tree)]) == 0
    elsewhere = tree / "elsewhere"
    elsewhere.mkdir()
    shutil.copytree(tree / "rules", elsewhere / "rules")
    shutil.copytree(tree / "tests", elsewhere / "tests")
    assert first == builder.compile_bundle(elsewhere)
    assert "stale bundle" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("severity", "urgent", "schema"),
        ("match", {"regex": "("}, "does not compile"),
        ("match", {"regex": "(a+)+!"}, "nested unbounded"),
        ("match", {"regex": "a*"}, "empty string"),
        ("match", {"regex": "BEGIN[^!]*!"}, "warnings are errors"),
    ],
)
def test_schema_and_lint_failures_never_write(tree: Path, field: str, value: object, error: str) -> None:
    path = tree / "rules/pack.yaml"
    raw = json.loads(path.read_text())
    raw[0][field] = value
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(RuleError, match=error):
        builder.compile_bundle(tree)
    assert builder.main(["--root", str(tree)]) == 1
    assert not (tree / builder.TARGETS[0]).exists()


def test_duplicate_ids_fail(tree: Path) -> None:
    shutil.copyfile(tree / "rules/pack.yaml", tree / "rules/duplicate.yaml")
    with pytest.raises(RuleError, match="duplicate"):
        builder.compile_bundle(tree)


@pytest.mark.parametrize("polarity", ["pos", "neg"])
def test_missing_fixtures_fail(tree: Path, polarity: str) -> None:
    (tree / f"tests/fixtures/WS-INJ-900/{polarity}.py").unlink()
    with pytest.raises(RuleError, match="no " + polarity):
        builder.compile_bundle(tree)


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("pos.py", "safe"),
        ("neg.py", "DANGER"),
        ("pos.py", "DANGER\n# expect: WS-INJ-900\n"),
    ],
)
def test_fixture_verdict_failures(tree: Path, name: str, content: str) -> None:
    (tree / "tests/fixtures/WS-INJ-900" / name).write_text(content, encoding="utf-8")
    with pytest.raises(RuleError, match="rule contract failed"):
        builder.compile_bundle(tree)


def test_timing_failure_is_a_build_failure(tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(builder, "redos_checks", lambda rules: iter([("WS-INJ-900", False, "ReDoS budget")]))
    with pytest.raises(RuleError, match="ReDoS budget"):
        builder.compile_bundle(tree)
    assert not redos_check("(a+)+!", ())  # worker is killed, not the test process


def test_malformed_yaml_missing_source_and_empty_sources(tree: Path) -> None:
    pack = tree / "rules/pack.yaml"
    pack.write_text("- [", encoding="utf-8")
    assert builder.main(["--root", str(tree)]) == 1
    pack.unlink()
    with pytest.raises(RuleError, match="no YAML rules"):
        builder.compile_bundle(tree)
    with pytest.raises(RuleError):
        builder.compile_bundle(tree / "missing")


def test_source_order_and_yaml_formatting_do_not_change_content_hash(tree: Path) -> None:
    first = json.loads(builder.compile_bundle(tree))
    pack = tree / "rules/pack.yaml"
    raw = default_yaml_loader(pack.read_text())[0]
    pack.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
    assert json.loads(builder.compile_bundle(tree))["bundle_hash"] == first["bundle_hash"]


def test_bundle_checkout_preserves_lf_with_autocrlf(tmp_path: Path) -> None:
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is required to exercise checkout line endings")
    repository = tmp_path / "repository"
    repository.mkdir()
    shutil.copyfile(ROOT / ".gitattributes", repository / ".gitattributes")
    for target in builder.TARGETS:
        destination = repository / target
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / target).read_bytes())

    def run(*args: str) -> None:
        subprocess.run(
            [git, "-c", "core.autocrlf=true", "-C", str(repository), *args],
            capture_output=True,
            check=True,
        )

    run("init")
    run("add", ".gitattributes", *builder.TARGETS)
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    run("checkout-index", "--all", "--prefix=" + checkout.as_posix() + "/")
    for target in builder.TARGETS:
        data = (checkout / target).read_bytes()
        assert data == (ROOT / target).read_bytes()
        assert b"\r" not in data and data.endswith(b"\n")


def test_checked_in_bundle_is_reproducible() -> None:
    assert builder.main(["--check"]) == 0
