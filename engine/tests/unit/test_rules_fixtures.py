"""Tests for whalescan.rules.fixtures: fixture discovery and expectations for `rules test` (spec §2.6)."""

from __future__ import annotations

import json
import os
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from whalescan.rules import fixtures as F

RID = "WS-INJ-003"


def put(path: Any, content: str | bytes) -> None:
    os.makedirs(os.path.dirname(str(path)), exist_ok=True)
    mode = "wb" if isinstance(content, bytes) else "w"
    with open(path, mode) as fh:
        fh.write(content)


# ------------------------------------------------------------------------------------------ annotations


def test_parse_expectations_comment_styles() -> None:
    text = "\n".join(
        [
            "subprocess.run(cmd, shell=True)  # expect: WS-INJ-003",
            "x = 1",
            "exec(q) // expect: WS-INJ-003, WS-INJ-004",
            "SELECT 1; -- expect:WS-SQL-001",
            "<p>hi</p> <!-- expect: WS-AGT-001 -->",
            "# expect: not-an-id",
            "#   expect:\tWS-INJ-003 ,WS-INJ-009",
        ]
    )
    assert F.parse_expectations(text) == {
        "WS-INJ-003": frozenset({1, 3, 7}),
        "WS-INJ-004": frozenset({3}),
        "WS-SQL-001": frozenset({4}),
        "WS-AGT-001": frozenset({5}),
        "WS-INJ-009": frozenset({7}),
    }


def test_only_newline_breaks_lines() -> None:
    text = "a\r\nb # expect: WS-A-001\rstill line 2 same\n# expect: WS-B-001"
    assert F.parse_expectations(text) == {"WS-A-001": frozenset({2}), "WS-B-001": frozenset({3})}


def test_no_annotations() -> None:
    assert F.parse_expectations("print('expect: nothing')\n") == {}


def test_parse_directive() -> None:
    assert (
        F.parse_directive("# whalescan-fixture: path=.github/workflows/pr.yml\non: push\n")
        == ".github/workflows/pr.yml"
    )
    assert F.parse_directive("<!-- whalescan-fixture: path=CLAUDE.md -->\n") == "CLAUDE.md"
    assert F.parse_directive("<!-- whalescan-fixture: path=AGENTS.md-->\n") == "AGENTS.md"
    assert F.parse_directive("// whalescan-fixture: path=src/app.ts\r\n") == "src/app.ts"
    assert F.parse_directive("x\n# whalescan-fixture: path=a.yml\n") is None  # first line only
    assert F.parse_directive("") is None
    for bad in ("/etc/passwd", "../x.yml", "a/../../b", "a//b"):
        with pytest.raises(F.FixtureError):
            F.parse_directive(f"# whalescan-fixture: path={bad}\n")


def test_decode_boms() -> None:
    assert F.decode(b"\xef\xbb\xbfabc") == "abc"
    assert F.decode("# expect: WS-A-001".encode("utf-16-le").join([b"\xff\xfe", b""])) == "# expect: WS-A-001"
    assert F.decode(b"\xfe\xff" + "x".encode("utf-16-be")) == "x"
    assert F.decode(b"\xff\xfe\x00\x00" + "y".encode("utf-32-le")) == "y"
    assert F.decode(b"\xff") == "�"


@given(
    st.lists(st.sampled_from(["WS-A-001", "WS-B-002", "WS-C-D-003"]), min_size=1, max_size=3),
    st.integers(0, 20),
    st.sampled_from(["#", "//", "--", "<!--"]),
)
def test_annotation_roundtrip(ids: list[str], blank_lines: int, leader: str) -> None:
    text = "\n" * blank_lines + f"code() {leader} expect: {', '.join(ids)}\n"
    assert F.parse_expectations(text) == {i: frozenset({blank_lines + 1}) for i in set(ids)}


# ------------------------------------------------------------------------------------------ discovery


def test_discover_auto(tmp_path: Any) -> None:
    d = tmp_path / RID
    put(d / "pos.py", "subprocess.run(cmd, shell=True)  # expect: WS-INJ-003\n")
    put(d / "pos_flask.py", "os.system(request.args['x'])\n")
    put(d / "neg.py", "subprocess.run(['ls'])\n")
    put(d / "neg-2.txt", "nothing\n")
    put(d / ".hidden.py", "x")
    put(d / "README.md", "docs")
    put(d / "positive", "no extension: not a fixture")
    fs = F.discover(tmp_path, RID)
    assert fs.problems == ()
    assert [f.name for f in fs.pos] == [f"{RID}/pos.py", f"{RID}/pos_flask.py"]
    assert [f.name for f in fs.neg] == [f"{RID}/neg-2.txt", f"{RID}/neg.py"]
    assert fs.complete
    first = fs.pos[0]
    assert (
        first.polarity == "pos"
        and first.virtual_path == "pos.py"
        and first.expected_lines() == frozenset({1})
    )
    assert fs.pos[1].expected_lines() is None and not fs.pos[1].annotated
    assert first.text.startswith("subprocess.run") and first.data.endswith(b"\n")
    assert len(fs.all) == 4


def test_directive_sets_the_virtual_path(tmp_path: Any) -> None:
    put(tmp_path / "WS-GHA-001" / "pos.yml", "# whalescan-fixture: path=.github/workflows/pr.yml\non: push\n")
    put(tmp_path / "WS-GHA-001" / "neg.yml", "on: push\n")
    fs = F.discover(tmp_path, "WS-GHA-001")
    assert fs.pos[0].virtual_path == ".github/workflows/pr.yml"
    assert fs.neg[0].virtual_path == "neg.yml"


def test_sidecar_expectations(tmp_path: Any) -> None:
    d = tmp_path / "WS-AGT-MCP-010"
    put(d / "pos.json", '{\n  "mcpServers": {\n    "x": {\n      "command": "npx"\n    }\n  }\n}\n')
    put(d / "pos2.json", "{}")
    put(d / "neg.json", "{}")
    put(
        d / "expect.json",
        json.dumps(
            {"pos.json": {"WS-AGT-MCP-010": [4]}, "pos2.json": {"path": ".mcp.json", "WS-AGT-MCP-010": [1]}}
        ),
    )
    fs = F.discover(tmp_path, "WS-AGT-MCP-010")
    assert fs.problems == ()
    assert fs.pos[0].expected_lines() == frozenset({4})
    assert fs.pos[1].virtual_path == ".mcp.json"
    assert [f.name for f in fs.all] == [
        "WS-AGT-MCP-010/pos.json",
        "WS-AGT-MCP-010/pos2.json",
        "WS-AGT-MCP-010/neg.json",
    ]


def test_sidecar_and_inline_annotations_merge(tmp_path: Any) -> None:
    d = tmp_path / RID
    put(d / "pos.py", "a\nb  # expect: WS-INJ-003\n")
    put(d / "neg.py", "")
    put(d / "expect.json", json.dumps({"pos.py": {RID: [1]}}))
    fs = F.discover(tmp_path, RID)
    assert fs.pos[0].expected_lines() == frozenset({1, 2})


@pytest.mark.parametrize(
    ("sidecar", "message"),
    [
        ("{bad", "invalid JSON"),
        ("[]", "expected an object"),
        (json.dumps({"../pos.py": {RID: [1]}}), "bad fixture file name"),
        (json.dumps({"pos.py": [1]}), "expected an object"),
        (json.dumps({"pos.py": {"not-an-id": [1]}}), "is not a rule ID"),
        (json.dumps({"pos.py": {RID: [0]}}), "line numbers"),
        (json.dumps({"pos.py": {RID: [True]}}), "line numbers"),
        (json.dumps({"pos.py": {RID: "4"}}), "line numbers"),
        (json.dumps({"pos.py": {"path": "../x"}}), "`path`"),
    ],
)
def test_bad_sidecars_are_problems(tmp_path: Any, sidecar: str, message: str) -> None:
    d = tmp_path / RID
    put(d / "pos.py", "x\n")
    put(d / "neg.py", "y\n")
    put(d / "expect.json", sidecar)
    fs = F.discover(tmp_path, RID)
    assert any(message in p for p in fs.problems), fs.problems
    assert not fs.complete


def test_missing_directories(tmp_path: Any) -> None:
    fs = F.discover(tmp_path / "nope", RID)
    assert fs.problems == (f"fixtures directory not found: {tmp_path / 'nope'}",)
    fs = F.discover(tmp_path, RID)
    assert fs.problems[0] == f"no fixture directory {RID}"
    assert not fs.complete


def test_missing_polarity(tmp_path: Any) -> None:
    put(tmp_path / RID / "pos.py", "x\n")
    assert F.check_fixture_dir(tmp_path, RID) == [f"no neg* fixture for {RID}"]
    put(tmp_path / "WS-INJ-004" / "neg.py", "x\n")
    assert F.check_fixture_dir(tmp_path, "WS-INJ-004") == ["no pos* fixture for WS-INJ-004"]


def test_neg_fixture_with_annotations_is_a_problem(tmp_path: Any) -> None:
    put(tmp_path / RID / "pos.py", "x\n")
    put(tmp_path / RID / "neg.py", "y  # expect: WS-INJ-003\n")
    fs = F.discover(tmp_path, RID)
    assert fs.problems == (f"{RID}/neg.py: a neg fixture must not carry expect annotations for {RID}",)


def test_bad_directive_is_a_problem(tmp_path: Any) -> None:
    put(tmp_path / RID / "pos.py", "# whalescan-fixture: path=../../etc/passwd\n")
    put(tmp_path / RID / "neg.py", "")
    fs = F.discover(tmp_path, RID)
    assert any("must be relative" in p for p in fs.problems)
    assert not fs.pos


def test_explicit_fixture_spec(tmp_path: Any) -> None:
    put(tmp_path / "shared" / "vuln.py", "os.system(x)  # expect: WS-INJ-003\n")
    put(tmp_path / "shared" / "safe.py", "print(1)\n")
    fs = F.discover(tmp_path, RID, {"pos": ["shared/vuln.py"], "neg": ["shared/safe.py"]})
    assert fs.problems == ()
    assert [f.name for f in fs.pos] == ["shared/vuln.py"] and [f.name for f in fs.neg] == ["shared/safe.py"]
    fs = F.discover(tmp_path, RID, {"pos": ["../outside.py"], "neg": ["shared/missing.py"]})
    assert any("must be relative" in p for p in fs.problems)
    assert any("shared/missing.py: cannot read" in p for p in fs.problems)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_symlinks_leaving_the_root_are_refused(tmp_path: Any) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("AKIA...")
    root = tmp_path / "fixtures"
    put(root / RID / "neg.py", "x\n")
    os.symlink(secret, root / RID / "pos.py")
    fs = F.discover(root, RID)
    assert any("outside the fixtures directory" in p for p in fs.problems)
    assert not fs.pos


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_symlinks_inside_the_root_are_allowed(tmp_path: Any) -> None:
    put(tmp_path / "shared" / "p.py", "x\n")
    put(tmp_path / RID / "neg.py", "y\n")
    os.symlink(tmp_path / "shared" / "p.py", tmp_path / RID / "pos.py")
    fs = F.discover(tmp_path, RID)
    assert fs.problems == () and fs.pos[0].data == b"x\n"


def test_oversized_and_special_files(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(F, "MAX_FIXTURE_BYTES", 10)
    put(tmp_path / RID / "pos.py", "x" * 11)
    os.makedirs(tmp_path / RID / "neg.d")
    put(tmp_path / RID / "neg.py", "ok")
    fs = F.discover(tmp_path, RID)
    assert any("larger than 10 bytes" in p for p in fs.problems)
    assert [f.name for f in fs.neg] == [f"{RID}/neg.py"]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_fifo_fixture_does_not_hang(tmp_path: Any) -> None:
    put(tmp_path / RID / "neg.py", "ok")
    os.mkfifo(tmp_path / RID / "pos.fifo")
    fs = F.discover(tmp_path, RID)
    assert any("not a regular file" in p or "cannot read" in p for p in fs.problems)


def test_fixture_count_is_capped(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(F, "MAX_FIXTURES_PER_RULE", 3)
    for i in range(5):
        put(tmp_path / RID / f"pos{i}.py", "x")
    fs = F.discover(tmp_path, RID)
    assert len(fs.all) == 3
    assert any("more than 3 fixtures" in p for p in fs.problems)


def test_rule_id_is_validated(tmp_path: Any) -> None:
    with pytest.raises(F.FixtureError):
        F.discover(tmp_path, "../etc")
    with pytest.raises(F.FixtureError):
        F.fixture_dir(tmp_path, "WS-INJ-003/../x")


# ------------------------------------------------------------------------------------------ evaluation


def fixture(polarity: F.Polarity, expect: dict[str, frozenset[int]] | None = None) -> F.Fixture:
    return F.Fixture(RID, polarity, "/x", f"{RID}/{polarity}.py", f"{polarity}.py", b"", expect or {})


def test_evaluate_pos_without_annotations() -> None:
    assert F.evaluate(fixture("pos"), [3, 3, 1]).ok
    res = F.evaluate(fixture("pos"), [])
    assert not res.ok and res.message == "expected at least one hit, got none"
    assert F.evaluate(fixture("pos"), [3, 3, 1]).hit_lines == (1, 3)


def test_evaluate_pos_with_annotations() -> None:
    fx = fixture("pos", {RID: frozenset({2, 5})})
    assert F.evaluate(fx, [5, 2, 2]).ok
    res = F.evaluate(fx, [2, 7])
    assert not res.ok
    assert res.message == "hit lines 2, 7 != expected 2, 5 (missing 5; unexpected 7)"
    assert F.evaluate(fx, []).message == "hit lines none != expected 2, 5 (missing 2, 5)"


def test_evaluate_annotations_for_other_rules_only() -> None:
    res = F.evaluate(fixture("pos", {"WS-INJ-004": frozenset({1})}), [1])
    assert not res.ok and "none for WS-INJ-003" in res.message
    assert F.evaluate(fixture("pos", {"WS-INJ-004": frozenset({1})}), [1], rule_id="WS-INJ-004").ok


def test_evaluate_neg() -> None:
    assert F.evaluate(fixture("neg"), []).ok
    res = F.evaluate(fixture("neg"), [4, 4])
    assert not res.ok and res.message == "expected no hits, got 2 at line(s) 4"


@given(st.sets(st.integers(1, 50), min_size=1, max_size=6), st.sets(st.integers(1, 50), max_size=6))
def test_evaluate_exact_line_semantics(expected: set[int], hits: set[int]) -> None:
    res = F.evaluate(fixture("pos", {RID: frozenset(expected)}), sorted(hits))
    assert res.ok == (hits == expected)
