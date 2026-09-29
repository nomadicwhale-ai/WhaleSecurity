import datetime as dt

import pytest

from whalescan.config import SuppressConfig
from whalescan.errors import ConfigError, UsageError
from whalescan.model import Confidence, FileCtx, Finding, Severity
from whalescan.suppress import Baseline, inline_allowed, parse_markers

TODAY = dt.date(2026, 9, 29)
R = 'reason="fixed argv tuple, reviewed"'


def idx(text, **cfg):
    ctx = FileCtx(path="a.py", text=text, kind="code")
    return parse_markers(ctx, SuppressConfig(**cfg), TODAY)


def test_trailing_marker_covers_its_own_line():
    i = idx(f"x = 1\nrun(a, shell=True)  # whalescan:ignore[WS-INJ-003] {R}\ny = 2\n")
    assert i.match(2, "WS-INJ-003") and not i.match(3, "WS-INJ-003") and not i.match(2, "WS-INJ-004")


def test_standalone_marker_covers_next_nonblank_line():
    i = idx(f"# whalescan:ignore[WS-A-001] {R}\n\n\nbad()\nother()\n")
    assert i.match(4, "WS-A-001") and not i.match(1, "WS-A-001") and not i.match(5, "WS-A-001")


def test_next_line_form_and_yaml_comment():
    i = idx(
        '# whalescan:ignore-next-line[WS-K8S-001] reason="node-exporter needs host access" ticket=PLAT-412\n  privileged: true\n'
    )
    m = i.match(2, "WS-K8S-001")
    assert m and m.ticket == "PLAT-412"


def test_prefix_glob_ids_and_multiple_ids():
    i = idx(f"x  # whalescan:ignore[WS-SEC-*, WS-INJ-001] {R}\n")
    assert i.match(1, "WS-SEC-AWS-001") and i.match(1, "WS-INJ-001") and not i.match(1, "WS-INJ-002")


def test_missing_or_short_reason_is_invalid_and_does_not_suppress():
    for tail in ("", ' reason="short"'):
        i = idx(f"x  # whalescan:ignore[WS-A-001]{tail}\n")
        assert not i.match(1, "WS-A-001")
        assert [d.code for d in i.diagnostics] == ["suppression-invalid"]


def test_reason_not_required_when_configured():
    assert idx("x  # whalescan:ignore[WS-A-001]\n", require_reason=False).match(1, "WS-A-001")


def test_wildcard_needs_opt_in():
    text = f"x  # whalescan:ignore[*] {R}\ny  # whalescan:ignore {R}\n"
    assert not idx(text).match(1, "WS-A-001")
    i = idx(text, allow_wildcard=True)
    assert i.match(1, "WS-A-001") and i.match(2, "WS-Z-009")


def test_until_expiry():
    i = idx(f"x  # whalescan:ignore[WS-A-001] {R} until=2026-01-01\n")
    assert not i.match(1, "WS-A-001") and i.diagnostics[0].code == "suppression-expired"
    assert idx(f"x  # whalescan:ignore[WS-A-001] {R} until=2026-09-29\n").match(1, "WS-A-001")
    bad = idx(f"x  # whalescan:ignore[WS-A-001] {R} until=soon\n")
    assert bad.diagnostics[0].code == "suppression-invalid"


def test_file_level_window_and_permission():
    ok = idx(f"# whalescan:ignore-file[WS-A-001] {R}\n" + "x\n" * 30)
    assert ok.match(1, "WS-A-001") and ok.match(31, "WS-A-001")
    late = idx("x\n" * 25 + f"# whalescan:ignore-file[WS-A-001] {R}\n")
    assert not late.match(3, "WS-A-001") and late.diagnostics
    assert not idx(f"# whalescan:ignore-file[WS-A-001] {R}\nx\n", allow_file_level=False).match(2, "WS-A-001")


def test_block_start_end():
    i = idx(f"a\n# whalescan:ignore-start[WS-A-001] {R}\nb\nc\n# whalescan:ignore-end\nd\n")
    assert (
        i.match(3, "WS-A-001")
        and i.match(4, "WS-A-001")
        and not i.match(6, "WS-A-001")
        and not i.match(1, "WS-A-001")
    )


def test_unterminated_block_is_capped_and_reported():
    i = idx(f"# whalescan:ignore-start[WS-A-001] {R}\n" + "x\n" * 300, max_block_lines=50)
    assert i.match(30, "WS-A-001") and not i.match(100, "WS-A-001")
    assert any(d.code == "suppression-invalid" for d in i.diagnostics)


def test_stray_end_reported():
    assert idx("# whalescan:ignore-end\n").diagnostics[0].code == "suppression-invalid"


@pytest.mark.parametrize("lead", ["#", "//", "--", "/*", "<!--", ";", "{#"])
def test_comment_leaders(lead):
    assert idx(f"x {lead} whalescan:ignore[WS-A-001] {R}\n").match(1, "WS-A-001")


def test_unused_marker_reported():
    i = idx(f"x  # whalescan:ignore[WS-A-001] {R}\n")
    assert [d.code for d in i.unused("a.py")] == ["suppression-unused"]
    i.match(1, "WS-A-001")
    assert i.unused("a.py") == []


def test_no_marker_fast_path():
    assert idx("nothing here\n").markers == []


def test_hard_exclusions():
    assert not inline_allowed("WS-INJ-001", "code", is_inject=True)
    assert not inline_allowed("WS-AGT-OVR-001", "agent-config")
    assert not inline_allowed("WS-AGT-OVR-001", "doc")
    assert inline_allowed("WS-AGT-OVR-001", "code")
    assert inline_allowed("WS-SEC-AWS-001", "doc")


# ------------------------------------------------------------------ baseline


def fnd(fp, cfp=None, rule="WS-K8S-004", path="deploy/a.yaml", sev=Severity.MEDIUM, line=4):
    cfp = cfp or "sha256:" + "c" + fp[-63:]
    return Finding(
        rule,
        "t",
        sev,
        sev,
        5.0,
        Confidence.HIGH,
        "unknown",
        "default",
        "domain/k8s",
        path,
        "iac",
        line,
        1,
        line,
        5,
        "s",
        (),
        (),
        "m",
        None,
        (),
        fp,
        cfp,
    )


def fp(n):
    return "sha256:" + f"{n:x}".rjust(64, "0")


def test_create_roundtrip_sorted_no_snippets(tmp_path):
    b = Baseline.create(
        [fnd(fp(2), path="z.yaml"), fnd(fp(1), path="a.yaml"), fnd(fp(1), path="a.yaml")],
        reason="legacy, tracked in PLAT-1",
        now="2026-09-29T10:00:00Z",
    )
    assert [e["path"] for e in b.entries] == ["a.yaml", "z.yaml"] or len(b.entries) == 2
    p = tmp_path / ".whalesecurity" / "baseline.json"
    b.save(p)
    text = p.read_text()
    assert "snippet" not in text and text.endswith("\n")
    loaded = Baseline.load(p)
    assert [e["path"] for e in loaded.entries] == ["a.yaml", "z.yaml"]
    assert loaded.to_json() == text


def test_create_requires_reason_and_blocks_critical():
    with pytest.raises(UsageError):
        Baseline.create([fnd(fp(1))], reason=" ")
    with pytest.raises(UsageError, match="critical"):
        Baseline.create([fnd(fp(1), sev=Severity.CRITICAL)], reason="x")
    assert Baseline.create([fnd(fp(1), sev=Severity.CRITICAL)], reason="x", allow_critical=True).entries


def test_classify_by_fingerprint_and_expiry():
    b = Baseline.create([fnd(fp(1)), fnd(fp(2), line=9)], reason="legacy reason")
    b.entries[0]["expires"] = "2026-01-01"
    b.entries.sort(key=lambda e: e["fingerprint"])
    fs = [fnd(fp(1)), fnd(fp(2)), fnd(fp(3))]
    sup, diags = b.classify(fs, {"deploy/a.yaml"}, TODAY)
    assert set(sup) == {1} and sup[1].kind == "baseline" and sup[1].reason == "legacy reason"
    assert [d.code for d in diags] == ["baseline-expired"]


def test_classify_follows_moved_file_via_content_fingerprint():
    old = fnd(fp(1), cfp=fp(99), path="old.yaml")
    b = Baseline.create([old], reason="legacy reason")
    moved = fnd(fp(7), cfp=fp(99), path="new.yaml")
    assert 0 in b.classify([moved], {"new.yaml"}, TODAY)[0]
    # if the old path still exists, a content match must NOT suppress (it is a copy, not a move)
    assert not b.classify([moved], {"new.yaml", "old.yaml"}, TODAY)[0]


def test_update_prunes_only_in_scope_and_counts():
    b = Baseline.create(
        [fnd(fp(1), path="a/x.yaml"), fnd(fp(2), path="a/y.yaml"), fnd(fp(3), path="b/z.yaml")],
        reason="legacy reason",
    )
    kept, pruned, added = b.update([fnd(fp(1), path="a/x.yaml")], in_scope=lambda p: p.startswith("a/"))
    assert (kept, pruned, added) == (2, 1, 0)
    assert {e["path"] for e in b.entries} == {"a/x.yaml", "b/z.yaml"}


def test_update_no_prune_and_add_new():
    b = Baseline.create([fnd(fp(1))], reason="legacy reason")
    kept, pruned, added = b.update(
        [fnd(fp(5), line=8)], in_scope=lambda p: True, prune=False, add_new=True, reason="new debt"
    )
    assert (kept, pruned, added) == (1, 0, 1)
    with pytest.raises(UsageError):
        b.update([fnd(fp(6))], in_scope=lambda p: True, add_new=True)


def test_load_errors(tmp_path):
    with pytest.raises(ConfigError):
        Baseline.load(tmp_path / "missing.json")
    p = tmp_path / "b.json"
    p.write_text("{not json")
    with pytest.raises(ConfigError):
        Baseline.load(p)
    p.write_text('{"schema": "other", "entries": []}')
    with pytest.raises(ConfigError):
        Baseline.load(p)
    p.write_text('{"schema": "whalescan/baseline@1", "entries": [1]}')
    with pytest.raises(ConfigError):
        Baseline.load(p)
