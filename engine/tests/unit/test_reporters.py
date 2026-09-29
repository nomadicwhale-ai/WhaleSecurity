import json
from importlib import resources

import pytest
from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource

from whalescan.model import (
    Confidence,
    Diagnostic,
    Finding,
    RunInfo,
    ScanResult,
    Severity,
    Stats,
    Suppression,
)
from whalescan.report import markdown, sarif
from whalescan.report import text as text_report

FP = "sha256:" + "a" * 64
CFP = "sha256:" + "b" * 64


def load_schema(name):
    return json.loads(resources.files("whalescan.report.schemas").joinpath(name).read_text())


def validator(name):
    reg = Registry().with_resources(
        [
            (load_schema(n)["$id"], Resource.from_contents(load_schema(n)))
            for n in ("finding-1.json", "report-1.json")
        ]
    )
    return Draft202012Validator(load_schema(name), registry=reg)


def fnd(**kw):
    base = {
        "rule_id": "WS-GHA-001",
        "title": "pull_request_target checks out PR head code",
        "severity": Severity.CRITICAL,
        "base_severity": Severity.CRITICAL,
        "score": 10.0,
        "confidence": Confidence.HIGH,
        "reachability": "unknown",
        "exposure": "default",
        "pack": "domain/gha",
        "file": ".github/workflows/pr.yml",
        "file_kind": "ci",
        "line": 31,
        "col": 18,
        "end_line": 31,
        "end_col": 60,
        "snippet": "ref: ${{ github.event.pull_request.head.sha }}",
        "cwe": ("CWE-94",),
        "owasp": ("CICD-SEC-4",),
        "message": "Workflow runs with a write token but checks out untrusted code.",
        "fix": "Use pull_request, or split into a workflow_run job.",
        "references": ("https://example.com/x",),
        "fingerprint": FP,
        "content_fingerprint": CFP,
    }
    base.update(kw)
    return Finding(**base)


def result(findings=(), diags=(), **run_kw):
    run = RunInfo(
        started_at="2026-09-29T00:00:00Z", packs=["appsec", "secrets"], tool_version="0.1.0", **run_kw
    )
    return ScanResult(tuple(findings), tuple(diags), Stats(files_scanned=1204), run)


# ------------------------------------------------------------------ JSON


def test_json_validates_against_report_schema():
    f2 = fnd(
        rule_id="WS-SEC-DB-002",
        severity=Severity.HIGH,
        base_severity=Severity.HIGH,
        score=7.5,
        fingerprint="sha256:" + "c" * 64,
        suppressed=Suppression("inline", "reviewed fixture", ticket="T-1"),
    )
    r = result([fnd(), f2], [Diagnostic("warning", "parse-error", "bad yaml", "x.yml", 3)])
    doc = json.loads(r.to_json())
    validator("report-1.json").validate(doc)
    assert doc["schema"] == "whalescan/report@1" and len(doc["findings"]) == 2
    assert doc["stats"]["by_severity"]["critical"] == 1


def test_jsonl_one_valid_finding_per_line():
    r = result([fnd(), fnd(rule_id="WS-GHA-002", fingerprint="sha256:" + "d" * 64)])
    lines = r.to_jsonl().splitlines()
    assert len(lines) == 2
    v = validator("finding-1.json")
    for ln in lines:
        v.validate(json.loads(ln))
    assert result().to_jsonl() == ""


def test_json_is_deterministic_and_sorted():
    a, b = (
        fnd(),
        fnd(rule_id="WS-GHA-009", score=3.0, severity=Severity.LOW, fingerprint="sha256:" + "e" * 64),
    )
    assert result([a, b]).to_json() == result([b, a]).to_json()
    ids = [f["rule_id"] for f in json.loads(result([b, a]).to_json())["findings"]]
    assert ids == ["WS-GHA-001", "WS-GHA-009"]


def test_json_reveals_hidden_chars_and_escapes():
    f = fnd(snippet="ok\u200bhidden\x1b[31m", title="t‮x")
    out = result([f]).to_json()
    assert "\u200b" not in out and "‮" not in out and "\x1b" not in out
    assert "[ZWSP]" in out and "[BIDI:RLO]" in out and "[CTRL:U+001B]" in out


def test_json_valid_on_internal_error():
    r = result([fnd()], error={"type": "InternalError", "message": "boom"}, exit_code=3)
    doc = json.loads(r.to_json())
    validator("report-1.json").validate(doc)
    assert doc["run"]["error"]["message"] == "boom" and doc["findings"]


def test_other_schemas_are_valid_json_schema():
    for n in ("baseline-1.json", "mcp-pins-1.json"):
        Draft202012Validator.check_schema(load_schema(n))
    pins = {
        "schema": "whalescan/mcp-pins@1",
        "servers": {"jira": {"config_sha256": "0" * 64, "tools": {"t": {"sha256": "1" * 64}}}},
    }
    validator("mcp-pins-1.json").validate(pins)
    with pytest.raises(ValidationError):
        validator("mcp-pins-1.json").validate(
            {"schema": "whalescan/mcp-pins@1", "servers": {"x": {"config_sha256": "zz", "tools": {}}}}
        )


# ------------------------------------------------------------------ text


def test_text_layout_and_summary():
    r = result(
        [
            fnd(),
            fnd(
                rule_id="WS-SEC-DB-002",
                severity=Severity.HIGH,
                score=7.5,
                fingerprint="sha256:" + "c" * 64,
                title="Database URL with inline password",
                file="dags/etl.py",
                line=12,
                col=14,
            ),
        ],
        fail_on="high",
        exit_code=1,
    )
    out = text_report.render(r)
    lines = out.splitlines()
    assert lines[0].startswith("CRITICAL  WS-GHA-001  .github/workflows/pr.yml:31:18  pull_request_target")
    assert "          │ ref:" in out and "          fix: Use pull_request" in out
    assert "2 findings (1 critical, 1 high) · 1,204 files" in lines[-1] and lines[-1].endswith(
        "fail-on high → exit 1"
    )
    assert "\x1b" not in out


def test_text_color_and_ansi_injection_neutralized():
    f = fnd(title="evil \x1b[2J title", snippet="\x1b]0;pwn\x07")
    plain = text_report.render(result([f]))
    assert "\x1b" not in plain
    colored = text_report.render(result([f]), color=True)
    assert colored.count("\x1b") == 2 and colored.startswith("\x1b[31m")


def test_text_suppressed_hidden_but_counted():
    f = fnd(suppressed=Suppression("baseline", "legacy"))
    out = text_report.render(result([f]))
    assert "0 findings" in out and "1 suppressed (baseline 1)" in out and "WS-GHA-001" not in out


def test_text_shows_warnings():
    out = text_report.render(
        result([], [Diagnostic("warning", "decode-fallback-latin1", "not utf-8", "a.txt")])
    )
    assert "warning: decode-fallback-latin1: not utf-8 (a.txt)" in out


# ------------------------------------------------------------------ markdown


def test_markdown_structure():
    low = fnd(
        rule_id="WS-DKR-004",
        severity=Severity.LOW,
        score=2.5,
        title="Latest tag",
        fingerprint="sha256:" + "f" * 64,
    )
    out = markdown.render(result([fnd(), low]))
    assert out.startswith("## whalescan: 1 critical · 1 low")
    assert "| Sev | Rule | Location | Title |" in out
    assert "#### CRITICAL · `WS-GHA-001`" in out and "**Fix:**" in out
    assert "<details><summary>1 lower-severity finding(s)</summary>" in out
    assert result().to_markdown().startswith("## whalescan: no findings")


def test_markdown_escapes_html_links_mentions_and_pipes():
    f = fnd(
        title="x | <script>alert(1)</script> [click](http://evil) @octocat",
        message="<img src=x onerror=alert(1)> @admin `code`",
        fix="run <b>this</b>",
    )
    out = markdown.render(result([f]))
    assert "<script>" not in out and "<img" not in out and "<b>" not in out
    assert "&lt;script&gt;" in out and "\\|" in out and "&#64;octocat" in out and "&#64;admin" in out
    assert "\\[click\\]" in out and "[click](http" not in out


def test_markdown_fence_longer_than_backticks_in_snippet():
    f = fnd(snippet="a ```` b\n``` c")
    out = markdown.render(result([f]))
    assert "\n`````\n" in out


def test_markdown_code_span_with_backtick_in_path():
    out = markdown.render(result([fnd(file="we`ird.yml")]))
    assert "``we`ird.yml:31``" in out


def test_markdown_caps_findings():
    fs = [
        fnd(rule_id=f"WS-GHA-{i:03d}", fingerprint="sha256:" + f"{i:064x}", file=f"f{i}.yml")
        for i in range(1, 6)
    ]
    out = markdown.render(result(fs), max_findings=2)
    assert "3 more finding(s) omitted (limit 2)" in out and "f3.yml" not in out


def test_markdown_reveals_hidden_chars():
    out = markdown.render(result([fnd(snippet="a\u200bb")]))
    assert "\u200b" not in out and "[ZWSP]" in out


# ------------------------------------------------------------------ SARIF


def sar(r, **kw):
    return json.loads(sarif.render(r, **kw))


def test_sarif_document_shape():
    trace = [{"line": 3, "name": "user", "via": "param"}, {"line": 9, "name": "cmd"}]
    f1 = fnd(properties={"trace": trace})
    f2 = fnd(
        rule_id="WS-GHA-002",
        title="Second rule",
        severity=Severity.MEDIUM,
        base_severity=Severity.MEDIUM,
        fingerprint="sha256:" + "c" * 64,
        file="dir with space/é.yml",
    )
    doc = sar(result([f1, f2, fnd(fingerprint="sha256:" + "d" * 64, line=40)], exit_code=1))
    assert doc["version"] == "2.1.0" and doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    assert (
        run["columnKind"] == "unicodeCodePoints"
        and run["automationDetails"]["id"] == "whalescan/appsec+secrets/"
    )
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["WS-GHA-001", "WS-GHA-002"]
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["name"] == "PullRequestTargetChecksOutPRHeadCode"
    assert rule["defaultConfiguration"]["level"] == "error"
    assert rule["properties"]["security-severity"] == "9.5" and rule["properties"]["precision"] == "high"
    assert {"security", "domain/gha", "external/cwe/cwe-94", "owasp/CICD-SEC-4"} <= set(
        rule["properties"]["tags"]
    )
    assert rule["helpUri"] == "https://example.com/x"
    res = run["results"]
    assert [r["ruleIndex"] for r in res] == [0, 0, 1]
    first = res[0]
    assert first["level"] == "error" and first["partialFingerprints"]["whalescan/v1"] == FP
    loc = first["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"] == {"uri": ".github/workflows/pr.yml", "uriBaseId": "%SRCROOT%"}
    assert loc["region"]["startLine"] == 31 and loc["region"]["endColumn"] == 60
    assert len(first["codeFlows"][0]["threadFlows"][0]["locations"]) == 2
    assert res[2]["level"] == "warning"
    assert (
        res[2]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "dir%20with%20space/%C3%A9.yml"
    )


def test_sarif_level_uses_final_severity_but_rule_uses_base():
    f = fnd(severity=Severity.LOW, base_severity=Severity.HIGH, score=3.0)
    run = sar(result([f]))["runs"][0]
    assert run["results"][0]["level"] == "note"
    assert run["tool"]["driver"]["rules"][0]["defaultConfiguration"]["level"] == "error"


def test_sarif_info_has_no_security_severity():
    f = fnd(severity=Severity.INFO, base_severity=Severity.INFO)
    assert "security-severity" not in sar(result([f]))["runs"][0]["tool"]["driver"]["rules"][0]["properties"]


def test_sarif_suppressions():
    fs = [
        fnd(suppressed=Suppression("inline", "fixture only")),
        fnd(fingerprint="sha256:" + "c" * 64, suppressed=Suppression("baseline", "legacy")),
    ]
    sups = [r["suppressions"][0] for r in sar(result(fs))["runs"][0]["results"]]
    assert {(s["kind"], s["status"]) for s in sups} == {("inSource", "accepted"), ("external", "accepted")}
    assert {s["justification"] for s in sups} == {"fixture only", "legacy"}


def test_sarif_invocation_success_and_failure():
    ok = sar(result([fnd()], [Diagnostic("warning", "parse-error", "bad", "x.yml")], exit_code=1))["runs"][0][
        "invocations"
    ][0]
    assert ok["executionSuccessful"] is True and ok["exitCode"] == 1
    assert ok["toolExecutionNotifications"][0]["descriptor"]["id"] == "parse-error"
    bad = sar(result([], exit_code=3, error={"type": "InternalError", "message": "boom"}))["runs"][0][
        "invocations"
    ][0]
    assert bad["executionSuccessful"] is False
    assert any(n["message"]["text"] == "boom" for n in bad["toolExecutionNotifications"])


def test_sarif_absolute_root_only_when_asked_and_absolute_paths():
    assert "originalUriBaseIds" not in sar(result([fnd()]))["runs"][0]
    run = sar(result([fnd(file="/etc/x y.conf")]), absolute_root="/work/repo")["runs"][0]
    assert run["originalUriBaseIds"]["%SRCROOT%"]["uri"] == "file:///work/repo/"
    art = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert art == {"uri": "file:///etc/x%20y.conf"}


def test_sarif_adapter_extensions_and_hidden_chars():
    f = fnd(rule_id="semgrep:python.lang.eval", source="semgrep", snippet="a\u200bb", pack="")
    run = sar(result([f]))["runs"][0]
    assert run["tool"]["extensions"] == [{"name": "semgrep"}]
    assert "[ZWSP]" in run["results"][0]["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]


def test_sarif_validates_against_official_schema():
    from pathlib import Path

    schema = json.loads((Path(__file__).parent.parent / "data" / "sarif-2.1.0.schema.json").read_text())
    f1 = fnd(properties={"trace": [{"line": 3, "name": "user"}]})
    f2 = fnd(rule_id="WS-X-002", fingerprint="sha256:" + "c" * 64, suppressed=Suppression("inline", "why not"))
    r = result([f1, f2], [Diagnostic("warning", "parse-error", "bad", "x.yml")], exit_code=1)
    Draft202012Validator(schema).validate(json.loads(sarif.render(r, absolute_root="/w")))
