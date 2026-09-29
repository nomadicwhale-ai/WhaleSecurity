"""Tests for whalescan.rules.loader: sources, semantic checks (§7.3), normalization and RuleSet."""

from __future__ import annotations

import copy
import importlib
import json
import os
import sys
import types
from collections.abc import Callable
from typing import Any

import pytest
import yaml
from hypothesis import given, settings
from hypothesis import strategies as st

from whalescan.errors import RuleError
from whalescan.model import KINDS, AppliesTo, Confidence, Rule, Severity
from whalescan.rules import loader as LD
from whalescan.rules.loader import RawRule, RuleIssue, RuleLoadError, RuleSet


def pyyaml_loader(text: str) -> list[Any]:
    return list(yaml.safe_load_all(text))


def base_rule(**over: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": "WS-INJ-001",
        "title": "Shell command built from input",
        "pack": "appsec/injection",
        "severity": "high",
        "confidence": "medium",
        "owner": "@whalesecurity/appsec",
        "applies_to": {"kind": "code", "lang": "python"},
        "match": {"regex": {"pattern": r"os\.system\((?P<arg>[^)\n]{1,200})\)"}},
        "message": "os.system called with {{arg}}.",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    }
    rule.update(over)
    return rule


def rule_n(i: int, **over: Any) -> dict[str, Any]:
    return base_rule(id=f"WS-INJ-{i:03d}", **over)


def issues_of(raw: Any, lint: bool = True) -> list[RuleIssue]:
    return LD.check_rule(raw, source="t.yaml", lint=lint)


def error_codes(raw: Any) -> set[str]:
    return {i.code for i in issues_of(raw) if i.level == "error"}


SPEC_EXAMPLES = r"""
- id: WS-SEC-DB-002
  title: Database URL with inline password
  pack: secrets/generic
  severity: high
  confidence: high
  owner: "@whalesecurity/secrets"
  cwe: [CWE-798]
  owasp: [A07]
  applies_to: { kind: [code, iac, ci, data, doc] }
  keywords: ["://"]
  match:
    regex:
      pattern: '(?P<scheme>postgres(?:ql)?|mysql|mariadb|singlestore|memsql|mongodb(?:\+srv)?|rediss?|amqps?)://(?P<user>[^:/\s@]{1,128}):(?P<secret>[^@\s/]{1,256})@'
      secret_group: secret
  filters: { line_not_regex: '://[^:\s]{1,128}:(?:\$\{[^}]{1,64}\}|\{\{[^}]{1,64}\}\}|<[^>]{1,64}>|\*{3,})@' }
  message: "{{scheme}} connection string for user {{user}} embeds a password."
  fix: Read the DSN from Secrets Manager, Vault or a k8s Secret, and rotate this credential.
  references: ["https://cwe.mitre.org/data/definitions/798.html"]

- id: WS-K8S-001
  title: Privileged container
  pack: domain/k8s
  severity: high
  confidence: high
  owner: "@whalesecurity/platform"
  cwe: [CWE-250]
  applies_to: { kind: iac, tags_any: [k8s, helm] }
  match:
    yaml_path:
      each: "**.{containers,initContainers,ephemeralContainers}[*]"
      all:
        - { path: "securityContext.privileged", equals: true }
  message: Container runs privileged, with full host device and kernel access.
  fix: Remove privileged; grant only the specific capabilities needed (securityContext.capabilities.add).
  references: ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"]

- id: WS-GHA-001
  title: pull_request_target checks out PR head code
  pack: domain/gha
  severity: critical
  confidence: high
  owner: "@whalesecurity/platform"
  cwe: [CWE-94]
  owasp: [CICD-SEC-4]
  applies_to: { kind: ci, glob: [".github/workflows/*.y*ml"] }
  match:
    yaml_path:
      all:
        - path: "on.pull_request_target"
          exists: true
        - path: "jobs.*.steps[*].with.ref"
          regex: "github\\.event\\.pull_request\\.head\\.(sha|ref)"
  message: >
    Workflow runs with a write token and secrets, but checks out untrusted fork code.
  references: ["https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"]
  fixtures: auto

- id: WS-TF-001
  title: Security group open to the internet
  pack: domain/terraform
  severity: high
  confidence: high
  owner: "@whalesecurity/platform"
  applies_to: { kind: iac }
  match:
    hcl:
      block: "resource.aws_security_group.*"
      each: "ingress"
      all:
        - { attr: cidr_blocks, contains: "0.0.0.0/0" }
        - { range_includes: { lo: from_port, hi: to_port, any: [22, 3389, 5432, 3306, 6379, 9200] } }
  message: An ingress rule opens an administrative port to the whole internet.
  references: ["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"]

- id: WS-AGT-MCP-010
  title: MCP server launched from an unpinned package
  pack: agentsec/mcp
  severity: medium
  confidence: high
  owner: "@whalesecurity/agentsec"
  applies_to: { kind: agent-config, tags_any: [mcp] }
  match:
    yaml_path:
      each: "mcpServers.*"
      all:
        - { path: "command", in: [npx, bunx, pnpx, uvx] }
        - { path: "args[*]", regex: '^(?:@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$' }
  message: MCP server runs a package without a pinned version.
  references: ["https://modelcontextprotocol.io/specification"]
"""


def spec_rules() -> list[dict[str, Any]]:
    loaded: list[dict[str, Any]] = yaml.safe_load(SPEC_EXAMPLES)
    return loaded


# ============================================================================================== normalize


def test_spec_examples_load_cleanly() -> None:
    rs = LD.load_raw_rules(spec_rules())
    assert [r.id for r in rs] == ["WS-SEC-DB-002", "WS-K8S-001", "WS-GHA-001", "WS-TF-001", "WS-AGT-MCP-010"]
    assert rs.warnings == ()


def test_normalize_fields() -> None:
    rule = LD.normalize(spec_rules()[0], source_file="rules/secrets/generic.yaml")
    assert isinstance(rule, Rule)
    assert rule.severity is Severity.HIGH and rule.confidence is Confidence.HIGH
    assert rule.applies_to == AppliesTo(kinds=frozenset({"code", "iac", "ci", "data", "doc"}))
    assert rule.cwe == ("CWE-798",) and rule.owasp == ("A07",)
    assert rule.keywords == ("://",) and rule.keywords_case == "insensitive"
    assert rule.match["regex"]["secret_group"] == "secret"
    assert rule.filters["line_not_regex"].startswith("://")
    assert rule.exposure_sensitive is False  # §10: default for the secrets pack
    assert rule.is_secret_rule and rule.pack_root == "secrets"
    assert rule.max_hits_per_file == 50 and rule.enabled_by_default and not rule.deprecated
    assert rule.source_file == "rules/secrets/generic.yaml"


def test_normalize_scalar_and_list_forms() -> None:
    rule = LD.normalize(
        base_rule(
            applies_to={
                "kind": ["code", "doc"],
                "lang": ["python", "markdown"],
                "glob": ["a/**"],
                "exclude_glob": ["b/**"],
                "tags_any": ["x"],
                "tags_none": ["y"],
                "include_minified": True,
                "max_bytes": 10,
            }
        )
    )
    at = rule.applies_to
    assert at.kinds == frozenset({"code", "doc"}) and at.langs == frozenset({"python", "markdown"})
    assert at.globs == ("a/**",) and at.exclude_globs == ("b/**",)
    assert at.tags_any == frozenset({"x"}) and at.tags_none == frozenset({"y"})
    assert at.include_minified is True and at.max_bytes == 10


def test_normalize_optional_fields() -> None:
    raw = base_rule(
        cwe=["CWE-78"],
        tags=["shell"],
        atlas=["AML.T0051"],
        since="1.2.3",
        deprecated=True,
        replaced_by="WS-INJ-002",
        enabled_by_default=False,
        keywords=["System"],
        keywords_case="sensitive",
        redact=True,
        exposure_sensitive=False,
        supersedes=["WS-INJ-003"],
        max_hits_per_file=7,
        fix="Use a list argv.",
    )
    rule = LD.normalize(raw)
    assert rule.tags == ("shell",) and rule.atlas == ("AML.T0051",) and rule.since == "1.2.3"
    assert rule.deprecated and rule.replaced_by == "WS-INJ-002" and not rule.enabled_by_default
    assert rule.keywords_case == "sensitive" and rule.redact and not rule.exposure_sensitive
    assert (
        rule.supersedes == ("WS-INJ-003",) and rule.max_hits_per_file == 7 and rule.fix == "Use a list argv."
    )


def test_normalize_copies_the_match_expression() -> None:
    raw = base_rule()
    rule = LD.normalize(raw)
    raw["match"]["regex"]["pattern"] = "changed"
    assert rule.match["regex"]["pattern"] != "changed"


def test_normalize_raises_rule_error_with_issues() -> None:
    with pytest.raises(RuleLoadError) as exc:
        LD.normalize(base_rule(severity="severe"))
    assert exc.value.exit_code == 2
    assert isinstance(exc.value, RuleError)
    assert exc.value.issues[0].code == "schema"
    assert "severity" in str(exc.value)


def test_normalize_without_validation_trusts_input() -> None:
    rule = LD.normalize(base_rule(pack="secrets/x"), validate=False)  # namespace mismatch not checked
    assert rule.pack == "secrets/x"


def test_implied_langs_from_structured_matchers() -> None:
    rules = {r.id: r for r in LD.load_raw_rules(spec_rules())}
    assert rules["WS-K8S-001"].applies_to.langs == frozenset({"yaml", "json"})
    assert rules["WS-TF-001"].applies_to.langs == frozenset({"hcl", "json"})
    assert rules["WS-SEC-DB-002"].applies_to.langs == frozenset()
    py = LD.normalize(
        base_rule(
            applies_to={"kind": "code"},
            match={"py_ast": {"call": {"callee": "os.system"}}},
            message="os.system is called.",
        )
    )
    assert py.applies_to.langs == frozenset({"python"})
    mixed = LD.normalize(
        base_rule(
            applies_to={"kind": "code"},
            message="Shell call found in the file.",
            match={"any": [{"regex": "x"}, {"py_ast": {"call": {"callee": "f"}}}]},
        )
    )
    assert mixed.applies_to.langs == frozenset()
    both = LD.normalize(
        base_rule(
            applies_to={"kind": "code"},
            message="Shell call found in the file.",
            match={"all": [{"regex": "x"}, {"py_ast": {"call": {"callee": "f"}}}]},
        )
    )
    assert both.applies_to.langs == frozenset({"python"})


# ============================================================================================== semantics


def test_namespace_pack_mapping() -> None:
    assert error_codes(base_rule(id="WS-SEC-001", pack="appsec/x")) == {"namespace"}
    assert error_codes(base_rule(id="WS-AGT-001", pack="domain/x")) == {"namespace"}
    assert error_codes(base_rule(id="WS-K8S-001", pack="appsec/x")) == {"namespace"}
    assert error_codes(base_rule(id="WS-INJ-001", pack="secrets/x")) == {"namespace"}
    for ns, pack in (
        ("INJ", "appsec/x"),
        ("WEB", "domain/fastapi"),
        ("SSRF", "appsec/ssrf"),
        ("SEC", "secrets/x"),
        ("AGT", "agentsec/x"),
        ("TRD", "domain/trading"),
        ("LLM", "domain/llm"),
    ):
        assert error_codes(base_rule(id=f"WS-{ns}-001", pack=pack)) == set(), ns


def test_matcher_applies_to_compatibility() -> None:
    yaml_path = {"yaml_path": {"all": [{"path": "a", "exists": True}]}}
    assert error_codes(base_rule(match=yaml_path, message="Matched a yaml path.")) == {
        "applies-to"
    }  # lang python
    ok = base_rule(
        match=yaml_path, applies_to={"kind": "iac", "lang": ["yaml", "json"]}, message="Found a key."
    )
    assert error_codes(ok) == set()
    mostly = base_rule(match=yaml_path, applies_to={"lang": ["yaml", "python"]}, message="Found a key here.")
    assert error_codes(mostly) == {"applies-to"}
    hcl = base_rule(
        match={"hcl": {"block": "resource.x"}}, applies_to={"lang": "json"}, message="Found a block."
    )
    assert error_codes(hcl) == set()
    py = base_rule(
        match={"py_ast": {"call": {"callee": "f"}}}, applies_to={"lang": "yaml"}, message="Found a call."
    )
    assert error_codes(py) == {"applies-to"}
    any_mixed = base_rule(
        match={"any": [{"regex": "x"}, {"py_ast": {"call": {"callee": "f"}}}]},
        applies_to={"lang": "yaml"},
        message="Found something odd.",
    )
    assert error_codes(any_mixed) == {"applies-to"}
    impossible = base_rule(
        applies_to={"kind": "code"},
        message="Found something odd.",
        match={"all": [{"py_ast": {"call": {"callee": "f"}}}, yaml_path]},
    )
    assert error_codes(impossible) == {"applies-to"}


def test_builtin_only_in_agentsec_mcp() -> None:
    raw = base_rule(
        id="WS-AGT-MCP-001",
        pack="agentsec/mcp",
        match={"builtin": "mcp_drift"},
        applies_to={"kind": "agent-config"},
        message="Tool description drifted.",
    )
    assert error_codes(raw) == set()
    assert error_codes({**raw, "pack": "agentsec/tokens"}) == {"applies-to"}


def test_not_only_directly_under_all() -> None:
    ok = base_rule(match={"all": [{"regex": "a"}, {"not": {"regex": "b"}}]}, message="Matched a without b.")
    assert error_codes(ok) == set()
    under_any = base_rule(
        match={"any": [{"regex": "a"}, {"not": {"regex": "b"}}]}, message="Matched a or not b."
    )
    assert error_codes(under_any) == {"expr"}
    top = base_rule(match={"not": {"regex": "b"}}, message="Did not match b at all.")
    assert error_codes(top) == {"expr"}
    nested = base_rule(
        match={"all": [{"regex": "a"}, {"not": {"not": {"regex": "b"}}}]}, message="Double negation."
    )
    assert error_codes(nested) == {"expr"}
    only_neg = base_rule(
        match={"all": [{"not": {"regex": "a"}}, {"not": {"regex": "b"}}]}, message="Nothing here."
    )
    assert error_codes(only_neg) == {"expr"}


def test_group_names() -> None:
    def regex(**spec: Any) -> dict[str, Any]:
        return base_rule(
            match={"regex": {"pattern": r"(?P<a>x)(y)", **spec}}, message="Matched x and y here."
        )

    assert error_codes(regex(secret_group="a", report_group="a")) == set()
    assert error_codes(regex(report_group=2)) == set()
    assert error_codes(regex(secret_group="b")) == {"group"}
    assert error_codes(regex(report_group="b")) == {"group"}
    assert error_codes(regex(report_group=3)) == {"group"}
    ml = base_rule(
        match={"multiline": {"pattern": "(?P<k>x)y", "secret_group": "z"}}, message="Multiline match."
    )
    assert error_codes(ml) == {"group"}


def test_message_placeholders() -> None:
    assert error_codes(base_rule(message="os.system called with {{ arg }}.")) == set()
    assert error_codes(base_rule(message="os.system called with {{nope}}.")) == {"group"}
    assert error_codes(base_rule(message="Workflow uses ${{ secrets }} in a run step.")) == set()
    any_expr = {"any": [{"regex": "(?P<arg>a)"}, {"regex": "(?P<other>b)"}]}
    assert error_codes(base_rule(match=any_expr)) == {"group"}  # every `any` child must provide it
    all_expr = {"all": [{"not": {"regex": "z"}}, {"regex": "(?P<arg>a)"}, {"regex": "b"}]}
    assert error_codes(base_rule(match=all_expr)) == set()  # the first positive child reports
    seq = {"multiline": {"sequence": ["a", "(?P<arg>b)"], "within_lines": 3}}
    assert error_codes(base_rule(match=seq)) == set()
    uni = base_rule(
        id="WS-AGT-001",
        pack="agentsec/unicode",
        match={"unicode": {"classes": ["ZW"]}},
        applies_to={"kind": "doc"},
        message="Hidden {{arg}} characters.",
    )
    assert error_codes(uni) == {"group"}


def test_yaml_paths() -> None:
    good = [
        "a",
        "a.b",
        "$.a.b",
        "**",
        "**.x",
        "*.y",
        "a[0]",
        "a[-1]",
        "a[*].b",
        'metadata.annotations."k.io/x"',
        "**.{containers,initContainers}[*]",
        "on.pull_request_target",
        "jobs.*.steps[*].with.ref",
    ]
    bad = ["", "$.", ".a", "a..b", "a b", "a{b}", "[0]", "a[x]", "a.{b,}", "a.{b c}", "a*", 'a."unterminated']
    for p in good:
        assert LD.yaml_path_error(p) is None, p
    for p in bad:
        assert LD.yaml_path_error(p) is not None, p
    raw = base_rule(
        applies_to={"kind": "iac"},
        message="Found a yaml key.",
        match={"yaml_path": {"each": "a..b", "all": [{"path": "x y", "exists": True}]}},
    )
    assert {(i.code, i.where) for i in issues_of(raw)} == {
        ("path", "match.yaml_path.each"),
        ("path", "match.yaml_path.all[0].path"),
    }


def test_hcl_paths() -> None:
    def hcl(**spec: Any) -> dict[str, Any]:
        return base_rule(applies_to={"kind": "iac"}, message="Found an hcl block.", match={"hcl": spec})

    assert (
        error_codes(
            hcl(
                block="resource.aws_s3_bucket.*",
                each="rule.expiration",
                all=[{"attr": "tags.*", "exists": True}, {"attr": "rule[0].action", "equals": "x"}],
            )
        )
        == set()
    )
    assert error_codes(hcl(block="*.x")) == {"path"}
    assert error_codes(hcl(block="resource..x")) == {"path"}
    assert error_codes(hcl(block="r", all=[{"attr": "a b", "exists": True}])) == {"path"}
    assert error_codes(
        hcl(block="r", all=[{"range_includes": {"lo": "from port", "hi": "b", "any": [1]}}])
    ) == {"path"}


def test_py_ast_names() -> None:
    def call(**spec: Any) -> dict[str, Any]:
        return base_rule(
            match={"py_ast": {"call": {"callee": "os.system", **spec}}}, message="Found a call site."
        )

    assert (
        error_codes(
            call(
                callee=["subprocess.{run,Popen}", "**.execute", "{eval,exec}"],
                sources=["web", "cli", "request.args", "**.poll"],
                sanitizers=["shlex.quote", "int"],
                kwarg_absent=["Loader"],
                require_import=["yaml"],
            )
        )
        == set()
    )
    assert error_codes(call(sources=["webb"])) == {"path"}
    assert error_codes(call(callee="os..system")) == {"path"}
    assert error_codes(call(callee="os.{system, popen}")) == {"path"}
    assert error_codes(call(sanitizers=["shlex quote"])) == {"path"}
    assert error_codes(call(kwarg_absent=["a.b"])) == {"path"}


def test_misc_checks() -> None:
    ent = base_rule(
        id="WS-SEC-GEN-001",
        pack="secrets/generic",
        applies_to={"kind": "code"},
        match={"entropy": {"charset": "hex", "min_len": 100, "max_len": 50}},
        message="High entropy.",
    )
    assert error_codes(ent) == {"entropy"}
    assert error_codes(base_rule(replaced_by="WS-INJ-001")) == {"ref"}
    assert error_codes(base_rule(supersedes=["WS-INJ-001"])) == {"ref"}
    assert error_codes(base_rule(fixtures={"pos": ["../../etc/passwd"], "neg": ["n.py"]})) == {"fixtures"}
    assert error_codes(base_rule(fixtures={"pos": ["/abs.py"], "neg": ["n.py"]})) == {"fixtures"}
    assert error_codes(base_rule(fixtures={"pos": ["WS-INJ-001/p.py"], "neg": ["shared/n.py"]})) == set()


def test_lint_issues_are_reported_with_location() -> None:
    raw = base_rule(match={"regex": ".*os.system"}, message="Found os.system somewhere.")
    (issue,) = issues_of(raw)
    assert issue.code == "lint-R3" and issue.where == "match.regex" and issue.level == "error"
    assert issues_of(raw, lint=False) == []


def test_lint_warnings_do_not_fail_loading() -> None:
    raw = base_rule(match={"regex": r"os\.system\([^)]*\)"}, message="Found os.system somewhere.")
    rs = LD.load_raw_rules([raw])
    assert [w.code for w in rs.warnings] == ["lint-R6"]


def test_schema_errors_short_circuit_semantic_checks() -> None:
    issues = issues_of(base_rule(severity="severe", pack="secrets/x"))
    assert [i.code for i in issues] == ["schema"]
    assert (
        issues[0].rule_id == "WS-INJ-001" and issues[0].source == "t.yaml" and issues[0].where == "severity"
    )


# ============================================================================================== set checks


def raws(*rules: dict[str, Any], origin: LD.Origin = "file", source: str = "p.yaml") -> list[RawRule]:
    return [RawRule(r, source, origin, i) for i, r in enumerate(rules)]


def test_duplicate_ids() -> None:
    report = LD.check([*raws(rule_n(1)), *raws(rule_n(1), source="q.yaml")])
    assert [i.code for i in report.errors] == ["duplicate-id"]
    assert "p.yaml" in report.errors[0].message and report.errors[0].source == "q.yaml"
    assert [r.id for r in report.rules] == ["WS-INJ-001"]


def test_extra_rules_may_not_shadow_bundled_ones() -> None:
    bundled = LD.rule_to_dict(LD.normalize(rule_n(1)))
    report = LD.check(
        [
            RawRule(bundled, "bundle.json", "bundle", 0, normalized=True),
            *raws(rule_n(1), origin="extra", source=".whalesecurity/rules/x.yaml"),
        ]
    )
    assert [i.code for i in report.errors] == ["shadows-bundled"]


def test_cross_references() -> None:
    report = LD.check(
        raws(rule_n(1, replaced_by="WS-INJ-002", deprecated=True), rule_n(2, supersedes=["WS-INJ-001"]))
    )
    assert report.ok
    report = LD.check(raws(rule_n(1, replaced_by="WS-INJ-009"), rule_n(2, supersedes=["WS-INJ-008"])))
    assert sorted((i.code, i.rule_id) for i in report.errors) == [
        ("ref", "WS-INJ-001"),
        ("ref", "WS-INJ-002"),
    ]


def test_cross_reference_to_an_invalid_rule_is_not_double_reported() -> None:
    report = LD.check(raws(rule_n(1, severity="bogus"), rule_n(2, supersedes=["WS-INJ-001"])))
    assert [i.code for i in report.errors] == ["schema"]


def test_build_raises_with_all_errors_listed() -> None:
    with pytest.raises(RuleLoadError) as exc:
        LD.build(raws(rule_n(1, severity="x"), rule_n(2, pack="secrets/x"), rule_n(2)))
    codes = sorted(i.code for i in exc.value.issues)
    assert codes == ["duplicate-id", "namespace", "schema"]
    assert str(exc.value).startswith("3 rule errors:")


def test_rule_load_error_truncates_long_lists() -> None:
    issues = [RuleIssue("error", "schema", f"bad {i}") for i in range(80)]
    text = str(RuleLoadError(issues))
    assert "… and 30 more" in text and text.count("\n  - ") == 50


def test_issue_formatting_and_diagnostic() -> None:
    issue = RuleIssue("warning", "lint-R6", "use {0,N}", "WS-INJ-001", "rules/x.yaml", "match.regex")
    assert str(issue) == "rules/x.yaml: WS-INJ-001: match.regex: use {0,N} [lint-R6]"
    diag = issue.to_diagnostic()
    assert diag.level == "warning" and diag.code == "rule-lint-R6" and diag.rule_id == "WS-INJ-001"
    assert diag.file == "rules/x.yaml" and diag.message == "match.regex: use {0,N}"
    assert RuleIssue.from_dict(issue.to_dict()) == issue
    with pytest.raises(ValueError, match="level"):
        RuleIssue.from_dict({**issue.to_dict(), "level": "fatal"})


# ============================================================================================== sources


def write(path: str, text: str) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def dump_yaml(rules: list[dict[str, Any]]) -> str:
    return str(yaml.safe_dump(rules, sort_keys=False))


def test_load_yaml_and_json_packs_from_a_directory(tmp_path: Any) -> None:
    d = str(tmp_path / "rules")
    write(f"{d}/appsec/injection.yaml", dump_yaml([rule_n(1), rule_n(2)]))
    write(f"{d}/appsec/more.json", json.dumps([rule_n(3)]))
    write(f"{d}/domain/k8s.yml", dump_yaml([spec_rules()[1]]))
    write(f"{d}/.hidden/skip.yaml", "not: [valid")
    write(f"{d}/README.md", "# not a pack")
    rs = LD.load([d], builtin=False, yaml_loader=pyyaml_loader)
    assert [r.id for r in rs] == ["WS-INJ-001", "WS-INJ-002", "WS-INJ-003", "WS-K8S-001"]
    assert rs.get("WS-INJ-003") is not None
    assert (rs.by_id["WS-K8S-001"].source_file or "").endswith("domain/k8s.yml")
    assert rs.by_id["WS-INJ-001"].source_file == f"{d}/appsec/injection.yaml"


def test_multi_document_yaml_pack(tmp_path: Any) -> None:
    d = str(tmp_path)
    write(f"{d}/p.yaml", dump_yaml([rule_n(1)]) + "---\n" + dump_yaml([rule_n(2)]) + "---\n")
    assert [r.id for r in LD.load([d], builtin=False, yaml_loader=pyyaml_loader)] == [
        "WS-INJ-001",
        "WS-INJ-002",
    ]


@pytest.mark.parametrize(
    ("name", "content", "message"),
    [
        ("p.yaml", "id: WS-INJ-001\n", "must be a sequence"),
        ("p.json", '{"id": "x"}', "must be a sequence"),
        ("p.json", '[{"id": "a", "id": "b"}]', "duplicate key"),
        ("p.json", "[NaN]", "invalid JSON constant"),
        ("p.json", "[1,", "invalid JSON"),
        ("p.json", "[" * 100_000 + "]" * 100_000, "JSON"),
    ],
)
def test_bad_pack_files(tmp_path: Any, name: str, content: str, message: str) -> None:
    write(str(tmp_path / name), content)
    with pytest.raises(RuleError, match=message):
        LD.load([str(tmp_path)], builtin=False, yaml_loader=pyyaml_loader)


def test_invalid_utf8_and_oversized_files(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "bad.json").write_bytes(b"[\xff]")
    with pytest.raises(RuleError, match="UTF-8"):
        LD.load([str(tmp_path)], builtin=False)
    os.unlink(tmp_path / "bad.json")
    (tmp_path / "big.json").write_text("[" + " " * 2000 + "]")
    monkeypatch.setattr(LD, "MAX_RULE_FILE_BYTES", 1000)
    monkeypatch.setattr(LD.read_source, "__defaults__", (1000,))
    with pytest.raises(RuleError, match="larger than"):
        LD.load([str(tmp_path)], builtin=False)


def test_rule_errors_carry_the_source_file(tmp_path: Any) -> None:
    write(str(tmp_path / "x.yaml"), dump_yaml([rule_n(1, pack="secrets/x")]))
    with pytest.raises(RuleLoadError) as exc:
        LD.load([str(tmp_path)], builtin=False, yaml_loader=pyyaml_loader)
    (issue,) = exc.value.issues
    assert issue.source == f"{tmp_path}/x.yaml" and issue.code == "namespace"


def test_missing_directories(tmp_path: Any) -> None:
    missing = str(tmp_path / "nope")
    with pytest.raises(RuleError, match="not found"):
        LD.load([missing], builtin=False)
    assert len(LD.load([missing], builtin=False, missing_dirs_ok=True)) == 0
    write(str(tmp_path / "file"), "x")
    with pytest.raises(RuleError, match="not found"):
        LD.load([str(tmp_path / "file")], builtin=False, missing_dirs_ok=True)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_symlinks_are_confined_to_the_rules_directory(tmp_path: Any) -> None:
    outside = tmp_path / "outside"
    write(str(outside / "evil.json"), json.dumps([rule_n(9)]))
    d = tmp_path / "rules"
    write(str(d / "real" / "ok.json"), json.dumps([rule_n(1)]))
    os.symlink(outside / "evil.json", d / "escape.json")
    os.symlink(outside, d / "escape-dir")
    os.symlink(d / "real", d / "inside-link")  # inside the root: followed, but deduplicated
    os.symlink(d, d / "real" / "loop")  # a cycle must terminate
    rs = LD.load([str(d)], builtin=False)
    assert [r.id for r in rs] == ["WS-INJ-001"]
    assert {w.code for w in rs.warnings} == {"symlink-escape"}
    assert len(rs.warnings) == 2


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_explicit_files_may_be_symlinks(tmp_path: Any) -> None:
    target = write(str(tmp_path / "real.json"), json.dumps([rule_n(1)]))
    os.symlink(target, tmp_path / "link.json")
    rs = LD.load(files=[str(tmp_path / "link.json")], builtin=False)
    assert [r.id for r in rs] == ["WS-INJ-001"]


def test_default_yaml_loader_requires_yamlite(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = importlib.import_module

    def fake_import(name: str, package: str | None = None) -> Any:
        if name == "whalescan.yamlite":
            raise ImportError("no yamlite")
        return real_import(name, package)

    monkeypatch.setattr(importlib, "import_module", fake_import)
    with pytest.raises(RuleError, match="yamlite"):
        LD.default_yaml_loader("- a: 1\n")


class _Node:
    def __init__(self, value: Any) -> None:
        self.value = value


class _Key:
    def __init__(self, raw: str) -> None:
        self.raw = raw


def test_default_yaml_loader_converts_node_trees(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = types.ModuleType("whalescan.yamlite")

    def load_all(text: str) -> list[Any]:
        rule = yaml.safe_load(dump_yaml([rule_n(1)]))[0]
        tree = {_Key(k): _Node(v) for k, v in rule.items()}
        return [_Node([tree]), None]

    fake.load_all = load_all  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "whalescan.yamlite", fake)
    docs = LD.default_yaml_loader("ignored")
    assert docs[0][0]["id"] == "WS-INJ-001" and docs[1] is None


def test_default_yaml_loader_wraps_parser_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = types.ModuleType("whalescan.yamlite")

    def load_all(text: str) -> list[Any]:
        raise ValueError("line 3: bad indent")

    fake.load_all = load_all  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "whalescan.yamlite", fake)
    with pytest.raises(RuleError, match="bad indent"):
        LD.default_yaml_loader("x")


def test_to_plain_bounds_depth() -> None:
    deep: Any = "x"
    for _ in range(100):
        deep = [deep]
    with pytest.raises(RuleError, match="deeper"):
        LD.to_plain(deep)


def test_yaml_alias_cycles_are_rejected(tmp_path: Any) -> None:
    write(str(tmp_path / "p.yaml"), dump_yaml([rule_n(1)]).replace("title:", "tags: &a [*a]\n  title:", 1))
    # PyYAML builds a self-referencing list; the validator's pre-check must stop it.
    with pytest.raises(RuleLoadError, match="nesting deeper"):
        LD.load(
            [str(tmp_path)], builtin=False, yaml_loader=lambda t: list(yaml.load_all(t, Loader=yaml.Loader))
        )


def test_deeply_nested_expression_is_a_schema_error_not_a_crash() -> None:
    expr: dict[str, Any] = {"regex": "a"}
    for _ in range(3000):
        expr = {"all": [expr, {"regex": "b"}]}
    report = LD.check(raws(base_rule(match=expr)))
    assert [i.code for i in report.errors] == ["schema"]


# ============================================================================================== bundle


def test_bundle_roundtrip(tmp_path: Any) -> None:
    d = str(tmp_path / "rules")
    write(f"{d}/secrets/generic.yaml", dump_yaml([spec_rules()[0]]))
    write(
        f"{d}/domain/k8s.yaml",
        dump_yaml([spec_rules()[1], {**spec_rules()[2], "fixtures": {"pos": ["a/p.yml"], "neg": ["a/n"]}}]),
    )
    bundle = LD.build_bundle([d], yaml_loader=pyyaml_loader)
    assert bundle["schema"] == LD.BUNDLE_SCHEMA
    assert bundle["fixtures"] == {"WS-GHA-001": {"pos": ["a/p.yml"], "neg": ["a/n"]}}
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle))
    rs = LD.load(bundle_path=str(path))
    direct = LD.load([d], builtin=False, yaml_loader=pyyaml_loader)
    assert rs.bundle_hash == bundle["bundle_hash"] == direct.bundle_hash
    assert [LD.rule_to_dict(r, with_source=False) for r in rs] == [
        LD.rule_to_dict(r, with_source=False) for r in direct
    ]
    assert rs.fixture_specs == {"WS-GHA-001": {"pos": ["a/p.yml"], "neg": ["a/n"]}}
    assert rs.by_id["WS-K8S-001"].source_file == "rules/domain/k8s.yaml"


def test_tampered_bundle_is_rejected(tmp_path: Any) -> None:
    bundle: dict[str, Any] = {"schema": LD.BUNDLE_SCHEMA, "rules": [LD.rule_to_dict(LD.normalize(rule_n(1)))]}
    bundle["bundle_hash"] = LD.bundle_hash([LD.normalize(rule_n(1))])
    bundle["rules"][0]["severity"] = "info"
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle))
    with pytest.raises(RuleError, match="bundle_hash mismatch"):
        LD.load(bundle_path=str(path))


def test_bundle_without_hash_and_malformed_entries(tmp_path: Any) -> None:
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps({"schema": LD.BUNDLE_SCHEMA, "rules": [{"id": "WS-INJ-001"}]}))
    with pytest.raises(RuleLoadError) as exc:
        LD.load(bundle_path=str(path))
    assert exc.value.issues[0].code == "bundle"
    path.write_text(json.dumps({"schema": "other", "rules": []}))
    with pytest.raises(RuleError, match="not a whalescan/rules-bundle@1"):
        LD.load(bundle_path=str(path))
    with pytest.raises(RuleError, match="bundle not found"):
        LD.load(bundle_path=str(tmp_path / "missing.json"))


def test_extra_dir_cannot_shadow_bundle(tmp_path: Any) -> None:
    rule = LD.normalize(rule_n(1))
    path = tmp_path / "bundle.json"
    path.write_text(
        json.dumps(
            {
                "schema": LD.BUNDLE_SCHEMA,
                "bundle_hash": LD.bundle_hash([rule]),
                "rules": [LD.rule_to_dict(rule)],
            }
        )
    )
    write(str(tmp_path / "extra" / "x.json"), json.dumps([rule_n(1, severity="low")]))
    with pytest.raises(RuleLoadError) as exc:
        LD.load([str(tmp_path / "extra")], bundle_path=str(path))
    assert [i.code for i in exc.value.issues] == ["shadows-bundled"]


def test_builtin_sources_without_bundle(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    monkeypatch.setattr(LD, "BUNDLE_PATH", str(tmp_path / "absent.json"))
    monkeypatch.setattr(LD, "dev_rules_dir", lambda: None)
    sources, issues = LD.discover_sources()
    assert sources == [] and issues == []
    rules_dir = tmp_path / "rules"
    write(str(rules_dir / "appsec" / "x.json"), json.dumps([rule_n(1)]))
    monkeypatch.setattr(LD, "dev_rules_dir", lambda: str(rules_dir))
    sources, _ = LD.discover_sources()
    assert [(s.origin, s.display) for s in sources] == [("builtin", "rules/appsec/x.json")]
    assert [r.id for r in LD.load()] == ["WS-INJ-001"]


def test_dev_rules_dir_only_in_a_source_checkout() -> None:
    found = LD.dev_rules_dir()
    here = os.path.dirname(os.path.abspath(__file__))
    repo_rules = os.path.normpath(os.path.join(here, "..", "..", "..", "rules"))
    assert found is None or os.path.normpath(found) == repo_rules


# ============================================================================================== dict forms


def test_rule_dict_roundtrip() -> None:
    for raw in spec_rules():
        rule = LD.normalize(raw, source_file="x.yaml")
        d = LD.rule_to_dict(rule)
        assert json.loads(json.dumps(d)) == d
        assert LD.rule_from_dict(d) == rule
        assert "source_file" not in LD.rule_to_dict(rule, with_source=False)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("id"),
        lambda d: d.update(severity="severe"),
        lambda d: d.update(max_hits_per_file=True),
        lambda d: d.update(cwe="CWE-1"),
        lambda d: d.update(cwe=[1]),
        lambda d: d["applies_to"].update(kinds="code"),
        lambda d: d.update(keywords_case="upper"),
        lambda d: d.update(fix=3),
        lambda d: d.update(match=[]),
    ],
)
def test_rule_from_dict_rejects_malformed(mutate: Callable[[dict[str, Any]], Any]) -> None:
    d = LD.rule_to_dict(LD.normalize(base_rule()))
    mutate(d)
    with pytest.raises((KeyError, TypeError, ValueError)):
        LD.rule_from_dict(d)
    with pytest.raises(TypeError):
        LD.rule_from_dict([])


def test_bundle_hash_ignores_order_and_source() -> None:
    rules = [LD.normalize(r, source_file=f"f{i}") for i, r in enumerate(spec_rules())]
    moved = [LD.normalize(r, source_file="elsewhere") for r in reversed(spec_rules())]
    assert LD.bundle_hash(rules) == LD.bundle_hash(moved)
    assert LD.bundle_hash(rules).startswith("sha256:") and len(LD.bundle_hash(rules)) == 71
    changed = spec_rules()
    changed[0]["severity"] = "critical"
    assert LD.bundle_hash([LD.normalize(r) for r in changed]) != LD.bundle_hash(rules)


def test_ruleset_serialization_roundtrip() -> None:
    rs = LD.load_raw_rules(
        [
            *spec_rules(),
            rule_n(1, match={"regex": r"os\.system\([^)]*\)"}, message="Found os.system somewhere."),
        ]
    )
    d = rs.to_dict()
    back = RuleSet.from_dict(json.loads(json.dumps(d)))
    assert back.rules == rs.rules
    assert back.bundle_hash == rs.bundle_hash
    assert back.index == rs.index
    assert back.keyword_table == rs.keyword_table
    assert back.warnings == rs.warnings and len(back.warnings) == 1


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(rules={}),
        lambda d: d["index"]["code"].update({"python": [99]}),
        lambda d: d["index"].pop("*"),
        lambda d: d["keywords"].update(always=[True]),
        lambda d: d.update(warnings=[{"level": "x", "code": "c", "message": "m"}]),
        lambda d: d.update(bundle_hash=None),
    ],
)
def test_ruleset_from_dict_rejects_malformed(mutate: Callable[[dict[str, Any]], Any]) -> None:
    d = LD.load_raw_rules(spec_rules()).to_dict()
    mutate(d)
    with pytest.raises((KeyError, TypeError, ValueError)):
        RuleSet.from_dict(d)


def test_ruleset_rejects_duplicate_ids() -> None:
    rule = LD.normalize(base_rule())
    with pytest.raises(RuleError, match="duplicate"):
        RuleSet([rule, rule])


# ============================================================================================== selection


def catalog() -> RuleSet:
    return LD.load_raw_rules(
        [
            rule_n(1),
            rule_n(2, enabled_by_default=False),
            base_rule(
                id="WS-SEC-AWS-001",
                pack="secrets/cloud",
                applies_to={"kind": ["code", "data"]},
                message="AWS access key id found.",
                match={"regex": "AKIA[0-9A-Z]{16}"},
            ),
            base_rule(
                id="WS-TRD-001",
                pack="domain/trading",
                message="Order without client id.",
                match={"regex": r"create_order\("},
            ),
            base_rule(
                id="WS-K8S-001",
                pack="domain/k8s",
                applies_to={"kind": "iac", "tags_any": ["k8s"]},
                message="Privileged container found.",
                match={"yaml_path": {"all": [{"path": "privileged", "equals": True}]}},
            ),
            base_rule(
                id="WS-AGT-001",
                pack="agentsec/unicode",
                applies_to={"kind": ["doc", "agent-config"]},
                message="Hidden unicode found.",
                match={"unicode": {"classes": ["ZW"]}},
            ),
        ]
    )


def ids(rs: RuleSet) -> list[str]:
    return [r.id for r in rs]


def test_select_defaults_to_enabled_rules_in_every_pack() -> None:
    assert ids(catalog().select()) == [
        "WS-INJ-001",
        "WS-SEC-AWS-001",
        "WS-TRD-001",
        "WS-K8S-001",
        "WS-AGT-001",
    ]


def test_select_pack_selectors() -> None:
    rs = catalog()
    assert ids(rs.select(["appsec"])) == ["WS-INJ-001"]
    assert ids(rs.select(["domain/*"])) == ["WS-TRD-001", "WS-K8S-001"]
    assert ids(rs.select(["domain", "-domain/trading"])) == ["WS-K8S-001"]
    assert ids(rs.select(["-domain/trading", "domain"])) == ["WS-K8S-001"]  # removals always win
    assert ids(rs.select(["-domain"])) == ["WS-INJ-001", "WS-SEC-AWS-001", "WS-AGT-001"]
    assert ids(rs.select(["secrets/cloud", " agentsec ", ""])) == ["WS-SEC-AWS-001", "WS-AGT-001"]
    assert ids(rs.select(["*"])) == ids(rs.select())
    assert ids(rs.select([])) == []
    assert ids(rs.select(["domain/nonexistent"])) == []


@pytest.mark.parametrize("selector", ["misc", "-misc/x", "Appsec", "appsec/../x", "a b", "domain/x/y"])
def test_bad_pack_selectors(selector: str) -> None:
    with pytest.raises(RuleError):
        catalog().select([selector])


def test_select_enable_disable_and_rule_filters() -> None:
    rs = catalog()
    assert ids(rs.select(["appsec"], enable=["WS-INJ-002"])) == ["WS-INJ-001", "WS-INJ-002"]
    assert ids(rs.select(["appsec"], enable=["WS-SEC-*"])) == ["WS-INJ-001", "WS-SEC-AWS-001"]
    assert ids(rs.select(disable=["WS-INJ-*", "WS-TRD-001"])) == [
        "WS-SEC-AWS-001",
        "WS-K8S-001",
        "WS-AGT-001",
    ]
    assert ids(rs.select(rule_ids=["WS-K8S-*"])) == ["WS-K8S-001"]
    assert ids(rs.select(["appsec"], rule_ids=["WS-INJ-002"])) == ["WS-INJ-002"]  # exact ID forces it on
    assert ids(rs.select(["appsec"], rule_ids=["WS-INJ-*"])) == ["WS-INJ-001"]  # globs only restrict
    assert ids(rs.select(disable=["WS-INJ-001"], rule_ids=["WS-INJ-001"])) == [
        "WS-INJ-001"
    ]  # CLI beats config
    assert ids(rs.select(exclude=["WS-*-001"])) == []
    assert ids(rs.select(rule_ids=["WS-INJ-001"], exclude=["WS-INJ-001"])) == []


def test_select_unknown_ids() -> None:
    rs = catalog()
    with pytest.raises(RuleError, match="unknown rule ID: WS-NOPE-001"):
        rs.select(rule_ids=["WS-NOPE-001"])
    selected = rs.select(enable=["WS-NOPE-001"], disable=["WS-GONE-*"], exclude=["WS-X-001"])
    assert [w.code for w in selected.warnings] == ["unknown-rule"] * 3


def test_select_keeps_fixture_specs_for_selected_rules() -> None:
    rs = LD.load_raw_rules([rule_n(1, fixtures={"pos": ["a"], "neg": ["b"]}), rule_n(2)])
    assert rs.fixture_specs == {"WS-INJ-001": {"pos": ["a"], "neg": ["b"]}}
    assert rs.select(rule_ids=["WS-INJ-002"]).fixture_specs == {}


def test_applicability_index() -> None:
    rs = catalog()
    assert ids(RuleSet(rs.applicable("code", "python"))) == [
        "WS-INJ-001",
        "WS-INJ-002",
        "WS-SEC-AWS-001",
        "WS-TRD-001",
    ]
    assert ids(RuleSet(rs.applicable("code", "javascript"))) == ["WS-SEC-AWS-001"]
    assert ids(RuleSet(rs.applicable("iac", "yaml"))) == ["WS-K8S-001"]
    assert ids(RuleSet(rs.applicable("iac", "hcl"))) == []
    assert ids(RuleSet(rs.applicable("agent-config", "markdown"))) == ["WS-AGT-001"]
    assert rs.applicable("unknown-kind", "python") == ()
    assert rs.applicable("code", "python") is rs.applicable("code", "python")  # memoized
    assert ids(RuleSet(rs.candidates("iac", "yaml", {"k8s"}))) == ["WS-K8S-001"]
    assert rs.candidates("iac", "yaml", {"compose"}) == ()


def test_rules_without_kind_apply_to_unknown_kinds() -> None:
    rs = LD.load_raw_rules([base_rule(applies_to={"lang": "python"})])
    assert ids(RuleSet(rs.applicable("weird", "python"))) == ["WS-INJ-001"]
    assert ids(RuleSet(rs.applicable("code", "python"))) == ["WS-INJ-001"]


def test_tags_none_excludes() -> None:
    rs = LD.load_raw_rules([base_rule(applies_to={"kind": "code", "tags_none": ["test", "generated"]})])
    assert ids(RuleSet(rs.candidates("code", "python", {"fastapi"}))) == ["WS-INJ-001"]
    assert rs.candidates("code", "python", {"generated"}) == ()


def test_keyword_table() -> None:
    rs = LD.load_raw_rules(
        [
            rule_n(1, keywords=["OS.System", "popen", "os.system"]),
            rule_n(2, keywords=["AKIA"], keywords_case="sensitive"),
            rule_n(3),
        ]
    )
    table = rs.keyword_table
    assert table.insensitive == {"os.system": (0,), "popen": (0,)}
    assert table.sensitive == {"AKIA": (1,)}
    assert table.always == (2,)


def test_ruleset_container_protocol() -> None:
    rs = catalog()
    assert len(rs) == 6 and "WS-INJ-001" in rs and "WS-X" not in rs and repr(rs) == "RuleSet(6 rules)"
    assert rs.packs == (
        "agentsec/unicode",
        "appsec/injection",
        "domain/k8s",
        "domain/trading",
        "secrets/cloud",
    )
    assert rs.counts_by_pack()["appsec/injection"] == 2
    assert rs.get("nope") is None


# ============================================================================================== properties


@settings(max_examples=60, deadline=None)
@given(
    st.permutations(list(range(6))),
    st.sampled_from([*KINDS, "other"]),
    st.sampled_from(["python", "yaml", "json", "hcl", "markdown", "text"]),
)
def test_index_agrees_with_brute_force(order: list[int], kind: str, lang: str) -> None:
    rules = [catalog().rules[i] for i in order]
    rs = RuleSet(rules)

    def admits(r: Rule) -> bool:
        at = r.applies_to
        return (not at.kinds or kind in at.kinds) and (not at.langs or lang in at.langs)

    assert rs.applicable(kind, lang) == tuple(r for r in rules if admits(r))
    assert RuleSet(rules).bundle_hash == catalog().bundle_hash


@settings(max_examples=60, deadline=None)
@given(
    st.lists(
        st.sampled_from(
            [
                "appsec",
                "secrets",
                "domain",
                "agentsec",
                "domain/k8s",
                "domain/*",
                "-domain/trading",
                "-appsec",
                "secrets/cloud",
            ]
        ),
        max_size=4,
    )
)
def test_selection_is_a_subset_in_load_order(packs: list[str]) -> None:
    rs = catalog()
    picked = ids(rs.select(packs))
    assert picked == [i for i in ids(rs) if i in picked]
    assert all(rs.by_id[i].enabled_by_default for i in picked)


@settings(max_examples=40, deadline=None)
@given(st.data())
def test_normalize_is_deterministic_and_input_preserving(data: st.DataObject) -> None:
    raw = copy.deepcopy(data.draw(st.sampled_from(spec_rules())))
    before = copy.deepcopy(raw)
    assert LD.normalize(raw) == LD.normalize(raw)
    assert raw == before


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_fifos_never_hang_the_loader(tmp_path: Any) -> None:
    fifo = tmp_path / "rules" / "pack.yaml"
    os.makedirs(fifo.parent)
    os.mkfifo(fifo)
    assert LD.iter_pack_files(str(fifo.parent)) == ([], [])  # discovery skips non-regular files
    with pytest.raises(RuleError, match="not a regular file"):
        LD.load(files=[str(fifo)], builtin=False)  # an explicit FIFO is refused, not opened


def test_read_regular_file_checks(tmp_path: Any) -> None:
    path = tmp_path / "f.txt"
    path.write_bytes(b"abc")
    assert LD.read_regular_file(str(path), 3) == b"abc"
    with pytest.raises(LD.UnreadableFile, match="larger than 2 bytes"):
        LD.read_regular_file(str(path), 2)
    with pytest.raises(LD.UnreadableFile, match="vetoed"):
        LD.read_regular_file(str(path), 10, check=lambda st: "vetoed")
    with pytest.raises(LD.UnreadableFile, match="not a regular file"):
        LD.read_regular_file(str(tmp_path), 10)
    with pytest.raises(OSError):
        LD.read_regular_file(str(tmp_path / "missing"), 10)
