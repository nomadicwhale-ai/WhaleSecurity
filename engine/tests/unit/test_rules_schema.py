"""Tests for whalescan.rules.schema: the §7.2 rule schema and the stdlib validator.

The stdlib validator must agree with the reference `jsonschema` package (draft 2020-12) on every JSON-shaped
instance, except for the documented, stricter ECMA-262 handling of a trailing `$` in `pattern`.
"""

from __future__ import annotations

import copy
import json
import os
import re
from typing import Any

import jsonschema  # type: ignore[import-untyped]
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from whalescan.rules import schema as S
from whalescan.rules.loader import RULE_SCHEMA_VERSION

SPEC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "docs", "specs", "engine.md")
REF = jsonschema.Draft202012Validator(S.RULE_SCHEMA)


def ref_valid(instance: Any) -> bool:
    return bool(REF.is_valid(instance))


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


def with_match(match: Any, **over: Any) -> dict[str, Any]:
    return base_rule(match=match, **over)


# ------------------------------------------------------------------------------------------------ corpus

VALID: list[dict[str, Any]] = [
    base_rule(),
    {
        "id": "WS-SEC-DB-002",
        "title": "Database URL with inline password",
        "pack": "secrets/generic",
        "severity": "high",
        "confidence": "high",
        "owner": "@whalesecurity/secrets",
        "cwe": ["CWE-798"],
        "owasp": ["A07"],
        "applies_to": {"kind": ["code", "iac", "ci", "data", "doc"]},
        "keywords": ["://"],
        "match": {
            "regex": {
                "pattern": r"(?P<scheme>postgres(?:ql)?|mysql)://(?P<user>[^:/\s@]{1,128}):(?P<secret>[^@\s/]{1,256})@",
                "secret_group": "secret",
            }
        },
        "filters": {"line_not_regex": r"://[^:\s]{1,128}:(?:\$\{[^}]{1,64}\}|\*{3,})@"},
        "message": "{{scheme}} connection string for user {{user}} embeds a password.",
        "fix": "Read the DSN from Secrets Manager, Vault or a k8s Secret, and rotate this credential.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    base_rule(
        id="WS-K8S-001",
        pack="domain/k8s",
        title="Privileged container",
        applies_to={"kind": "iac", "tags_any": ["k8s", "helm"]},
        match={
            "yaml_path": {
                "each": "**.{containers,initContainers,ephemeralContainers}[*]",
                "all": [{"path": "securityContext.privileged", "equals": True}],
            }
        },
        message="Container runs privileged, with full host device and kernel access.",
    ),
    base_rule(
        id="WS-GHA-001",
        pack="domain/gha",
        title="pull_request_target checks out PR head code",
        applies_to={"kind": "ci", "glob": [".github/workflows/*.y*ml"]},
        match={
            "yaml_path": {
                "all": [
                    {"path": "on.pull_request_target", "exists": True},
                    {
                        "path": "jobs.*.steps[*].with.ref",
                        "regex": r"github\.event\.pull_request\.head\.(sha|ref)",
                    },
                ]
            }
        },
        message="Workflow runs with a write token and secrets, but checks out untrusted fork code.",
        fixtures="auto",
    ),
    base_rule(
        id="WS-AGT-MCP-010",
        pack="agentsec/mcp",
        title="MCP server launched from an unpinned package",
        applies_to={"kind": "agent-config", "tags_any": ["mcp"]},
        match={
            "yaml_path": {
                "each": "mcpServers.*",
                "all": [
                    {"path": "command", "in": ["npx", "bunx", "pnpx", "uvx"]},
                    {
                        "path": "args[*]",
                        "regex": r"^(?:@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$",
                        "quantifier": "any",
                    },
                ],
            }
        },
        message="MCP server runs a package without a pinned version.",
    ),
    base_rule(
        id="WS-TF-001",
        pack="domain/terraform",
        title="Security group open to the internet",
        applies_to={"kind": "iac", "lang": ["hcl", "json"]},
        match={
            "hcl": {
                "block": "resource.aws_security_group.*",
                "each": "ingress",
                "all": [
                    {"attr": "cidr_blocks", "contains": "0.0.0.0/0"},
                    {"range_includes": {"lo": "from_port", "hi": "to_port", "any": [22, 3389, 5432]}},
                ],
                "on_unknown": "match",
            }
        },
        message="Ingress rule opens an administrative port to 0.0.0.0/0.",
    ),
    base_rule(
        match={
            "py_ast": {
                "call": {
                    "callee": ["subprocess.{run,call,check_call,check_output,Popen}", "os.system"],
                    "args": {"0": {"tainted": True}, "*": {"dynamic_string": True}},
                    "kwargs": {"shell": {"equals": True}, "Loader": {"regex": "Safe"}},
                    "kwarg_absent": ["timeout"],
                    "sources": ["web", "cli", "request.query_params"],
                    "sanitizers": ["shlex.quote"],
                    "require_import": "subprocess",
                }
            }
        },
        message="Subprocess call built from untrusted input.",
    ),
    base_rule(
        id="WS-API-001",
        pack="domain/fastapi",
        title="FastAPI route without auth",
        match={"py_ast": {"fastapi_route": {"methods": ["post", "put"], "auth_regex": "(?i)auth"}}},
        message="State-changing route has no auth dependency.",
    ),
    base_rule(
        id="WS-SEC-KEY-001",
        pack="secrets/keys",
        title="Private key block",
        match={
            "multiline": {
                "pattern": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[A-Za-z0-9+/=\s]{64,8192}-----END",
                "flags": ["s"],
                "max_span_lines": 200,
                "secret_group": "k",
            }
        },
        message="A private key is committed to the repository.",
    ),
    base_rule(
        id="WS-AIR-001",
        pack="domain/airflow",
        title="Airflow template injection",
        match={
            "multiline": {
                "sequence": [r"\bBashOperator\(", r"bash_command\s*=", r"\{\{\s*params\b"],
                "within_lines": 12,
                "flags": ["i"],
            }
        },
        message="BashOperator renders untrusted params into a shell command.",
    ),
    base_rule(
        id="WS-AGT-001",
        pack="agentsec/unicode",
        title="Hidden unicode characters",
        match={
            "unicode": {
                "classes": ["ZW", "BIDI", "TAG"],
                "min_run": 2,
                "bidi_unbalanced_only": False,
                "allow_emoji_sequences": True,
            }
        },
        message="Hidden characters can smuggle instructions.",
    ),
    base_rule(
        id="WS-SEC-GEN-001",
        pack="secrets/generic",
        title="High-entropy secret value",
        match={
            "entropy": {
                "charset": "base64",
                "min_len": 20,
                "max_len": 200,
                "threshold": 4.5,
                "scope": "values",
                "min_classes": 2,
                "context": {"keywords": ["token"], "required": False, "window_chars": 80},
                "exclude_regex": ["^sha256-"],
            }
        },
        message="A high-entropy value looks like a secret.",
    ),
    base_rule(
        id="WS-AGT-MCP-001",
        pack="agentsec/mcp",
        title="MCP tool description drift",
        match={"builtin": "mcp_drift"},
        message="An MCP tool description changed since it was pinned.",
    ),
    base_rule(
        match={"all": [{"regex": "os\\.system"}, {"not": {"regex": "shlex\\.quote"}}], "near_lines": 3}
    ),
    base_rule(
        match={
            "any": [
                {"regex": "os\\.system"},
                {"regex": {"pattern": "popen", "flags": ["i", "a"], "report_group": 0}},
            ]
        }
    ),
    base_rule(
        cwe=["CWE-78", "CWE-77"],
        owasp=["A03:2021", "API8:2023", "LLM01:2025", "CICD-SEC-10", "K01", "A10"],
        atlas=["AML.T0051", "AML.T0051.001"],
        tags=["python", "shell-injection"],
        since="1.0.0",
        deprecated=True,
        replaced_by="WS-INJ-002",
        enabled_by_default=False,
        keywords=["os.system", "popen"],
        keywords_case="sensitive",
        redact=True,
        exposure_sensitive=False,
        supersedes=["WS-INJ-009"],
        max_hits_per_file=1000,
        fix="Use subprocess.run with a list argv.",
        filters={"file_regex": "import os", "file_not_regex": "# generated", "path_not_glob": ["tests/**"]},
        fixtures={"pos": ["WS-INJ-001/pos.py"], "neg": ["WS-INJ-001/neg.py"]},
    ),
    base_rule(match={"regex": {"pattern": "(?P<cmd>system)", "report_group": "cmd", "flags": ["x"]}}),
    base_rule(
        applies_to={
            "kind": ["code", "doc"],
            "lang": ["python", "markdown"],
            "glob": ["**/*.py"],
            "exclude_glob": ["vendor/**"],
            "tags_any": ["fastapi"],
            "tags_none": ["test"],
            "include_minified": True,
            "max_bytes": 1,
        }
    ),
    base_rule(
        match={"hcl": {"block": "module.*", "any": [{"range_includes": {"lo": "a", "hi": "b", "any": [0]}}]}}
    ),
    base_rule(
        match={
            "yaml_path": {
                "none": [
                    {
                        "path": "a",
                        "not_in": [1, "x", None, True],
                        "type": "seq",
                        "contains": 3,
                        "promote": False,
                    },
                    {"path": "b", "not_equals": 1.5, "not_regex": "x", "quantifier": "all"},
                ],
                "schema": "yaml11",
            }
        }
    ),
    base_rule(max_hits_per_file=50.0),  # JSON Schema integers include 50.0
]


def invalid(path: str, rule: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    return path, rule


def without(key: str) -> dict[str, Any]:
    r = base_rule()
    del r[key]
    return r


INVALID: list[tuple[str, dict[str, Any]]] = [
    *[invalid("", without(k)) for k in S.RULE_SCHEMA["required"]],
    invalid("", base_rule(extra=1)),
    invalid("id", base_rule(id="WS-FOO-001")),
    invalid("id", base_rule(id="WS-INJ-01")),
    invalid("id", base_rule(id="ws-inj-001")),
    invalid("id", base_rule(id="WS-SEC-TOOLONGSUBNS-001")),
    invalid("id", base_rule(id=7)),
    invalid("title", base_rule(title="short")),
    invalid("title", base_rule(title="x" * 121)),
    invalid("pack", base_rule(pack="misc/x")),
    invalid("pack", base_rule(pack="appsec/")),
    invalid("pack", base_rule(pack="appsec/Upper")),
    invalid("severity", base_rule(severity="severe")),
    invalid("confidence", base_rule(confidence="certain")),
    invalid("cwe", base_rule(cwe=["CWE-1", "CWE-1"])),
    invalid("cwe[0]", base_rule(cwe=["CWE-0"])),
    invalid("owasp[0]", base_rule(owasp=["A11"])),
    invalid("owasp[0]", base_rule(owasp=["A01:2020"])),
    invalid("atlas[0]", base_rule(atlas=["AML.T51"])),
    invalid("tags[0]", base_rule(tags=["Upper"])),
    invalid("owner", base_rule(owner="whalesecurity")),
    invalid("since", base_rule(since="1.0")),
    invalid("replaced_by", base_rule(replaced_by="INJ-001")),
    invalid("supersedes", base_rule(supersedes=["WS-A-001", "WS-A-001"])),
    invalid("applies_to", base_rule(applies_to={})),
    invalid("applies_to.kind", base_rule(applies_to={"kind": "binary"})),
    invalid("applies_to.kind", base_rule(applies_to={"kind": []})),
    invalid("applies_to.lang", base_rule(applies_to={"lang": ""})),
    invalid("applies_to.lang", base_rule(applies_to={"lang": []})),
    invalid("applies_to.glob", base_rule(applies_to={"glob": "*.py"})),
    invalid("applies_to.max_bytes", base_rule(applies_to={"max_bytes": 0})),
    invalid("applies_to", base_rule(applies_to={"kinds": ["code"]})),
    invalid("keywords[0]", base_rule(keywords=["x"])),
    invalid("keywords", base_rule(keywords=[f"k{i}" for i in range(33)])),
    invalid("keywords_case", base_rule(keywords_case="upper")),
    invalid("match", with_match({})),
    invalid("match", with_match({"regex": "a", "multiline": {"pattern": "b"}})),
    invalid("match.all", with_match({"all": [{"regex": "a"}]})),
    invalid("match.any", with_match({"any": [{"regex": "a"}]})),
    invalid("match", with_match({"any": [{"regex": "a"}, {"regex": "b"}], "near_lines": 2})),
    invalid("match.near_lines", with_match({"all": [{"regex": "a"}, {"regex": "b"}], "near_lines": 501})),
    invalid("match.not", with_match({"not": [{"regex": "a"}]})),
    invalid("match", with_match("os.system")),
    invalid("match.regex", with_match({"regex": ""})),
    invalid("match.regex.flags[0]", with_match({"regex": {"pattern": "a", "flags": ["s"]}})),
    invalid("match.regex.flags", with_match({"regex": {"pattern": "a", "flags": ["i", "i"]}})),
    invalid("match.regex.report_group", with_match({"regex": {"pattern": "a", "report_group": -1}})),
    invalid("match.regex.secret_group", with_match({"regex": {"pattern": "a", "secret_group": "1bad"}})),
    invalid("match.regex.pattern", with_match({"regex": {"pattern": "a" * 4097}})),
    invalid("match.regex", with_match({"regex": {"pattern": "a", "group": 1}})),
    invalid(
        "match.multiline",
        with_match({"multiline": {"pattern": "a", "sequence": ["a", "b"], "within_lines": 2}}),
    ),
    invalid("match.multiline.sequence", with_match({"multiline": {"sequence": ["a"], "within_lines": 2}})),
    invalid(
        "match.multiline.sequence", with_match({"multiline": {"sequence": list("abcdef"), "within_lines": 2}})
    ),
    invalid("match.multiline", with_match({"multiline": {"sequence": ["a", "b"]}})),
    invalid(
        "match.multiline.max_span_lines", with_match({"multiline": {"pattern": "a", "max_span_lines": 0}})
    ),
    invalid("match.multiline.flags[0]", with_match({"multiline": {"pattern": "a", "flags": ["m"]}})),
    invalid("match.unicode.classes", with_match({"unicode": {"classes": []}})),
    invalid("match.unicode.classes[0]", with_match({"unicode": {"classes": ["EMOJI"]}})),
    invalid("match.unicode.min_run", with_match({"unicode": {"classes": ["ZW"], "min_run": 0}})),
    invalid("match.entropy", with_match({"entropy": {"min_len": 20}})),
    invalid("match.entropy.min_len", with_match({"entropy": {"charset": "hex", "min_len": 11}})),
    invalid("match.entropy.threshold", with_match({"entropy": {"charset": "hex", "threshold": 7}})),
    invalid("match.entropy.scope", with_match({"entropy": {"charset": "hex", "scope": "lines"}})),
    invalid("match.entropy.context", with_match({"entropy": {"charset": "hex", "context": {"words": []}}})),
    invalid(
        "match.entropy.context.window_chars",
        with_match({"entropy": {"charset": "hex", "context": {"window_chars": 7}}}),
    ),
    invalid("match.yaml_path", with_match({"yaml_path": {"each": "a"}})),
    invalid("match.yaml_path.all[0]", with_match({"yaml_path": {"all": [{"exists": True}]}})),
    invalid("match.yaml_path.all[0]", with_match({"yaml_path": {"all": [{"path": "a"}]}})),
    invalid(
        "match.yaml_path.all[0]", with_match({"yaml_path": {"all": [{"path": "a", "exists": True, "x": 1}]}})
    ),
    invalid(
        "match.yaml_path.schema",
        with_match({"yaml_path": {"all": [{"path": "a", "exists": True}], "schema": "yaml13"}}),
    ),
    invalid("match.yaml_path.all[0].in", with_match({"yaml_path": {"all": [{"path": "a", "in": []}]}})),
    invalid(
        "match.yaml_path.all[0].type", with_match({"yaml_path": {"all": [{"path": "a", "type": "list"}]}})
    ),
    invalid(
        "match.yaml_path.all[0].quantifier",
        with_match({"yaml_path": {"all": [{"path": "a", "exists": True, "quantifier": "some"}]}}),
    ),
    invalid(
        "match.yaml_path.all[0].equals", with_match({"yaml_path": {"all": [{"path": "a", "equals": [1]}]}})
    ),
    invalid("match.py_ast", with_match({"py_ast": {}})),
    invalid("match.py_ast.call", with_match({"py_ast": {"call": {"args": {}}}})),
    invalid(
        "match.py_ast.call.args",
        with_match({"py_ast": {"call": {"callee": "f", "args": {"abc": {"tainted": True}}}}}),
    ),
    invalid(
        "match.py_ast.call.kwargs",
        with_match({"py_ast": {"call": {"callee": "f", "kwargs": {"1x": {"tainted": True}}}}}),
    ),
    invalid(
        'match.py_ast.call.args["0"]', with_match({"py_ast": {"call": {"callee": "f", "args": {"0": {}}}}})
    ),
    invalid("match.py_ast.call.callee", with_match({"py_ast": {"call": {"callee": []}}})),
    invalid(
        "match.py_ast.fastapi_route.methods[0]",
        with_match({"py_ast": {"fastapi_route": {"methods": ["head"]}}}),
    ),
    invalid("match.hcl", with_match({"hcl": {"each": "x"}})),
    invalid("match.hcl.all[0]", with_match({"hcl": {"block": "a", "all": [{"equals": 1}]}})),
    invalid(
        "match.hcl.all[0].range_includes",
        with_match({"hcl": {"block": "a", "all": [{"range_includes": {"lo": "a", "any": [1]}}]}}),
    ),
    invalid(
        "match.hcl.all[0].range_includes.any[0]",
        with_match(
            {"hcl": {"block": "a", "all": [{"range_includes": {"lo": "a", "hi": "b", "any": [70000]}}]}}
        ),
    ),
    invalid("match.hcl.on_unknown", with_match({"hcl": {"block": "a", "on_unknown": "maybe"}})),
    invalid("match.hcl.all[0]", with_match({"hcl": {"block": "a", "all": [{"attr": "x", "path": "y"}]}})),
    invalid("match.builtin", with_match({"builtin": "other"})),
    invalid("filters", base_rule(filters={"glob": "x"})),
    invalid("filters.path_not_glob", base_rule(filters={"path_not_glob": "tests/**"})),
    invalid("redact", base_rule(redact="yes")),
    invalid("max_hits_per_file", base_rule(max_hits_per_file=0)),
    invalid("max_hits_per_file", base_rule(max_hits_per_file=1001)),
    invalid("max_hits_per_file", base_rule(max_hits_per_file=1.5)),
    invalid("max_hits_per_file", base_rule(max_hits_per_file=True)),
    invalid("message", base_rule(message="too short")),
    invalid("fix", base_rule(fix="x" * 1201)),
    invalid("references", base_rule(references=[])),
    invalid("references[0]", base_rule(references=["http://example.com"])),
    invalid("references[0]", base_rule(references=["https://exa mple.com"])),
    invalid("fixtures", base_rule(fixtures="manual")),
    invalid("fixtures.pos", base_rule(fixtures={"pos": [], "neg": ["n"]})),
    invalid("fixtures", base_rule(fixtures={"pos": ["a"]})),
]


# ------------------------------------------------------------------------------------------------ spec sync


def spec_schema() -> dict[str, Any]:
    if not os.path.exists(SPEC):
        pytest.skip("engine spec not available")
    with open(SPEC, encoding="utf-8") as fh:
        text = fh.read()
    section = text.split("### 7.2 JSON Schema (draft 2020-12)", 1)[1]
    block = section.split("```json", 1)[1].split("```", 1)[0]
    loaded: dict[str, Any] = json.loads(block)
    return loaded


def test_schema_matches_spec_verbatim() -> None:
    assert spec_schema() == S.RULE_SCHEMA


def test_schema_is_a_valid_draft_2020_12_schema() -> None:
    jsonschema.Draft202012Validator.check_schema(S.RULE_SCHEMA)


def test_schema_version_matches_id() -> None:
    assert S.RULE_SCHEMA["$id"] == S.SCHEMA_ID == f"urn:whalescan:schema:rule:{S.SCHEMA_VERSION}"
    assert RULE_SCHEMA_VERSION == S.SCHEMA_VERSION


def test_validator_implements_every_keyword_the_schema_uses() -> None:
    used = set(S.iter_keywords(S.RULE_SCHEMA))
    assert used <= S.IMPLEMENTED_KEYWORDS | S.ANNOTATION_KEYWORDS
    # and nothing implemented is dead: every assertion keyword is exercised by the schema
    assert used >= S.IMPLEMENTED_KEYWORDS


def test_validator_refuses_schemas_with_unknown_keywords() -> None:
    with pytest.raises(ValueError, match="patternProperties"):
        S.Validator({"type": "object", "patternProperties": {"^x": {}}})


# ------------------------------------------------------------------------------------------------ corpus


@pytest.mark.parametrize("rule", VALID, ids=lambda r: str(r.get("id")))
def test_valid_corpus(rule: dict[str, Any]) -> None:
    assert S.validate_rule(rule) == []
    assert ref_valid(rule)


@pytest.mark.parametrize(("where", "rule"), INVALID, ids=[f"{i}:{w}" for i, (w, _) in enumerate(INVALID)])
def test_invalid_corpus(where: str, rule: dict[str, Any]) -> None:
    issues = S.validate_rule(rule)
    assert issues, "stdlib validator accepted an invalid rule"
    assert not ref_valid(rule), "reference validator accepted it: the corpus entry is wrong"
    assert any(i.path == where for i in issues), [str(i) for i in issues]


def test_validation_does_not_mutate_input() -> None:
    rule = base_rule(match={"yaml_path": {"all": [{"path": "a", "exists": True}]}})
    before = copy.deepcopy(rule)
    S.validate_rule(rule)
    assert rule == before


# ------------------------------------------------------------------------------------------------ messages


def messages(rule: Any) -> list[str]:
    return [str(i) for i in S.validate_rule(rule)]


def test_messages_point_at_the_failing_leaf() -> None:
    assert messages(with_match({"regex": {"pattern": ""}})) == [
        "match.regex.pattern: must be at least 1 characters long (got 0)"
    ]
    assert messages(with_match({"yaml_path": {"each": "x"}})) == [
        'match.yaml_path: requires one of the properties "all", "any", "none"'
    ]
    assert messages(with_match({"yaml_path": {"all": [{"path": "a", "exists": True, "bogus": 1}]}})) == [
        'match.yaml_path.all[0]: unexpected property "bogus"'
    ]
    assert messages(base_rule(severity="severe"))[0].startswith(
        'severity: "severe" is not one of: "critical"'
    )
    assert messages(base_rule(extra=1)) == ['(rule): unexpected property "extra"']
    assert messages(without("id")) == ['(rule): missing required property "id"']
    two = messages(with_match({"regex": "a", "multiline": {"pattern": "b"}}))
    assert two == ['match: must have at most 1 property, got "regex", "multiline"']


def test_alternatives_mismatch_message_lists_types() -> None:
    assert messages(with_match("x")) == ["match: expected object, got string"]
    msg = messages(base_rule(applies_to={"lang": 5}))
    assert msg == ["applies_to.lang: expected string or array, got integer"]


def test_schema_issue_formatting() -> None:
    assert S.format_path(["match", "all", 0, "regex"]) == "match.all[0].regex"
    assert S.format_path(["args", "0"]) == 'args["0"]'
    assert S.format_path([]) == ""
    assert str(S.SchemaIssue("", "boom")) == "(rule): boom"


# ------------------------------------------------------------------------------------------------ semantics


def test_json_equality_distinguishes_booleans_from_numbers() -> None:
    assert S.json_equal(1, 1.0)
    assert not S.json_equal(1, True)
    assert not S.json_equal(0, False)
    assert S.json_equal({"a": [1, None]}, {"a": [1.0, None]})
    assert not S.json_equal([1], [1, 2])
    assert not S.json_equal("1", 1)


@pytest.mark.parametrize(
    ("items", "unique"),
    [
        ([1, True], True),
        ([0, False], True),
        ([1, 1.0], False),
        (["a", "b"], True),
        ([[1], [1.0]], False),
        ([{"a": 1}, {"a": True}], True),
        ([None, None], False),
    ],
)
def test_unique_items_semantics(items: list[Any], unique: bool) -> None:
    v = S.Validator({"type": "array", "uniqueItems": True})
    assert v.is_valid(items) is unique
    assert jsonschema.Draft202012Validator({"type": "array", "uniqueItems": True}).is_valid(items) is unique


def test_enum_does_not_confuse_true_and_one() -> None:
    v = S.Validator({"enum": [1]})
    assert v.is_valid(1) and v.is_valid(1.0)
    assert not v.is_valid(True)


def test_trailing_newline_is_rejected_unlike_python_re_dollar() -> None:
    """Documented divergence: ECMA-262 `$` is end of input; Python's `$` also matches before a final "\\n"."""
    rule = base_rule(id="WS-INJ-001\n")
    assert ref_valid(rule)  # the reference package uses re.search with Python semantics
    assert [i.path for i in S.validate_rule(rule)] == ["id"]


def test_escaped_dollar_is_not_rewritten() -> None:
    v = S.Validator({"type": "string", "pattern": r"^a\$"})
    assert v.is_valid("a$")
    assert v.is_valid("a$b")


# ------------------------------------------------------------------------------------------------ precheck


def test_precheck_rejects_non_json_values() -> None:
    import datetime

    assert S.precheck({"a": float("nan")}) is not None
    assert S.precheck({"a": float("inf")}) is not None
    assert "not a string" in str(S.precheck({1: "x"}))
    assert "date" in str(S.precheck({"since": datetime.date(2024, 1, 1)}))
    assert S.precheck({"a": [1, "x", None, True, 1.5, {"b": []}]}) is None


def test_deeply_nested_rule_is_rejected_without_recursion_error() -> None:
    expr: dict[str, Any] = {"regex": "a"}
    for _ in range(5000):
        expr = {"all": [expr, {"regex": "b"}]}
    issues = S.validate_rule(with_match(expr))
    assert len(issues) == 1
    assert "nesting deeper" in issues[0].message


def test_self_referencing_structure_terminates() -> None:
    cyclic: list[Any] = []
    cyclic.append(cyclic)
    issues = S.validate_rule(base_rule(tags=cyclic))
    assert len(issues) == 1


def test_oversized_rule_is_rejected() -> None:
    issues = S.validate_rule(base_rule(keywords=["ab"] * (S.MAX_NODES + 1)))
    assert issues and "too large" in issues[0].message


def test_non_object_rule() -> None:
    values: tuple[Any, ...] = (None, [], "rule", 3)
    for value in values:
        issues = S.validate_rule(value)
        assert len(issues) == 1 and issues[0].path == ""


# ------------------------------------------------------------------------------------------------ properties

_WORDS = [
    "WS-INJ-002",
    "WS-SEC-AWS-001",
    "high",
    "low",
    "medium",
    "code",
    "iac",
    "python",
    "yaml",
    "json",
    "all",
    "any",
    "not",
    "regex",
    "pattern",
    "path",
    "exists",
    "equals",
    "in",
    "classes",
    "ZW",
    "charset",
    "hex",
    "block",
    "attr",
    "call",
    "callee",
    "fastapi_route",
    "sequence",
    "within_lines",
    "flags",
    "i",
    "s",
    "secret_group",
    "auto",
    "appsec/x",
    "@team",
    "https://x",
    "CWE-79",
    "A01",
    "mcp_drift",
    "range_includes",
    "lo",
    "hi",
    "kind",
]
_text = st.one_of(
    st.sampled_from(_WORDS),
    st.text(alphabet=st.characters(codec="utf-8", exclude_characters="\n"), max_size=12),
)
_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(-3, 70000),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    _text,
)
_json = st.recursive(
    _scalars,
    lambda inner: st.lists(inner, max_size=4) | st.dictionaries(_text, inner, max_size=4),
    max_leaves=12,
)


def _container_paths(value: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    out = [prefix]
    if isinstance(value, dict):
        for k, v in value.items():
            out += _container_paths(v, (*prefix, k))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            out += _container_paths(v, (*prefix, i))
    return out


@st.composite
def mutated_rules(draw: st.DrawFn) -> Any:
    rule = copy.deepcopy(draw(st.sampled_from(VALID)))
    for _ in range(draw(st.integers(1, 3))):
        paths = _container_paths(rule)
        path = draw(st.sampled_from(paths))
        if not path:
            continue
        parent: Any = rule
        for seg in path[:-1]:
            parent = parent[seg]
        last = path[-1]
        action = draw(st.sampled_from(["replace", "delete", "add"]))
        if action == "replace":
            parent[last] = draw(_json)
        elif action == "delete" and isinstance(parent, dict):
            del parent[last]
        elif action == "delete" and isinstance(parent, list):
            parent.pop(last)
        elif isinstance(parent, dict):
            parent[draw(_text)] = draw(_json)
        elif isinstance(parent, list):
            parent.append(draw(_json))
    return rule


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(mutated_rules())
def test_agrees_with_reference_validator_on_mutated_rules(rule: Any) -> None:
    assert S.is_valid_rule(rule) == ref_valid(rule), [str(i) for i in S.validate_rule(rule)]


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(_json)
def test_agrees_with_reference_validator_on_arbitrary_matchers(match: Any) -> None:
    rule = base_rule(match=match)
    assert S.is_valid_rule(rule) == ref_valid(rule)


@settings(max_examples=200, deadline=None)
@given(
    st.dictionaries(
        st.sampled_from([*sorted(S.RULE_SCHEMA["$defs"]["applies_to"]["properties"]), "x"]), _json, max_size=4
    )
)
def test_agrees_on_applies_to(applies_to: dict[str, Any]) -> None:
    rule = base_rule(applies_to=applies_to)
    assert S.is_valid_rule(rule) == ref_valid(rule)


@given(st.text(alphabet=st.characters(codec="utf-8"), max_size=40))
def test_id_pattern_agrees_except_for_trailing_newline(value: str) -> None:
    rule = base_rule(id=value)
    ours, ref = S.is_valid_rule(rule), ref_valid(rule)
    if value.endswith("\n"):
        assert not ours
    else:
        assert ours == ref
    if ours:
        assert re.fullmatch(S.RULE_SCHEMA["properties"]["id"]["pattern"].rstrip("$"), value)
