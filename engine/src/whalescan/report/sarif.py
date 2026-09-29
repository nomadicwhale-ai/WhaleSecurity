"""SARIF 2.1.0 reporter (spec §12.3). One run; adapter results share it under prefixed rule ids."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote

from ..model import Finding, ScanResult, Severity
from ._common import clean_obj, ordered, pascal_case

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
}


def _uri(path: str) -> tuple[str, str | None]:
    """``(uri, uriBaseId)``: relative POSIX paths are percent-encoded against ``%SRCROOT%``."""
    p = path.replace("\\", "/")
    if p.startswith("/"):
        return "file://" + quote(p, safe="/"), None
    return quote(p.lstrip("./") if p.startswith("./") else p, safe="/"), "%SRCROOT%"


def _tags(f: Finding) -> list[str]:
    tags = ["security", f.pack] if f.pack else ["security"]
    tags += [f"external/cwe/{c.lower()}" for c in f.cwe]
    tags += [f"owasp/{o}" for o in f.owasp]
    return list(dict.fromkeys(t for t in tags if t))


def _rule(f: Finding) -> dict[str, Any]:
    help_text = (f.fix or "") + ("\n\n" if f.fix and f.references else "") + "\n".join(f.references)
    rule: dict[str, Any] = {
        "id": f.rule_id,
        "name": pascal_case(f.title),
        "shortDescription": {"text": f.title},
        "fullDescription": {"text": re.sub(r"\{\{[^}]*\}\}", "", f.message).strip() or f.title},
        "defaultConfiguration": {"level": _LEVEL[f.base_severity]},
        "properties": {"tags": _tags(f), "precision": f.confidence.label},
    }
    if help_text:
        rule["help"] = {"text": help_text, "markdown": help_text}
    if f.references:
        rule["helpUri"] = f.references[0]
    if f.base_severity in _SECURITY_SEVERITY:
        rule["properties"]["security-severity"] = _SECURITY_SEVERITY[f.base_severity]
    return rule


def _result(f: Finding, rule_index: int) -> dict[str, Any]:
    uri, base = _uri(f.file)
    artifact: dict[str, Any] = {"uri": uri}
    if base:
        artifact["uriBaseId"] = base
    region: dict[str, Any] = {
        "startLine": f.line,
        "startColumn": f.col,
        "endLine": f.end_line,
        "endColumn": f.end_col,
    }
    if f.snippet:
        region["snippet"] = {"text": f.snippet}
    res: dict[str, Any] = {
        "ruleId": f.rule_id,
        "ruleIndex": rule_index,
        "level": _LEVEL[f.severity],
        "message": {"text": f.message},
        "locations": [{"physicalLocation": {"artifactLocation": artifact, "region": region}}],
        "partialFingerprints": {"whalescan/v1": f.fingerprint, "whalescan/content/v1": f.content_fingerprint},
        "properties": {
            "severity": f.severity.label,
            "base_severity": f.base_severity.label,
            "score": round(f.score, 2),
            "confidence": f.confidence.label,
            "reachability": f.reachability,
            "exposure": f.exposure,
            "source": f.source,
            "pack": f.pack,
            "cwe": list(f.cwe),
            "owasp": list(f.owasp),
        },
    }
    trace = f.properties.get("trace") if f.properties else None
    if trace:
        steps = [
            {
                "location": {
                    "physicalLocation": {
                        "artifactLocation": dict(artifact),
                        "region": {"startLine": int(t["line"])},
                    },
                    "message": {"text": str(t.get("name") or t.get("via") or "")},
                }
            }
            for t in trace
        ]
        res["codeFlows"] = [{"threadFlows": [{"locations": steps}]}]
    if f.suppressed:
        s = f.suppressed
        res["suppressions"] = [
            {
                "kind": "inSource" if s.kind == "inline" else "external",
                "status": "accepted",
                **({"justification": s.reason} if s.reason else {}),
            }
        ]
    return res


def render(result: ScanResult, absolute_root: str | None = None) -> str:
    findings = ordered(result, include_suppressed=True)
    rules: list[dict[str, Any]] = []
    index: dict[str, int] = {}
    results = []
    for f in findings:
        if f.rule_id not in index:
            index[f.rule_id] = len(rules)
            rules.append(_rule(f))
        results.append(_result(f, index[f.rule_id]))
    driver: dict[str, Any] = {
        "name": "whalescan",
        "version": result.run.tool_version,
        "semanticVersion": result.run.tool_version,
        "rules": rules,
    }
    if not driver["version"]:
        del driver["version"], driver["semanticVersion"]
    tool: dict[str, Any] = {"driver": driver}
    ext = sorted({f.source for f in findings if f.source != "engine"})
    if ext:
        tool["extensions"] = [{"name": name} for name in ext]
    notifications = [
        {
            "level": {"error": "error", "warning": "warning"}.get(d.level, "note"),
            "message": {"text": d.message},
            "descriptor": {"id": d.code},
            **(
                {"locations": [{"physicalLocation": {"artifactLocation": {"uri": _uri(d.file)[0]}}}]}
                if d.file
                else {}
            ),
        }
        for d in result.diagnostics
    ]
    ok = result.run.error is None and result.run.exit_code != 3
    invocation: dict[str, Any] = {
        "executionSuccessful": ok,
        "exitCode": result.run.exit_code,
        "toolExecutionNotifications": notifications,
    }
    if result.run.error:
        invocation["toolExecutionNotifications"].append(
            {
                "level": "error",
                "message": {"text": result.run.error.get("message", "internal error")},
                "descriptor": {"id": result.run.error.get("type", "internal-error")},
            }
        )
    packs = "+".join(sorted(result.run.packs)) or "all"
    run: dict[str, Any] = {
        "tool": tool,
        "columnKind": "unicodeCodePoints",
        "automationDetails": {"id": f"whalescan/{packs}/"},
        "invocations": [invocation],
        "results": results,
    }
    if absolute_root:
        run["originalUriBaseIds"] = {
            "%SRCROOT%": {"uri": "file://" + quote(absolute_root.rstrip("/") + "/", safe="/")}
        }
    doc = {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}
    return json.dumps(clean_obj(doc), sort_keys=True, ensure_ascii=False, indent=2) + "\n"
