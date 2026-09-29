"""JSON reporters: the ``whalescan/report@1`` envelope and streamable JSON Lines (spec §12.2)."""

from __future__ import annotations

import json as _json

from ..model import REPORT_SCHEMA, ScanResult
from ._common import clean_obj, ordered


def _dumps(obj: object) -> str:
    return _json.dumps(clean_obj(obj), sort_keys=True, ensure_ascii=False, indent=2) + "\n"


def envelope(result: ScanResult) -> dict[str, object]:
    findings = ordered(result, include_suppressed=True)
    stats = result.stats.to_dict()
    if not stats["by_severity"]:
        for f in result.active:
            stats["by_severity"][f.severity.label] = stats["by_severity"].get(f.severity.label, 0) + 1
    return {
        "schema": REPORT_SCHEMA,
        "tool": {
            "name": "whalescan",
            "version": result.run.tool_version,
            "rules_hash": result.run.rules_hash,
        },
        "run": result.run.to_dict(),
        "stats": stats,
        "findings": [f.to_dict() for f in findings],
        "diagnostics": [d.to_dict() for d in result.diagnostics],
    }


def render(result: ScanResult) -> str:
    """One document. Stays valid on an internal error: ``run.error`` carries the partial result."""
    return _dumps(envelope(result))


def render_jsonl(result: ScanResult) -> str:
    """One finding@1 per line, no envelope."""
    lines = [
        _json.dumps(clean_obj(f.to_dict()), sort_keys=True, ensure_ascii=False)
        for f in ordered(result, include_suppressed=True)
    ]
    return "\n".join(lines) + ("\n" if lines else "")
