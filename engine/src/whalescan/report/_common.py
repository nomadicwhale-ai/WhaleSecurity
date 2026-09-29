"""Shared helpers for reporters (spec §12, §13)."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from typing import Any

from ..matchers.unicode import reveal
from ..model import Finding, ScanResult, Severity

SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


def clean(text: str) -> str:
    """Reveal hidden code points (including terminal escapes) in any output string."""
    return reveal(text)


def clean_obj(obj: Any) -> Any:
    """Recursively apply :func:`clean` to every string in a JSON-like structure."""
    if isinstance(obj, str):
        return clean(obj)
    if isinstance(obj, dict):
        return {clean(k) if isinstance(k, str) else k: clean_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [clean_obj(v) for v in obj]
    return obj


def ordered(result: ScanResult, *, include_suppressed: bool = False) -> list[Finding]:
    fs = result.findings if include_suppressed else result.active
    return sorted(fs, key=lambda f: f.sort_key)


def severity_counts(findings: Iterable[Finding]) -> Counter[Severity]:
    return Counter(f.severity for f in findings)


def suppressed_counts(result: ScanResult) -> Counter[str]:
    return Counter(f.suppressed.kind for f in result.findings if f.suppressed)


def pascal_case(title: str) -> str:
    """ASCII PascalCase name for a SARIF rule (``Privileged container`` -> ``PrivilegedContainer``)."""
    words = re.findall(r"[A-Za-z0-9]+", title)
    return "".join(w[:1].upper() + w[1:] for w in words) or "Rule"
