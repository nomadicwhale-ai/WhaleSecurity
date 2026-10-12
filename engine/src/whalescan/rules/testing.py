"""Shared fixture and killable regex checks for the CLI and release bundle builder.

Only rule IDs, paths and numeric positions are returned: attack samples and raw secrets
must never enter build or CI logs.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

from ..config import Config
from . import fixtures
from .lint import Context, compile_flags, iter_patterns
from .loader import RuleSet, rule_to_dict

Check = tuple[str, bool, str]


def fixture_checks(rules: RuleSet, cfg: Config, root: str | Path) -> Iterator[Check]:
    from ..api import Scanner

    test_cfg = cfg.with_overrides(
        {
            "scan.baseline": "",
            "scan.min_severity": "info",
            "scan.min_confidence": "low",
            "scan.time_budget_ms": 0,
            "suppress.require_reason": True,
        }
    )
    for rule in rules:
        discovered = fixtures.discover(root, rule.id, rules.fixture_specs.get(rule.id))
        for problem in discovered.problems:
            yield rule.id, False, problem
        scanner = Scanner(RuleSet([rule]), test_cfg)
        for fixture in discovered.all:
            result = scanner.scan_text(fixture.data, filename=fixture.virtual_path)
            verdict = fixtures.evaluate(fixture, (f.line for f in result.findings if f.suppressed is None))
            yield fixture.name, verdict.ok, verdict.message
            if result.diagnostics:
                yield (
                    fixture.name,
                    False,
                    "fixture diagnostics: " + ", ".join(sorted({d.code for d in result.diagnostics})),
                )


def redos_checks(rules: RuleSet) -> Iterator[Check]:
    for rule in rules:
        for pattern in iter_patterns(rule_to_dict(rule)):
            yield (
                rule.id + ":" + pattern.where,
                redos_check(pattern.pattern, pattern.flags, pattern.context),
                "ReDoS budget (100 KB, 50 ms/input, 2 s hard kill)",
            )


def redos_check(pattern: str, flags: tuple[str, ...], context: Context = "regex") -> bool:
    """Run every input in a subprocess; dash-leading patterns travel only on stdin.

    Use the engine's compilation flags and drain finditer (search for predicate/filter
    contexts). Eight adversarial inputs cover classes, literal prefix and a failing suffix.
    """
    script = (
        "import json,re,sys,time\n"
        "from collections import deque\n"
        "p,bits,context=json.load(sys.stdin)\n"
        "rx=re.compile(p,bits); prefix=re.match(r'[A-Za-z0-9_-]+',p.lstrip('^'))\n"
        "prefix=prefix.group() if prefix else 'literal'\n"
        "classes=re.findall(r'\\[(?:\\\\.|[^\\]\\\\])+\\]',p); representatives=[]\n"
        "for cls in classes:\n"
        " for c in 'aA019bB_ /:!@\\n':\n"
        "  if re.fullmatch(cls,c,bits): representatives.append(c); break\n"
        "chars=(representatives+list('aA0 \\n!'))[:6]\n"
        "inputs=[c*100000 for c in chars]+[(prefix*100000)[:100000], 'a'*99999+'!']\n"
        "for s in inputs:\n"
        " start=time.perf_counter()\n"
        " if context == 'search': rx.search(s)\n"
        " else: deque(rx.finditer(s),maxlen=0)\n"
        " if time.perf_counter()-start >= .05: sys.exit(1)\n"
    )
    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-c", script],
            input=json.dumps([pattern, compile_flags(flags, context), context]).encode(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False
    return proc.returncode == 0
