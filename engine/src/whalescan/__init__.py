"""whalescan: deterministic security and prompt-injection scanner (WhaleSecurity engine)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .api import Scanner, load_rules, scan_injection, scan_text
    from .config import load_config
    from .errors import ConfigError, RuleError, UsageError, WhalescanError
    from .matchers.unicode import reveal
    from .model import Confidence, Diagnostic, Finding, ScanResult, Severity
    from .redact import redact_value as redact
    from .suppress import Baseline

__version__ = "0.1.0.dev0"

__all__ = [
    "Baseline",
    "Confidence",
    "ConfigError",
    "Diagnostic",
    "Finding",
    "RuleError",
    "ScanResult",
    "Scanner",
    "Severity",
    "UsageError",
    "WhalescanError",
    "__version__",
    "load_config",
    "load_rules",
    "redact",
    "reveal",
    "scan_injection",
    "scan_text",
]


def __getattr__(name: str) -> object:
    """Lazy public exports keep `python -m whalescan version` free of scanner imports."""
    from importlib import import_module

    modules = {
        "Scanner": "api",
        "scan_text": "api",
        "scan_injection": "api",
        "load_rules": "api",
        "load_config": "config",
        "Baseline": "suppress",
        "reveal": "matchers.unicode",
        "redact": "redact",
        "Finding": "model",
        "ScanResult": "model",
        "Severity": "model",
        "Confidence": "model",
        "Diagnostic": "model",
        "WhalescanError": "errors",
        "UsageError": "errors",
        "ConfigError": "errors",
        "RuleError": "errors",
    }
    module = modules.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(f".{module}", __name__), "redact_value" if name == "redact" else name)
    globals()[name] = value
    return value
