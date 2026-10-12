"""whalescan: deterministic security and prompt-injection scanner (WhaleSecurity engine)."""

from __future__ import annotations

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
    return getattr(import_module(f".{module}", __name__), "redact_value" if name == "redact" else name)
