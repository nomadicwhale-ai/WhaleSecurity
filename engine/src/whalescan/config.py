"""Configuration: discovery, layered merge, validation and the trust boundary (spec §3).

Layers, lowest to highest precedence: built-in defaults < user config
(``$XDG_CONFIG_HOME/whalescan/config.toml``) < project config (``--config`` →
``$WHALESCAN_CONFIG`` → first ``.whalesecurity/config.toml`` walking up) < environment < CLI
overrides. Tables deep-merge; scalars and arrays replace, except ``rules.enable`` and
``rules.disable`` (unioned) and ``severity.overrides`` (dict-updated).

Trust boundary: keys that cause code execution, network access or writes outside the repository
(:data:`TRUSTED_ONLY`) are honored only from user config, environment or CLI. A project config
that sets one gets a ``config-untrusted-key`` diagnostic and the value is dropped. As a hardening
beyond the key list, project-config *paths* (``scan.baseline``, ``mcp.pins``,
``rules.extra_dirs``) must stay inside the project root. Weakening project settings (disabled
rules, severity overrides, raised thresholds, excludes, allow-lists ...) are honored but listed in
:attr:`Config.changes` for ``run.config_changes``.

The module is stdlib-only; the TOML parser is imported lazily (``tomllib`` on 3.11+, the vendored
``tomli`` on 3.10).
"""

from __future__ import annotations

import copy
import os
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any

from .errors import ConfigError
from .model import KINDS, Diagnostic

__all__ = [
    "ADAPTER_NAMES",
    "SUPPORTED_SCHEMA",
    "TRUSTED_ONLY",
    "AdapterSettings",
    "AdaptersConfig",
    "CacheConfig",
    "ClassifyConfig",
    "ClassifyRule",
    "Config",
    "ExposureConfig",
    "InjectConfig",
    "LoggingConfig",
    "McpConfig",
    "ReportConfig",
    "RulesConfig",
    "ScanConfig",
    "SecretsConfig",
    "SeverityConfig",
    "SuppressConfig",
    "discover_project_config",
    "find_git_root",
    "load_config",
    "parse_size",
    "user_config_path",
]

SUPPORTED_SCHEMA = 1
PROJECT_CONFIG_REL = os.path.join(".whalesecurity", "config.toml")
MAX_CONFIG_BYTES = 1 << 20
_MAX_WALK_UP = 256

SEVERITIES = ("critical", "high", "medium", "low", "info")
FAIL_ON = (*SEVERITIES, "never")
CONFIDENCES = ("high", "medium", "low")
ADAPTER_NAMES = ("semgrep", "gitleaks", "trivy", "osv")
REPORT_FORMATS = ("text", "json", "jsonl", "sarif", "markdown")
LOG_LEVELS = ("error", "warning", "info", "debug")

#: Keys honored only from user config, env or CLI (spec §3.1).
TRUSTED_ONLY: frozenset[str] = frozenset(
    {f"adapters.{a}.{k}" for a in ADAPTER_NAMES for k in ("bin", "args", "env")}
    | {"adapters.osv.allow_network", "mcp.live", "cache.dir", "logging.file"}
)

#: Project-config paths that must stay inside the project root (hardening; see module doc).
_CONTAINED_PATHS = frozenset({"scan.baseline", "mcp.pins", "rules.extra_dirs"})


# =========================================================================== typed tree


@dataclass(frozen=True, slots=True)
class ScanConfig:
    packs: tuple[str, ...] = ("appsec", "secrets", "domain", "agentsec")
    fail_on: str = "high"
    min_severity: str = "low"
    min_confidence: str = "low"
    jobs: int = 0
    time_budget_ms: int = 0
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    walker: str = "auto"
    respect_gitignore: bool = True
    follow_symlinks: bool = False
    max_file_bytes: int = 1_048_576
    max_files: int = 50_000
    max_total_bytes: int = 536_870_912
    max_stdin_bytes: int = 16_777_216
    baseline: str = ".whalesecurity/baseline.json"
    diff_lines_only: bool = False
    skip_minified: bool = True

    @property
    def effective_jobs(self) -> int:
        """``jobs`` with 0 resolved to ``min(os.cpu_count(), 8)``."""
        if self.jobs > 0:
            return self.jobs
        return max(1, min(os.cpu_count() or 1, 8))


@dataclass(frozen=True, slots=True)
class RulesConfig:
    extra_dirs: tuple[str, ...] = (".whalesecurity/rules",)
    enable: tuple[str, ...] = ()
    disable: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ExposureConfig:
    """Exposure classes; the first matching class wins, in field order."""

    test: tuple[str, ...] = (
        "tests/**", "test/**", "**/test_*.py", "**/*_test.py", "**/conftest.py",
        "**/fixtures/**", "examples/**", "docs/**", "**/.env.example",
    )  # fmt: skip
    vendored: tuple[str, ...] = ("vendor/**", "third_party/**", "**/site-packages/**", "**/node_modules/**")
    internet: tuple[str, ...] = (
        "**/routers/**", "**/routes/**", "**/api/**", "**/webhooks/**", "**/ingress*.y*ml",
        "**/nginx/**", "**/traefik/**",
    )  # fmt: skip
    internal: tuple[str, ...] = ("scripts/**", "tools/**", "ops/**", "notebooks/**")

    def classes(self) -> tuple[tuple[str, tuple[str, ...]], ...]:
        """``((class, globs), ...)`` in evaluation order."""
        return (
            ("test", self.test),
            ("vendored", self.vendored),
            ("internet", self.internet),
            ("internal", self.internal),
        )


@dataclass(frozen=True, slots=True)
class SeverityConfig:
    overrides: Mapping[str, str] = field(default_factory=dict)  # rule id/glob -> severity
    exposure: ExposureConfig = field(default_factory=ExposureConfig)


@dataclass(frozen=True, slots=True)
class ClassifyRule:
    glob: str
    kind: str | None = None
    lang: str | None = None
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ClassifyConfig:
    rules: tuple[ClassifyRule, ...] = ()


@dataclass(frozen=True, slots=True)
class SuppressConfig:
    require_reason: bool = True
    min_reason_chars: int = 10
    allow_file_level: bool = True
    allow_wildcard: bool = False
    max_block_lines: int = 200
    report_unused: bool = False


@dataclass(frozen=True, slots=True)
class SecretsConfig:
    allow_values: tuple[str, ...] = ()
    entropy_delta: float = 0.0


@dataclass(frozen=True, slots=True)
class InjectConfig:
    max_bytes: int = 2_097_152
    reveal: bool = True


@dataclass(frozen=True, slots=True)
class AdapterSettings:
    """Settings of one external adapter. ``bin``/``args``/``env`` are trusted-only."""

    bin: str = ""
    args: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    scanners: tuple[str, ...] = ()  # trivy only
    backend: str = ""  # osv only: osv-scanner|pip-audit|api
    allow_network: bool = False  # osv only (trusted-only)


@dataclass(frozen=True, slots=True)
class AdaptersConfig:
    enabled: tuple[str, ...] = ()
    timeout_s: int = 300
    strict: bool = False
    semgrep: AdapterSettings = field(
        default_factory=lambda: AdapterSettings(bin="semgrep", args=("--config", "p/default"))
    )
    gitleaks: AdapterSettings = field(default_factory=lambda: AdapterSettings(bin="gitleaks"))
    trivy: AdapterSettings = field(
        default_factory=lambda: AdapterSettings(bin="trivy", scanners=("vuln", "misconfig"))
    )
    osv: AdapterSettings = field(
        default_factory=lambda: AdapterSettings(bin="osv-scanner", backend="osv-scanner")
    )

    def get(self, name: str) -> AdapterSettings:
        if name not in ADAPTER_NAMES:
            raise KeyError(name)
        settings: AdapterSettings = getattr(self, name)
        return settings


@dataclass(frozen=True, slots=True)
class McpConfig:
    pins: str = ".whalesecurity/mcp-pins.json"
    config_files: tuple[str, ...] = (".mcp.json", "~/.claude.json")
    live: bool = False
    timeout_s: int = 10


@dataclass(frozen=True, slots=True)
class ReportConfig:
    format: str = "text"
    max_snippet_chars: int = 240
    markdown_max_findings: int = 200
    sarif_include_all_rules: bool = False
    sarif_absolute_root: bool = False


@dataclass(frozen=True, slots=True)
class CacheConfig:
    enabled: bool = True
    dir: str = ""


@dataclass(frozen=True, slots=True)
class LoggingConfig:
    level: str = "warning"
    format: str = "text"
    file: str = ""


@dataclass(frozen=True, slots=True)
class Config:
    """The effective, validated configuration. Immutable and picklable.

    Metadata fields: ``root`` (absolute base for relative output paths), ``project_root``
    (directory holding ``.whalesecurity/``, else ``root``), ``sources`` (layers that contributed,
    for ``run.config_sources``), ``changes`` (weakening project settings, for
    ``run.config_changes``), ``diagnostics`` (unknown/untrusted keys), ``cache_path`` (resolved
    cache directory).
    """

    schema: int = SUPPORTED_SCHEMA
    scan: ScanConfig = field(default_factory=ScanConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
    severity: SeverityConfig = field(default_factory=SeverityConfig)
    classify: ClassifyConfig = field(default_factory=ClassifyConfig)
    suppress: SuppressConfig = field(default_factory=SuppressConfig)
    secrets: SecretsConfig = field(default_factory=SecretsConfig)
    inject: InjectConfig = field(default_factory=InjectConfig)
    adapters: AdaptersConfig = field(default_factory=AdaptersConfig)
    mcp: McpConfig = field(default_factory=McpConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    hooks: Mapping[str, Any] = field(default_factory=dict)
    # ---- metadata
    root: str = ""
    project_root: str = ""
    project_config: str | None = None
    user_config: str | None = None
    sources: tuple[str, ...] = ()
    changes: tuple[str, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    cache_path: str = ""
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def default(cls, root: str | os.PathLike[str] | None = None) -> Config:
        """Built-in defaults only: no files, no environment."""
        r = os.path.abspath(os.fspath(root)) if root is not None else os.getcwd()
        meta = _Meta(root=r, project_root=r, sources=("defaults",), cache_path=_default_cache_dir(os.environ))
        return _build(_defaults_raw(), meta)

    def with_overrides(self, overrides: Mapping[str, Any]) -> Config:
        """A copy with CLI-level ``overrides`` applied (validated, trusted)."""
        layer = _Layer("cli", _expand_dotted(overrides), trusted=True)
        clean = _validate_layer(layer)
        raw = copy.deepcopy(dict(self.raw)) if self.raw else _defaults_raw()
        _merge(raw, clean)
        meta = _Meta(
            root=self.root,
            project_root=self.project_root,
            project_config=self.project_config,
            user_config=self.user_config,
            sources=(*self.sources, "cli") if clean else self.sources,
            changes=list(self.changes),
            diagnostics=[*self.diagnostics, *layer.diagnostics],
            cache_path=self.cache_path,
        )
        if clean.get("cache", {}).get("dir"):
            meta.cache_path = os.path.expanduser(str(clean["cache"]["dir"]))
        return _build(raw, meta)

    def resolve_path(self, path: str) -> str:
        """Resolve a config path: ``~`` expanded, relative paths against ``project_root``."""
        p = os.path.expanduser(path)
        if os.path.isabs(p):
            return os.path.normpath(p)
        return os.path.normpath(os.path.join(self.project_root or self.root or os.getcwd(), p))

    def to_dict(self) -> dict[str, Any]:
        """The effective settings as plain data (no metadata)."""
        return {f.name: _to_plain(getattr(self, f.name)) for f in fields(self) if f.name in _SECTION_NAMES}


_SECTION_NAMES = (
    "schema", "scan", "rules", "severity", "classify", "suppress", "secrets", "inject",
    "adapters", "mcp", "report", "cache", "logging", "hooks",
)  # fmt: skip


def _to_plain(v: Any) -> Any:
    if is_dataclass(v) and not isinstance(v, type):
        return {f.name: _to_plain(getattr(v, f.name)) for f in fields(v)}
    if isinstance(v, tuple | list):
        return [_to_plain(x) for x in v]
    if isinstance(v, Mapping):
        return {str(k): _to_plain(x) for k, x in v.items()}
    return v


def _defaults_raw() -> dict[str, Any]:
    d: dict[str, Any] = _to_plain(Config())
    return {k: d[k] for k in _SECTION_NAMES}


# =========================================================================== value specs


def _tname(v: object) -> str:
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "float"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list | tuple):
        return "array"
    if isinstance(v, Mapping):
        return "table"
    return type(v).__name__


_SIZE_UNITS = {"": 1, "B": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30}


def parse_size(value: str | int) -> int:
    """Parse a byte size: ``1048576``, ``"512K"``, ``"1M"``, ``"2GiB"`` (binary units)."""
    if isinstance(value, bool):
        raise ValueError("expected a size, got boolean")
    if isinstance(value, int):
        if value < 0:
            raise ValueError("size must be >= 0")
        return value
    s = value.strip().upper().replace("_", "")
    if s.endswith("IB"):
        s = s[:-2]
    elif s.endswith("B") and len(s) > 1 and not s[-2].isdigit():
        s = s[:-1]
    unit = s[-1:] if s[-1:] in ("K", "M", "G", "B") else ""
    num = s[: len(s) - len(unit)].strip()
    if not num.isdigit():
        raise ValueError(f"invalid size {value!r}; use an integer with an optional K, M or G suffix")
    return int(num) * _SIZE_UNITS[unit]


class _Spec:
    """Validates and normalizes one leaf value. Raises ``ValueError`` with a user message."""

    def check(self, v: Any) -> Any:  # pragma: no cover - abstract
        raise NotImplementedError


class _Bool(_Spec):
    def check(self, v: Any) -> bool:
        if not isinstance(v, bool):
            raise ValueError(f"expected boolean, got {_tname(v)}")
        return v


class _Int(_Spec):
    def __init__(self, lo: int = 0, hi: int = 2**62) -> None:
        self.lo, self.hi = lo, hi

    def check(self, v: Any) -> int:
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError(f"expected integer, got {_tname(v)}")
        if not self.lo <= v <= self.hi:
            raise ValueError(f"expected an integer between {self.lo} and {self.hi}, got {v}")
        return v


class _Size(_Int):
    def check(self, v: Any) -> int:
        if isinstance(v, str):
            try:
                v = parse_size(v)
            except ValueError as exc:
                raise ValueError(str(exc)) from None
        return super().check(v)


class _Float(_Spec):
    def __init__(self, lo: float, hi: float) -> None:
        self.lo, self.hi = lo, hi

    def check(self, v: Any) -> float:
        if isinstance(v, bool) or not isinstance(v, int | float):
            raise ValueError(f"expected number, got {_tname(v)}")
        f = float(v)
        if not self.lo <= f <= self.hi:
            raise ValueError(f"expected a number between {self.lo} and {self.hi}, got {v}")
        return f


class _Str(_Spec):
    def __init__(self, nonempty: bool = False) -> None:
        self.nonempty = nonempty

    def check(self, v: Any) -> str:
        if not isinstance(v, str):
            raise ValueError(f"expected string, got {_tname(v)}")
        if "\x00" in v:
            raise ValueError("NUL character not allowed")
        if self.nonempty and not v.strip():
            raise ValueError("expected a non-empty string")
        return v


class _Enum(_Spec):
    def __init__(self, choices: Iterable[str]) -> None:
        self.choices = tuple(choices)

    def check(self, v: Any) -> str:
        if isinstance(v, str):
            low = v.strip().lower()
            if low in self.choices:
                return low
        raise ValueError(f"expected one of {'|'.join(self.choices)}")


class _List(_Spec):
    def __init__(self, item: _Spec) -> None:
        self.item = item

    def check(self, v: Any) -> list[Any]:
        if not isinstance(v, list | tuple):
            raise ValueError(f"expected array, got {_tname(v)}")
        out: list[Any] = []
        for i, x in enumerate(v):
            try:
                out.append(self.item.check(x))
            except ValueError as exc:
                raise ValueError(f"[{i}]: {exc}") from None
        return out


class _Regexes(_List):
    def __init__(self) -> None:
        super().__init__(_Str(nonempty=True))

    def check(self, v: Any) -> list[Any]:
        out = super().check(v)
        import re

        for i, pat in enumerate(out):
            try:
                re.compile(pat)
            except re.error as exc:
                raise ValueError(f"[{i}]: invalid regular expression: {exc}") from None
        return out


class _Map(_Spec):
    """Table of string keys to validated values (``severity.overrides``, ``adapters.*.env``)."""

    def __init__(self, value: _Spec) -> None:
        self.value = value

    def check(self, v: Any) -> dict[str, Any]:
        if not isinstance(v, Mapping):
            raise ValueError(f"expected table, got {_tname(v)}")
        out: dict[str, Any] = {}
        for k, x in v.items():
            if not isinstance(k, str) or not k:
                raise ValueError("keys must be non-empty strings")
            try:
                out[k] = self.value.check(x)
            except ValueError as exc:
                raise ValueError(f"{k}: {exc}") from None
        return out


class _AnyTable(_Spec):
    def check(self, v: Any) -> dict[str, Any]:
        if not isinstance(v, Mapping):
            raise ValueError(f"expected table, got {_tname(v)}")
        return copy.deepcopy(dict(v))


_KIND_ENUM = _Enum(KINDS)


class _ClassifyRules(_Spec):
    _keys = ("glob", "kind", "lang", "tags")

    def check(self, v: Any) -> list[dict[str, Any]]:
        if not isinstance(v, list | tuple):
            raise ValueError(f"expected array of tables, got {_tname(v)}")
        out: list[dict[str, Any]] = []
        for i, item in enumerate(v):
            if not isinstance(item, Mapping):
                raise ValueError(f"[{i}]: expected table, got {_tname(item)}")
            unknown = [k for k in item if k not in self._keys]
            if unknown:
                raise ValueError(f"[{i}]: unknown key(s) {', '.join(map(str, unknown))}")
            if "glob" not in item:
                raise ValueError(f"[{i}]: missing required key 'glob'")
            try:
                rule: dict[str, Any] = {"glob": _Str(nonempty=True).check(item["glob"])}
                if item.get("kind") is not None:
                    rule["kind"] = _KIND_ENUM.check(item["kind"])
                if item.get("lang") is not None:
                    rule["lang"] = _Str(nonempty=True).check(item["lang"])
                rule["tags"] = _List(_Str(nonempty=True)).check(item.get("tags", []))
            except ValueError as exc:
                raise ValueError(f"[{i}]: {exc}") from None
            if len(rule) == 2 and not rule["tags"]:
                raise ValueError(f"[{i}]: needs at least one of kind, lang or tags")
            out.append(rule)
        return out


_STRS = _List(_Str())
_NONEMPTY_STRS = _List(_Str(nonempty=True))


def _adapter_schema(name: str) -> dict[str, Any]:
    s: dict[str, Any] = {"bin": _Str(nonempty=True), "args": _STRS, "env": _Map(_Str())}
    if name == "trivy":
        s["scanners"] = _List(_Enum(("vuln", "misconfig", "secret", "license")))
    if name == "osv":
        s["backend"] = _Enum(("osv-scanner", "pip-audit", "api"))
        s["allow_network"] = _Bool()
    return s


SCHEMA: dict[str, Any] = {
    "schema": _Int(0, 10_000),
    "scan": {
        "packs": _NONEMPTY_STRS,
        "fail_on": _Enum(FAIL_ON),
        "min_severity": _Enum(SEVERITIES),
        "min_confidence": _Enum(CONFIDENCES),
        "jobs": _Int(0, 1024),
        "time_budget_ms": _Int(0, 86_400_000),
        "include": _NONEMPTY_STRS,
        "exclude": _NONEMPTY_STRS,
        "walker": _Enum(("auto", "git", "fs")),
        "respect_gitignore": _Bool(),
        "follow_symlinks": _Bool(),
        "max_file_bytes": _Size(1, 1 << 40),
        "max_files": _Int(1, 100_000_000),
        "max_total_bytes": _Size(1, 1 << 50),
        "max_stdin_bytes": _Size(1, 1 << 40),
        "baseline": _Str(),
        "diff_lines_only": _Bool(),
        "skip_minified": _Bool(),
    },
    "rules": {"extra_dirs": _NONEMPTY_STRS, "enable": _NONEMPTY_STRS, "disable": _NONEMPTY_STRS},
    "severity": {
        "overrides": _Map(_Enum(SEVERITIES)),
        "exposure": {k: _NONEMPTY_STRS for k in ("test", "vendored", "internet", "internal")},
    },
    "classify": {"rules": _ClassifyRules()},
    "suppress": {
        "require_reason": _Bool(),
        "min_reason_chars": _Int(0, 10_000),
        "allow_file_level": _Bool(),
        "allow_wildcard": _Bool(),
        "max_block_lines": _Int(0, 1_000_000),
        "report_unused": _Bool(),
    },
    "secrets": {"allow_values": _Regexes(), "entropy_delta": _Float(-1.0, 1.0)},
    "inject": {"max_bytes": _Size(1, 1 << 40), "reveal": _Bool()},
    "adapters": {
        "enabled": _List(_Enum((*ADAPTER_NAMES, "auto"))),
        "timeout_s": _Int(1, 86_400),
        "strict": _Bool(),
        **{name: _adapter_schema(name) for name in ADAPTER_NAMES},
    },
    "mcp": {
        "pins": _Str(nonempty=True),
        "config_files": _NONEMPTY_STRS,
        "live": _Bool(),
        "timeout_s": _Int(1, 3600),
    },
    "report": {
        "format": _Enum(REPORT_FORMATS),
        "max_snippet_chars": _Int(0, 1_000_000),
        "markdown_max_findings": _Int(0, 1_000_000),
        "sarif_include_all_rules": _Bool(),
        "sarif_absolute_root": _Bool(),
    },
    "cache": {"enabled": _Bool(), "dir": _Str()},
    "logging": {"level": _Enum(LOG_LEVELS), "format": _Enum(("text", "json")), "file": _Str()},
    "hooks": _AnyTable(),
}


# =========================================================================== layers


@dataclass(slots=True)
class _Layer:
    source: str  # "user", "project", "env", "cli"
    data: dict[str, Any]
    trusted: bool
    path: str | None = None  # file path for file layers
    project_root: str | None = None  # for path containment checks
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.source} config {self.path}" if self.path else self.source


def _err(layer: _Layer, key: str, msg: str) -> ConfigError:
    return ConfigError(f"{key}: {msg} (in {layer.label})")


def _escapes(path: str) -> bool:
    """Does a project-config path leave the project directory?"""
    if not path:
        return False
    if path.startswith("~") or os.path.isabs(path) or path.startswith(("/", "\\")):
        return True
    if len(path) > 1 and path[1] == ":":  # Windows drive
        return True
    norm = os.path.normpath(path.replace("\\", "/"))
    return norm == ".." or norm.startswith(".." + os.sep) or norm.startswith("../")


def _validate_table(
    raw: Mapping[str, Any], schema: Mapping[str, Any], prefix: str, layer: _Layer
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in raw.items():
        dotted = f"{prefix}{key}"
        spec = schema.get(key)
        if spec is None:
            layer.diagnostics.append(
                Diagnostic(
                    "warning",
                    "config-unknown-key",
                    f"unknown config key '{dotted}' ignored ({layer.label})",
                    file=layer.path,
                )
            )
            continue
        if isinstance(spec, Mapping):
            if not isinstance(value, Mapping):
                raise _err(layer, dotted, f"expected table, got {_tname(value)}")
            sub = _validate_table(value, spec, dotted + ".", layer)
            if sub:
                out[key] = sub
            continue
        if dotted in TRUSTED_ONLY and not layer.trusted:
            layer.diagnostics.append(
                Diagnostic(
                    "warning",
                    "config-untrusted-key",
                    f"'{dotted}' is honored only from user config, environment or CLI; "
                    f"ignored in {layer.label}",
                    file=layer.path,
                )
            )
            continue
        try:
            clean = spec.check(value)
        except ValueError as exc:
            raise _err(layer, dotted, str(exc)) from None
        if not layer.trusted and dotted in _CONTAINED_PATHS:
            clean = _contain(clean, dotted, layer)
            if clean is None:
                continue
        out[key] = clean
    return out


def _contain(value: Any, dotted: str, layer: _Layer) -> Any:
    items = value if isinstance(value, list) else [value]
    kept = [p for p in items if not _escapes(p)]
    for p in items:
        if _escapes(p):
            layer.diagnostics.append(
                Diagnostic(
                    "warning",
                    "config-untrusted-key",
                    f"'{dotted}' path {p!r} leaves the project directory; ignored in {layer.label}",
                    file=layer.path,
                )
            )
    if isinstance(value, list):
        return kept
    return kept[0] if kept else None


def _validate_layer(layer: _Layer) -> dict[str, Any]:
    data = dict(layer.data)
    if layer.path is not None:  # file layers carry the schema version
        if "schema" not in data:
            raise _err(layer, "schema", f"required integer (supported: {SUPPORTED_SCHEMA})")
        ver = data["schema"]
        if isinstance(ver, bool) or not isinstance(ver, int):
            raise _err(layer, "schema", f"expected integer, got {_tname(ver)}")
        if ver > SUPPORTED_SCHEMA:
            raise _err(
                layer,
                "schema",
                f"version {ver} is newer than supported version {SUPPORTED_SCHEMA}; upgrade whalescan",
            )
        if ver < 1:
            raise _err(layer, "schema", f"expected a version >= 1, got {ver}")
    data.pop("schema", None)
    return _validate_table(data, SCHEMA, "", layer)


def _expand_dotted(overrides: Mapping[str, Any]) -> dict[str, Any]:
    """``{"scan.fail_on": "x"}`` → ``{"scan": {"fail_on": "x"}}``; nested dicts pass through."""
    out: dict[str, Any] = {}
    for key, value in overrides.items():
        parts = str(key).split(".")
        cur = out
        for p in parts[:-1]:
            nxt = cur.setdefault(p, {})
            if not isinstance(nxt, dict):
                raise ConfigError(f"{key}: conflicts with another override")
            cur = nxt
        leaf = parts[-1]
        if isinstance(value, Mapping) and isinstance(cur.get(leaf), dict):
            _merge(cur[leaf], _expand_dotted(value))
        elif isinstance(value, Mapping) and leaf not in ("overrides", "env", "hooks"):
            cur[leaf] = _expand_dotted(value)
        else:
            cur[leaf] = value
    return out


_UNION_KEYS = frozenset({("rules", "enable"), ("rules", "disable")})


def _merge(dst: dict[str, Any], src: Mapping[str, Any], path: tuple[str, ...] = ()) -> None:
    """Deep-merge ``src`` into ``dst`` in place (spec §3.1 merging rules)."""
    for key, value in src.items():
        here = (*path, key)
        cur = dst.get(key)
        if here in _UNION_KEYS and isinstance(cur, list) and isinstance(value, list):
            dst[key] = cur + [v for v in value if v not in cur]
        elif isinstance(cur, dict) and isinstance(value, Mapping):
            _merge(cur, value, here)
        else:
            dst[key] = copy.deepcopy(value)


# =========================================================================== changes


_SEV_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # info=0 .. critical=4
_CONF_RANK = {"low": 0, "medium": 1, "high": 2}


def _fmt(v: Any) -> str:
    if isinstance(v, list | tuple):
        return "[" + ", ".join(_fmt(x) for x in v) + "]"
    if isinstance(v, str):
        return v
    return repr(v).lower() if isinstance(v, bool) else repr(v)


def _project_changes(clean: Mapping[str, Any], defaults: Mapping[str, Any]) -> list[str]:
    """Weakening settings from the project layer, for ``run.config_changes``."""
    out: list[str] = []
    scan = clean.get("scan", {})
    dscan = defaults["scan"]
    for rid in clean.get("rules", {}).get("disable", []):
        out.append(f"rules.disable += {rid}")
    for rid, sev in clean.get("severity", {}).get("overrides", {}).items():
        out.append(f"severity.overrides.{rid} = {sev}")
    if "packs" in scan and list(scan["packs"]) != list(dscan["packs"]):
        out.append(f"scan.packs = {_fmt(scan['packs'])}")
    if "fail_on" in scan:
        fo = scan["fail_on"]
        if fo == "never" or _SEV_RANK.get(fo, 0) > _SEV_RANK[dscan["fail_on"]]:
            out.append(f"scan.fail_on = {fo}")
    if "min_severity" in scan and _SEV_RANK[scan["min_severity"]] > _SEV_RANK[dscan["min_severity"]]:
        out.append(f"scan.min_severity = {scan['min_severity']}")
    if "min_confidence" in scan and _CONF_RANK[scan["min_confidence"]] > _CONF_RANK[dscan["min_confidence"]]:
        out.append(f"scan.min_confidence = {scan['min_confidence']}")
    for key in ("exclude", "include"):
        if scan.get(key):
            out.append(f"scan.{key} = {_fmt(scan[key])}")
    if scan.get("respect_gitignore") is False:
        pass  # scanning *more* files is not a weakening
    secrets = clean.get("secrets", {})
    if secrets.get("allow_values"):
        out.append(f"secrets.allow_values = {_fmt(secrets['allow_values'])}")
    if secrets.get("entropy_delta", 0.0) > 0.0:
        out.append(f"secrets.entropy_delta = {secrets['entropy_delta']}")
    sup = clean.get("suppress", {})
    if sup.get("require_reason") is False:
        out.append("suppress.require_reason = false")
    if sup.get("allow_wildcard") is True:
        out.append("suppress.allow_wildcard = true")
    if "min_reason_chars" in sup and sup["min_reason_chars"] < defaults["suppress"]["min_reason_chars"]:
        out.append(f"suppress.min_reason_chars = {sup['min_reason_chars']}")
    exposure = clean.get("severity", {}).get("exposure", {})
    for cls in ("test", "vendored", "internal"):
        if cls in exposure and list(exposure[cls]) != list(defaults["severity"]["exposure"][cls]):
            out.append(f"severity.exposure.{cls} = {_fmt(exposure[cls])}")
    return out


# =========================================================================== build


@dataclass(slots=True)
class _Meta:
    root: str
    project_root: str
    project_config: str | None = None
    user_config: str | None = None
    sources: tuple[str, ...] = ()
    changes: list[str] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    cache_path: str = ""


def _t(v: Iterable[Any]) -> tuple[Any, ...]:
    return tuple(v)


def _adapter(raw: Mapping[str, Any]) -> AdapterSettings:
    return AdapterSettings(
        bin=raw.get("bin", ""),
        args=_t(raw.get("args", ())),
        env=dict(raw.get("env", {})),
        scanners=_t(raw.get("scanners", ())),
        backend=raw.get("backend", ""),
        allow_network=bool(raw.get("allow_network", False)),
    )


def _section(cls: Callable[..., Any], raw: Mapping[str, Any]) -> Any:
    return cls(**{k: _t(v) if isinstance(v, list) else v for k, v in raw.items()})


def _build(raw: dict[str, Any], meta: _Meta) -> Config:
    sev = raw["severity"]
    ad = raw["adapters"]
    return Config(
        schema=SUPPORTED_SCHEMA,
        scan=_section(ScanConfig, raw["scan"]),
        rules=_section(RulesConfig, raw["rules"]),
        severity=SeverityConfig(
            overrides=dict(sev.get("overrides", {})),
            exposure=_section(ExposureConfig, sev.get("exposure", {})),
        ),
        classify=ClassifyConfig(
            rules=tuple(
                ClassifyRule(r["glob"], kind=r.get("kind"), lang=r.get("lang"), tags=_t(r.get("tags", ())))
                for r in raw["classify"].get("rules", [])
            )
        ),
        suppress=_section(SuppressConfig, raw["suppress"]),
        secrets=_section(SecretsConfig, raw["secrets"]),
        inject=_section(InjectConfig, raw["inject"]),
        adapters=AdaptersConfig(
            enabled=_t(ad.get("enabled", ())),
            timeout_s=ad["timeout_s"],
            strict=ad["strict"],
            semgrep=_adapter(ad.get("semgrep", {})),
            gitleaks=_adapter(ad.get("gitleaks", {})),
            trivy=_adapter(ad.get("trivy", {})),
            osv=_adapter(ad.get("osv", {})),
        ),
        mcp=_section(McpConfig, raw["mcp"]),
        report=_section(ReportConfig, raw["report"]),
        cache=_section(CacheConfig, raw["cache"]),
        logging=_section(LoggingConfig, raw["logging"]),
        hooks=dict(raw.get("hooks", {})),
        root=meta.root,
        project_root=meta.project_root,
        project_config=meta.project_config,
        user_config=meta.user_config,
        sources=meta.sources,
        changes=tuple(dict.fromkeys(meta.changes)),
        diagnostics=tuple(meta.diagnostics),
        cache_path=meta.cache_path,
        raw=raw,
    )


# =========================================================================== discovery & IO


def find_git_root(start: str | os.PathLike[str]) -> str | None:
    """Nearest ancestor of ``start`` (inclusive) containing a ``.git`` entry. No subprocess."""
    d = os.path.abspath(os.fspath(start))
    for _ in range(_MAX_WALK_UP):
        if os.path.lexists(os.path.join(d, ".git")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent
    return None


def _home(env: Mapping[str, str]) -> str:
    h = env.get("HOME") or os.path.expanduser("~")
    return os.path.abspath(h) if h else ""


def user_config_path(env: Mapping[str, str] | None = None) -> str:
    """``$XDG_CONFIG_HOME/whalescan/config.toml`` (relative XDG values are ignored per XDG)."""
    env = os.environ if env is None else env
    xdg = env.get("XDG_CONFIG_HOME", "")
    base = xdg if xdg and os.path.isabs(xdg) else os.path.join(_home(env), ".config")
    return os.path.join(base, "whalescan", "config.toml")


def _default_cache_dir(env: Mapping[str, str]) -> str:
    xdg = env.get("XDG_CACHE_HOME", "")
    base = xdg if xdg and os.path.isabs(xdg) else os.path.join(_home(env), ".cache")
    return os.path.join(base, "whalescan")


def discover_project_config(
    start: str | os.PathLike[str], env: Mapping[str, str] | None = None
) -> str | None:
    """First ``.whalesecurity/config.toml`` walking up from ``start``.

    The walk checks each directory and stops after a directory containing ``.git``, after
    ``$HOME``, or at ``/``.
    """
    env = os.environ if env is None else env
    home = _home(env)
    d = os.path.abspath(os.fspath(start))
    for _ in range(_MAX_WALK_UP):
        cand = os.path.join(d, PROJECT_CONFIG_REL)
        if os.path.isfile(cand):
            return cand
        if os.path.lexists(os.path.join(d, ".git")) or (home and d == home):
            return None
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent
    return None


def _truthy(v: str | None) -> bool:
    return (v or "").strip().lower() in ("1", "true", "yes", "on")


def _load_toml(path: str, source: str) -> dict[str, Any]:
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_CONFIG_BYTES + 1)
    except FileNotFoundError:
        raise ConfigError(f"{source} config file not found: {path}") from None
    except OSError as exc:
        raise ConfigError(f"cannot read {source} config {path}: {exc.strerror or exc}") from None
    if len(data) > MAX_CONFIG_BYTES:
        raise ConfigError(f"{source} config {path} is larger than {MAX_CONFIG_BYTES} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{source} config {path}: not valid UTF-8 (byte {exc.start})") from None
    if sys.version_info >= (3, 11):
        import tomllib
    else:  # pragma: no cover - exercised on 3.10 only
        from ._vendor import tomli as tomllib
    try:
        doc: dict[str, Any] = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{source} config {path}: invalid TOML: {exc}") from None
    except RecursionError:
        raise ConfigError(f"{source} config {path}: invalid TOML: nesting too deep") from None
    return doc


def _env_layer(env: Mapping[str, str]) -> _Layer:
    data: dict[str, Any] = {}

    def put(section: str, key: str, value: Any) -> None:
        data.setdefault(section, {})[key] = value

    if env.get("WHALESCAN_FAIL_ON", "").strip():
        put("scan", "fail_on", env["WHALESCAN_FAIL_ON"])
    if env.get("WHALESCAN_PACKS", "").strip():
        put("scan", "packs", [p.strip() for p in env["WHALESCAN_PACKS"].split(",") if p.strip()])
    if env.get("WHALESCAN_JOBS", "").strip():
        raw = env["WHALESCAN_JOBS"].strip()
        try:
            put("scan", "jobs", int(raw))
        except ValueError:
            raise ConfigError(f"scan.jobs: expected integer, got {raw!r} (in env WHALESCAN_JOBS)") from None
    if env.get("WHALESCAN_CACHE_DIR", "").strip():
        put("cache", "dir", env["WHALESCAN_CACHE_DIR"])
    if _truthy(env.get("WHALESCAN_NO_CACHE")):
        put("cache", "enabled", False)
    if env.get("WHALESCAN_LOG_LEVEL", "").strip():
        lvl = env["WHALESCAN_LOG_LEVEL"].strip().lower()
        put("logging", "level", "warning" if lvl == "warn" else lvl)
    return _Layer("env", data, trusted=True)


def _project_root_for(config_path: str, fallback: str) -> str:
    d = os.path.dirname(os.path.abspath(config_path))
    if os.path.basename(d) == ".whalesecurity":
        return os.path.dirname(d)
    return fallback


def load_config(
    root: str | os.PathLike[str] | None = None,
    *,
    path: str | os.PathLike[str] | None = None,
    project: bool = True,
    overrides: Mapping[str, Any] | None = None,
    env: Mapping[str, str] | None = None,
    user: bool = True,
) -> Config:
    """Load the effective configuration (spec §3, §16).

    - ``root``: base for relative output paths and project-config discovery (default: git
      toplevel of cwd, else cwd).
    - ``path``: explicit project config (``--config``); always loaded when given.
    - ``project=False`` (``--no-project-config``; also ``WHALESCAN_NO_PROJECT_CONFIG=1``)
      disables ``$WHALESCAN_CONFIG`` and discovery.
    - ``overrides``: CLI values, nested (``{"scan": {"fail_on": "low"}}``) or dotted
      (``{"scan.fail_on": "low"}``); trusted.
    - ``env``: environment mapping (default ``os.environ``); ``user=False`` skips user config.

    Raises :class:`~whalescan.errors.ConfigError` (exit 2) on syntax, type, enum or schema errors.
    """
    env = os.environ if env is None else env
    cwd = os.getcwd()
    base = os.path.abspath(os.fspath(root)) if root is not None else (find_git_root(cwd) or cwd)
    raw = _defaults_raw()
    defaults = copy.deepcopy(raw)
    meta = _Meta(root=base, project_root=base, sources=("defaults",), cache_path=_default_cache_dir(env))

    layers: list[_Layer] = []
    if user:
        upath = user_config_path(env)
        if os.path.isfile(upath):
            layers.append(_Layer("user", _load_toml(upath, "user"), trusted=True, path=upath))
            meta.user_config = upath

    project_path: str | None = None
    explicit = False
    if path is not None:
        project_path, explicit = os.path.abspath(os.fspath(path)), True
    elif project and not _truthy(env.get("WHALESCAN_NO_PROJECT_CONFIG")):
        if env.get("WHALESCAN_CONFIG", "").strip():
            project_path, explicit = os.path.abspath(env["WHALESCAN_CONFIG"].strip()), True
        else:
            project_path = discover_project_config(base, env)
    if project_path is not None:
        proot = _project_root_for(project_path, base)
        if not explicit:
            real = os.path.realpath(project_path)
            real_root = os.path.realpath(proot)
            if not (real == real_root or real.startswith(real_root.rstrip(os.sep) + os.sep)):
                meta.diagnostics.append(
                    Diagnostic(
                        "warning",
                        "config-symlink-escape",
                        "project config is a symlink that resolves outside the project; ignored",
                        file=project_path,
                    )
                )
                project_path = None
        if project_path is not None:
            doc = _load_toml(project_path, "project")
            layers.append(_Layer("project", doc, trusted=False, path=project_path, project_root=proot))
            meta.project_config = project_path
            meta.project_root = proot

    env_layer = _env_layer(env)
    if env_layer.data:
        layers.append(env_layer)
    if overrides:
        layers.append(_Layer("cli", _expand_dotted(overrides), trusted=True))

    sources = ["defaults"]
    for layer in layers:
        clean = _validate_layer(layer)
        meta.diagnostics.extend(layer.diagnostics)
        if layer.source == "project":
            meta.changes.extend(_project_changes(clean, defaults))
        _merge(raw, clean)
        sources.append(layer.path or layer.source)
        if layer.source != "project" and clean.get("cache", {}).get("dir"):
            meta.cache_path = os.path.expanduser(str(clean["cache"]["dir"]))
    meta.sources = tuple(sources)
    return _build(raw, meta)
