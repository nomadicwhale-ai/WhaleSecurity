"""Exception hierarchy. Each class carries the process exit code it maps to (spec §17)."""

from __future__ import annotations


class WhalescanError(Exception):
    """Base class for every error raised by whalescan."""

    exit_code: int = 3


class UsageError(WhalescanError):
    """Bad flags, missing paths, conflicting options."""

    exit_code = 2


class ConfigError(WhalescanError):
    """TOML syntax, type/enum errors, unsupported schema version."""

    exit_code = 2


class RuleError(WhalescanError):
    """Rule schema, lint or semantic failure; unknown rule ID."""

    exit_code = 2


class AdapterError(WhalescanError):
    """An external adapter failed. A diagnostic unless --adapters-strict."""

    exit_code = 3


class InternalError(WhalescanError):
    """Any unexpected exception."""

    exit_code = 3
