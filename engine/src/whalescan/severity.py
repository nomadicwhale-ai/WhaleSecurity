"""Severity model (spec §10): ``score = min(10, BASE x R x E)`` mapped to a band."""

from __future__ import annotations

from collections.abc import Collection, Mapping

from .config import ExposureConfig
from .ignore import any_glob_match, rule_glob_match
from .model import Confidence, Severity

BASE: Mapping[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFO: 0.5,
}
REACHABILITY: Mapping[str, float] = {"tainted": 1.25, "unknown": 1.0, "constant": 0.6}
EXPOSURE: Mapping[str, float] = {
    "internet": 1.1,
    "default": 1.0,
    "internal": 0.8,
    "vendored": 0.5,
    "test": 0.4,
}
CONFIDENCE_WEIGHT: Mapping[Confidence, float] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.8,
    Confidence.LOW: 0.5,
}
# (minimum score, band), checked in order
_BANDS: tuple[tuple[float, Severity], ...] = (
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (1.0, Severity.LOW),
)


def band(score: float) -> Severity:
    for floor, sev in _BANDS:
        if score >= floor:
            return sev
    return Severity.INFO


def score(
    base: Severity,
    reachability: str = "unknown",
    exposure: str = "default",
    *,
    exposure_sensitive: bool = True,
) -> tuple[float, Severity]:
    """Return ``(score, final_band)``. ``exposure_sensitive=False`` pins E to 1.0."""
    r = REACHABILITY.get(reachability, 1.0)
    e = EXPOSURE.get(exposure, 1.0) if exposure_sensitive else 1.0
    s = min(10.0, BASE[base] * r * e)
    return s, band(s)


def exposure_for(
    path: str,
    tags: Collection[str] = (),
    cfg: ExposureConfig | None = None,
    *,
    is_inject: bool = False,
    hint: str | None = None,
) -> str:
    """First matching exposure class (spec §3.2 / §10).

    ``inject`` input always reports ``default``. Files tagged ``test`` are ``test``; a rule
    ``hint`` (e.g. ``internet`` from ``fastapi_route``) applies when no config class matched.
    """
    if is_inject:
        return "default"
    cfg = cfg or ExposureConfig()
    if "test" in tags:
        return "test"
    for name, globs in cfg.classes():
        if globs and any_glob_match(globs, path):
            return name
    return hint if hint is not None and hint in EXPOSURE else "default"


def effective_base(rule_id: str, rule_severity: Severity, overrides: Mapping[str, str] | None) -> Severity:
    """Apply ``severity.overrides``. An exact id beats a glob; among globs the longest wins."""
    if not overrides:
        return rule_severity
    if rule_id in overrides:
        return Severity.parse(overrides[rule_id])
    best: tuple[int, str] | None = None
    for pat, sev in overrides.items():
        if pat != rule_id and rule_glob_match(pat, rule_id) and (best is None or len(pat) > best[0]):
            best = (len(pat), sev)
    return Severity.parse(best[1]) if best else rule_severity


def order_key(final_score: float, confidence: Confidence) -> float:
    """Sort key (descending): ``score x W[confidence]``."""
    return final_score * CONFIDENCE_WEIGHT[confidence]
