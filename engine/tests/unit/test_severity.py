import pytest

from whalescan.config import ExposureConfig
from whalescan.model import Confidence, Severity
from whalescan.severity import band, effective_base, exposure_for, order_key, score


@pytest.mark.parametrize(
    ("base", "reach", "exp", "sens", "want_score", "want_band"),
    [
        (Severity.HIGH, "tainted", "internet", True, 10.0, Severity.CRITICAL),  # 10.3 capped
        (Severity.HIGH, "unknown", "internal", True, 6.0, Severity.MEDIUM),
        (Severity.HIGH, "constant", "default", True, 4.5, Severity.MEDIUM),
        (Severity.HIGH, "unknown", "test", True, 3.0, Severity.LOW),
        (
            Severity.CRITICAL,
            "unknown",
            "test",
            False,
            10.0,
            Severity.CRITICAL,
        ),  # secrets: not exposure-sensitive
    ],
)
def test_spec_examples(base, reach, exp, sens, want_score, want_band):
    s, b = score(base, reach, exp, exposure_sensitive=sens)
    assert s == pytest.approx(want_score)
    assert b is want_band


@pytest.mark.parametrize(
    ("s", "b"),
    [
        (10, Severity.CRITICAL),
        (9.0, Severity.CRITICAL),
        (8.99, Severity.HIGH),
        (7.0, Severity.HIGH),
        (6.99, Severity.MEDIUM),
        (4.0, Severity.MEDIUM),
        (3.99, Severity.LOW),
        (1.0, Severity.LOW),
        (0.99, Severity.INFO),
        (0, Severity.INFO),
    ],
)
def test_band_edges(s, b):
    assert band(s) is b


def test_exposure_classes():
    cfg = ExposureConfig()
    assert exposure_for("tests/test_a.py", (), cfg) == "test"
    assert exposure_for("src/x.py", {"test"}, cfg) == "test"
    assert exposure_for("vendor/lib/a.py", (), cfg) == "vendored"
    assert exposure_for("app/routers/orders.py", (), cfg) == "internet"
    assert exposure_for("scripts/backfill.py", (), cfg) == "internal"
    assert exposure_for("src/x.py", (), cfg) == "default"
    assert exposure_for("src/x.py", (), cfg, hint="internet") == "internet"
    assert exposure_for("app/routers/orders.py", (), cfg, is_inject=True) == "default"


def test_test_class_precedes_internet():
    assert exposure_for("tests/api/test_x.py", (), ExposureConfig()) == "test"


def test_overrides_exact_beats_glob_and_longest_glob():
    ov = {"WS-DKR-*": "low", "WS-DKR-00*": "medium", "WS-DKR-003": "critical"}
    assert effective_base("WS-DKR-003", Severity.HIGH, ov) is Severity.CRITICAL
    assert effective_base("WS-DKR-001", Severity.HIGH, ov) is Severity.MEDIUM
    assert effective_base("WS-DKR-101", Severity.HIGH, ov) is Severity.LOW
    assert effective_base("WS-K8S-001", Severity.HIGH, ov) is Severity.HIGH
    assert effective_base("WS-K8S-001", Severity.HIGH, None) is Severity.HIGH


def test_order_key_weights_confidence():
    assert order_key(8, Confidence.HIGH) > order_key(8, Confidence.MEDIUM) > order_key(8, Confidence.LOW)
