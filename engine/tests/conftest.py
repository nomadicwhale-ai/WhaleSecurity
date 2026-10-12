"""Reproducible property tests, including when CI has no Hypothesis example database."""

from hypothesis import settings

settings.register_profile("deterministic", derandomize=True, database=None)
settings.load_profile("deterministic")
