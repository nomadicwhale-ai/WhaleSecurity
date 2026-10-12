"""Shared test profiles; platform-specific tests use the explicit posix marker."""

import os

import pytest
from hypothesis import is_hypothesis_test, settings

settings.register_profile("ci", max_examples=200, deadline=500, derandomize=True, database=None)
settings.register_profile("deterministic", derandomize=True, database=None)
settings.register_profile("nightly", max_examples=5000, deadline=None)
settings.register_profile("dev", max_examples=100)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "dev"))


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if is_hypothesis_test(getattr(item, "obj", None)):
            item.add_marker(pytest.mark.property)
        if os.name == "nt" and item.get_closest_marker("posix"):
            item.add_marker(pytest.mark.skip(reason="requires POSIX filesystem semantics"))
