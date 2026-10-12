"""Regression tests for repository quality gates and workflow safety."""

from __future__ import annotations

import re
import sys
import zipfile
from pathlib import Path

import pytest
import yaml
from whalescan._vendor import tomli

from tools.check_dist import check_wheel
from tools.check_pins import check
from tools.check_stdlib_only import check_dependencies, check_imports
from tools.verify_release import tag_version

ROOT = Path(__file__).resolve().parents[1]


def test_action_pins_reject_tags_and_non_allowlisted_actions() -> None:
    assert check("- uses: actions/checkout@v5") == [1]
    assert check("- uses: untrusted/action@" + "a" * 40) == [1]
    assert check("- { uses: actions/checkout@v5 }") == [1]
    assert check("- uses: actions/checkout@" + "a" * 40) == []
    assert check("- uses: ./.github/actions/setup") == []
    assert check("# uses: actions/checkout@v5") == []


@pytest.mark.parametrize(
    "source",
    [
        "import requests",
        "from requests import get",
        "def f():\n    import requests\n",
        "try:\n    import requests\nexcept ImportError:\n    pass\n",
    ],
)
def test_stdlib_gate_rejects_dependency_imports(tmp_path: Path, source: str) -> None:
    (tmp_path / "sample.py").write_text(source, encoding="utf-8")
    assert check_imports(tmp_path)


def test_stdlib_gate_accepts_relative_imports_and_guarded_function_extra(tmp_path: Path) -> None:
    (tmp_path / "sample.py").write_text(
        "import ast\nfrom . import module\ndef extra():\n"
        "    try:\n        import mcp\n    except ImportError:\n        pass\n",
        encoding="utf-8",
    )
    assert not check_imports(tmp_path)


@pytest.mark.parametrize(
    ("source", "accepted"),
    [
        (
            "if sys.version_info >= (3, 11):\n    import tomllib\n"
            "else:\n    from ._vendor import tomli as tomllib\n",
            True,
        ),
        (
            "def load():\n    if sys.version_info >= (3, 11):\n        import tomllib\n"
            "    else:\n        from ._vendor import tomli as tomllib\n",
            True,
        ),
        ("import tomllib\n", False),
        ("if sys.version_info >= (3, 10):\n    import tomllib\n", False),
        ("if sys.version_info >= (3, 11):\n    import requests\n", False),
        (
            "if sys.version_info >= (3, 11):\n    import tomllib\nelse:\n    import requests\n",
            False,
        ),
        ("if sys.version_info >= (3, 11):\n    pass\nelse:\n    import tomllib\n", False),
    ],
)
def test_stdlib_gate_recognizes_guarded_tomllib_on_python_310(
    tmp_path: Path, source: str, accepted: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "stdlib_module_names", sys.stdlib_module_names - {"tomllib"})
    (tmp_path / "sample.py").write_text(source, encoding="utf-8")
    assert (not check_imports(tmp_path)) is accepted


@pytest.mark.parametrize("dependencies", ["['requests']", "[]", "None"])
def test_dependency_manifest_gate(tmp_path: Path, dependencies: str) -> None:
    manifest = tmp_path / "pyproject.toml"
    body = "[project]\n" + (f"dependencies = {dependencies}\n" if dependencies != "None" else "")
    manifest.write_text(body, encoding="utf-8")
    if dependencies == "[]":
        check_dependencies(manifest)
    else:
        with pytest.raises(ValueError):
            check_dependencies(manifest)


@pytest.mark.parametrize("tag", ["v1.2.3", "v0.1.0rc1"])
def test_release_tag_formats(tag: str) -> None:
    assert tag_version(tag) == tag[1:]


@pytest.mark.parametrize("tag", ["1.2.3", "v01.2.3", "v1.2.3.dev1", "v1.2.3\n", "v1.2.3;echo"])
def test_release_tag_rejects_other_formats(tag: str) -> None:
    with pytest.raises(ValueError):
        tag_version(tag)


def make_wheel(path: Path, *, metadata: str = "", omit: str = "") -> None:
    members = [
        "whalescan/py.typed",
        "whalescan/_vendor/tomli/LICENSE",
        "whalescan-1.0.0.dist-info/licenses/LICENSE",
    ]
    members += [
        f"whalescan/report/schemas/{name}-1.json" for name in ("baseline", "finding", "mcp-pins", "report")
    ]
    with zipfile.ZipFile(path, "w") as wheel:
        for name in members:
            if name != omit:
                wheel.writestr(name, "")
        wheel.writestr("whalescan-1.0.0.dist-info/METADATA", "Name: whalescan\n" + metadata)


def test_wheel_metadata_and_required_data(tmp_path: Path) -> None:
    wheel = tmp_path / "test.whl"
    make_wheel(wheel, metadata='Requires-Dist: mcp; extra == "mcp"\n')
    check_wheel(wheel)
    make_wheel(wheel, metadata="Requires-Dist: requests\n")
    with pytest.raises(ValueError, match="runtime dependency"):
        check_wheel(wheel)
    make_wheel(wheel, omit="whalescan/py.typed")
    with pytest.raises(ValueError, match="missing"):
        check_wheel(wheel)


def test_workflows_are_pinned_read_only_and_hardened() -> None:
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        text = path.read_text(encoding="utf-8")
        assert not check(text), path
        # BaseLoader keeps YAML 1.1's 'on' as a string, just like GitHub's YAML 1.2.
        workflow = yaml.load(text, Loader=yaml.BaseLoader)
        assert workflow["permissions"] == {"contents": "read"}
        assert not {"pull_request_target", "workflow_run"} & workflow["on"].keys()
        assert "concurrency" in workflow
        for job in workflow["jobs"].values():
            assert "timeout-minutes" in job
            for step in job.get("steps", []):
                if "run" in step:
                    assert "${{" not in step["run"]
                if step.get("uses", "").startswith("actions/checkout@"):
                    assert step["with"]["persist-credentials"] == "false"


def test_publication_is_opt_in_and_fails_closed() -> None:
    workflow = yaml.load((ROOT / ".github/workflows/release.yml").read_text(), Loader=yaml.BaseLoader)
    publish = workflow["jobs"]["publish-pypi"]
    assert publish["if"] == "vars.PYPI_PUBLISH_ENABLED == 'true'"
    assert "release-gates" in publish["needs"]
    assert publish["environment"]["name"] == "pypi"
    assert publish["permissions"] == {"id-token": "write"}
    assert "exit 1" in workflow["jobs"]["release-gates"]["steps"][-1]["run"]


def test_ci_required_check_and_supported_matrix() -> None:
    workflow = yaml.load((ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)
    jobs = workflow["jobs"]
    assert set(jobs["ci-ok"]["needs"]) == {"lint", "types", "test", "build", "stdlib-only"}
    matrix = jobs["test"]["strategy"]["matrix"]
    assert matrix["python"] == ["3.10", "3.11", "3.12", "3.13", "3.14"]
    assert all("continue-on-error" not in job for job in jobs.values())
    assert {item["os"] for item in matrix["include"]} == {"macos-15", "windows-2025"}
    assert "--cov-fail-under=90" in jobs["test"]["steps"][2]["run"]


def test_release_tools_are_optional_and_hash_locked() -> None:
    manifest = tomli.loads((ROOT / "engine/pyproject.toml").read_text())
    assert manifest["project"]["dependencies"] == []
    assert set(manifest["project"]["optional-dependencies"]["release"]) == {"build", "twine"}
    for suite, required in (("release", {"build", "twine"}), ("ci", {"pip-audit"})):
        lock = (ROOT / "requirements" / f"{suite}.txt").read_text()
        entries = re.findall(r"(?m)^[a-z][a-z0-9-]*==[^\n]+(?:\n[ \t]+[^\n]+)*", lock)
        assert required <= {entry.split("==", 1)[0] for entry in entries}
        assert all("--hash=sha256:" in entry for entry in entries)


def test_issue_forms_parse_and_require_fields() -> None:
    for path in (ROOT / ".github/ISSUE_TEMPLATE").glob("*.yml"):
        if path.name == "config.yml":
            continue
        form = yaml.safe_load(path.read_text(encoding="utf-8"))
        fields = [field for field in form["body"] if field["type"] != "markdown"]
        assert len({field["id"] for field in fields}) == len(fields)
        assert all(field["validations"]["required"] for field in fields)
