"""Fail closed on malformed/off-main tags and inconsistent engine versions."""

from __future__ import annotations

import ast
import os
import re
import subprocess
from pathlib import Path

TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:rc(0|[1-9][0-9]*))?\Z")


def tag_version(tag: str) -> str:
    if not TAG.fullmatch(tag):
        raise ValueError("Expected vX.Y.Z or vX.Y.ZrcN")
    return tag[1:]


def main() -> None:
    import tomllib

    tag = os.environ["RELEASE_TAG"]
    version = tag_version(tag)
    subprocess.run(["git", "merge-base", "--is-ancestor", "HEAD", "origin/main"], check=True)
    with Path("engine/pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)["project"]
    tree = ast.parse(Path("engine/src/whalescan/__init__.py").read_text(encoding="utf-8"))
    source_version = next(
        ast.literal_eval(n.value)
        for n in tree.body
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "__version__" for t in n.targets)
    )
    if project["version"] != version or source_version != version:
        raise ValueError("tag, pyproject version and whalescan.__version__ must agree")
    changelog = Path("CHANGELOG.md")
    if not changelog.exists() or not re.search(
        rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$",
        changelog.read_text(encoding="utf-8"),
        re.MULTILINE,
    ):
        raise ValueError("release needs a dated CHANGELOG section")
    if list(Path("changelog.d").glob("*.md")):
        raise ValueError("assemble changelog fragments before tagging")
    if os.environ.get("GITHUB_OUTPUT"):
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
            stream.write(f"version={version}\n")
    # TODO: plugin/marketplace/pack version and minimum-bump checks when they exist.


if __name__ == "__main__":
    main()
