"""Check action pinning and the narrow allowlist in quality-and-release §8.1."""

from __future__ import annotations

import re
from pathlib import Path

USES = re.compile(r"(?:^|[\s{,])uses:\s*[\"']?([^\s\"'#},]+)")
PINNED = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}\Z")
ALLOWED = ("actions/", "github/")
EXCEPTIONS = {"pypa/gh-action-pypi-publish", "sigstore/gh-action-sigstore-python"}


def check(text: str) -> list[int]:
    errors = []
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for match in USES.finditer(line):
            ref = match.group(1)
            if ref.startswith("./"):
                continue
            action = ref.split("@", 1)[0]
            if not PINNED.fullmatch(ref) or not (action.startswith(ALLOWED) or action in EXCEPTIONS):
                errors.append(number)
    return errors


def main() -> None:
    paths = sorted(Path(".github").rglob("*.yml")) + sorted(Path(".github").rglob("*.yaml"))
    if Path("action.yml").exists():
        paths.append(Path("action.yml"))
    errors = [
        f"{path}:{line}: unpinned or disallowed action"
        for path in paths
        for line in check(path.read_text(encoding="utf-8"))
    ]
    if errors:
        raise SystemExit("\n".join(errors))
    print("All action references are SHA-pinned and allowlisted")


if __name__ == "__main__":
    main()
