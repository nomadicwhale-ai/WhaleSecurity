"""Regenerate universal hash locks via uv; runtime dependency metadata is untouched."""

from __future__ import annotations

import subprocess
from pathlib import Path

import tomllib


def main() -> None:
    with Path("engine/pyproject.toml").open("rb") as stream:
        manifest = tomllib.load(stream)
    build = manifest["build-system"]["requires"]
    dev = manifest["project"]["optional-dependencies"]["dev"]
    audit = manifest["project"]["optional-dependencies"]["adapters"]
    release = manifest["project"]["optional-dependencies"]["release"]
    suites = {"test": build + dev, "ci": build + dev + audit, "release": build + release}
    for name, requirements in suites.items():
        subprocess.run(
            [
                "uv",
                "pip",
                "compile",
                "-",
                "--universal",
                "--generate-hashes",
                "--python-version",
                "3.10",
                "--output-file",
                f"requirements/{name}.txt",
            ],
            input="\n".join(requirements),
            text=True,
            check=True,
            stdout=subprocess.DEVNULL,
        )


if __name__ == "__main__":
    main()
