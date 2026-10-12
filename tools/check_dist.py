"""Inspect artifacts and smoke-import each distribution in a dependency-free venv."""

from __future__ import annotations

import email
import os
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path


def check_wheel(path: Path) -> None:
    with zipfile.ZipFile(path) as wheel:
        names = wheel.namelist()
        required = ["whalescan/py.typed", "whalescan/_vendor/tomli/LICENSE"]
        required += [
            f"whalescan/report/schemas/{name}-1.json"
            for name in ("finding", "report", "baseline", "mcp-pins")
        ]
        if not all(name in names for name in required):
            raise ValueError("wheel missing typed marker, schemas or vendor license")
        if not any(".dist-info/" in name and name.endswith("/LICENSE") for name in names):
            raise ValueError("wheel missing project license")
        if any(name.startswith(("tests/", "evals/", "tools/")) for name in names):
            raise ValueError("wheel includes development-only content")
        metadata = email.message_from_bytes(wheel.read(next(n for n in names if n.endswith("/METADATA"))))
        if any("extra ==" not in req for req in metadata.get_all("Requires-Dist", [])):
            raise ValueError("wheel declares a core runtime dependency")
        # TODO: require rules/bundle.json once the rule bundle is implemented.


def smoke_import(path: Path, *, build_tools: bool = False) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        venv.EnvBuilder(with_pip=True).create(root / "venv")
        python = root / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if build_tools:
            subprocess.run(
                [
                    str(python),
                    "-m",
                    "pip",
                    "install",
                    "--require-hashes",
                    "--no-deps",
                    "-r",
                    str(Path("requirements/release.txt").resolve()),
                ],
                check=True,
            )
        subprocess.run(
            [str(python), "-m", "pip", "install", "--no-deps", "--no-build-isolation", str(path.resolve())],
            check=True,
        )
        subprocess.run(
            [
                str(python),
                "-I",
                "-c",
                "import importlib.metadata as m; import whalescan; "
                "from whalescan import config, model; from whalescan.report import sarif; "
                "assert m.version('whalescan') == whalescan.__version__; "
                "assert not [r for r in m.requires('whalescan') or [] if 'extra ==' not in r]",
            ],
            cwd=root,
            check=True,
        )


def main() -> None:
    dist = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
    wheels, sdists = list(dist.glob("*.whl")), list(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit("Expected exactly one wheel and one sdist")
    check_wheel(wheels[0])
    with tarfile.open(sdists[0]) as archive:
        if not any(n.endswith("/pyproject.toml") for n in archive.getnames()):
            raise SystemExit("sdist missing pyproject.toml")
    smoke_import(wheels[0])
    smoke_import(sdists[0], build_tools=True)


if __name__ == "__main__":
    main()
