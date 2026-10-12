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
        required = ["whalescan/py.typed", "whalescan/_vendor/tomli/LICENSE", "whalescan/rules/bundle.json"]
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
        from whalescan.rules.loader import SourceFile, build, parse_source

        rules = build(
            parse_source(
                SourceFile("bundle", "bundle.json", "bundle.json", "bundle"),
                wheel.read("whalescan/rules/bundle.json"),
            )
        )
        if not rules:
            raise ValueError("wheel contains an empty rule bundle")


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
        # A real positive seed is read by the isolated installed interpreter, not this checkout.
        fixture = Path(__file__).resolve().parents[1] / "tests/fixtures/WS-INJ-009/pos.py"
        (root / "positive.py").write_bytes(fixture.read_bytes())
        subprocess.run(
            [
                str(python),
                "-I",
                "-c",
                "import importlib.metadata as m; import whalescan; "
                "from whalescan import config, model; from whalescan.report import sarif; "
                "assert m.version('whalescan') == whalescan.__version__; "
                "assert not [r for r in m.requires('whalescan') or [] if 'extra ==' not in r]; "
                "from whalescan import Scanner; from whalescan.config import Config; "
                "from whalescan.rules.loader import load; "
                "rules=load(); assert len(rules) >= 15; "
                "sample=open('positive.py', encoding='utf-8').read(); "
                "result=Scanner(rules, Config.default()).scan_text(sample, filename='app.py'); "
                "assert any(f.rule_id == 'WS-INJ-009' for f in result.findings)",
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
        names = archive.getnames()
        if not any(n.endswith("/pyproject.toml") for n in names):
            raise SystemExit("sdist missing pyproject.toml")
        if not any(n.endswith("/src/whalescan/rules/bundle.json") for n in names):
            raise SystemExit("sdist missing built-in rule bundle")
    smoke_import(wheels[0])
    smoke_import(sdists[0], build_tools=True)


if __name__ == "__main__":
    main()
