"""Compile YAML seeds using the engine's loader, lint and fixture/ReDoS checks.

Run from any directory with Python 3.10+: no installation or third-party packages
required. Both committed copies must match; the package copy ships in wheel/sdist.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

# Always use this checkout's engine, not an older installed whalescan.
REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "engine" / "src"))

from whalescan.config import Config  # noqa: E402
from whalescan.errors import RuleError  # noqa: E402
from whalescan.rules.loader import (  # noqa: E402
    SourceFile,
    build,
    build_bundle,
    canonical_json,
    parse_source,
)
from whalescan.rules.testing import fixture_checks, redos_checks  # noqa: E402

TARGETS = ("rules/bundle.json", "engine/src/whalescan/rules/bundle.json")


def compile_bundle(root: Path) -> bytes:
    document = build_bundle([root / "rules"], yaml_only=True, strict=True)
    data = canonical_json(document)
    rules = build(parse_source(SourceFile("bundle", "bundle.json", "bundle.json", "bundle"), data))
    if not rules:
        raise RuleError("no YAML rules to bundle")
    checks = [*fixture_checks(rules, Config.default(root), root / "tests" / "fixtures"), *redos_checks(rules)]
    failures = [(name, message) for name, ok, message in checks if not ok]
    if failures:
        raise RuleError("rule contract failed:\n" + "\n".join(f"  {name}: {msg}" for name, msg in failures))
    return data + b"\n"


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    stream = tempfile.NamedTemporaryFile(dir=path.parent, prefix=".bundle-", suffix=".tmp", delete=False)
    temporary = Path(stream.name)
    try:
        with stream:
            stream.write(data)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail without writing if either bundle is stale")
    parser.add_argument("--root", type=Path, default=REPO, help="repository root (defaults to this checkout)")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        data = compile_bundle(root)
        stale = [
            name for name in TARGETS if not (root / name).is_file() or (root / name).read_bytes() != data
        ]
        if args.check:
            if stale:
                print(
                    "stale bundle: " + ", ".join(stale) + "; run python tools/build_bundle.py",
                    file=sys.stderr,
                )
                return 1
        else:
            for name in stale:
                _atomic_write(root / name, data)
    except (RuleError, OSError) as exc:
        print(f"build_bundle: {exc}", file=sys.stderr)
        return 1
    print("bundle is up to date" if args.check else "built validated rule bundle")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
