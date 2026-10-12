"""Fresh-process CLI smoke uses only the bundled rules and synthetic fixtures."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def run(tmp_path: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    env = {**os.environ, "XDG_CONFIG_HOME": str(tmp_path / "config"), "WHALESCAN_NO_CACHE": "1"}
    for key in ("WHALESCAN_CONFIG", "WHALESCAN_PACKS", "WHALESCAN_FAIL_ON"):
        env.pop(key, None)
    return subprocess.run(
        [sys.executable, "-m", "whalescan", "--root", str(tmp_path), "--no-project-config", *arguments],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        check=False,
        timeout=30,
    )


@pytest.mark.parametrize("fmt", ["json", "sarif"])
def test_default_bundle_scan_reports_and_exit_codes(tmp_path: Path, fmt: str) -> None:
    (tmp_path / "app.py").write_text('eval(request.args["expression"])\n', encoding="utf-8")
    proc = run(tmp_path, "scan", ".", "-f", fmt, "--deterministic")
    assert proc.returncode == 1
    doc = json.loads(proc.stdout)
    if fmt == "json":
        findings = doc["findings"]
        assert [(f["rule_id"], f["file"], f["line"], f["col"]) for f in findings] == [
            ("WS-INJ-009", "app.py", 1, 1)
        ]
    else:
        findings = doc["runs"][0]["results"]
        assert [f["ruleId"] for f in findings] == ["WS-INJ-009"]
        assert findings[0]["locations"][0]["physicalLocation"]["region"]["startColumn"] == 1
    (tmp_path / "app.py").write_text("json.loads(request.data)\n", encoding="utf-8")
    assert run(tmp_path, "scan", ".", "-f", fmt).returncode == 0


def test_dash_pattern_listing_explanation_and_fixture_redos(tmp_path: Path) -> None:
    listed = run(tmp_path, "rules", "list", "-f", "json")
    assert listed.returncode == 0 and len(json.loads(listed.stdout)) == 15
    explained = run(tmp_path, "rules", "explain", "WS-SEC-PK-001", "--grep")
    assert explained.returncode == 0
    argv = shlex.split(explained.stdout.decode())
    assert argv[argv.index("-e") + 1].startswith("-") and "--" in argv and "-U" in argv
    tested = run(tmp_path, "rules", "test", "--fixtures", str(ROOT / "tests/fixtures"), "--redos")
    assert tested.returncode == 0, tested.stderr.decode()


def test_real_cli_redacts_private_body_and_vendor_values(tmp_path: Path) -> None:
    for rule, ext in [("WS-SEC-PK-001", "pem"), ("WS-SEC-AWS-001", "env"), ("WS-SEC-GH-001", "env")]:
        fixture = ROOT / "tests/fixtures" / rule / f"pos.{ext}"
        (tmp_path / f"sample-{rule}.{ext}").write_bytes(fixture.read_bytes())
    proc = run(tmp_path, "scan", ".", "-f", "json", "--also", "sarif=out.sarif")
    assert proc.returncode == 1
    findings = json.loads(proc.stdout)["findings"]
    assert {f["rule_id"] for f in findings} == {"WS-SEC-PK-001", "WS-SEC-AWS-001", "WS-SEC-GH-001"}
    for rule, ext in [("WS-SEC-PK-001", "pem"), ("WS-SEC-AWS-001", "env"), ("WS-SEC-GH-001", "env")]:
        for line in (ROOT / "tests/fixtures" / rule / f"pos.{ext}").read_bytes().splitlines()[1:]:
            if line and not line.startswith(b"-----"):
                if line in proc.stdout or line in (tmp_path / "out.sarif").read_bytes():
                    pytest.fail("raw synthetic secret leaked (value intentionally not printed)")
