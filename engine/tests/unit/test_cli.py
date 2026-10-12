"""CLI contract tests with temp repositories and in-test rule packs."""

from __future__ import annotations

import ast
import io
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from whalescan import cli
from whalescan.config import Config


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "user-config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    for name in ("WHALESCAN_CONFIG", "WHALESCAN_PACKS", "WHALESCAN_FAIL_ON", "WHALESCAN_JOBS"):
        monkeypatch.delenv(name, raising=False)
    packs = tmp_path / ".whalesecurity" / "rules"
    packs.mkdir(parents=True)
    common = {
        "title": "Unsafe fixture operation",
        "severity": "high",
        "confidence": "high",
        "owner": "@whalesecurity",
        "applies_to": {"kind": ["code", "doc", "data", "agent-config"]},
        "message": "Unsafe fixture operation found.",
        "references": ["https://example.com/security"],
    }
    rules = [
        {**common, "id": "WS-INJ-001", "pack": "appsec/python", "match": {"regex": "DANGER"}},
        {
            **common,
            "id": "WS-SEC-001",
            "pack": "secrets/generic",
            "exposure_sensitive": False,
            "match": {"regex": {"pattern": "TOKEN=(?P<secret>[A-Za-z0-9]{12,32})", "secret_group": "secret"}},
            "message": "Fixture contains {{secret}} credential.",
        },
        {
            **common,
            "id": "WS-AGT-001",
            "pack": "agentsec/injection",
            "exposure_sensitive": False,
            "match": {"any": [{"regex": "INJECT"}, {"unicode": {"classes": ["ZW"]}}]},
        },
    ]
    (packs / "rules.json").write_text(json.dumps(rules), encoding="utf-8")
    (tmp_path / "app.py").write_text("DANGER\nTOKEN=FixtureCredential123456", encoding="utf-8")
    fixtures = tmp_path / "tests" / "fixtures"
    for rule in rules:
        folder = fixtures / rule["id"]
        folder.mkdir(parents=True)
        positive = {
            "WS-INJ-001": "DANGER",
            "WS-SEC-001": "TOKEN=FixtureCredential123456",
            "WS-AGT-001": "INJECT",
        }[rule["id"]]
        (folder / "pos.py").write_text(positive, encoding="utf-8")
        (folder / "neg.py").write_text("safe", encoding="utf-8")
    return tmp_path


def run(repo: Path, *args: str, data: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    from contextlib import redirect_stderr, redirect_stdout

    output, errors = io.StringIO(), io.StringIO()
    stream = io.TextIOWrapper(io.BytesIO(data), encoding="utf-8")
    with pytest.MonkeyPatch.context() as patch, redirect_stdout(output), redirect_stderr(errors):
        patch.setattr(sys, "stdin", stream)
        patch.chdir(repo)
        try:
            code = cli.main(["--root", str(repo), *args])
        except SystemExit as exc:
            code = int(exc.code)
    return subprocess.CompletedProcess(args, code, output.getvalue().encode(), errors.getvalue().encode())


def test_import_discipline() -> None:
    tree = ast.parse(Path(cli.__file__).read_text(encoding="utf-8"))
    imports = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    assert all(isinstance(n, ast.Import) for n in imports)
    assert {a.name for n in imports for a in n.names} == {"argparse", "os", "sys"}
    code = "import sys; import whalescan.cli; print(','.join(sorted(n for n in sys.modules if n.startswith('whalescan'))))"
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, check=True)
    assert proc.stdout.strip() == b"whalescan,whalescan.cli"


def test_startup_time_and_version() -> None:
    samples = []
    for _ in range(3):
        start = time.perf_counter()
        proc = subprocess.run(
            [sys.executable, "-X", "importtime", "-m", "whalescan", "version", "-f", "json"],
            capture_output=True,
            check=True,
        )
        samples.append(time.perf_counter() - start)
        assert "version" in json.loads(proc.stdout)
        assert b"whalescan.api" not in proc.stderr
    assert min(samples) < 0.080


@pytest.mark.parametrize("fmt", ["text", "json", "jsonl", "sarif", "markdown"])
def test_reports_and_fail_on(repo: Path, fmt: str) -> None:
    proc = run(repo, "scan", "app.py", "-f", fmt, "--deterministic")
    assert proc.returncode == 1
    assert b"FixtureCredential123456" not in proc.stdout + proc.stderr
    if fmt == "json":
        doc = json.loads(proc.stdout)
        assert doc["run"]["duration_ms"] == 0
        assert len(doc["findings"]) == 2
        assert doc["run"]["exit_code"] == 1
    elif fmt == "jsonl":
        assert len([json.loads(line) for line in proc.stdout.splitlines()]) == 2
    elif fmt == "sarif":
        assert json.loads(proc.stdout)["version"] == "2.1.0"
    assert run(repo, "scan", "app.py", "--fail-on", "never").returncode == 0


def test_scan_defaults_never_implicit_stdin(repo: Path) -> None:
    proc = run(repo, "scan", "-f", "json", data=b"INJECT")
    assert proc.returncode == 1
    assert all(f["file"] != "<stdin>" for f in json.loads(proc.stdout)["findings"])


def test_also_same_run_and_output_file(repo: Path) -> None:
    proc = run(
        repo,
        "scan",
        "app.py",
        "-f",
        "json",
        "-o",
        "out.json",
        "--also",
        "sarif=out.sarif",
        "--also",
        "markdown=out.md",
        "--deterministic",
    )
    assert proc.returncode == 1 and not proc.stdout
    primary = (repo / "out.json").read_bytes()
    assert len(json.loads(primary)["findings"]) == 2
    assert json.loads((repo / "out.sarif").read_bytes())["version"] == "2.1.0"
    assert (repo / "out.md").read_text().startswith("## whalescan")
    assert (
        b"FixtureCredential123456"
        not in primary + (repo / "out.sarif").read_bytes() + (repo / "out.md").read_bytes()
    )
    assert primary == run(repo, "scan", "app.py", "-f", "json", "--deterministic").stdout


@pytest.mark.parametrize("extra", ["wrong", "bad=path", "json=", "json=-"])
def test_bad_also(repo: Path, extra: str) -> None:
    assert run(repo, "scan", "app.py", "--also", extra).returncode == 2


@pytest.mark.parametrize(
    "args",
    [
        ("scan", "missing"),
        ("scan", "-", "-"),
        ("scan", "--stdin", "-"),
        ("scan", "--stdin", "--files-from", "-"),
        ("scan", "--diff-lines"),
        ("scan", "--jobs", "-1"),
        ("scan", "--time-budget-ms", "-1"),
        ("scan", "--max-file-size", "bogus"),
        ("scan", "--rule", "WS-INJ-999"),
        ("scan", "--config", "missing.toml"),
        ("secrets", "--since", "HEAD"),
        ("inject", "--max-bytes", "0"),
    ],
)
def test_exit_two(repo: Path, args: tuple[str, ...]) -> None:
    proc = run(repo, *args, data=b"safe")
    assert proc.returncode == 2
    assert b"Traceback" not in proc.stderr


def test_stdin_virtual_path_filters_and_implicit_modes(repo: Path) -> None:
    proc = run(repo, "scan", "--stdin", "--stdin-filename", "app.py", "-f", "json", data=b"DANGER")
    assert json.loads(proc.stdout)["findings"][0]["file"] == "app.py"
    proc = run(repo, "secrets", "-f", "json", data=b"TOKEN=FixtureCredential123456")
    assert proc.returncode == 1 and len(json.loads(proc.stdout)["findings"]) == 1
    proc = run(repo, "inject", "-f", "json", "--source", "web:fixture", data=b"INJECT")
    assert proc.returncode == 1
    finding = json.loads(proc.stdout)["findings"][0]
    assert finding["file_kind"] == "doc" and finding["properties"]["source_label"] == "web:fixture"
    proc = run(
        repo,
        "inject",
        "--max-bytes",
        "20",
        "--reveal-out",
        "reveal.txt",
        "-f",
        "json",
        data=("a" * 100 + "INJECT\u200b").encode(),
    )
    assert proc.returncode == 1
    assert json.loads(proc.stdout)["stats"]["truncated"]
    assert "[ZWSP]" in (repo / "reveal.txt").read_text()
    (repo / "notes.md").write_text("INJECT\u200b", encoding="utf-8")
    assert (
        run(repo, "inject", "notes.md", "--reveal-out", "-", "--no-reveal", "-o", "report.txt").returncode
        == 1
    )


def test_files_from_and_global_locations(repo: Path) -> None:
    (repo / "files.txt").write_bytes(b"app.py\0")
    proc = run(
        repo,
        "scan",
        "--files-from",
        "files.txt",
        "--no-cache",
        "--no-project-config",
        "--color",
        "never",
        "-f",
        "json",
    )
    assert proc.returncode == 1 and len(json.loads(proc.stdout)["findings"]) == 2
    assert run(repo, "scan", "--files-from", "-", data=b"app.py\n").returncode == 1
    assert (
        run(
            repo,
            "--no-cache",
            "scan",
            "app.py",
            "--cache-dir",
            "cache",
            "--rules-dir",
            ".whalesecurity/rules",
        ).returncode
        == 2
    )  # duplicate IDs are rejected
    empty = repo / "empty.txt"
    empty.write_text("", encoding="utf-8")
    assert run(repo, "scan", "--files-from", "empty.txt").returncode == 0
    assert run(repo, "scan", "--files-from", "-", data=b"-\n").returncode == 2


def test_filters_packs_fail_gate_and_severity(repo: Path) -> None:
    proc = run(
        repo,
        "scan",
        "app.py",
        "--packs",
        "appsec",
        "--rule",
        "WS-INJ-*",
        "--min-severity",
        "critical",
        "-f",
        "json",
    )
    assert proc.returncode == 1 and not json.loads(proc.stdout)["findings"]
    assert run(repo, "scan", "app.py", "--exclude-rule", "WS-*").returncode == 0
    assert run(repo, "scan", "app.py", "--min-confidence", "high", "--exclude", "app.py").returncode == 0
    assert (
        run(
            repo,
            "scan",
            "app.py",
            "--no-gitignore",
            "--follow-symlinks",
            "--max-file-size",
            "1M",
            "--max-files",
            "3",
            "--include",
            "*.py",
            "--profile",
            "-vv",
        ).returncode
        == 1
    )


def test_baseline_create_update_partial_critical(repo: Path) -> None:
    proc = run(repo, "baseline", "create", "app.py", "--reason", "approved fixture risk")
    assert proc.returncode == 0 and b"added 2" in proc.stdout
    assert run(repo, "baseline", "create", "app.py", "--reason", "fixture risk").returncode == 2
    assert run(repo, "scan", "app.py").returncode == 0
    assert run(repo, "scan", "app.py", "--no-baseline").returncode == 1
    for fmt in ("json", "sarif", "markdown", "text"):
        proc = run(repo, "scan", "app.py", "-f", fmt, "--show-suppressed")
        assert b"WS-INJ-001" in proc.stdout
    proc = run(repo, "baseline", "update", "app.py", "--no-prune")
    assert proc.returncode == 0 and b"kept 2" in proc.stdout
    (repo / "empty.py").write_text("safe", encoding="utf-8")
    assert run(repo, "baseline", "update", "empty.py").returncode == 0
    assert len(json.loads((repo / ".whalesecurity/baseline.json").read_text())["entries"]) == 2
    (repo / "app.py").write_text("safe", encoding="utf-8")
    proc = run(repo, "baseline", "update", "app.py")
    assert proc.returncode == 0 and b"pruned 2" in proc.stdout
    (repo / "app.py").write_text("DANGER", encoding="utf-8")
    assert run(repo, "baseline", "update", "app.py", "--add-new").returncode == 2
    assert run(repo, "baseline", "update", "app.py", "--add-new", "--reason", "fixture risk").returncode == 0
    assert (
        run(
            repo,
            "baseline",
            "create",
            "app.py",
            "--reason",
            "fixture risk",
            "--force",
            "--baseline-out",
            "custom.json",
        ).returncode
        == 0
    )
    config = repo / ".whalesecurity/config.toml"
    config.write_text('schema = 1\n[severity.overrides]\n"WS-INJ-001" = "critical"\n', encoding="utf-8")
    assert run(repo, "baseline", "create", "app.py", "--reason", "fixture risk", "--force").returncode == 2
    assert (
        run(
            repo, "baseline", "create", "app.py", "--reason", "fixture risk", "--force", "--allow-critical"
        ).returncode
        == 0
    )


def test_rules_list_explain_test_redos(repo: Path) -> None:
    proc = run(
        repo, "rules", "list", "-f", "json", "--packs", "appsec", "--kind", "code", "--severity-min", "high"
    )
    assert len(json.loads(proc.stdout)) == 1
    assert run(repo, "rules", "list", "--tag", "nonexistent").returncode == 0
    assert b"| ID |" in run(repo, "rules", "list", "-f", "markdown").stdout
    assert b"WS-INJ-001" in run(repo, "rules", "list").stdout
    for fmt in ("text", "json", "markdown"):
        proc = run(repo, "rules", "explain", "WS-INJ-001", "-f", fmt)
        assert proc.returncode == 0 and b"WS-INJ-001" in proc.stdout
    assert b"rg -n -P -e DANGER -- ." in run(repo, "rules", "explain", "WS-INJ-001", "--grep").stdout
    assert run(repo, "rules", "explain", "WS-AGT-001", "--grep").returncode == 2
    assert run(repo, "rules", "explain", "WS-INJ-999").returncode == 2
    assert run(repo, "rules", "test", "WS-INJ-*", "--redos", "--junit", "tests.xml").returncode == 0
    assert (repo / "tests.xml").read_text().startswith("<testsuite")
    assert run(repo, "rules", "test", "--schema-only").returncode == 0
    assert run(repo, "rules", "test", "--fixtures", "missing").returncode == 2
    (repo / "tests/fixtures/WS-INJ-001/pos.py").write_text("safe", encoding="utf-8")
    assert run(repo, "rules", "test", "WS-INJ-001", "--junit", "failed.xml").returncode == 1
    assert "<failure" in (repo / "failed.xml").read_text()


def test_exit_three_json_sarif_and_no_secret(repo: Path) -> None:
    for fmt in ("json", "sarif"):
        proc = run(repo, "scan", "app.py", "--adapters", "semgrep", "--adapters-strict", "-f", fmt)
        assert proc.returncode == 3
        doc = json.loads(proc.stdout)
        if fmt == "sarif":
            assert not doc["runs"][0]["invocations"][0]["executionSuccessful"]
        else:
            assert doc["run"]["exit_code"] == 3
        assert b"FixtureCredential123456" not in proc.stdout + proc.stderr


def test_internal_interrupt_broken_pipe(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(args: object, cfg: object) -> object:
        raise RuntimeError("FixtureCredential123456")

    monkeypatch.setattr(cli, "_scan", fail)
    for fmt in ("json", "sarif"):
        assert cli.main(["scan", "app.py", "-f", fmt]) == 3
        out = capsys.readouterr()
        assert "FixtureCredential123456" not in out.out + out.err
        doc = json.loads(out.out)
        assert doc.get("run", {}).get("exit_code", 3) == 3

    def interrupt(args: object, cfg: object) -> object:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_scan", interrupt)
    assert cli.main(["scan", "app.py"]) == 130
    monkeypatch.undo()
    # Broken pipe preserves the already computed finding gate.
    monkeypatch.chdir(repo)

    class Broken(io.StringIO):
        def write(self, value: str) -> int:
            raise BrokenPipeError

    monkeypatch.setattr(sys, "stdout", Broken())
    assert cli.main(["scan", "app.py"]) == 1
    sys.stdout.close()


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=True)


def test_git_diff_staged_history(repo: Path) -> None:
    git(repo, "init")
    (repo / "app.py").write_text("DANGER\nTOKEN=FixtureCredential123456\n", encoding="utf-8")
    git(repo, "config", "user.name", "Fixture")
    git(repo, "config", "user.email", "fixture@example.com")
    git(repo, "add", "app.py")
    git(repo, "commit", "-m", "fixture")
    (repo / "app.py").write_text("DANGER\nTOKEN=FixtureCredential123456\nDANGER", encoding="utf-8")
    proc = run(repo, "scan", "app.py", "--diff", "HEAD", "--diff-lines", "-f", "json")
    assert [f["line"] for f in json.loads(proc.stdout)["findings"]] == [3]
    git(repo, "add", "app.py")
    proc = run(repo, "scan", "app.py", "--staged", "--diff-lines", "-f", "json")
    assert [f["line"] for f in json.loads(proc.stdout)["findings"]] == [3]
    git(repo, "commit", "-m", "fixture update")
    proc = run(repo, "secrets", "--git-history", "-f", "json")
    assert proc.returncode == 1
    assert "commit" in json.loads(proc.stdout)["findings"][0]["properties"]
    assert b"FixtureCredential123456" not in proc.stdout + proc.stderr
    assert run(repo, "secrets", "--git-history", "--since", "HEAD~1").returncode == 0
    assert run(repo, "secrets", "--git-history", "--max-commits", "0").returncode == 2
    assert run(repo, "secrets", "--git-history", "--since", "missing").returncode == 2


def test_redos_timeout_and_fast(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert cli._redos("DANGER", ())
    assert cli._redos("^z+", ("i", "a"))

    def timeout(*args: object, **kwargs: object) -> object:
        raise subprocess.TimeoutExpired("test", 2)

    monkeypatch.setattr(subprocess, "run", timeout)
    assert not cli._redos("DANGER", ())


def test_version_probe_and_bundle(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["version", "--probe-adapters", "-f", "json"]) == 0
    assert "adapters" in json.loads(capsys.readouterr().out)
    assert cli.main(["version"]) == 0
    assert "whalescan" in capsys.readouterr().out
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: "/fixture/tool")
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess([], 0, b"fixture v1", b"")
    )
    assert cli.main(["version", "--probe-adapters", "-f", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["adapters"]["semgrep"] == "fixture v1"


def test_config_logging_options(repo: Path) -> None:
    proc = run(
        repo, "scan", "app.py", "-q", "--log-format", "json", "--color", "always", "--adapters", "none"
    )
    assert proc.returncode == 1
    assert run(repo, "scan", "app.py", "-v").returncode == 1


@pytest.mark.parametrize(
    "arguments,code",
    [
        (["scan", "app.py", "--fail-on", "never"], 0),
        (["scan", "app.py"], 1),
        (["scan", "missing"], 2),
        (["scan", "app.py", "--adapters", "semgrep", "--adapters-strict"], 3),
    ],
)
def test_real_process_exit_codes(repo: Path, arguments: list[str], code: int) -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "whalescan", "--root", str(repo), *arguments],
        input=b"",
        capture_output=True,
        check=False,
        cwd=repo,
    )
    assert proc.returncode == code
    assert b"FixtureCredential123456" not in proc.stdout + proc.stderr


def test_real_process_interrupt(repo: Path) -> None:
    script = (
        "from whalescan import cli\n"
        "def interrupted(*args): raise KeyboardInterrupt\n"
        "cli._scan=interrupted\n"
        "raise SystemExit(cli.main(['scan','app.py']))\n"
    )
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, check=False, cwd=repo)
    assert proc.returncode == 130 and b"Traceback" not in proc.stderr


def test_injection_retains_actual_tail_beyond_stdin_cap(repo: Path) -> None:
    (repo / ".whalesecurity/config.toml").write_text(
        "schema=1\n[scan]\nmax_stdin_bytes=32\n[inject]\nmax_bytes=20\n", encoding="utf-8"
    )
    proc = run(repo, "inject", "-f", "json", data=b"padding" * 10000 + b"INJECT")
    doc = json.loads(proc.stdout)
    assert proc.returncode == 1 and doc["run"]["truncated"]
    assert any(f["rule_id"] == "WS-AGT-001" for f in doc["findings"])
    proc = run(repo, "inject", "-f", "json", "--reveal-out", "whole.txt", data=b"padding" * 100 + b"INJECT")
    assert proc.returncode == 1 and (repo / "whole.txt").read_bytes().endswith(b"INJECT")
    assert len((repo / "whole.txt").read_bytes()) == 706


def test_partial_internal_result_and_verbose_traceback(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from whalescan import api
    from whalescan.errors import RuleError

    real = api.evaluate

    def fail_second(expr: object, ctx: object, rule: object) -> object:
        if rule.id == "WS-SEC-001":
            raise RuntimeError("FixtureCredential123456")
        return real(expr, ctx, rule)

    monkeypatch.setattr(api, "evaluate", fail_second)
    assert cli.main(["scan", "app.py", "-f", "json", "-vv"]) == 3
    out = capsys.readouterr()
    doc = json.loads(out.out)
    assert len(doc["findings"]) == 1
    assert doc["run"]["error"]["type"] == "RuntimeError"
    assert "Traceback" in out.err and "FixtureCredential123456" not in out.out + out.err

    def rule_failure(*args: object) -> object:
        raise RuleError("fixture rule failure")

    monkeypatch.setattr(api, "evaluate", rule_failure)
    assert cli.main(["scan", "app.py"]) == 2
    capsys.readouterr()


def test_logging_json_file_and_profile(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import logging

    cfg = Config.default(repo).with_overrides(
        {"logging.format": "json", "logging.level": "info", "logging.file": str(repo / "scanner.log")}
    )
    cli._logging(cfg)
    logging.getLogger("whalescan").info("fixture\\u200b log")
    doc = json.loads(capsys.readouterr().err)
    assert doc["level"] == "info" and doc["logger"] == "whalescan"
    assert (repo / "scanner.log").exists()
    proc = run(repo, "scan", "app.py", "--profile")
    assert b"WS-INJ-001:" in proc.stderr
    cli._logging(Config.default(repo))


def test_rules_schema_failure_and_dash_pattern(repo: Path) -> None:
    packs = repo / ".whalesecurity/rules/rules.json"
    rules = json.loads(packs.read_text())
    rules[0]["match"] = {"regex": "^-----BEGIN FIXTURE KEY-----"}
    rules[0]["keywords"] = ["BEGIN"]
    rules[0]["match"]["regex"] = {"pattern": "-----BEGIN FIXTURE KEY-----", "flags": ["i"]}
    packs.write_text(json.dumps(rules), encoding="utf-8")
    proc = run(repo, "rules", "explain", "WS-INJ-001", "--grep")
    assert b"rg -n -P -e '(?i)-----BEGIN FIXTURE KEY-----' -- ." in proc.stdout
    rules[0]["title"] = "bad"
    packs.write_text(json.dumps(rules), encoding="utf-8")
    assert run(repo, "rules", "test", "--schema-only", "--junit", "schema.xml").returncode == 1
    assert "<failure" in (repo / "schema.xml").read_text()
    assert run(repo, "rules", "list").returncode == 2


def test_baseline_update_diff_scope(repo: Path) -> None:
    git(repo, "init")
    git(repo, "config", "user.name", "Fixture")
    git(repo, "config", "user.email", "fixture@example.com")
    (repo / "other.py").write_text("DANGER", encoding="utf-8")
    git(repo, "add", "app.py", "other.py")
    git(repo, "commit", "-m", "fixture")
    assert run(repo, "baseline", "create", "app.py", "other.py", "--reason", "fixture risk").returncode == 0
    (repo / "app.py").write_text("safe", encoding="utf-8")
    assert run(repo, "baseline", "update", ".", "--diff", "HEAD").returncode == 0
    entries = json.loads((repo / ".whalesecurity/baseline.json").read_text())["entries"]
    assert [e["path"] for e in entries] == ["other.py"]


def test_reveal_out_secret_doc_rule(repo: Path) -> None:
    packs = repo / ".whalesecurity/rules/rules.json"
    rules = json.loads(packs.read_text())
    rule = dict(rules[1], id="WS-AGT-002", pack="agentsec/injection", applies_to={"kind": "doc"}, redact=True)
    rules.append(rule)
    packs.write_text(json.dumps(rules), encoding="utf-8")
    proc = run(
        repo, "inject", "--reveal-out", "revealed.txt", "-f", "json", data=b"TOKEN=FixtureCredential123456"
    )
    assert proc.returncode == 1
    assert b"FixtureCredential123456" not in proc.stdout + proc.stderr + (repo / "revealed.txt").read_bytes()


def test_python_module_entry_point(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import runpy

    monkeypatch.setattr(sys, "argv", ["whalescan", "version"])
    with pytest.raises(SystemExit) as stopped:
        runpy.run_module("whalescan", run_name="__main__")
    assert stopped.value.code == 0
    capsys.readouterr()


def test_baseline_truncated_and_stdin_cap(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = repo / ".whalesecurity/config.toml"
    config.write_text("schema = 1\n[scan]\nmax_stdin_bytes = 5\n", encoding="utf-8")
    proc = run(repo, "scan", "-", "-f", "json", data=b"DANGER")
    assert json.loads(proc.stdout)["run"]["truncated"]
    assert run(repo, "baseline", "create", "--max-files", "1", "--reason", "fixture risk").returncode == 2
    assert cli._combine([], Config.default(repo)).findings == ()
