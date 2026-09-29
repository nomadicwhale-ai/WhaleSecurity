"""Tests for whalescan.config (spec §3: discovery, precedence, trust boundary, schema, env)."""

from __future__ import annotations

import os
import pickle
import sys
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from whalescan.config import (
    SUPPORTED_SCHEMA,
    TRUSTED_ONLY,
    ClassifyRule,
    Config,
    discover_project_config,
    find_git_root,
    load_config,
    parse_size,
    user_config_path,
)
from whalescan.errors import ConfigError


def write(p: Path, text: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    """An isolated environment: HOME and XDG dirs inside tmp_path, no WHALESCAN_* variables."""
    home = tmp_path / "home"
    home.mkdir()
    return {
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
    }


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    (r / ".git").mkdir(parents=True)
    return r


def project(repo: Path, body: str, schema: int = 1) -> Path:
    return write(repo / ".whalesecurity" / "config.toml", f"schema = {schema}\n{body}")


def user(env: dict[str, str], body: str) -> Path:
    return write(Path(env["XDG_CONFIG_HOME"]) / "whalescan" / "config.toml", f"schema = 1\n{body}")


# --------------------------------------------------------------------------- defaults


def test_defaults_match_spec(env: dict[str, str], tmp_path: Path) -> None:
    cfg = load_config(tmp_path, env=env)
    s = cfg.scan
    assert s.packs == ("appsec", "secrets", "domain", "agentsec")
    assert (s.fail_on, s.min_severity, s.min_confidence) == ("high", "low", "low")
    assert (s.jobs, s.time_budget_ms, s.include, s.exclude) == (0, 0, (), ())
    assert (s.walker, s.respect_gitignore, s.follow_symlinks) == ("auto", True, False)
    assert (s.max_file_bytes, s.max_files) == (1_048_576, 50_000)
    assert (s.max_total_bytes, s.max_stdin_bytes) == (536_870_912, 16_777_216)
    assert (s.baseline, s.diff_lines_only, s.skip_minified) == (".whalesecurity/baseline.json", False, True)
    assert cfg.rules.extra_dirs == (".whalesecurity/rules",)
    assert cfg.rules.enable == () and cfg.rules.disable == ()
    assert cfg.severity.overrides == {}
    exp = cfg.severity.exposure
    assert [c for c, _ in exp.classes()] == ["test", "vendored", "internet", "internal"]
    assert "**/conftest.py" in exp.test and "**/.env.example" in exp.test
    assert exp.vendored == ("vendor/**", "third_party/**", "**/site-packages/**", "**/node_modules/**")
    assert "**/ingress*.y*ml" in exp.internet
    assert exp.internal == ("scripts/**", "tools/**", "ops/**", "notebooks/**")
    assert cfg.classify.rules == ()
    sup = cfg.suppress
    assert (sup.require_reason, sup.min_reason_chars, sup.allow_file_level) == (True, 10, True)
    assert (sup.allow_wildcard, sup.max_block_lines, sup.report_unused) == (False, 200, False)
    assert cfg.secrets.allow_values == () and cfg.secrets.entropy_delta == 0.0
    assert (cfg.inject.max_bytes, cfg.inject.reveal) == (2_097_152, True)
    ad = cfg.adapters
    assert (ad.enabled, ad.timeout_s, ad.strict) == ((), 300, False)
    assert ad.semgrep.bin == "semgrep" and ad.semgrep.args == ("--config", "p/default")
    assert ad.trivy.scanners == ("vuln", "misconfig")
    assert ad.osv.backend == "osv-scanner" and ad.osv.allow_network is False
    assert ad.get("gitleaks").bin == "gitleaks"
    with pytest.raises(KeyError):
        ad.get("nope")
    assert cfg.mcp.pins == ".whalesecurity/mcp-pins.json"
    assert cfg.mcp.config_files == (".mcp.json", "~/.claude.json")
    assert (cfg.mcp.live, cfg.mcp.timeout_s) == (False, 10)
    r = cfg.report
    assert (r.format, r.max_snippet_chars, r.markdown_max_findings) == ("text", 240, 200)
    assert (r.sarif_include_all_rules, r.sarif_absolute_root) == (False, False)
    assert (cfg.cache.enabled, cfg.cache.dir) == (True, "")
    assert (cfg.logging.level, cfg.logging.format, cfg.logging.file) == ("warning", "text", "")
    assert cfg.hooks == {}
    assert cfg.schema == SUPPORTED_SCHEMA
    assert cfg.sources == ("defaults",)
    assert cfg.cache_path == os.path.join(env["XDG_CACHE_HOME"], "whalescan")


def test_config_default_equals_loaded_defaults(env: dict[str, str], tmp_path: Path) -> None:
    assert Config.default(tmp_path).to_dict() == load_config(tmp_path, env=env).to_dict()


def test_effective_jobs() -> None:
    cfg = Config.default()
    assert 1 <= cfg.scan.effective_jobs <= 8
    assert cfg.with_overrides({"scan.jobs": 3}).scan.effective_jobs == 3


def test_config_is_picklable_and_frozen(env: dict[str, str], repo: Path) -> None:
    project(repo, '[classify]\nrules = [{ glob = "a/**", kind = "iac" }]\n')
    cfg = load_config(repo, env=env)
    clone = pickle.loads(pickle.dumps(cfg))  # noqa: S301 - our own trusted bytes
    assert clone.to_dict() == cfg.to_dict()
    with pytest.raises(AttributeError):
        cfg.scan.fail_on = "low"  # type: ignore[misc]


# --------------------------------------------------------------------------- discovery


def test_discovery_walks_up_to_git_root(env: dict[str, str], repo: Path) -> None:
    cfg_file = project(repo, '[scan]\nfail_on = "medium"\n')
    deep = repo / "a" / "b" / "c"
    deep.mkdir(parents=True)
    assert discover_project_config(deep, env) == str(cfg_file)
    cfg = load_config(deep, env=env)
    assert cfg.scan.fail_on == "medium"
    assert cfg.project_config == str(cfg_file)
    assert cfg.project_root == str(repo)
    assert cfg.root == str(deep)
    assert cfg.sources == ("defaults", str(cfg_file))


def test_discovery_stops_at_git_dir(env: dict[str, str], tmp_path: Path) -> None:
    project(tmp_path, '[scan]\nfail_on = "low"\n')  # above the repo: must not be found
    inner = tmp_path / "inner"
    (inner / ".git").mkdir(parents=True)
    (inner / "src").mkdir()
    assert discover_project_config(inner / "src", env) is None
    assert load_config(inner / "src", env=env).scan.fail_on == "high"


def test_discovery_stops_at_home(tmp_path: Path) -> None:
    home = tmp_path / "home"
    work = home / "work" / "proj"
    work.mkdir(parents=True)
    project(tmp_path, "")  # above $HOME
    assert discover_project_config(work, {"HOME": str(home)}) is None
    cfg_file = project(home, "")  # at $HOME (inclusive)
    assert discover_project_config(work, {"HOME": str(home)}) == str(cfg_file)


def test_git_file_also_stops_walk(env: dict[str, str], tmp_path: Path) -> None:
    project(tmp_path, "")
    wt = tmp_path / "worktree"
    wt.mkdir()
    (wt / ".git").write_text("gitdir: /elsewhere\n")
    assert discover_project_config(wt, env) is None
    assert find_git_root(wt / "x") == str(wt)


def test_find_git_root(tmp_path: Path, repo: Path) -> None:
    (repo / "a").mkdir()
    assert find_git_root(repo / "a") == str(repo)
    assert find_git_root(repo) == str(repo)


def test_explicit_path_and_env(env: dict[str, str], repo: Path, tmp_path: Path) -> None:
    project(repo, '[scan]\nfail_on = "medium"\n')
    other = write(tmp_path / "other.toml", 'schema = 1\n[scan]\nfail_on = "critical"\n')
    assert load_config(repo, path=other, env=env).scan.fail_on == "critical"
    e2 = {**env, "WHALESCAN_CONFIG": str(other)}
    assert load_config(repo, env=e2).scan.fail_on == "critical"
    # an explicit file outside .whalesecurity/ uses the root as project root
    assert load_config(repo, path=other, env=env).project_root == str(repo)


def test_explicit_missing_file_is_config_error(env: dict[str, str], tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path, path=tmp_path / "nope.toml", env=env)
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path, env={**env, "WHALESCAN_CONFIG": str(tmp_path / "nope.toml")})


def test_no_project_config(env: dict[str, str], repo: Path) -> None:
    project(repo, '[scan]\nfail_on = "medium"\n')
    assert load_config(repo, project=False, env=env).scan.fail_on == "high"
    assert load_config(repo, env={**env, "WHALESCAN_NO_PROJECT_CONFIG": "1"}).scan.fail_on == "high"
    assert load_config(repo, env={**env, "WHALESCAN_NO_PROJECT_CONFIG": "0"}).scan.fail_on == "medium"
    # WHALESCAN_CONFIG is also disabled by project=False
    assert load_config(repo, project=False, env={**env, "WHALESCAN_CONFIG": "/nope"}).scan.fail_on == "high"


def test_symlinked_project_config_escaping_is_ignored(
    env: dict[str, str], repo: Path, tmp_path: Path
) -> None:
    outside = write(tmp_path / "evil.toml", 'schema = 1\n[scan]\nfail_on = "never"\n')
    (repo / ".whalesecurity").mkdir()
    os.symlink(outside, repo / ".whalesecurity" / "config.toml")
    cfg = load_config(repo, env=env)
    assert cfg.scan.fail_on == "high"
    assert "config-symlink-escape" in [d.code for d in cfg.diagnostics]


def test_user_config_location(env: dict[str, str], tmp_path: Path) -> None:
    assert user_config_path(env) == os.path.join(env["XDG_CONFIG_HOME"], "whalescan", "config.toml")
    rel = {"HOME": env["HOME"], "XDG_CONFIG_HOME": "relative/dir"}
    assert user_config_path(rel) == os.path.join(env["HOME"], ".config", "whalescan", "config.toml")
    user(env, '[scan]\nfail_on = "low"\n')
    cfg = load_config(tmp_path, env=env)
    assert cfg.scan.fail_on == "low"
    assert cfg.user_config == user_config_path(env)
    assert load_config(tmp_path, env=env, user=False).scan.fail_on == "high"


# --------------------------------------------------------------------------- precedence & merge


def test_precedence_defaults_user_project_env_cli(env: dict[str, str], repo: Path) -> None:
    user(env, '[scan]\nfail_on = "low"\nmin_severity = "medium"\njobs = 2\n')
    project(repo, '[scan]\nfail_on = "medium"\njobs = 3\n')
    e = {**env, "WHALESCAN_JOBS": "5"}
    cfg = load_config(repo, env=e, overrides={"scan": {"jobs": 7}})
    assert cfg.scan.min_severity == "medium"  # user
    assert cfg.scan.fail_on == "medium"  # project over user
    assert cfg.scan.jobs == 7  # cli over env over project
    assert load_config(repo, env=e).scan.jobs == 5
    assert cfg.sources[0] == "defaults" and cfg.sources[-2:] == ("env", "cli")


def test_tables_deep_merge_arrays_replace(env: dict[str, str], repo: Path) -> None:
    user(env, '[scan]\npacks = ["appsec"]\nexclude = ["a/"]\n[report]\nformat = "json"\n')
    project(repo, '[scan]\nexclude = ["b/"]\n')
    cfg = load_config(repo, env=env)
    assert cfg.scan.packs == ("appsec",)
    assert cfg.scan.exclude == ("b/",)  # replaced, not appended
    assert cfg.report.format == "json"  # sibling table survives


def test_union_and_dict_update_keys(env: dict[str, str], repo: Path) -> None:
    user(
        env,
        '[rules]\nenable = ["WS-A-001"]\ndisable = ["WS-B-*"]\n[severity.overrides]\n"WS-X-001" = "low"\n',
    )
    project(
        repo,
        '[rules]\nenable = ["WS-C-001", "WS-A-001"]\ndisable = ["WS-D-001"]\n'
        '[severity]\noverrides = { "WS-Y-001" = "info", "WS-X-001" = "medium" }\n',
    )
    cfg = load_config(repo, env=env, overrides={"rules.disable": ["WS-E-001"]})
    assert cfg.rules.enable == ("WS-A-001", "WS-C-001")
    assert cfg.rules.disable == ("WS-B-*", "WS-D-001", "WS-E-001")
    assert cfg.severity.overrides == {"WS-X-001": "medium", "WS-Y-001": "info"}


def test_exposure_subtable_deep_merges(env: dict[str, str], repo: Path) -> None:
    project(repo, '[severity.exposure]\ninternal = ["jobs/**"]\n')
    cfg = load_config(repo, env=env)
    assert cfg.severity.exposure.internal == ("jobs/**",)
    assert "tests/**" in cfg.severity.exposure.test


def test_dotted_and_nested_overrides(env: dict[str, str], tmp_path: Path) -> None:
    cfg = load_config(
        tmp_path,
        env=env,
        overrides={
            "scan.fail_on": "CRITICAL",
            "report": {"format": "sarif"},
            "severity.overrides": {"WS.A": "low"},
        },
    )
    assert cfg.scan.fail_on == "critical"  # enums are case-insensitive, normalized
    assert cfg.report.format == "sarif"
    assert cfg.severity.overrides == {"WS.A": "low"}


def test_with_overrides(env: dict[str, str], repo: Path, tmp_path: Path) -> None:
    project(repo, '[rules]\ndisable = ["WS-A-001"]\n')
    cfg = load_config(repo, env=env)
    wc = str(tmp_path / "wc")
    c2 = cfg.with_overrides({"scan.time_budget_ms": 150, "rules.disable": ["WS-B-001"], "cache.dir": wc})
    assert c2.scan.time_budget_ms == 150
    assert c2.rules.disable == ("WS-A-001", "WS-B-001")
    assert c2.cache_path == wc
    assert c2.project_config == cfg.project_config and c2.changes == cfg.changes
    assert cfg.scan.time_budget_ms == 0  # original untouched
    with pytest.raises(ConfigError):
        cfg.with_overrides({"scan.fail_on": "bogus"})


# --------------------------------------------------------------------------- trust boundary


@pytest.mark.parametrize(
    ("toml", "key"),
    [
        ('[adapters.semgrep]\nbin = "/tmp/evil"\n', "adapters.semgrep.bin"),
        ('[adapters.gitleaks]\nargs = ["--x"]\n', "adapters.gitleaks.args"),
        ('[adapters.trivy]\nenv = { A = "b" }\n', "adapters.trivy.env"),
        ("[adapters.osv]\nallow_network = true\n", "adapters.osv.allow_network"),
        ("[mcp]\nlive = true\n", "mcp.live"),
        ('[cache]\ndir = "/tmp/pwn"\n', "cache.dir"),
        ('[logging]\nfile = "/etc/cron.d/x"\n', "logging.file"),
    ],
)
def test_trusted_only_keys_ignored_in_project(env: dict[str, str], repo: Path, toml: str, key: str) -> None:
    assert key in TRUSTED_ONLY
    project(repo, toml)
    cfg = load_config(repo, env=env)
    diags = [d for d in cfg.diagnostics if d.code == "config-untrusted-key"]
    assert len(diags) == 1 and key in diags[0].message
    assert diags[0].level == "warning"
    d = Config.default().to_dict()
    assert cfg.to_dict() == d
    assert cfg.cache_path == os.path.join(env["XDG_CACHE_HOME"], "whalescan")


def test_trusted_only_keys_honored_from_user_env_cli(env: dict[str, str], repo: Path, tmp_path: Path) -> None:
    log_file = str(tmp_path / "w.log")
    cache_dir = str(tmp_path / "cachex")
    user(
        env, f'[adapters.semgrep]\nbin = "/opt/semgrep"\n[mcp]\nlive = true\n[logging]\nfile = "{log_file}"\n'
    )
    cfg = load_config(
        repo, env={**env, "WHALESCAN_CACHE_DIR": cache_dir}, overrides={"adapters.osv.allow_network": True}
    )
    assert cfg.adapters.semgrep.bin == "/opt/semgrep"
    assert cfg.mcp.live is True
    assert cfg.logging.file == log_file
    assert cfg.cache.dir == cache_dir and cfg.cache_path == cache_dir
    assert cfg.adapters.osv.allow_network is True
    assert not [d for d in cfg.diagnostics if d.code == "config-untrusted-key"]


def test_explicit_config_is_still_untrusted(env: dict[str, str], tmp_path: Path) -> None:
    other = write(tmp_path / "c.toml", 'schema = 1\n[adapters.semgrep]\nbin = "/tmp/evil"\n')
    cfg = load_config(tmp_path, path=other, env=env)
    assert cfg.adapters.semgrep.bin == "semgrep"


def test_project_paths_must_stay_inside(env: dict[str, str], repo: Path) -> None:
    project(
        repo,
        '[scan]\nbaseline = "../../etc/baseline.json"\n[mcp]\npins = "/abs/pins.json"\n'
        '[rules]\nextra_dirs = ["ok/rules", "~/rules", "../x", "a/../../b"]\n',
    )
    cfg = load_config(repo, env=env)
    assert cfg.scan.baseline == ".whalesecurity/baseline.json"
    assert cfg.mcp.pins == ".whalesecurity/mcp-pins.json"
    assert cfg.rules.extra_dirs == ("ok/rules",)
    assert len([d for d in cfg.diagnostics if d.code == "config-untrusted-key"]) == 5
    # the same values are fine from user config
    user(env, '[scan]\nbaseline = "/srv/baseline.json"\n')
    assert load_config(repo, env=env, project=False).scan.baseline == "/srv/baseline.json"


def test_config_changes_recorded_for_project(env: dict[str, str], repo: Path) -> None:
    project(
        repo,
        "[scan]\n"
        'packs = ["appsec"]\nfail_on = "critical"\nmin_severity = "high"\nmin_confidence = "medium"\n'
        'exclude = ["docs/"]\n'
        '[rules]\ndisable = ["WS-K8S-001", "WS-DKR-*"]\nenable = ["WS-X-001"]\n'
        '[severity.overrides]\n"WS-DKR-003" = "low"\n'
        '[secrets]\nallow_values = ["^AKIAEXAMPLE"]\nentropy_delta = 0.5\n'
        "[suppress]\nrequire_reason = false\nallow_wildcard = true\nmin_reason_chars = 2\n"
        '[severity.exposure]\ntest = ["src/**"]\n',
    )
    changes = load_config(repo, env=env).changes
    expected = {
        "rules.disable += WS-K8S-001",
        "rules.disable += WS-DKR-*",
        "severity.overrides.WS-DKR-003 = low",
        "scan.packs = [appsec]",
        "scan.fail_on = critical",
        "scan.min_severity = high",
        "scan.min_confidence = medium",
        "scan.exclude = [docs/]",
        "secrets.allow_values = [^AKIAEXAMPLE]",
        "secrets.entropy_delta = 0.5",
        "suppress.require_reason = false",
        "suppress.allow_wildcard = true",
        "suppress.min_reason_chars = 2",
        "severity.exposure.test = [src/**]",
    }
    assert set(changes) == expected
    assert not any("WS-X-001" in c for c in changes)


def test_strengthening_project_settings_not_listed(env: dict[str, str], repo: Path) -> None:
    project(repo, '[scan]\nfail_on = "low"\nmin_severity = "low"\n[secrets]\nentropy_delta = -0.2\n')
    assert load_config(repo, env=env).changes == ()


def test_user_config_changes_are_not_listed(env: dict[str, str], tmp_path: Path) -> None:
    user(env, '[rules]\ndisable = ["WS-A-001"]\n')
    assert load_config(tmp_path, env=env).changes == ()


# --------------------------------------------------------------------------- validation


@pytest.mark.parametrize(
    ("toml", "message"),
    [
        ('[scan]\nfail_on = "bogus"\n', "scan.fail_on: expected one of critical|high|medium|low|info|never"),
        ('[scan]\nmin_confidence = "certain"\n', "scan.min_confidence: expected one of high|medium|low"),
        ('[scan]\njobs = "4"\n', "scan.jobs: expected integer, got string"),
        ("[scan]\njobs = true\n", "scan.jobs: expected integer, got boolean"),
        ("[scan]\njobs = -1\n", "scan.jobs: expected an integer between 0 and 1024"),
        ('[scan]\nwalker = "svn"\n', "scan.walker: expected one of auto|git|fs"),
        ('[scan]\npacks = "appsec"\n', "scan.packs: expected array, got string"),
        ("[scan]\npacks = [1]\n", "scan.packs: [0]: expected string, got integer"),
        ('[scan]\nfollow_symlinks = "yes"\n', "scan.follow_symlinks: expected boolean"),
        ('[scan]\nmax_file_bytes = "lots"\n', "scan.max_file_bytes: invalid size"),
        ("scan = 3\n", "scan: expected table, got integer"),
        ('[severity.overrides]\n"WS-A" = "urgent"\n', "severity.overrides: WS-A: expected one of"),
        ("[secrets]\nentropy_delta = 2.0\n", "secrets.entropy_delta: expected a number between -1.0 and 1.0"),
        ('[secrets]\nallow_values = ["("]\n', "secrets.allow_values: [0]: invalid regular expression"),
        ('[adapters]\nenabled = ["nmap"]\n', "adapters.enabled: [0]: expected one of"),
        (
            '[adapters.osv]\nbackend = "x"\n',
            "adapters.osv.backend: expected one of osv-scanner|pip-audit|api",
        ),
        ('[report]\nformat = "html"\n', "report.format: expected one of text|json|jsonl|sarif|markdown"),
        ('[logging]\nlevel = "trace"\n', "logging.level: expected one of error|warning|info|debug"),
        ('[classify]\nrules = [{ kind = "iac" }]\n', "classify.rules: [0]: missing required key 'glob'"),
        (
            '[classify]\nrules = [{ glob = "x", kind = "binary" }]\n',
            "classify.rules: [0]: expected one of code",
        ),
        ('[classify]\nrules = [{ glob = "x" }]\n', "needs at least one of kind, lang or tags"),
        ('[classify]\nrules = [{ glob = "x", kind = "iac", color = 1 }]\n', "unknown key(s) color"),
        ("hooks = 1\n", "hooks: expected table"),
    ],
)
def test_validation_errors(env: dict[str, str], repo: Path, toml: str, message: str) -> None:
    project(repo, toml)
    with pytest.raises(ConfigError) as ei:
        load_config(repo, env=env)
    assert message in str(ei.value)
    assert str(repo / ".whalesecurity" / "config.toml") in str(ei.value)
    assert ei.value.exit_code == 2


def test_schema_required_and_versioned(env: dict[str, str], repo: Path) -> None:
    write(repo / ".whalesecurity" / "config.toml", '[scan]\nfail_on = "low"\n')
    with pytest.raises(ConfigError, match="schema: required"):
        load_config(repo, env=env)
    project(repo, "", schema=SUPPORTED_SCHEMA + 1)
    with pytest.raises(ConfigError, match="newer than supported"):
        load_config(repo, env=env)
    project(repo, "", schema=0)
    with pytest.raises(ConfigError, match="schema"):
        load_config(repo, env=env)
    write(repo / ".whalesecurity" / "config.toml", 'schema = "1"\n')
    with pytest.raises(ConfigError, match="schema: expected integer"):
        load_config(repo, env=env)


def test_unknown_keys_warn(env: dict[str, str], repo: Path) -> None:
    project(
        repo,
        '[scan]\nfail_on = "low"\ncolour = 1\n[nope]\nx = 1\n'
        '[adapters.nmap]\nbin = "x"\n[hooks]\nany = { thing = 1 }\n',
    )
    cfg = load_config(repo, env=env)
    unknown = sorted(d.message.split("'")[1] for d in cfg.diagnostics if d.code == "config-unknown-key")
    assert unknown == ["adapters.nmap", "nope", "scan.colour"]
    assert cfg.scan.fail_on == "low"
    assert cfg.hooks == {"any": {"thing": 1}}  # hooks are reserved and passed through


def test_toml_syntax_and_encoding_errors(env: dict[str, str], repo: Path) -> None:
    write(repo / ".whalesecurity" / "config.toml", "schema = 1\n[scan\n")
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(repo, env=env)
    (repo / ".whalesecurity" / "config.toml").write_bytes(b"schema = 1\n# \xff\n")
    with pytest.raises(ConfigError, match="not valid UTF-8"):
        load_config(repo, env=env)
    write(repo / ".whalesecurity" / "config.toml", "x = " + "[" * 5000 + "]" * 5000 + "\n")
    with pytest.raises(ConfigError):
        load_config(repo, env=env)


def test_oversized_config_rejected(env: dict[str, str], repo: Path) -> None:
    write(repo / ".whalesecurity" / "config.toml", "schema = 1\n" + "#" * (1 << 20) + "\n")
    with pytest.raises(ConfigError, match="larger than"):
        load_config(repo, env=env)


def test_sizes_accept_suffixes(env: dict[str, str], repo: Path) -> None:
    project(
        repo,
        '[scan]\nmax_file_bytes = "2M"\nmax_total_bytes = "1G"\nmax_stdin_bytes = 4096\n'
        '[inject]\nmax_bytes = "512K"\n',
    )
    cfg = load_config(repo, env=env)
    assert cfg.scan.max_file_bytes == 2 << 20
    assert cfg.scan.max_total_bytes == 1 << 30
    assert cfg.scan.max_stdin_bytes == 4096
    assert cfg.inject.max_bytes == 512 << 10


@pytest.mark.parametrize(
    ("text", "value"),
    [("0", 0), ("10", 10), ("1K", 1024), ("1k", 1024), ("3M", 3 << 20), ("2G", 2 << 30), ("1MiB", 1 << 20),
     ("5KB", 5 << 10), ("1_000", 1000), (" 7 ", 7), ("12B", 12)],
)  # fmt: skip
def test_parse_size(text: str, value: int) -> None:
    assert parse_size(text) == value


@pytest.mark.parametrize("bad", ["", "M", "1.5M", "-1", "1T", "abc", "1 M B"])
def test_parse_size_rejects(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_size(bad)
    with pytest.raises(ValueError):
        parse_size(-5)
    with pytest.raises(ValueError):
        parse_size(True)  # bool is an int subclass but must be rejected


def test_classify_rules_loaded(env: dict[str, str], repo: Path) -> None:
    project(
        repo,
        '[classify]\nrules = [{ glob = "platform/**/*.yaml", kind = "IAC", lang = "yaml",'
        ' tags = ["k8s"] }]\n',
    )
    cfg = load_config(repo, env=env)
    assert cfg.classify.rules == (ClassifyRule("platform/**/*.yaml", kind="iac", lang="yaml", tags=("k8s",)),)


# --------------------------------------------------------------------------- env vars


def test_env_vars(env: dict[str, str], tmp_path: Path) -> None:
    e = {
        **env,
        "WHALESCAN_FAIL_ON": "Medium",
        "WHALESCAN_PACKS": "appsec, secrets,,",
        "WHALESCAN_JOBS": " 4 ",
        "WHALESCAN_NO_CACHE": "true",
        "WHALESCAN_LOG_LEVEL": "DEBUG",
    }
    cfg = load_config(tmp_path, env=e)
    assert cfg.scan.fail_on == "medium"
    assert cfg.scan.packs == ("appsec", "secrets")
    assert cfg.scan.jobs == 4
    assert cfg.cache.enabled is False
    assert cfg.logging.level == "debug"
    assert cfg.sources == ("defaults", "env")
    assert load_config(tmp_path, env={**env, "WHALESCAN_LOG_LEVEL": "warn"}).logging.level == "warning"
    assert load_config(tmp_path, env={**env, "WHALESCAN_NO_CACHE": "0"}).cache.enabled is True
    assert load_config(tmp_path, env={**env, "WHALESCAN_FAIL_ON": ""}).scan.fail_on == "high"


def test_env_errors(env: dict[str, str], tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="WHALESCAN_JOBS"):
        load_config(tmp_path, env={**env, "WHALESCAN_JOBS": "many"})
    with pytest.raises(ConfigError, match=r"scan\.fail_on: expected one of"):
        load_config(tmp_path, env={**env, "WHALESCAN_FAIL_ON": "bogus"})


def test_xdg_cache_home(tmp_path: Path) -> None:
    e = {"HOME": str(tmp_path), "XDG_CACHE_HOME": str(tmp_path / "xc")}
    assert load_config(tmp_path, env=e).cache_path == str(tmp_path / "xc" / "whalescan")
    e2 = {"HOME": str(tmp_path), "XDG_CACHE_HOME": "rel"}
    assert load_config(tmp_path, env=e2).cache_path == str(tmp_path / ".cache" / "whalescan")


def test_resolve_path(env: dict[str, str], repo: Path) -> None:
    project(repo, "")
    cfg = load_config(repo / ".whalesecurity", env=env)
    assert cfg.resolve_path(".whalesecurity/rules") == str(repo / ".whalesecurity" / "rules")
    assert cfg.resolve_path("/abs/x") == "/abs/x"
    assert cfg.resolve_path("~/x") == os.path.expanduser("~/x")


def test_root_defaults_to_git_toplevel(
    env: dict[str, str], repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (repo / "sub").mkdir()
    monkeypatch.chdir(repo / "sub")
    assert load_config(env=env).root == str(repo)


# --------------------------------------------------------------------------- vendored tomli


def test_vendored_tomli_matches_stdlib() -> None:
    from whalescan._vendor import tomli

    doc = 'schema = 1\n[scan]\npacks = ["a", "b"]\nx = { y = 1.5, z = 1979-05-27T07:32:00Z }\n'
    assert tomli.loads(doc)["scan"]["packs"] == ["a", "b"]
    if sys.version_info >= (3, 11):
        import tomllib

        assert tomli.loads(doc) == tomllib.loads(doc)
    with pytest.raises(tomli.TOMLDecodeError):
        tomli.loads("[x")


def test_vendored_license_present() -> None:
    import whalescan._vendor.tomli as t

    lic = Path(t.__file__).with_name("LICENSE").read_text()
    assert "MIT License" in lic


@given(
    st.fixed_dictionaries(
        {},
        optional={
            "fail_on": st.sampled_from(["critical", "high", "medium", "low", "info", "never"]),
            "jobs": st.integers(0, 64),
            "follow_symlinks": st.booleans(),
            "exclude": st.lists(st.text(alphabet="ab*/!", min_size=1, max_size=5), max_size=3),
        },
    )
)
def test_valid_scan_tables_roundtrip(scan: dict[str, Any]) -> None:
    cfg = Config.default().with_overrides({"scan": scan})
    for k, v in scan.items():
        got = getattr(cfg.scan, k)
        assert (list(got) if isinstance(got, tuple) else got) == v
