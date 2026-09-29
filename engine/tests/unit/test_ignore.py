"""Tests for whalescan.ignore: gitignore semantics, rule-scoped sections, built-ins (spec §4)."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from whalescan.ignore import (
    BUILTIN_EXCLUDES,
    GlobSet,
    IgnoreMatcher,
    any_glob_match,
    compile_pattern,
    glob_match,
    normalize_relpath,
    parse_patterns,
    rule_glob_match,
)

GIT = shutil.which("git")


def m_of(text: str, **kw: object) -> IgnoreMatcher:
    return IgnoreMatcher.from_text(text, **kw)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- syntax

GITIGNORE = (
    "\n".join(
        [
            "# comment",
            "*.log",
            "!keep.log",
            "/build",
            "docs/**/*.md",
            "a/**/b",
            "abc/**",
            "!abc/keep",
            "foo/",
            "\\#hash",
            "\\!bang",
            "trail\\ ",  # escaped trailing space is kept
            "spaces   ",  # unescaped trailing spaces are trimmed
            "*.[ch]",
            "[!x]y.txt",
            "x[a-c]?z",
            "**/deep",
            "mid/**/end/",
        ]
    )
    + "\n"
)

CASES = [
    ("x.log", True),
    ("keep.log", False),
    ("sub/x.log", True),
    ("sub/keep.log", False),
    ("build", True),
    ("build/x", True),
    ("sub/build", False),
    ("docs/a.md", True),
    ("docs/x/y/a.md", True),
    ("docs/a.txt", False),
    ("other/docs/a.md", False),
    ("a/b", True),
    ("a/x/b", True),
    ("a/x/y/b", True),
    ("a/bb", False),
    ("abc", False),
    ("abc/keep", False),
    ("abc/other", True),
    ("abc/d/e", True),
    ("foo", False),  # dir-only pattern, queried as a file
    ("foo/x", True),
    ("q/foo/x", True),
    ("#hash", True),
    ("!bang", True),
    ("trail ", True),
    ("trail", False),
    ("spaces", True),
    ("spaces   ", False),
    ("m.c", True),
    ("m.h", True),
    ("m.d", False),
    ("ay.txt", True),
    ("xy.txt", False),
    ("xbqz", True),
    ("xdqz", False),
    ("deep", True),
    ("p/q/deep", True),
    ("mid/end/f", True),
    ("mid/1/2/end/f", True),
    ("mid/end", False),
]


@pytest.mark.parametrize(("path", "expected"), CASES)
def test_gitignore_semantics(path: str, expected: bool) -> None:
    assert m_of(GITIGNORE).is_ignored(path) is expected


def test_dir_only_pattern_matches_directories() -> None:
    m = m_of("foo/\n")
    assert m.is_ignored("foo", is_dir=True)
    assert not m.is_ignored("foo", is_dir=False)


def test_cannot_reinclude_under_excluded_directory() -> None:
    m = m_of("foo/\n!foo/x\nbar\n!bar/y\n")
    assert m.is_ignored("foo/x")
    assert m.is_ignored("bar/y")


def test_reinclude_works_when_parent_not_excluded() -> None:
    m = m_of("q/**\n!q/k\n")
    assert not m.is_ignored("q/k")
    assert m.is_ignored("q/z/k")
    assert not m.is_ignored("q", is_dir=True)  # trailing /** matches only inside


def test_last_match_wins() -> None:
    assert not m_of("*.py\n!*.py\n").is_ignored("a.py")
    assert m_of("!*.py\n*.py\n").is_ignored("a.py")


def test_check_parents_false_skips_ancestors() -> None:
    m = m_of("vendor/\n")
    assert m.is_ignored("vendor/x.py")
    assert not m.is_ignored("vendor/x.py", check_parents=False)


def test_crlf_and_bom_in_ignore_file() -> None:
    m = m_of("\ufeff*.tmp\r\n# c\r\n/out\r\n")
    assert m.is_ignored("a.tmp")
    assert m.is_ignored("out/x")


def test_compile_pattern_noops() -> None:
    for line in ["", "   ", "# comment", "/", "!", "!/", "//"]:
        assert compile_pattern(line) is None, line


def test_escaped_star_is_literal() -> None:
    m = m_of("a\\*b\n")
    assert m.is_ignored("a*b")
    assert not m.is_ignored("axb")


def test_escaped_question_and_bracket() -> None:
    m = m_of("q\\?\n\\[x]\n")
    assert m.is_ignored("q?")
    assert not m.is_ignored("qa")
    assert m.is_ignored("[x]")
    assert not m.is_ignored("x")


def test_unclosed_bracket_is_literal() -> None:
    m = m_of("a[b\n")
    assert m.is_ignored("a[b")
    assert not m.is_ignored("ab")


def test_reversed_range_matches_nothing() -> None:
    m = m_of("x[z-a]\n")
    assert not m.is_ignored("xb")
    assert not m.is_ignored("xz")


def test_posix_classes() -> None:
    m = m_of("f[[:digit:]]\ng[![:alpha:]]\nh[[:bogus:]]\n")
    assert m.is_ignored("f7")
    assert not m.is_ignored("fa")
    assert m.is_ignored("g1")
    assert not m.is_ignored("gb")
    assert not m.is_ignored("hx")


def test_stars_do_not_cross_slashes() -> None:
    m = m_of("a*z\n/src/*.py\n")
    assert m.is_ignored("abcz")
    assert m.is_ignored("x/abcz")  # basename pattern at any depth
    assert m.is_ignored("src/m.py")
    assert not m.is_ignored("src/sub/m.py")


def test_consecutive_stars_inside_component_act_as_one() -> None:
    m = m_of("a**z\n")
    assert m.is_ignored("abcz")
    assert not m.is_ignored("ab/cz")


def test_star_matches_dotfiles() -> None:
    assert m_of("*\n").is_ignored(".hidden")


def test_names_with_newlines() -> None:
    assert m_of("a*b\n").is_ignored("a\nb")


def test_many_star_component_uses_linear_matcher() -> None:
    m = m_of("*a*b*c*d*\n")
    assert m.is_ignored("xaybzcwdv")
    assert not m.is_ignored("abdc")


# git's slash-crossing "X**" (found by the differential test; see ignore._expand_crossing_stars)


@pytest.mark.parametrize(
    ("patterns", "path", "expected"),
    [
        ("a**/b", "ab", True),  # "**/" may match nothing
        ("a**/b", "a/b", True),
        ("a**/b", "ax/b", True),
        ("a**/b", "a/x/b", True),
        ("a**/b", "ax/y/b", True),
        ("a**/b", "axb", False),
        ("/a**/a", "aa", True),
        ("a/a**", "a/a/b", True),  # first wildcard: crosses slashes
        ("x\n!a?/a**", "ab/a/x", True),  # an earlier wildcard: plain "*", no re-include
        ("x\n!a/a**", "a/a/x", False),  # first wildcard: crosses, re-includes
        ("a\\**/b", "a*/b", True),  # escaped star is literal
        ("a\\**/b", "ax/b", False),
        ("a\na/a**\n!a", "a/a/b", True),
        ("a\na\n!a?/a**", "ab/a/a", True),
        ("x**y", "xz/y", False),  # not before "/" or the end: plain "*"
        ("**a/b", "ba/b", True),
    ],
)
def test_git_crossing_double_star(patterns: str, path: str, expected: bool) -> None:
    assert m_of(patterns + "\n").is_ignored(path) is expected


# --------------------------------------------------------------------------- hostile input


def test_no_catastrophic_backtracking_in_component() -> None:
    m = m_of("*a*a*a*a*a*a*a*a*b\n")
    name = "a" * 5000
    t = time.perf_counter()
    assert not m.is_ignored(name)
    assert time.perf_counter() - t < 1.0


def test_no_catastrophic_backtracking_across_components() -> None:
    m = m_of("**/a/**/a/**/a/**/a/**/a/**/b\n")
    path = "/".join(["a"] * 2000) + "/c"
    t = time.perf_counter()
    assert not m.is_ignored(path, check_parents=False)
    assert m.is_ignored("/".join(["a"] * 10) + "/b")
    assert time.perf_counter() - t < 1.0


def test_very_deep_path_no_recursion_error(tmp_path: Path) -> None:
    m = IgnoreMatcher(tmp_path)
    path = "/".join(["d"] * 3000) + "/f.py"
    assert not m.is_ignored(path)
    assert m.is_ignored("/".join(["d"] * 3000) + "/node_modules/x.js")


def test_huge_pattern_count_is_capped() -> None:
    diags: list[object] = []
    text = "\n".join(f"p{i}" for i in range(20_010))
    pats = parse_patterns(text, diagnostics=diags)  # type: ignore[arg-type]
    assert len(pats) == 20_000
    assert diags


def test_long_pattern_skipped() -> None:
    diags: list[object] = []
    pats = parse_patterns("x" * 5000 + "\nok\n", diagnostics=diags)  # type: ignore[arg-type]
    assert [p.source for p in pats] == ["ok"]
    assert diags


# --------------------------------------------------------------------------- built-ins & .git


@pytest.mark.parametrize(
    "path",
    [
        "node_modules/x/index.js",
        "a/node_modules/x.js",
        ".venv/lib/x.py",
        "venv/x",
        "pkg/__pycache__/m.pyc",
        ".tox/x",
        ".mypy_cache/x",
        ".ruff_cache/x",
        "infra/.terraform/x",
        ".terragrunt-cache/x",
        "dist/app.js",
        "build/out",
        "target/classes/x",
        ".idea/workspace.xml",
        "static/app.min.js.map",
    ],
)
def test_builtin_excludes(path: str) -> None:
    assert IgnoreMatcher(None, filename=None).is_ignored(path)


def test_builtin_excludes_listed() -> None:
    assert "node_modules/" in BUILTIN_EXCLUDES and "*.min.js.map" in BUILTIN_EXCLUDES


def test_builtin_excludes_negatable(tmp_path: Path) -> None:
    (tmp_path / ".whalescanignore").write_text("!node_modules/\n!dist/\n")
    m = IgnoreMatcher(tmp_path)
    assert not m.is_ignored("node_modules/x.js")
    assert not m.is_ignored("dist/app.js")
    assert m.is_ignored("build/x")


def test_builtin_off() -> None:
    assert not IgnoreMatcher(None, filename=None, builtin=False).is_ignored("node_modules/x")


def test_dot_git_always_excluded_and_not_negatable(tmp_path: Path) -> None:
    (tmp_path / ".whalescanignore").write_text("!.git/\n!.git\n!**\n")
    m = IgnoreMatcher(tmp_path)
    assert m.is_ignored(".git/config")
    assert m.is_ignored("sub/.git/HEAD")
    assert m.is_ignored(".git", is_dir=True)


# --------------------------------------------------------------------------- per-directory files


def test_nested_ignore_files(tmp_path: Path) -> None:
    (tmp_path / ".whalescanignore").write_text("*.gen\n/rootonly.txt\n")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / ".whalescanignore").write_text("!keep.gen\n/local.txt\nnested/\n")
    m = IgnoreMatcher(tmp_path)
    assert m.is_ignored("a.gen")
    assert m.is_ignored("sub/a.gen")
    assert not m.is_ignored("sub/keep.gen")  # deeper file overrides
    assert m.is_ignored("keep.gen")  # but only in its subtree
    assert m.is_ignored("rootonly.txt")
    assert not m.is_ignored("sub/rootonly.txt")
    assert m.is_ignored("sub/local.txt")  # anchored to sub/
    assert not m.is_ignored("local.txt")
    assert m.is_ignored("sub/x/nested/f")
    assert not m.is_ignored("nested/f")


def test_ignore_file_cannot_ignore_its_own_directory(tmp_path: Path) -> None:
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / ".whalescanignore").write_text("sub\n")
    m = IgnoreMatcher(tmp_path)
    assert not m.is_ignored("sub", is_dir=True)
    assert m.is_ignored("sub/sub/x")


def test_symlinked_ignore_file_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_text("*\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    os.symlink(outside, repo / ".whalescanignore")
    m = IgnoreMatcher(repo)
    assert not m.is_ignored("anything.py")


def test_oversized_ignore_file_skipped_with_diagnostic(tmp_path: Path) -> None:
    (tmp_path / ".whalescanignore").write_text("*\n" + "#" * 200)
    m = IgnoreMatcher(tmp_path, max_file_bytes=100)
    assert not m.is_ignored("x.py")
    assert [d.code for d in m.diagnostics] == ["ignore-file-too-large"]


def test_paths_outside_root_use_only_builtins_and_extra(tmp_path: Path) -> None:
    (tmp_path / ".whalescanignore").write_text("*.py\n")
    m = IgnoreMatcher(tmp_path, extra=["*.secret"])
    assert not m.is_ignored("/elsewhere/x.py")
    assert not m.is_ignored("../x.py")
    assert m.is_ignored("/elsewhere/node_modules/x.js")
    assert m.is_ignored("/elsewhere/a.secret")


def test_extra_patterns_have_highest_priority(tmp_path: Path) -> None:
    (tmp_path / ".whalescanignore").write_text("!*.md\n")
    m = IgnoreMatcher(tmp_path, extra=["docs/", "*.md"])
    assert m.is_ignored("README.md")
    assert m.is_ignored("docs/x.txt")
    m2 = IgnoreMatcher(tmp_path, extra=["*.md", "!README.md"])
    assert not m2.is_ignored("README.md")


# --------------------------------------------------------------------------- rule-scoped sections

SCOPED = """\
rules/
tests/fixtures/
#!rules WS-SEC-*
docs/examples/**/*.env
#!rules WS-AGT-*, WS-INJ-003
prompts/*.md
!prompts/strict.md
scoped-dir/
!scoped-dir/x.md
#!rules *
evals/
"""


def test_rule_sections_do_not_skip_file_for_all_rules() -> None:
    m = m_of(SCOPED)
    assert m.is_ignored("rules/x.yaml")
    assert m.is_ignored("evals/x")  # after "#!rules *": global again
    assert not m.is_ignored("docs/examples/a/b.env")
    assert not m.is_ignored("prompts/a.md")


def test_rule_sections_apply_to_listed_rules() -> None:
    m = m_of(SCOPED)
    assert m.is_ignored("docs/examples/a/b.env", rule_id="WS-SEC-AWS-001")
    assert not m.is_ignored("docs/examples/a/b.env", rule_id="WS-K8S-001")
    assert m.is_ignored("prompts/a.md", rule_id="WS-AGT-010")
    assert m.is_ignored("prompts/a.md", rule_id="WS-INJ-003")
    assert not m.is_ignored("prompts/a.md", rule_id="WS-INJ-004")
    assert not m.is_ignored("prompts/strict.md", rule_id="WS-AGT-010")
    assert m.is_ignored("rules/x.yaml", rule_id="WS-SEC-001")  # global patterns still apply
    # a directory excluded for a rule cannot re-include children for that rule either
    assert m.is_ignored("scoped-dir/x.md", rule_id="WS-AGT-001")
    assert not m.is_ignored("scoped-dir/x.md")


def test_ignored_rules_and_fast_path(tmp_path: Path) -> None:
    m = m_of(SCOPED)
    ids = ["WS-SEC-GEN-001", "WS-AGT-001", "WS-K8S-001", "WS-INJ-003"]
    assert m.ignored_rules("docs/examples/x.env", ids) == {"WS-SEC-GEN-001"}
    assert m.ignored_rules("prompts/p.md", ids) == {"WS-AGT-001", "WS-INJ-003"}
    assert m.ignored_rules("src/app.py", ids) == frozenset()
    plain = IgnoreMatcher(tmp_path)
    assert not plain.has_rule_sections("a/b.py")
    assert plain.ignored_rules("a/b.py", ids) == frozenset()


def test_rule_section_directive_parsing() -> None:
    pats = parse_patterns("#!rulesfoo\na\n#!rules\nb\n#!rules X-*,  ,Y\nc\n#!rules *,Z\nd\n")
    assert [(p.source, p.scope) for p in pats] == [("a", None), ("b", None), ("c", ("X-*", "Y")), ("d", None)]


def test_rule_sections_disabled_for_gitignore() -> None:
    pats = parse_patterns("#!rules X\na\n", rule_sections=False)
    assert pats[0].scope is None


def test_rule_sections_in_nested_file(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / ".whalescanignore").write_text("#!rules WS-SEC-*\n*.txt\n")
    m = IgnoreMatcher(tmp_path)
    assert m.has_rule_sections("pkg/a.txt")
    assert not m.has_rule_sections("other/a.txt")
    assert m.is_ignored("pkg/a.txt", rule_id="WS-SEC-001")
    assert not m.is_ignored("pkg/a.txt")


@pytest.mark.parametrize(
    ("pattern", "rid", "ok"),
    [
        ("WS-SEC-*", "WS-SEC-AWS-001", True),
        ("WS-SEC-*", "WS-SECX", False),
        ("*", "ANY", True),
        ("WS-K8S-00?", "WS-K8S-001", True),
        ("ws-k8s-001", "WS-K8S-001", False),
        ("WS-K8S-001", "WS-K8S-001", True),
    ],
)
def test_rule_glob_match(pattern: str, rid: str, ok: bool) -> None:
    assert rule_glob_match(pattern, rid) is ok


# --------------------------------------------------------------------------- globs


@pytest.mark.parametrize(
    ("glob", "path", "ok"),
    [
        ("tests/**", "tests/a/b.py", True),
        ("tests/**", "src/tests/a.py", False),
        ("**/test_*.py", "a/b/test_x.py", True),
        ("**/test_*.py", "test_x.py", True),
        ("**/.env.example", ".env.example", True),
        ("**/ingress*.y*ml", "k8s/ingress-public.yaml", True),
        ("**/ingress*.y*ml", "k8s/ingress.yml", True),
        ("**/site-packages/**", "venv/lib/site-packages/x/y.py", True),
        ("*.env", "deep/dir/prod.env", True),
        ("platform/manifests/**/*.yaml", "platform/manifests/a/b.yaml", True),
        ("platform/manifests/**/*.yaml", "platform/manifests/b.yaml", True),
        ("platform/manifests/**/*.yaml", "platform/b.yaml", False),
    ],
)
def test_glob_match(glob: str, path: str, ok: bool) -> None:
    assert glob_match(glob, path) is ok


def test_any_glob_match() -> None:
    assert any_glob_match(["vendor/**", "**/node_modules/**"], "a/node_modules/x.js")
    assert not any_glob_match(["vendor/**"], "src/x.js")
    assert not any_glob_match(["x"], "")


def test_globset_include_semantics() -> None:
    assert GlobSet([]).matches("anything") and not GlobSet([])
    g = GlobSet(["src/", "*.md"])
    assert g
    assert g.matches("src/a/b.py")
    assert g.matches("docs/x.md")
    assert not g.matches("lib/x.py")
    g2 = GlobSet(["*.py", "!test_*.py"])
    assert g2.matches("a/b.py")
    assert not g2.matches("a/test_b.py")
    assert GlobSet(["*"]).matches(".git/config")  # the include set never special-cases .git


@pytest.mark.skipif(os.sep != "/", reason="backslash is a separator on Windows")
def test_backslash_is_a_name_character_on_posix() -> None:
    # a root-level file literally named "tests\\fixtures\\payload.md" must not hide under tests/fixtures/
    m = m_of("tests/fixtures/\n")
    assert m.is_ignored("tests/fixtures/payload.md")
    assert not m.is_ignored("tests\\fixtures\\payload.md")
    assert m_of("a\\\\b\n").is_ignored("a\\b")  # escaped backslash in a pattern


def test_normalize_relpath() -> None:
    assert normalize_relpath("./a//b/./c/") == "a/b/c"
    assert normalize_relpath("/abs//x") == "/abs/x"
    assert normalize_relpath(".") == ""
    assert normalize_relpath("a/../b") == "b"
    assert normalize_relpath("a/../../x") == "../x"
    assert normalize_relpath("../../x") == "../../x"
    assert normalize_relpath("/../x") == "/x"


def test_dotdot_paths_never_load_ignore_files_outside_root(tmp_path: Path) -> None:
    (tmp_path / ".whalescanignore").write_text("*\n")  # above the root: must never be read
    root = tmp_path / "root"
    (root / "a").mkdir(parents=True)
    m = IgnoreMatcher(root)
    assert not m.is_ignored("a/../../x.py")
    assert not m.is_ignored("../x.py")


# --------------------------------------------------------------------------- properties


NAME = st.text(alphabet="abc._-", min_size=1, max_size=6).filter(lambda s: s not in (".", ".."))


@given(st.lists(NAME, min_size=1, max_size=5), NAME)
def test_literal_basename_matches_at_any_depth(dirs: list[str], name: str) -> None:
    m = m_of(name.replace("\\", "\\\\") + "\n")
    assert m.is_ignored("/".join([*dirs, name]), check_parents=False)
    assert m.is_ignored(name)


@given(st.lists(NAME, min_size=2, max_size=5))
def test_anchored_literal_matches_only_at_root(parts: list[str]) -> None:
    m = m_of("/" + "/".join(parts) + "\n")
    assert m.is_ignored("/".join(parts))
    assert not m.is_ignored("/".join(["zz", *parts]), check_parents=False)


@given(st.lists(NAME, min_size=1, max_size=6))
def test_negating_everything_is_never_ignored(parts: list[str]) -> None:
    m = m_of("*\n!*\n")
    assert not m.is_ignored("/".join(parts))


# --------------------------------------------------------------------------- differential vs git

SEG = st.sampled_from(["a", "b", "ab", "*", "?", "**", "a*", "*b", "[ab]", "[!a]", "a?", "*.b", "a**", ".a"])
PATTERN = st.builds(
    lambda neg, lead, segs, trail: (
        ("!" if neg else "") + ("/" if lead else "") + "/".join(segs) + ("/" if trail else "")
    ),
    st.booleans(),
    st.booleans(),
    st.lists(SEG, min_size=1, max_size=3),
    st.booleans(),
)
COMP = st.sampled_from(["a", "b", "ab", "a.b", ".a", "ba", "aa"])
PATH = st.lists(COMP, min_size=1, max_size=4).map("/".join)


@pytest.mark.skipif(GIT is None, reason="git not available")
@given(st.lists(PATTERN, min_size=1, max_size=5), st.lists(PATH, min_size=1, max_size=12, unique=True))
@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_matches_git_check_ignore(
    tmp_path_factory: pytest.TempPathFactory, patterns: list[str], paths: list[str]
) -> None:
    assert GIT is not None
    repo = tmp_path_factory.mktemp("gi")
    subprocess.run([GIT, "init", "-q", str(repo)], check=True, capture_output=True)
    text = "\n".join(patterns) + "\n"
    (repo / ".gitignore").write_text(text)
    proc = subprocess.run(
        [GIT, "-C", str(repo), "check-ignore", "--no-index", "-v", "-n", "--stdin"],
        input="\n".join(paths) + "\n",
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
    )
    assert proc.returncode in (0, 1), proc.stderr
    git_says: dict[str, bool] = {}
    for line in proc.stdout.splitlines():
        info, _, path = line.partition("\t")
        src = info.split(":", 2)[2] if info != "::" else ""
        git_says[path] = bool(src) and not src.startswith("!")
    m = IgnoreMatcher(repo, filename=".gitignore", builtin=False, rule_sections=False)
    for p in paths:
        assert m.is_ignored(p) == git_says[p], (text, p)
