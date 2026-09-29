"""Tests for whalescan.walker (spec §5: enumeration, symlinks, caps, stdin, loading, diff)."""

from __future__ import annotations

import io
import os
import pickle
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Any

import pytest

from whalescan import walker as walker_mod
from whalescan.config import Config
from whalescan.errors import UsageError
from whalescan.model import Stats
from whalescan.walker import (
    Candidate,
    Walker,
    ctx_from_bytes,
    ctx_from_text,
    git_changed_files,
    git_diff_hunks,
    load,
    make_probe,
    read_files_from,
    walk,
)

GIT = shutil.which("git")
needs_git = pytest.mark.skipif(GIT is None, reason="git not available")


def cfg_for(root: Path, **scan: Any) -> Config:
    return Config.default(root).with_overrides({"scan": scan}) if scan else Config.default(root)


def touch(root: Path, rel: str, data: bytes | str = b"x\n") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode()
    p.write_bytes(data)
    return p


def paths(w: Walker, roots: list[str | os.PathLike[str]]) -> list[str]:
    return [c.path for c in w.walk(roots)]


@pytest.fixture
def git_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    home = tmp_path / "_home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_AUTHOR_NAME", "t")
    monkeypatch.setenv("GIT_AUTHOR_EMAIL", "t@example.invalid")
    monkeypatch.setenv("GIT_COMMITTER_NAME", "t")
    monkeypatch.setenv("GIT_COMMITTER_EMAIL", "t@example.invalid")


def git(repo: Path, *args: str) -> str:
    assert GIT is not None
    out = subprocess.run([GIT, "-C", str(repo), *args], check=True, capture_output=True, text=True)
    return out.stdout


# --------------------------------------------------------------------------- tree fixture


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    touch(root, "a.py")
    touch(root, "a.txt")
    touch(root, "a/b.py")
    touch(root, "a/c/d.py")
    touch(root, "b.md")
    touch(root, "node_modules/x/index.js")
    touch(root, "src/app.min.js.map")
    touch(root, "src/main.py")
    touch(root, "src/gen/out.py")
    touch(root, "tests/fixtures/evil.md")
    touch(root, "logs/debug.log")
    touch(root, ".git/config", "[core]\n")
    touch(root, ".gitignore", "*.log\n/src/gen/\n")
    touch(root, ".whalescanignore", "tests/fixtures/\n")
    return root


EXPECTED_FS = [
    ".gitignore",
    ".whalescanignore",
    "a/b.py",
    "a/c/d.py",
    "a.py",
    "a.txt",
    "b.md",
    "src/main.py",
]


def test_fs_walk_order_and_filters(tree: Path) -> None:
    w = Walker(cfg_for(tree, walker="fs"), root=tree)
    assert paths(w, [tree]) == EXPECTED_FS
    # node_modules (built-in), tests/fixtures (.whalescanignore); .gitignore'd ones are not counted
    assert w.stats.skipped["ignored"] == 3  # node_modules/, *.min.js.map, tests/fixtures/
    assert w.stats.files == len(EXPECTED_FS)
    assert not w.truncated and w.diagnostics == []


def test_fs_walk_without_gitignore(tree: Path) -> None:
    w = Walker(cfg_for(tree, walker="fs", respect_gitignore=False), root=tree)
    got = paths(w, [tree])
    assert "logs/debug.log" in got and "src/gen/out.py" in got
    assert "node_modules/x/index.js" not in got


def test_relative_root_and_output_paths(tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tree)
    w = Walker(cfg_for(tree, walker="fs"), root=tree)
    assert paths(w, ["a"]) == ["a/b.py", "a/c/d.py"]
    w2 = Walker(cfg_for(tree, walker="fs"), root=tree)
    assert paths(w2, ["."]) == EXPECTED_FS


def test_include_and_exclude(tree: Path) -> None:
    w = Walker(cfg_for(tree, walker="fs", include=["*.py"], exclude=["a/c/"]), root=tree)
    assert paths(w, [tree]) == ["a/b.py", "a.py", "src/main.py"]


def test_exclude_applies_to_explicit_files_but_include_does_not(tree: Path) -> None:
    cfg = cfg_for(tree, walker="fs", include=["*.py"], exclude=["b.md", "a/"])
    w = Walker(cfg, root=tree)
    assert paths(w, [tree / "b.md", tree / "a.txt", tree / "a" / "b.py"]) == ["a.txt"]


def test_dedupe_roots_and_overlap(tree: Path) -> None:
    w = Walker(cfg_for(tree, walker="fs"), root=tree)
    got = paths(w, [tree / "a", tree / "a", tree, tree / "a" / "b.py"])
    assert got == ["a/b.py", "a/c/d.py", *[p for p in EXPECTED_FS if not p.startswith("a/")]]


def test_missing_root_is_usage_error(tree: Path) -> None:
    w = Walker(cfg_for(tree), root=tree)
    with pytest.raises(UsageError, match="not found"):
        w.walk([tree / "nope"])  # raised eagerly, before iteration


def test_stdin_at_most_once(tree: Path) -> None:
    with pytest.raises(UsageError):
        Walker(cfg_for(tree), root=tree).walk(["-", "-"])


def test_candidates_are_picklable(tree: Path) -> None:
    c = next(iter(Walker(cfg_for(tree, walker="fs"), root=tree).walk([tree])))
    assert pickle.loads(pickle.dumps(c)) == c  # noqa: S301 - our own trusted bytes


def test_walk_convenience(tree: Path) -> None:
    assert [c.path for c in walk([tree], cfg_for(tree, walker="fs"), root=tree)] == EXPECTED_FS


# --------------------------------------------------------------------------- explicit paths


def test_explicit_gitignored_file_is_scanned(tree: Path) -> None:
    w = Walker(cfg_for(tree, walker="fs"), root=tree)
    got = list(w.walk([tree / "logs" / "debug.log"]))
    assert [c.path for c in got] == ["logs/debug.log"]
    assert got[0].explicit and got[0].abs_path == str(tree / "logs" / "debug.log")


def test_explicit_whalescanignored_file_is_skipped(tree: Path) -> None:
    w = Walker(cfg_for(tree), root=tree)
    assert paths(w, [tree / "tests" / "fixtures" / "evil.md"]) == []
    assert w.stats.skipped["ignored"] == 1
    w2 = Walker(cfg_for(tree), root=tree)
    assert paths(w2, [tree / "node_modules" / "x" / "index.js"]) == []


def test_explicit_ignored_directory_is_skipped(tree: Path) -> None:
    w = Walker(cfg_for(tree, walker="fs"), root=tree)
    assert paths(w, [tree / "tests" / "fixtures"]) == []
    assert paths(Walker(cfg_for(tree, walker="fs"), root=tree), [tree / ".git"]) == []


def test_explicit_path_outside_root_is_absolute(tree: Path, tmp_path: Path) -> None:
    other = touch(tmp_path / "elsewhere", "x.py")
    touch(tmp_path / "elsewhere", "node_modules/y.js")
    w = Walker(cfg_for(tree, walker="fs"), root=tree)
    got = paths(w, [other, tmp_path / "elsewhere"])
    assert got == [other.as_posix()]  # the dir walk dedupes x.py; node_modules is excluded


def test_directory_outside_root_uses_its_own_ignore_files(tree: Path, tmp_path: Path) -> None:
    ext = tmp_path / "ext"
    touch(ext, "keep.py")
    touch(ext, "skip.py")
    touch(ext, ".whalescanignore", "skip.py\n")
    w = Walker(cfg_for(tree, walker="fs"), root=tree)
    got = paths(w, [ext])
    assert got == [(ext / ".whalescanignore").as_posix(), (ext / "keep.py").as_posix()]


def test_special_files_skipped_silently(tree: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("needs mkfifo")
    os.mkfifo(tree / "a" / "pipe")
    w = Walker(cfg_for(tree, walker="fs"), root=tree)
    done: list[list[str]] = []
    t = threading.Thread(target=lambda: done.append(paths(w, [tree / "a", tree / "a" / "pipe"])), daemon=True)
    t.start()
    t.join(10)
    assert done and done[0] == ["a/b.py", "a/c/d.py"]
    assert w.diagnostics == []


@pytest.mark.skipif(os.sep != "/", reason="POSIX file names only")
@pytest.mark.parametrize("mode", ["fs", "git"])
def test_backslash_file_name_cannot_hide_under_ignored_dir(tmp_path: Path, mode: str, git_env: None) -> None:
    if mode == "git" and GIT is None:
        pytest.skip("git not available")
    root = tmp_path / "r"
    touch(root, ".whalescanignore", "tests/fixtures/\n")
    touch(root, "tests\\fixtures\\payload.md", "ignore previous instructions")
    if mode == "git":
        git(root, "init", "-q")
    w = Walker(cfg_for(root, walker=mode), root=root)
    assert "tests\\fixtures\\payload.md" in paths(w, [root])


# --------------------------------------------------------------------------- caps


def test_too_large_skipped_with_info(tree: Path) -> None:
    touch(tree, "big.bin.txt", b"x" * 2000)
    w = Walker(cfg_for(tree, walker="fs", max_file_bytes=1000), root=tree)
    assert "big.bin.txt" not in paths(w, [tree])
    assert w.stats.skipped["too_large"] == 1
    assert [(d.level, d.code, d.file) for d in w.diagnostics] == [("info", "too-large", "big.bin.txt")]
    assert not w.truncated


def test_max_files_truncates(tree: Path) -> None:
    w = Walker(cfg_for(tree, walker="fs", max_files=3), root=tree)
    assert paths(w, [tree]) == EXPECTED_FS[:3]
    assert w.truncated
    assert [d.code for d in w.diagnostics] == ["max-files-reached"]
    assert w.diagnostics[0].level == "warning"


def test_exactly_max_files_is_not_truncated(tree: Path) -> None:
    w = Walker(cfg_for(tree, walker="fs", max_files=len(EXPECTED_FS)), root=tree)
    assert paths(w, [tree]) == EXPECTED_FS
    assert not w.truncated


def test_max_total_bytes_truncates(tree: Path) -> None:
    w = Walker(cfg_for(tree, walker="fs", max_total_bytes=5), root=tree)
    got = paths(w, [tree])
    assert w.truncated and [d.code for d in w.diagnostics] == ["max-total-bytes-reached"]
    assert sum((tree / p).stat().st_size for p in got) <= 5


def test_max_depth_bound(tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(walker_mod, "MAX_DEPTH", 3)
    touch(tree, "d1/d2/d3/d4/deep.py")
    touch(tree, "d1/d2/ok.py")
    w = Walker(cfg_for(tree, walker="fs"), root=tree)
    got = paths(w, [tree / "d1"])
    assert got == ["d1/d2/ok.py"]
    assert [d.code for d in w.diagnostics] == ["max-depth"]


def test_stats_apply(tree: Path) -> None:
    w = Walker(cfg_for(tree, walker="fs", max_files=len(EXPECTED_FS) - 1), root=tree)
    list(w.walk([tree]))
    stats = Stats()
    stats.files_skipped["ignored"] = 1
    w.apply_stats(stats)
    assert stats.truncated and stats.files_skipped["ignored"] == 1 + 2  # node_modules/, *.min.js.map


# --------------------------------------------------------------------------- symlinks


@pytest.fixture
def links(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    touch(root, "real/a.py", "a")
    touch(root, "real/sub/b.py", "b")
    touch(tmp_path, "secret/credentials", "aws_secret_access_key = x")
    os.symlink(root / "real" / "a.py", root / "link_file.py")
    os.symlink(root / "real", root / "link_dir")
    os.symlink(tmp_path / "secret" / "credentials", root / "config")
    os.symlink(tmp_path / "secret", root / "escape_dir")
    os.symlink("..", root / "real" / "sub" / "loop")
    os.symlink(root / "missing", root / "dangling")
    return root


def test_symlinks_not_followed_by_default(links: Path) -> None:
    w = Walker(cfg_for(links, walker="fs"), root=links)
    assert paths(w, [links]) == ["real/a.py", "real/sub/b.py"]
    assert w.stats.skipped["symlink"] == 6
    escapes = sorted(d.file or "" for d in w.diagnostics if d.code == "symlink-escape")
    assert escapes == ["config", "escape_dir"]
    assert all("secret" not in d.message for d in w.diagnostics)  # target paths are not disclosed


def test_follow_symlinks_inside_roots(links: Path) -> None:
    w = Walker(cfg_for(links, walker="fs", follow_symlinks=True), root=links)
    got = list(w.walk([links]))
    by_path = {c.path: c for c in got}
    # real paths first; the file link duplicates real/a.py and the dir link real/ -> skipped
    assert [c.path for c in got] == ["real/a.py", "real/sub/b.py"]
    assert "config" not in by_path and not any(p.startswith("escape_dir") for p in by_path)
    assert sorted(d.file or "" for d in w.diagnostics if d.code == "symlink-escape") == [
        "config",
        "escape_dir",
    ]


def test_follow_symlinks_links_first_when_real_not_scanned(links: Path) -> None:
    # scan the link directory explicitly alongside a file link: they resolve inside the roots
    w = Walker(cfg_for(links, walker="fs", follow_symlinks=True), root=links)
    got = list(w.walk([links / "link_dir", links / "link_file.py", links / "real"]))
    assert [c.path for c in got][:3] == ["link_dir/a.py", "link_dir/sub/b.py", "link_file.py"]
    assert got[2].abs_path == str(links / "real" / "a.py")


def test_follow_never_escapes(links: Path) -> None:
    w = Walker(cfg_for(links, walker="fs", follow_symlinks=True), root=links)
    got = paths(w, [links / "config", links / "escape_dir", links / "real"])
    assert "config" not in got
    assert not any("credentials" in p for p in got)


def test_explicit_symlink_root_default_skipped(links: Path) -> None:
    w = Walker(cfg_for(links), root=links)
    assert paths(w, [links / "link_file.py"]) == []
    assert w.stats.skipped["symlink"] == 1


def test_explicit_symlink_root_does_not_whitelist_its_target(links: Path) -> None:
    # regression: a link named on the command line must not count as a root for itself
    w = Walker(cfg_for(links, follow_symlinks=True), root=links)
    assert paths(w, [links / "config"]) == []
    assert [d.code for d in w.diagnostics] == ["symlink-escape"]
    w2 = Walker(cfg_for(links, follow_symlinks=True), root=links)
    assert paths(w2, [links / "link_file.py"]) == []  # target is outside every *real* root
    w3 = Walker(cfg_for(links, follow_symlinks=True), root=links)
    # with the target's file as a real root, the explicit link is allowed (both were named)
    assert paths(w3, [links / "link_file.py", links / "real" / "a.py"]) == ["link_file.py", "real/a.py"]


def test_include_applies_to_files_under_followed_dir_links(tmp_path: Path) -> None:
    root = tmp_path / "r"
    touch(root, "hidden/x.py")
    touch(root, "hidden/y.txt")
    touch(root, ".whalescanignore", "hidden/\n")
    os.symlink(root / "hidden", root / "view")
    w = Walker(cfg_for(root, walker="fs", follow_symlinks=True, include=["*.py"]), root=root)
    got = list(w.walk([root]))
    assert [c.path for c in got] == ["view/x.py"]
    assert got[0].abs_path == str(root / "hidden" / "x.py")


def test_explicit_symlink_root_respects_whalescanignore(links: Path) -> None:
    touch(links, ".whalescanignore", "link_file.py\n")
    w = Walker(cfg_for(links, follow_symlinks=True), root=links)
    assert paths(w, [links / "link_file.py", links / "real"]) == ["real/a.py", "real/sub/b.py"]
    assert w.stats.skipped["ignored"] == 1


def test_too_large_counted_once_for_overlapping_roots(tree: Path) -> None:
    touch(tree, "a/big.txt", b"x" * 100)
    w = Walker(cfg_for(tree, walker="fs", max_file_bytes=50), root=tree)
    list(w.walk([tree / "a", tree]))
    assert w.stats.skipped["too_large"] == 1


def test_symlink_cycle_terminates(tmp_path: Path) -> None:
    root = tmp_path / "r"
    touch(root, "a/x.py")
    os.symlink(root / "a", root / "a" / "self")
    os.symlink(root, root / "a" / "up")
    w = Walker(cfg_for(root, walker="fs", follow_symlinks=True), root=root)
    assert paths(w, [root]) == ["a/x.py"]


# --------------------------------------------------------------------------- stdin


def test_stdin_candidate(tree: Path) -> None:
    w = Walker(cfg_for(tree), root=tree, stdin=io.BytesIO(b"print(1)\n"), stdin_filename="dags/etl.py")
    got = list(w.walk(["-"]))
    assert len(got) == 1
    c = got[0]
    assert (c.path, c.stdin, c.data, c.abs_path, c.size) == ("dags/etl.py", True, b"print(1)\n", None, 9)


def test_stdin_default_name_and_truncation(tree: Path) -> None:
    w = Walker(cfg_for(tree, max_stdin_bytes=4), root=tree, stdin=io.BytesIO(b"123456"))
    c = next(iter(w.walk(["-"])))
    assert c.path == "<stdin>" and c.data == b"1234"
    assert w.truncated and [d.code for d in w.diagnostics] == ["input-truncated"]


def test_stdin_filename_respects_whalescanignore(tree: Path) -> None:
    w = Walker(cfg_for(tree), root=tree, stdin=io.BytesIO(b"x"), stdin_filename="tests/fixtures/a.md")
    assert list(w.walk(["-"])) == []
    assert w.stats.skipped["ignored"] == 1


def test_stdin_with_paths(tree: Path) -> None:
    w = Walker(cfg_for(tree, walker="fs"), root=tree, stdin=io.BytesIO(b"x"))
    assert paths(w, [tree / "a", "-"]) == ["a/b.py", "a/c/d.py", "<stdin>"]


# --------------------------------------------------------------------------- rule-scoped sections


def test_candidates_carry_ignored_rules(tmp_path: Path) -> None:
    root = tmp_path / "r"
    touch(root, "docs/examples/prod.env", "A=1")
    touch(root, "src/a.py")
    touch(root, ".whalescanignore", "#!rules WS-SEC-*\ndocs/examples/**/*.env\n")
    w = Walker(cfg_for(root, walker="fs"), root=root, rule_ids=["WS-SEC-GEN-001", "WS-K8S-001"])
    got = {c.path: c.ignored_rules for c in w.walk([root])}
    assert got["docs/examples/prod.env"] == {"WS-SEC-GEN-001"}
    assert got["src/a.py"] == frozenset()
    assert w.matcher().is_ignored("docs/examples/prod.env", rule_id="WS-SEC-X")


# --------------------------------------------------------------------------- only (diff mode)


def test_only_restricts_to_listed_files(tree: Path) -> None:
    only = ["a/b.py", "src/main.py", "tests/fixtures/evil.md", "gone.py", "../etc/passwd", "b.md"]
    w = Walker(cfg_for(tree), root=tree, only=only)
    assert paths(w, [tree / "a", tree / "src", tree / "b.md", tree / "a.py"]) == [
        "a/b.py",
        "src/main.py",
        "b.md",
    ]
    w2 = Walker(cfg_for(tree), root=tree, only=only)
    assert paths(w2, [tree]) == ["a/b.py", "b.md", "src/main.py"]


# --------------------------------------------------------------------------- git mode


@pytest.fixture
def git_tree(tree: Path, git_env: None) -> Path:
    git(tree, "init", "-q")
    git(tree, "add", "a.py", "a/b.py", "src/main.py", ".gitignore")
    return tree


@needs_git
def test_git_mode_matches_fs_mode(git_tree: Path) -> None:
    wg = Walker(cfg_for(git_tree, walker="git"), root=git_tree)
    wf = Walker(cfg_for(git_tree, walker="fs"), root=git_tree)
    assert paths(wg, [git_tree]) == paths(wf, [git_tree]) == EXPECTED_FS
    assert wg.diagnostics == []


@needs_git
def test_git_mode_subdirectory_root(git_tree: Path) -> None:
    w = Walker(cfg_for(git_tree), root=git_tree)
    assert paths(w, [git_tree / "src"]) == ["src/main.py"]


@needs_git
def test_git_mode_deleted_tracked_file_and_submodule(git_tree: Path) -> None:
    (git_tree / "a.py").unlink()
    sub = git_tree / "vendor_repo"
    touch(sub, "f.py")
    git(sub, "init", "-q")
    git(sub, "add", "f.py")
    git(sub, "commit", "-q", "-m", "x")
    w = Walker(cfg_for(git_tree), root=git_tree)
    got = paths(w, [git_tree])
    assert "a.py" not in got
    assert not any(p.startswith("vendor_repo") for p in got)


@needs_git
def test_git_fsmonitor_is_never_executed(git_tree: Path, tmp_path: Path) -> None:
    marker = tmp_path / "pwned"
    hook = tmp_path / "fsmon.sh"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
    hook.chmod(0o755)
    git(git_tree, "config", "core.fsmonitor", str(hook))
    w = Walker(cfg_for(git_tree, walker="git"), root=git_tree)
    assert paths(w, [git_tree]) == EXPECTED_FS
    assert not marker.exists()


@needs_git
def test_git_missing_binary_falls_back(git_tree: Path) -> None:
    w = Walker(cfg_for(git_tree, walker="git"), root=git_tree, git="/nonexistent/git")
    assert paths(w, [git_tree]) == EXPECTED_FS
    assert [d.code for d in w.diagnostics] == ["git-ls-files-failed"]


def test_git_walker_outside_work_tree_falls_back(tree: Path) -> None:
    shutil.rmtree(tree / ".git")
    w = Walker(cfg_for(tree, walker="git"), root=tree)
    assert paths(w, [tree]) == EXPECTED_FS
    assert [d.code for d in w.diagnostics] == ["git-walker-unavailable"]


def test_auto_without_git_repo_uses_fs(tree: Path) -> None:
    shutil.rmtree(tree / ".git")
    w = Walker(cfg_for(tree), root=tree, git="/nonexistent/git")
    assert paths(w, [tree]) == EXPECTED_FS
    assert w.diagnostics == []


@needs_git
def test_git_changed_files_and_hunks(tmp_path: Path, git_env: None) -> None:
    repo = tmp_path / "g"
    touch(repo, "keep.py", "a\nb\nc\n")
    touch(repo, "mod.py", "1\n2\n3\n4\n")
    touch(repo, "gone.py", "x\n")
    touch(repo, "sp ace/é.py", "x\n")
    git(repo, "init", "-q")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "base")
    touch(repo, "mod.py", "1\nTWO\n3\n4\nfive\nsix\n")
    (repo / "gone.py").unlink()
    touch(repo, "new.py", "n\n")
    touch(repo, "sp ace/é.py", "y\n")
    git(repo, "add", "-A")
    assert git_changed_files(repo, staged=True) == ["mod.py", "new.py", "sp ace/é.py"]
    assert git_changed_files(repo, "HEAD") == ["mod.py", "new.py", "sp ace/é.py"]
    hunks = git_diff_hunks(repo, "HEAD")
    assert hunks["mod.py"] == [(2, 2), (5, 6)]
    assert hunks["new.py"] == [(1, 1)]
    assert hunks["sp ace/é.py"] == [(1, 1)]
    assert "gone.py" not in hunks
    # --relative: paths are relative to the given root
    assert git_changed_files(repo / "sp ace", "HEAD") == ["é.py"]


@needs_git
def test_git_diff_errors(tmp_path: Path, git_env: None) -> None:
    with pytest.raises(UsageError, match="invalid git revision"):
        git_changed_files(tmp_path, "--output=/tmp/x")
    with pytest.raises(UsageError):
        git_changed_files(tmp_path)
    with pytest.raises(UsageError, match="git diff failed"):
        git_changed_files(tmp_path, "HEAD")  # not a repository
    with pytest.raises(UsageError):
        git_diff_hunks(tmp_path)


def test_c_unquote() -> None:
    q = walker_mod._c_unquote
    assert q('"b/sp\\303\\251cial\\tx\\"y\\\\"') == 'b/spécial\tx"y\\'
    assert q("b/plain") == "b/plain"


def test_parse_hunk_header() -> None:
    p = walker_mod._parse_hunk_header
    assert p(b"@@ -1,2 +3,4 @@ def f():") == (3, 4)
    assert p(b"@@ -1 +7 @@") == (7, 1)
    assert p(b"@@ -5,2 +4,0 @@") == (4, 0)
    assert p(b"@@ garbage") is None


# --------------------------------------------------------------------------- files-from


def test_read_files_from(tmp_path: Path) -> None:
    f = tmp_path / "list"
    f.write_bytes(b"a.py\r\nb c.py\n\nsub/d.py\n")
    assert read_files_from(f) == ["a.py", "b c.py", "sub/d.py"]
    f.write_bytes(b"x\ny.py\0z.py\0")
    assert read_files_from(f) == ["x\ny.py", "z.py"]
    assert read_files_from(io.BytesIO(b"one\ntwo")) == ["one", "two"]
    with pytest.raises(UsageError):
        read_files_from(tmp_path / "missing")
    with pytest.raises(UsageError, match="larger"):
        read_files_from(io.BytesIO(b"x" * 20), max_bytes=10)


# --------------------------------------------------------------------------- loading


def test_load_text_file(tree: Path) -> None:
    touch(tree, "deploy/app.yaml", "apiVersion: v1\nkind: Pod\n")
    c = Candidate("deploy/app.yaml", str(tree / "deploy/app.yaml"), 25)
    res = load(c, cfg_for(tree))
    assert res.skip is None and res.ctx is not None
    ctx = res.ctx
    assert (ctx.path, ctx.lang, ctx.kind, ctx.encoding, ctx.encoding_fallback) == (
        "deploy/app.yaml", "yaml", "iac", "utf-8", False,
    )  # fmt: skip
    assert "k8s" in ctx.tags and ctx.size == 25 and ctx.abs_path == str(tree / "deploy/app.yaml")


def test_load_binary_and_fallback_and_bom(tree: Path) -> None:
    touch(tree, "img.png", b"\x89PNG....")
    touch(tree, "blob.dat", b"ab\x00cd")
    touch(tree, "legacy.txt", b"caf\xe9\n")
    touch(tree, "win.sql", b"\xff\xfe" + "SELECT 1;\r\n".encode("utf-16-le"))
    cfg = cfg_for(tree)

    def ld(rel: str) -> Any:
        return load(Candidate(rel, str(tree / rel), (tree / rel).stat().st_size), cfg)

    assert ld("img.png").skip == "binary"
    assert ld("blob.dat").skip == "binary"
    legacy = ld("legacy.txt")
    assert legacy.ctx.encoding_fallback and legacy.ctx.text == "café\n"
    assert [d.code for d in legacy.diagnostics] == ["decode-fallback-latin1"]
    win = ld("win.sql")
    assert win.ctx.text == "SELECT 1;\r\n" and win.ctx.encoding == "utf-16-le" and win.ctx.lang == "sql"


def test_load_skips_are_not_exceptions(tree: Path, tmp_path: Path) -> None:
    cfg = cfg_for(tree, max_file_bytes=10)
    big = touch(tree, "big.txt", b"x" * 50)
    r = load(Candidate("big.txt", str(big), 5), cfg)  # grew after enumeration
    assert r.skip == "too_large" and [d.code for d in r.diagnostics] == ["too-large"]
    link = tree / "l.txt"
    os.symlink(big, link)
    assert load(Candidate("l.txt", str(link), 1), cfg).skip == "symlink"
    r2 = load(Candidate("gone.txt", str(tree / "gone.txt"), 1), cfg)
    assert r2.skip == "unreadable" and [d.code for d in r2.diagnostics] == ["read-error"]
    assert load(Candidate("dir", str(tree / "a"), 1), cfg).skip in ("special", "unreadable")
    if hasattr(os, "mkfifo"):
        os.mkfifo(tree / "fifo")
        assert load(Candidate("fifo", str(tree / "fifo"), 0), cfg).skip == "special"


def test_load_stdin_candidate() -> None:
    c = Candidate("<stdin>", None, 3, stdin=True, data=b'{"mcpServers": {}}')
    res = load(c, Config.default())
    assert res.ctx is not None and res.ctx.kind == "agent-config" and res.ctx.abs_path is None


def test_ctx_helpers_and_probe(tree: Path) -> None:
    touch(tree, "charts/api/Chart.yaml", "name: api\n")
    probe = make_probe(str(tree))
    ctx = ctx_from_text("replicas: 1\n", "charts/api/values.yaml", cfg=cfg_for(tree), probe=probe)
    assert (ctx.lang, ctx.kind) == ("yaml", "iac") and "helm" in ctx.tags
    assert ctx.size == len(b"replicas: 1\n")
    res = ctx_from_bytes(b"x = 1\n", "m.py", source_label="file:m.py")
    assert res.ctx is not None and res.ctx.source_label == "file:m.py"
    values = touch(tree, "charts/api/values.yaml", "a: 1\n")
    loaded = load(Candidate("charts/api/values.yaml", str(values), 5), cfg_for(tree))
    assert loaded.ctx is not None and "helm" in loaded.ctx.tags


def test_classify_rules_from_config_used_by_load(tree: Path) -> None:
    cfg = Config.default(tree).with_overrides(
        {"classify.rules": [{"glob": "*.txt", "kind": "iac", "tags": ["x"]}]}
    )
    res = load(Candidate("a.txt", str(tree / "a.txt"), 2), cfg)
    assert res.ctx is not None and res.ctx.kind == "iac" and "x" in res.ctx.tags
