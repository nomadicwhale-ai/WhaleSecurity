"""File enumeration and loading (spec §5).

:class:`Walker` turns scan roots into :class:`Candidate` files:

* explicit files are scanned even if gitignored, but ``.whalescanignore`` (and ``scan.exclude``)
  still apply;
* directories are enumerated with ``git ls-files --cached --others --exclude-standard -z`` when
  ``walker="auto"``, the directory is inside a work tree, ``git`` is on PATH and
  ``respect_gitignore`` is true; otherwise with a deterministic ``os.scandir`` walk that applies
  ``.gitignore`` files itself;
* symlinks are never followed by default (``skipped.symlink``); with ``follow_symlinks`` a link is
  followed only when its real path lies inside one of the scan roots, directory cycles are cut by
  a ``(st_dev, st_ino)`` visited set, and links are processed after the real tree so real paths
  win. Links that resolve outside the roots always get a ``symlink-escape`` warning;
* only regular files are yielded (FIFOs, sockets and devices are skipped silently);
  ``max_file_bytes`` skips a file, ``max_files``/``max_total_bytes`` stop enumeration and mark
  the walk truncated.

Visit order is lexicographic by UTF-8 bytes per directory, depth first, identical in git and fs
mode. :func:`load` reads, sniffs, decodes and classifies a candidate into a
:class:`~whalescan.model.FileCtx`. :func:`git_changed_files`, :func:`git_diff_hunks` and
:func:`read_files_from` back ``--diff``/``--staged``/``--diff-lines``/``--files-from``.

Git is run with ``core.fsmonitor=false`` so that an untrusted repository's config cannot make
``git ls-files`` execute a program.
"""

from __future__ import annotations

import errno
import logging
import os
import stat
import sys
from collections import deque
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from typing import TYPE_CHECKING, BinaryIO, Literal

from . import textio
from .classify import classify
from .config import Config, find_git_root
from .errors import UsageError
from .ignore import GlobSet, IgnoreMatcher, normalize_relpath
from .model import Diagnostic, FileCtx, Stats

if TYPE_CHECKING:
    import subprocess

__all__ = [
    "STDIN",
    "STDIN_NAME",
    "Candidate",
    "Loaded",
    "WalkStats",
    "Walker",
    "ctx_from_bytes",
    "ctx_from_text",
    "git_changed_files",
    "git_diff_hunks",
    "load",
    "make_probe",
    "read_files_from",
    "walk",
]

log = logging.getLogger("whalescan.walker")

STDIN = "-"
STDIN_NAME = "<stdin>"
MAX_DEPTH = 512  # directory nesting bound (bind-mount loops, hostile trees)
GIT_TIMEOUT_S = 60.0
MAX_FILES_FROM_BYTES = 64 << 20
_SKIP_KEYS = ("binary", "too_large", "ignored", "symlink")
Level = Literal["error", "warning", "info"]


# =========================================================================== data


@dataclass(frozen=True, slots=True)
class Candidate:
    """A file selected for scanning. Picklable (sent to worker processes)."""

    path: str  # output path: root-relative POSIX, absolute, or virtual
    abs_path: str | None  # what to open (a link's resolved target); None for stdin
    size: int  # bytes, from lstat/stat (stdin: bytes read)
    explicit: bool = False  # named on the command line
    stdin: bool = False
    data: bytes | None = None  # stdin payload
    ignored_rules: frozenset[str] = frozenset()  # excluded by `#!rules` sections for this path


@dataclass(slots=True)
class WalkStats:
    files: int = 0
    bytes: int = 0
    skipped: dict[str, int] = field(default_factory=lambda: dict.fromkeys(_SKIP_KEYS, 0))
    truncated: bool = False

    def apply(self, stats: Stats) -> None:
        """Add skip counts and the truncation flag to a run's :class:`~whalescan.model.Stats`."""
        for k, v in self.skipped.items():
            stats.files_skipped[k] = stats.files_skipped.get(k, 0) + v
        stats.truncated = stats.truncated or self.truncated


@dataclass(slots=True)
class Loaded:
    """Result of :func:`load`: a :class:`FileCtx`, or ``skip`` with the reason."""

    ctx: FileCtx | None
    skip: str | None = None  # binary | too_large | symlink | special | unreadable
    diagnostics: list[Diagnostic] = field(default_factory=list)


# =========================================================================== helpers


def _sort_key(rel: str) -> bytes:
    """Depth-first lexicographic order by UTF-8 bytes (``/`` sorts before every other byte)."""
    return rel.replace("/", "\0").encode("utf-8", "surrogateescape")


def _join(prefix: str, rel: str) -> str:
    if not prefix:
        return rel
    if not rel:
        return prefix
    return prefix.rstrip("/") + "/" + rel


def _rel_or_none(path: str, base: str) -> str | None:
    """POSIX path of ``path`` relative to ``base`` (both absolute, normalized), or None."""
    if path == base:
        return ""
    b = base if base.endswith(os.sep) else base + os.sep
    if path.startswith(b):
        rel = path[len(b) :]
        return rel.replace(os.sep, "/") if os.sep != "/" else rel
    return None


def _posix(path: str) -> str:
    return path.replace(os.sep, "/") if os.sep != "/" else path


def _git_env() -> dict[str, str]:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env.pop("GIT_EXTERNAL_DIFF", None)
    return env


@lru_cache(maxsize=1)
def _which_git() -> str | None:
    import shutil

    return shutil.which("git")


def _run_git(git: str, cwd: str, args: Sequence[str], timeout: float) -> subprocess.CompletedProcess[bytes]:
    import subprocess

    cmd = [git, "-C", cwd, "-c", "core.fsmonitor=false", "-c", "core.quotePath=false", *args]
    return subprocess.run(
        cmd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        env=_git_env(),
        check=False,
    )


def _first_line(b: bytes) -> str:
    return b.decode("utf-8", "replace").strip().splitlines()[0][:200] if b.strip() else ""


# =========================================================================== walker


class Walker:
    """Enumerates scan candidates for one run. Not thread-safe; create one per run.

    After (or during) iteration, :attr:`stats`, :attr:`diagnostics` and :attr:`truncated`
    describe what was skipped and why.
    """

    def __init__(
        self,
        cfg: Config,
        *,
        root: str | os.PathLike[str] | None = None,
        rule_ids: Iterable[str] = (),
        stdin: BinaryIO | None = None,
        stdin_filename: str = STDIN_NAME,
        only: Iterable[str] | None = None,
        git: str | None = None,
    ) -> None:
        """
        - ``root``: base for output paths and ``.whalescanignore`` (default ``cfg.root``, cwd).
        - ``rule_ids``: when given, each candidate's ``ignored_rules`` lists the IDs excluded
          for it by ``#!rules`` sections.
        - ``stdin``/``stdin_filename``: source and virtual path for the ``-`` root.
        - ``only``: restrict to these root-relative paths (``--diff``/``--staged``); directory
          roots then yield only listed files under them, without enumerating the tree.
        - ``git``: git executable (default: found on PATH).
        """
        self.cfg = cfg
        sc = cfg.scan
        self.root = os.path.abspath(os.fspath(root) if root is not None else (cfg.root or os.getcwd()))
        self.follow = sc.follow_symlinks
        self.respect_gitignore = sc.respect_gitignore
        self.mode = sc.walker
        self.max_file_bytes = sc.max_file_bytes
        self.max_files = sc.max_files
        self.max_total_bytes = sc.max_total_bytes
        self.max_stdin_bytes = sc.max_stdin_bytes
        self.include = GlobSet(sc.include)
        self.exclude = tuple(sc.exclude)
        self.rule_ids = tuple(rule_ids)
        self.stdin = stdin
        self.stdin_filename = stdin_filename or STDIN_NAME
        self.only = None if only is None else {normalize_relpath(p) for p in only if p}
        self._git_bin = git
        self.stats = WalkStats()
        self._diags: list[Diagnostic] = []
        self._matchers: dict[str, IgnoreMatcher] = {}
        self._gitignores: dict[str, IgnoreMatcher] = {}
        self._outside = IgnoreMatcher(None, filename=None, extra=self.exclude)
        self._seen: set[str] = set()
        self._stopped = False
        self._allowed: tuple[str, ...] = ()
        self._visited: set[tuple[int, int]] = set()
        self._file_inodes: set[tuple[int, int]] = set()
        self._deferred: deque[tuple[str, str, IgnoreMatcher, str]] = deque()

    # ------------------------------------------------------------------ public state

    @property
    def truncated(self) -> bool:
        return self.stats.truncated

    @property
    def diagnostics(self) -> list[Diagnostic]:
        out = list(self._diags)
        for m in (*self._matchers.values(), *self._gitignores.values(), self._outside):
            out.extend(m.diagnostics)
        return out

    def apply_stats(self, stats: Stats) -> None:
        self.stats.apply(stats)

    def matcher(self) -> IgnoreMatcher:
        """The ``.whalescanignore`` matcher for :attr:`root` (for per-rule checks by callers)."""
        return self._wsi(self.root)

    # ------------------------------------------------------------------ bookkeeping

    def _diag(self, level: Level, code: str, msg: str, file: str | None = None) -> None:
        self._diags.append(Diagnostic(level, code, msg, file=file))

    def _skip(self, reason: str) -> None:
        self.stats.skipped[reason] = self.stats.skipped.get(reason, 0) + 1

    def _truncate(self, code: str, msg: str) -> None:
        if not self._stopped:
            self._stopped = True
            self.stats.truncated = True
            self._diag("warning", code, msg)

    def _wsi(self, base: str) -> IgnoreMatcher:
        m = self._matchers.get(base)
        if m is None:
            m = IgnoreMatcher(base, extra=self.exclude)
            self._matchers[base] = m
        return m

    def _wsi_for(self, abs_path: str) -> tuple[IgnoreMatcher, str]:
        rel = _rel_or_none(abs_path, self.root)
        if rel is not None:
            return self._wsi(self.root), rel
        return self._outside, _posix(abs_path)

    def _display(self, abs_path: str) -> str:
        rel = _rel_or_none(abs_path, self.root)
        return rel if rel is not None else _posix(abs_path)

    def _inside_roots(self, real: str) -> bool:
        for r in self._allowed:
            if real == r or real.startswith(r if r.endswith(os.sep) else r + os.sep):
                return True
        return False

    def _git(self) -> str | None:
        return self._git_bin if self._git_bin is not None else _which_git()

    def _gitignore_pair(self, dir_abs: str) -> tuple[IgnoreMatcher, str] | None:
        if not self.respect_gitignore:
            return None
        groot = find_git_root(dir_abs) or dir_abs
        m = self._gitignores.get(groot)
        if m is None:
            pre: list[str] = []
            info = os.path.join(groot, ".git", "info", "exclude")
            try:
                pre = textio.read_file(info, 1 << 20).decode("utf-8", "surrogateescape").split("\n")
            except OSError:
                pre = []
            m = IgnoreMatcher(groot, filename=".gitignore", builtin=False, pre=pre, rule_sections=False)
            self._gitignores[groot] = m
        prefix = _rel_or_none(dir_abs, groot)
        return m, prefix or ""

    # ------------------------------------------------------------------ emit

    def _emit(
        self,
        disp: str,
        abs_path: str,
        size: int,
        *,
        explicit: bool = False,
        m: IgnoreMatcher | None = None,
        key: str | None = None,
    ) -> Candidate | None:
        if disp in self._seen or self._stopped:
            return None
        if size > self.max_file_bytes:
            self._seen.add(disp)
            self._skip("too_large")
            self._diag(
                "info", "too-large", f"skipped: {size} bytes > max_file_bytes {self.max_file_bytes}", disp
            )
            return None
        if self.stats.files >= self.max_files:
            self._truncate(
                "max-files-reached", f"stopped after max_files={self.max_files} files; run truncated"
            )
            return None
        if self.stats.bytes + size > self.max_total_bytes:
            self._truncate(
                "max-total-bytes-reached",
                f"stopped at max_total_bytes={self.max_total_bytes}; run truncated",
            )
            return None
        self._seen.add(disp)
        self.stats.files += 1
        self.stats.bytes += size
        ignored: frozenset[str] = frozenset()
        if self.rule_ids and m is not None and key is not None:
            ignored = m.ignored_rules(key, self.rule_ids)
        return Candidate(disp, abs_path, size, explicit=explicit, ignored_rules=ignored)

    # ------------------------------------------------------------------ entry points

    def walk(self, roots: Iterable[str | os.PathLike[str]] = (".",)) -> Iterator[Candidate]:
        """Validate ``roots`` now (``UsageError`` for missing paths) and return the iterator."""
        items = [os.fspath(r) for r in roots] or ["."]
        if items.count(STDIN) > 1:
            raise UsageError("'-' (stdin) may appear at most once")
        seen: set[str] = set()
        entries: list[tuple[str | None, os.stat_result | None]] = []
        for r in items:
            if r == STDIN:
                if STDIN not in seen:
                    seen.add(STDIN)
                    entries.append((None, None))
                continue
            a = os.path.abspath(r)
            if a in seen:
                continue
            seen.add(a)
            try:
                st = os.lstat(a)
            except FileNotFoundError:
                raise UsageError(f"path not found: {r}") from None
            except OSError as exc:
                raise UsageError(f"cannot access {r}: {exc.strerror or exc}") from None
            entries.append((a, st))
        # Only real (non-symlink) roots define where links may lead: an explicit link root must
        # never whitelist its own target (``config -> ~/.aws/credentials``).
        self._allowed = tuple(
            os.path.realpath(a)
            for a, st in entries
            if a is not None and st is not None and not stat.S_ISLNK(st.st_mode)
        )
        return self._walk(entries)

    def _walk(self, entries: list[tuple[str | None, os.stat_result | None]]) -> Iterator[Candidate]:
        for a, st in entries:
            if self._stopped:
                return
            if a is None or st is None:
                yield from self._stdin_candidate()
                continue
            mode = st.st_mode
            if stat.S_ISLNK(mode):
                m, key = self._wsi_for(a)
                if m.is_ignored(key):
                    self._skip("ignored")
                    continue
                yield from self._symlink(a, self._display(a), m, key, explicit=True)
            elif stat.S_ISREG(mode):
                yield from self._explicit_file(a, st)
            elif stat.S_ISDIR(mode):
                yield from self._walk_dir_root(a)
            else:
                log.debug("skipping non-regular file %s", a)
        while self._deferred and not self._stopped:
            link_abs, disp, m, key = self._deferred.popleft()
            yield from self._follow(link_abs, disp, m, key, explicit=False)

    # ------------------------------------------------------------------ stdin & explicit files

    def _stdin_candidate(self) -> Iterator[Candidate]:
        name = self.stdin_filename
        m: IgnoreMatcher | None = None
        key: str | None = None
        if name != STDIN_NAME:
            key = normalize_relpath(name)
            m = self._wsi(self.root) if not key.startswith(("/", "../")) else self._outside
            if m.is_ignored(key):
                self._skip("ignored")
                return
        stream = self.stdin if self.stdin is not None else sys.stdin.buffer
        data, truncated = textio.read_stream(stream, self.max_stdin_bytes)
        if truncated:
            self.stats.truncated = True
            self._diag(
                "warning",
                "input-truncated",
                f"stdin larger than max_stdin_bytes={self.max_stdin_bytes}; only the first "
                f"{self.max_stdin_bytes} bytes are scanned",
                name,
            )
        ignored: frozenset[str] = frozenset()
        if self.rule_ids and m is not None and key is not None:
            ignored = m.ignored_rules(key, self.rule_ids)
        self.stats.files += 1
        self.stats.bytes += len(data)
        yield Candidate(name, None, len(data), explicit=True, stdin=True, data=data, ignored_rules=ignored)

    def _explicit_file(self, a: str, st: os.stat_result) -> Iterator[Candidate]:
        disp = self._display(a)
        if self.only is not None and disp not in self.only:
            return
        m, key = self._wsi_for(a)
        if m.is_ignored(key):
            self._skip("ignored")
            return
        c = self._emit(disp, a, st.st_size, explicit=True, m=m, key=key)
        if c is not None:
            yield c

    # ------------------------------------------------------------------ directories

    def _walk_dir_root(self, a: str) -> Iterator[Candidate]:
        disp_prefix = self._display(a)
        rel = _rel_or_none(a, self.root)
        if rel is not None:
            m, mprefix = self._wsi(self.root), rel
        else:
            m, mprefix = self._wsi(a), ""
        if mprefix and m.is_ignored(mprefix, is_dir=True):
            self._skip("ignored")
            return
        if self.follow:
            try:
                st = os.stat(a)
                self._visited.add((st.st_dev, st.st_ino))
            except OSError:
                pass
        if self.only is not None:
            yield from self._walk_only(self.only, a, disp_prefix, m, mprefix)
            return
        rels = self._git_ls_files(a) if self._use_git(a) else None
        if rels is not None:
            for r in rels:
                if self._stopped:
                    return
                yield from self._found(os.path.join(a, r), _join(disp_prefix, r), m, _join(mprefix, r))
            return
        yield from self._fs_walk(a, disp_prefix, m, mprefix, self._gitignore_pair(a), via_link=False)

    def _walk_only(
        self, only: set[str], a: str, disp_prefix: str, m: IgnoreMatcher, mprefix: str
    ) -> Iterator[Candidate]:
        prefix = disp_prefix + "/" if disp_prefix else ""
        for p in sorted(only, key=_sort_key):
            if self._stopped:
                return
            if prefix and not p.startswith(prefix):
                continue
            r = p[len(prefix) :]
            if not r or r.startswith("/") or ".." in r.split("/"):
                continue
            yield from self._found(os.path.join(a, *r.split("/")), p, m, _join(mprefix, r))

    def _found(
        self,
        abs_path: str,
        disp: str,
        m: IgnoreMatcher,
        key: str,
        *,
        check_parents: bool = True,
        st: os.stat_result | None = None,
        via_link: bool = False,
    ) -> Iterator[Candidate]:
        """A path found by enumeration (not named explicitly)."""
        if m.is_ignored(key, False, check_parents=check_parents):
            self._skip("ignored")
            return
        if st is None:
            try:
                st = os.lstat(abs_path)
            except (FileNotFoundError, NotADirectoryError):
                return  # tracked in the index but deleted from the work tree
            except OSError as exc:
                self._diag("warning", "read-error", f"cannot stat: {exc.strerror or exc}", disp)
                return
        mode = st.st_mode
        if stat.S_ISLNK(mode):
            yield from self._symlink(abs_path, disp, m, key, explicit=False)
            return
        if stat.S_ISDIR(mode):
            log.info("skipping submodule or nested repository %s", disp)
            return
        if not stat.S_ISREG(mode):
            return
        if not self.include.matches(key):
            self._skip("ignored")
            return
        if self.follow:
            ino = (st.st_dev, st.st_ino)
            if via_link and ino in self._file_inodes:
                log.debug("skipping %s: same file already reached through its real path", disp)
                return
            self._file_inodes.add(ino)
        c = self._emit(disp, abs_path, st.st_size, m=m, key=key)
        if c is not None:
            yield c

    def _scandir(self, d: str, disp: str) -> list[os.DirEntry[str]] | None:
        try:
            with os.scandir(d) as it:
                entries = list(it)
        except OSError as exc:
            self._diag("warning", "read-error", f"cannot list directory: {exc.strerror or exc}", disp or ".")
            return None
        entries.sort(key=lambda e: e.name.encode("utf-8", "surrogateescape"))
        return entries

    def _fs_walk(
        self,
        top: str,
        disp_prefix: str,
        m: IgnoreMatcher,
        mprefix: str,
        g: tuple[IgnoreMatcher, str] | None,
        *,
        via_link: bool,
    ) -> Iterator[Candidate]:
        first = self._scandir(top, disp_prefix)
        if first is None:
            return
        stack: list[tuple[str, Iterator[os.DirEntry[str]], int]] = [("", iter(first), 0)]
        while stack:
            if self._stopped:
                return
            d_rel, it, depth = stack[-1]
            e = next(it, None)
            if e is None:
                stack.pop()
                continue
            name = e.name
            if name == ".git":
                continue
            rel = f"{d_rel}/{name}" if d_rel else name
            key = _join(mprefix, rel)
            disp = _join(disp_prefix, rel)
            try:
                if e.is_symlink():
                    if g is not None and g[0].is_ignored(_join(g[1], rel), False, check_parents=False):
                        continue
                    yield from self._found(e.path, disp, m, key, check_parents=False, via_link=via_link)
                    continue
                if e.is_dir(follow_symlinks=False):
                    if g is not None and g[0].is_ignored(_join(g[1], rel), True, check_parents=False):
                        continue
                    if m.is_ignored(key, True, check_parents=False):
                        self._skip("ignored")
                        continue
                    if depth + 1 >= MAX_DEPTH:
                        self._diag(
                            "warning",
                            "max-depth",
                            f"directory nesting deeper than {MAX_DEPTH}; not entered",
                            disp,
                        )
                        continue
                    if self.follow:
                        st = e.stat(follow_symlinks=False)
                        ino = (st.st_dev, st.st_ino)
                        if ino in self._visited:
                            continue
                        self._visited.add(ino)
                    sub = self._scandir(e.path, disp)
                    if sub is not None:
                        stack.append((rel, iter(sub), depth + 1))
                    continue
                if e.is_file(follow_symlinks=False):
                    if g is not None and g[0].is_ignored(_join(g[1], rel), False, check_parents=False):
                        continue
                    st = e.stat(follow_symlinks=False)
                    yield from self._found(
                        e.path, disp, m, key, check_parents=False, st=st, via_link=via_link
                    )
                # FIFOs, sockets and devices are never yielded
            except OSError as exc:
                self._diag("warning", "read-error", f"cannot stat: {exc.strerror or exc}", disp)

    # ------------------------------------------------------------------ symlinks

    def _symlink(
        self, link_abs: str, disp: str, m: IgnoreMatcher, key: str, *, explicit: bool
    ) -> Iterator[Candidate]:
        real = os.path.realpath(link_abs)
        if not self._inside_roots(real):
            self._skip("symlink")
            self._diag(
                "warning", "symlink-escape", "symlink resolves outside the scan roots; not followed", disp
            )
            return
        if not self.follow:
            self._skip("symlink")
            return
        if explicit:
            yield from self._follow(link_abs, disp, m, key, explicit=True)
        else:
            self._deferred.append((link_abs, disp, m, key))  # real paths first, links after

    def _follow(
        self, link_abs: str, disp: str, m: IgnoreMatcher, key: str, *, explicit: bool
    ) -> Iterator[Candidate]:
        real = os.path.realpath(link_abs)
        if not self._inside_roots(real):  # re-check: the tree may have changed meanwhile
            self._skip("symlink")
            return
        try:
            st = os.stat(real)
        except OSError:
            self._skip("symlink")  # dangling link or loop
            return
        if stat.S_ISREG(st.st_mode):
            ino = (st.st_dev, st.st_ino)
            if ino in self._file_inodes and not explicit:
                self._skip("symlink")
                return
            if explicit and self.only is not None and disp not in self.only:
                return
            if not explicit and not self.include.matches(key):
                self._skip("ignored")
                return
            self._file_inodes.add(ino)
            c = self._emit(disp, real, st.st_size, explicit=explicit, m=m, key=key)
            if c is not None:
                yield c
        elif stat.S_ISDIR(st.st_mode):
            ino = (st.st_dev, st.st_ino)
            if ino in self._visited:
                self._skip("symlink")
                return
            self._visited.add(ino)
            if m.is_ignored(key, True):
                self._skip("ignored")
                return
            yield from self._fs_walk(real, disp, m, key, self._gitignore_pair(link_abs), via_link=True)

    # ------------------------------------------------------------------ git

    def _use_git(self, a: str) -> bool:
        if self.mode == "fs":
            return False
        if self.mode == "auto" and not self.respect_gitignore:
            return False
        if find_git_root(a) is None or self._git() is None:
            if self.mode == "git":
                self._diag(
                    "warning",
                    "git-walker-unavailable",
                    "walker=git but git or a work tree is unavailable; using the filesystem walker",
                    _posix(a),
                )
            return False
        return True

    def _git_ls_files(self, a: str) -> list[str] | None:
        git = self._git()
        if git is None:
            return None
        args = ["ls-files", "--cached", "--others", "-z"]
        if self.respect_gitignore:
            args.append("--exclude-standard")
        import subprocess

        try:
            proc = _run_git(git, a, args, GIT_TIMEOUT_S)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            self._diag(
                "info",
                "git-ls-files-failed",
                f"git ls-files failed ({type(exc).__name__}); using the filesystem walker",
            )
            return None
        if proc.returncode != 0:
            self._diag(
                "info",
                "git-ls-files-failed",
                f"git ls-files exited {proc.returncode}: {_first_line(proc.stderr)}; "
                "using the filesystem walker",
            )
            return None
        out: dict[str, None] = {}
        for raw in proc.stdout.split(b"\0"):
            if not raw:
                continue
            p = os.fsdecode(raw)
            if p.endswith("/"):
                log.info("skipping nested repository %s", p)
                continue
            out[p] = None
        return sorted(out, key=_sort_key)


def walk(
    roots: Iterable[str | os.PathLike[str]],
    cfg: Config,
    **kwargs: object,
) -> Iterator[Candidate]:
    """Convenience wrapper: ``Walker(cfg, **kwargs).walk(roots)``.

    Use :class:`Walker` directly to read skip statistics and diagnostics afterwards.
    """
    return Walker(cfg, **kwargs).walk(roots)  # type: ignore[arg-type]


# =========================================================================== loading


@lru_cache(maxsize=4096)
def _isfile(path: str) -> bool:
    return os.path.isfile(path)


def make_probe(root: str) -> Callable[[str], bool]:
    """``probe(path)`` for :func:`~whalescan.classify.classify`: does ``root/path`` exist?"""
    base = os.path.abspath(root)

    def probe(path: str) -> bool:
        return _isfile(os.path.join(base, path))

    return probe


def ctx_from_text(
    text: str,
    path: str,
    *,
    cfg: Config | None = None,
    size: int | None = None,
    encoding: str = "utf-8",
    fallback: bool = False,
    abs_path: str | None = None,
    probe: Callable[[str], bool] | None = None,
    source_label: str | None = None,
) -> FileCtx:
    """Classify decoded text into a :class:`FileCtx` (``scan_text`` path)."""
    nbytes = size if size is not None else len(text.encode("utf-8", "surrogatepass"))
    rules = cfg.classify.rules if cfg is not None else ()
    lang, kind, tags = classify(path, text, rules, size=nbytes, probe=probe)
    return FileCtx(
        path=path,
        text=text,
        lang=lang,
        kind=kind,
        tags=tags,
        size=nbytes,
        encoding=encoding,
        encoding_fallback=fallback,
        abs_path=abs_path,
        source_label=source_label,
    )


def ctx_from_bytes(
    data: bytes,
    path: str,
    *,
    cfg: Config | None = None,
    abs_path: str | None = None,
    probe: Callable[[str], bool] | None = None,
    source_label: str | None = None,
) -> Loaded:
    """Binary sniff, decode (BOM/UTF-8/latin-1) and classify raw bytes."""
    is_binary, _ = textio.sniff(data[: textio.SNIFF_BYTES], path)
    if is_binary:
        return Loaded(None, "binary")
    dec = textio.decode(data, path)
    ctx = ctx_from_text(
        dec.text,
        path,
        cfg=cfg,
        size=len(data),
        encoding=dec.encoding,
        fallback=dec.fallback,
        abs_path=abs_path,
        probe=probe,
        source_label=source_label,
    )
    return Loaded(ctx, None, list(dec.diagnostics))


def load(
    cand: Candidate,
    cfg: Config | None = None,
    *,
    max_bytes: int | None = None,
    probe: Callable[[str], bool] | None = None,
) -> Loaded:
    """Read (``O_NOFOLLOW``, capped), sniff, decode and classify one candidate. Never raises
    for per-file problems: they become ``skip`` reasons and diagnostics (spec §17)."""
    limit = max_bytes if max_bytes is not None else (cfg.scan.max_file_bytes if cfg is not None else 1 << 20)
    if probe is None and not cand.stdin:
        root = cfg.root if cfg is not None and cfg.root else os.getcwd()
        probe = make_probe(root)
    if cand.stdin or cand.abs_path is None:
        data = cand.data or b""
    else:
        try:
            data = textio.read_file(cand.abs_path, limit)
        except textio.FileTooLargeError as exc:
            return Loaded(
                None,
                "too_large",
                [
                    Diagnostic(
                        "info",
                        "too-large",
                        f"skipped: {exc.size} bytes > max_file_bytes {limit}",
                        file=cand.path,
                    )
                ],
            )
        except textio.NotRegularFileError:
            return Loaded(None, "special")
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                return Loaded(None, "symlink")
            return Loaded(
                None,
                "unreadable",
                [
                    Diagnostic(
                        "warning",
                        "read-error",
                        f"cannot read: {exc.strerror or type(exc).__name__}",
                        file=cand.path,
                    )
                ],
            )
    return ctx_from_bytes(data, cand.path, cfg=cfg, abs_path=cand.abs_path, probe=probe)


# =========================================================================== diff / files-from


def read_files_from(
    source: str | os.PathLike[str] | BinaryIO, *, max_bytes: int = MAX_FILES_FROM_BYTES
) -> list[str]:
    """Paths from ``--files-from``: NUL-separated if the data contains ``\\0``, else one per line.

    ``source`` is a path, ``"-"`` for stdin, or a binary stream. Empty entries are dropped and a
    trailing ``\\r`` is removed in newline mode. Raises :class:`UsageError` if unreadable.
    """
    try:
        if isinstance(source, str | os.PathLike):
            spath = os.fspath(source)
            if spath == STDIN:
                data, truncated = textio.read_stream(sys.stdin.buffer, max_bytes)
            else:
                with open(spath, "rb") as fh:
                    data, truncated = textio.read_stream(fh, max_bytes)
        else:
            data, truncated = textio.read_stream(source, max_bytes)
    except OSError as exc:
        raise UsageError(f"cannot read --files-from list: {exc.strerror or exc}") from None
    if truncated:
        raise UsageError(f"--files-from list is larger than {max_bytes} bytes")
    text = data.decode("utf-8", "surrogateescape")
    if "\0" in text:
        items = text.split("\0")
    else:
        items = [s[:-1] if s.endswith("\r") else s for s in text.split("\n")]
    return [s for s in items if s]


def _check_ref(ref: str) -> None:
    if not ref or ref.startswith("-") or "\0" in ref or any(c.isspace() for c in ref):
        raise UsageError(f"invalid git revision: {ref!r}")


def _diff_args(ref: str | None, staged: bool) -> list[str]:
    args = ["--no-ext-diff", "--no-textconv", "--no-color", "--diff-filter=ACMR", "--relative"]
    if staged:
        args.append("--cached")
    if ref is not None:
        _check_ref(ref)
        args.append(ref)
    args.append("--")
    return args


def git_changed_files(
    root: str | os.PathLike[str],
    ref: str | None = None,
    *,
    staged: bool = False,
    git: str | None = None,
    timeout: float = GIT_TIMEOUT_S,
) -> list[str]:
    """Files added, copied, modified or renamed vs ``ref`` (``--diff``) or in the index
    (``--staged``), as POSIX paths relative to ``root``. Raises :class:`UsageError` on failure."""
    if ref is None and not staged:
        raise UsageError("--diff needs a revision (or use --staged)")
    gbin = git or _which_git()
    if gbin is None:
        raise UsageError("--diff/--staged need git on PATH")
    cwd = os.path.abspath(os.fspath(root))
    import subprocess

    try:
        proc = _run_git(gbin, cwd, ["diff", "--name-only", "-z", *_diff_args(ref, staged)], timeout)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise UsageError(f"git diff failed: {type(exc).__name__}: {exc}") from None
    if proc.returncode != 0:
        raise UsageError(f"git diff failed: {_first_line(proc.stderr) or f'exit {proc.returncode}'}")
    out = [os.fsdecode(p) for p in proc.stdout.split(b"\0") if p]
    return sorted(dict.fromkeys(out), key=_sort_key)


_C_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


def _c_unquote(s: str) -> str:
    """Undo git's C-style path quoting (``"a\\tb\\303\\251"``)."""
    if not (len(s) >= 2 and s[0] == '"' and s[-1] == '"'):
        return s
    body = s[1:-1]
    out = bytearray()
    i = 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt in _C_ESCAPES:
                out.append(_C_ESCAPES[nxt])
                i += 2
                continue
            if nxt in "01234567" and i + 3 < len(body) + 1:
                digits = body[i + 1 : i + 4]
                if len(digits) == 3 and all(d in "01234567" for d in digits):
                    out.append(int(digits, 8) & 0xFF)
                    i += 4
                    continue
        out.extend(c.encode("utf-8", "surrogateescape"))
        i += 1
    return out.decode("utf-8", "surrogateescape")


def git_diff_hunks(
    root: str | os.PathLike[str],
    ref: str | None = None,
    *,
    staged: bool = False,
    git: str | None = None,
    timeout: float = GIT_TIMEOUT_S,
) -> dict[str, list[tuple[int, int]]]:
    """Added/modified line ranges per file for ``--diff-lines``: ``{path: [(first, last), ...]}``.

    Ranges are 1-based and inclusive in the new version. Pure deletions contribute nothing.
    """
    if ref is None and not staged:
        raise UsageError("--diff-lines needs --diff REF or --staged")
    gbin = git or _which_git()
    if gbin is None:
        raise UsageError("--diff-lines needs git on PATH")
    cwd = os.path.abspath(os.fspath(root))
    args = ["diff", "-U0", "--src-prefix=a/", "--dst-prefix=b/", "--no-renames", *_diff_args(ref, staged)]
    import subprocess

    try:
        proc = _run_git(gbin, cwd, args, timeout)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise UsageError(f"git diff failed: {type(exc).__name__}: {exc}") from None
    if proc.returncode != 0:
        raise UsageError(f"git diff failed: {_first_line(proc.stderr) or f'exit {proc.returncode}'}")
    hunks: dict[str, list[tuple[int, int]]] = {}
    current: str | None = None
    for raw in proc.stdout.split(b"\n"):
        if raw.startswith(b"+++ "):
            name = _c_unquote(os.fsdecode(raw[4:]).rstrip("\t"))
            if name == "/dev/null":
                current = None
            else:
                current = name[2:] if name.startswith("b/") else name
                hunks.setdefault(current, [])
        elif raw.startswith(b"@@ ") and current is not None:
            parsed = _parse_hunk_header(raw)
            if parsed is not None:
                start, count = parsed
                if count > 0:
                    hunks[current].append((start, start + count - 1))
        elif raw.startswith(b"diff --git "):
            current = None
    return hunks


def _parse_hunk_header(raw: bytes) -> tuple[int, int] | None:
    # @@ -a[,b] +c[,d] @@ ...
    try:
        plus = raw.index(b" +", 2)
        end = raw.index(b" ", plus + 2)
    except ValueError:
        return None
    spec = raw[plus + 2 : end]
    start_s, _, count_s = spec.partition(b",")
    if not start_s.isdigit() or (count_s and not count_s.isdigit()):
        return None
    return int(start_s), int(count_s) if count_s else 1
