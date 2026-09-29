"""Normalized-rule cache (spec §15.2).

The expensive part of loading rules is YAML parsing, schema validation and lint. The cache stores the
normalized rule set, its applicability index and keyword tables as JSON (never pickle: a writable cache
directory must not become a code-execution vector).

* Key: `sha256(engine_version | schema_version | sorted (relpath, sha256(file)) of every rule source |
  rule-affecting config)`, plus the cache format and the Python minor version (lint results can differ).
* File: `<cache>/rules-<key[:16]>.json`, written atomically (tmp + `os.replace`), mode 0600 in a 0700
  directory owned by the current user. The newest `KEEP` files survive pruning; a hit refreshes the mtime.
* Anything unexpected (foreign owner, loose permissions, symlinks, corrupt or mismatched JSON) is a cache
  miss, never an error: the cache can only make loading faster.
"""

from __future__ import annotations

import contextlib
import os
import re
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Final

from .loader import (
    RULE_SCHEMA_VERSION,
    RuleIssue,
    RuleSet,
    SourceFile,
    UnreadableFile,
    YamlLoader,
    build,
    canonical_json,
    discover_sources,
    parse_source,
    read_regular_file,
    read_source,
)

CACHE_SCHEMA: Final = "whalescan/rules-cache@1"
CACHE_FORMAT: Final = "1"
KEEP: Final = 5
MAX_CACHE_BYTES: Final = 64 * 1024 * 1024
_ENTRY = re.compile(r"rules-[0-9a-f]{16}\.json\Z")
_TMP = re.compile(r"\.rules-.*\.tmp\Z")
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def default_cache_dir(env: Mapping[str, str] | None = None) -> str:
    """`$WHALESCAN_CACHE_DIR`, else `$XDG_CACHE_HOME/whalescan`, else `~/.cache/whalescan`."""
    env = os.environ if env is None else env
    explicit = env.get("WHALESCAN_CACHE_DIR", "").strip()
    if explicit:
        return os.path.expanduser(explicit)
    base = env.get("XDG_CACHE_HOME", "").strip()
    if not base or not os.path.isabs(base):  # XDG: relative values are invalid and ignored
        base = os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "whalescan")


def cache_disabled(env: Mapping[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    return env.get("WHALESCAN_NO_CACHE", "").strip().lower() in _TRUTHY


def compute_key(
    engine_version: str,
    sources: Sequence[tuple[str, bytes]],
    config: Mapping[str, Any] | None = None,
) -> str:
    """Hex sha256 cache key over the engine version, schema version, rule sources and rule config."""
    import hashlib

    files = sorted((label, hashlib.sha256(data).hexdigest()) for label, data in sources)
    parts = [
        f"whalescan-rules-cache/{CACHE_FORMAT}",
        engine_version,
        str(RULE_SCHEMA_VERSION),
        f"py{sys.version_info[0]}.{sys.version_info[1]}",
        *(f"{label}\x1e{digest}" for label, digest in files),
        canonical_json(dict(config or {})).decode("utf-8"),
    ]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8", "surrogatepass")).hexdigest()


class RuleCache:
    """A directory of JSON rule-set snapshots keyed by `compute_key`."""

    def __init__(self, directory: str | os.PathLike[str], *, keep: int = KEEP) -> None:
        self.directory = os.path.abspath(os.fspath(directory))
        self.keep = max(1, keep)

    def path_for(self, key: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{64}", key):
            raise ValueError("cache key must be a sha256 hex digest")
        return os.path.join(self.directory, f"rules-{key[:16]}.json")

    # -- directory safety ------------------------------------------------------------------------------------

    def _usable_dir(self, create: bool) -> bool:
        """True when the directory exists (or was created) as a real directory we own, tightened to 0700."""
        try:
            if create:
                os.makedirs(self.directory, mode=0o700, exist_ok=True)
            st = os.lstat(self.directory)
        except OSError:
            return False
        if not stat.S_ISDIR(st.st_mode) or not _owned(st):
            return False
        if st.st_mode & 0o077:
            try:
                os.chmod(self.directory, 0o700)
            except OSError:
                return False
        return True

    # -- read ----------------------------------------------------------------------------------------------

    def load(self, key: str) -> RuleSet | None:
        """The cached `RuleSet` for `key`, or None on a miss or any problem with the entry."""
        import json

        path = self.path_for(key)
        if not self._usable_dir(create=False):
            return None
        data = _read_private(path)
        if data is None:
            return None
        try:
            doc = json.loads(data.decode("utf-8"))
            if not isinstance(doc, dict) or doc.get("schema") != CACHE_SCHEMA or doc.get("key") != key:
                raise ValueError("cache entry does not match its key")
            ruleset = RuleSet.from_dict(_expect_dict(doc.get("ruleset")))
        except (ValueError, TypeError, KeyError, RecursionError, UnicodeDecodeError):
            _unlink_quietly(path)
            return None
        with contextlib.suppress(OSError):
            os.utime(path)  # keep frequently used entries among the newest
        return ruleset

    # -- write ---------------------------------------------------------------------------------------------

    def store(self, key: str, ruleset: RuleSet) -> str | None:
        """Write `ruleset` atomically; returns the path, or None when the cache directory is unusable."""
        import json
        import tempfile

        path = self.path_for(key)
        if not self._usable_dir(create=True):
            return None
        payload = json.dumps(
            {"schema": CACHE_SCHEMA, "key": key, "ruleset": ruleset.to_dict()},
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        try:
            fd, tmp = tempfile.mkstemp(prefix=".rules-", suffix=".tmp", dir=self.directory)
        except OSError:
            return None
        try:
            with os.fdopen(fd, "wb") as fh:
                if hasattr(os, "fchmod"):
                    os.fchmod(fh.fileno(), 0o600)
                fh.write(payload)
            os.replace(tmp, path)
        except OSError:
            _unlink_quietly(tmp)
            return None
        self.prune()
        return path

    def prune(self) -> None:
        """Keep the newest `keep` entries; drop leftover temp files older than an hour."""
        import time

        try:
            with os.scandir(self.directory) as it:
                entries = [e for e in it if e.is_file(follow_symlinks=False)]
        except OSError:
            return
        now = time.time()
        snapshots: list[tuple[float, str]] = []
        for e in entries:
            try:
                mtime = e.stat(follow_symlinks=False).st_mtime
            except OSError:
                continue
            if _ENTRY.match(e.name):
                snapshots.append((mtime, e.path))
            elif _TMP.match(e.name) and now - mtime > 3600:
                _unlink_quietly(e.path)
        snapshots.sort(reverse=True)
        for _, stale in snapshots[self.keep :]:
            _unlink_quietly(stale)

    # -- convenience -----------------------------------------------------------------------------------------

    def load_or_build(self, key: str, builder: Callable[[], RuleSet]) -> RuleSet:
        hit = self.load(key)
        if hit is not None:
            return hit
        ruleset = builder()
        self.store(key, ruleset)
        return ruleset


def _owned(st: os.stat_result) -> bool:
    getuid = getattr(os, "getuid", None)
    return getuid is None or st.st_uid == getuid()


def _read_private(path: str) -> bytes | None:
    """Read a cache file only if it is a regular, non-symlink file we own that nobody else can write."""

    def private(st: os.stat_result) -> str | None:
        return None if _owned(st) and not st.st_mode & 0o022 else "not private"

    try:
        return read_regular_file(path, MAX_CACHE_BYTES, check=private)
    except (OSError, UnreadableFile):
        return None


def _expect_dict(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError("expected an object")
    return value


def _unlink_quietly(path: str) -> None:
    with contextlib.suppress(OSError):
        os.unlink(path)


def load_rules(
    extra_dirs: Sequence[str | os.PathLike[str]] = (),
    files: Sequence[str | os.PathLike[str]] = (),
    *,
    builtin: bool = True,
    bundle_path: str | os.PathLike[str] | None = None,
    yaml_loader: YamlLoader | None = None,
    config: Mapping[str, Any] | None = None,
    cache_dir: str | os.PathLike[str] | None = None,
    use_cache: bool = True,
    engine_version: str | None = None,
    missing_dirs_ok: bool = False,
) -> RuleSet:
    """`loader.load` behind the cache: sources are read once, hashed for the key, and parsed only on a miss.

    `config` carries whatever rule-affecting configuration the caller wants in the key. `cache_dir` defaults
    to `default_cache_dir()`; `use_cache=False` (or `WHALESCAN_NO_CACHE=1`) bypasses the cache entirely.
    """
    if engine_version is None:
        from .. import __version__

        engine_version = __version__
    sources, issues = discover_sources(
        extra_dirs, files, builtin=builtin, bundle_path=bundle_path, missing_dirs_ok=missing_dirs_ok
    )
    blobs = [read_source(src) for src in sources]

    def build_now() -> RuleSet:
        return _build(sources, blobs, issues, yaml_loader)

    if not use_cache or cache_disabled():
        return build_now()
    key = compute_key(engine_version, [(s.key, b) for s, b in zip(sources, blobs, strict=True)], config)
    cache = RuleCache(cache_dir if cache_dir is not None else default_cache_dir())
    return cache.load_or_build(key, build_now)


def _build(
    sources: Sequence[SourceFile],
    blobs: Sequence[bytes],
    issues: Sequence[RuleIssue],
    yaml_loader: YamlLoader | None,
) -> RuleSet:
    raws = []
    for src, data in zip(sources, blobs, strict=True):
        raws += parse_source(src, data, yaml_loader=yaml_loader)
    return build(raws, extra_issues=issues)
