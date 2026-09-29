"""Rule fixture conventions for `whalescan rules test` (spec §2.6).

Layout: `<fixtures root>/<RULE-ID>/pos*.*` must produce at least one hit and `neg*.*` none.

* **Annotations.** A comment `# expect: WS-INJ-003` (also `//`, `--`, `<!--`; several comma-separated IDs
  allowed) marks the line it sits on as an expected hit start line. When a fixture carries annotations, the
  set of hit start lines of the rule under test MUST equal its annotated lines.
* **Sidecar.** Comment-less formats (JSON) use `expect.json` next to the fixture:
  `{"pos.json": {"WS-AGT-MCP-010": [4]}}`. As an extension, an entry may also carry `"path"` to set the
  virtual path of a fixture that cannot hold a directive comment.
* **Virtual path.** A first-line directive `# whalescan-fixture: path=.github/workflows/pr.yml` sets the path
  the fixture is scanned as (glob-restricted rules need it); otherwise the fixture's file name is used.
* **Explicit fixtures.** A rule's `fixtures: {pos: [...], neg: [...]}` lists paths relative to the fixtures
  root instead of the automatic `<RULE-ID>/pos*` / `neg*` discovery.

This module only discovers fixtures and judges hit lines; running the scanner is the caller's job. Fixture
directories are attack samples: every path is confined to the fixtures root, reads are size-capped, and
symlinks that leave the root are refused.
"""

from __future__ import annotations

import fnmatch
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from .loader import UnreadableFile, read_regular_file, safe_relpath

Polarity = Literal["pos", "neg"]

SIDECAR: Final = "expect.json"
MAX_FIXTURE_BYTES: Final = 1024 * 1024
MAX_FIXTURES_PER_RULE: Final = 200
MAX_SIDECAR_BYTES: Final = 256 * 1024

EXPECT_RE: Final = re.compile(
    r"(?:#|//|--|<!--)[ \t]*expect:[ \t]*(?P<ids>WS-[A-Z0-9-]+(?:[ \t]*,[ \t]*WS-[A-Z0-9-]+)*)"
)
DIRECTIVE_RE: Final = re.compile(r"[ \t]*(?:#|//|--|<!--)[ \t]*whalescan-fixture:[ \t]*path=(?P<path>\S+)")
RULE_ID_RE: Final = re.compile(r"WS-[A-Z0-9-]+\Z")
_ID_SPLIT = re.compile(r"[ \t]*,[ \t]*")
_BOMS: Final = (
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\xef\xbb\xbf", "utf-8"),
    (b"\xfe\xff", "utf-16-be"),
    (b"\xff\xfe", "utf-16-le"),
)


class FixtureError(ValueError):
    """A fixture file or sidecar that cannot be used."""


@dataclass(frozen=True, slots=True)
class Fixture:
    rule_id: str  # the rule whose directory (or `fixtures:` spec) listed it
    polarity: Polarity
    path: str  # filesystem path
    name: str  # path relative to the fixtures root, for display
    virtual_path: str  # what the scanner should see as the file name
    data: bytes
    expect: Mapping[str, frozenset[int]] = field(default_factory=dict)  # rule id -> expected start lines

    @property
    def text(self) -> str:
        return decode(self.data)

    @property
    def annotated(self) -> bool:
        return bool(self.expect)

    def expected_lines(self, rule_id: str | None = None) -> frozenset[int] | None:
        """Expected hit start lines for `rule_id` (default: the owning rule), or None without annotations."""
        return self.expect.get(rule_id or self.rule_id)


@dataclass(frozen=True, slots=True)
class FixtureSet:
    rule_id: str
    directory: str
    pos: tuple[Fixture, ...] = ()
    neg: tuple[Fixture, ...] = ()
    problems: tuple[str, ...] = ()

    @property
    def all(self) -> tuple[Fixture, ...]:
        return self.pos + self.neg

    @property
    def complete(self) -> bool:
        """The (dev) semantic check of §7.3: at least one `pos*` and one `neg*` fixture."""
        return bool(self.pos) and bool(self.neg)


@dataclass(frozen=True, slots=True)
class FixtureResult:
    fixture: Fixture
    rule_id: str
    ok: bool
    message: str
    hit_lines: tuple[int, ...] = ()


# ------------------------------------------------------------------------------------------ text helpers


def decode(data: bytes) -> str:
    """Decode fixture bytes like the walker does for BOMs (§5.5); otherwise UTF-8 with replacement."""
    for bom, codec in _BOMS:
        if data.startswith(bom):
            return data[len(bom) :].decode(codec, errors="replace")
    return data.decode("utf-8", errors="replace")


def parse_expectations(text: str) -> dict[str, frozenset[int]]:
    """`# expect:` annotations: rule id -> 1-based lines carrying an annotation for it (only `\\n` breaks)."""
    found: dict[str, set[int]] = {}
    for lineno, line in enumerate(text.split("\n"), start=1):
        if "expect:" not in line:
            continue
        for m in EXPECT_RE.finditer(line):
            for rid in _ID_SPLIT.split(m.group("ids").strip()):
                found.setdefault(rid, set()).add(lineno)
    return {rid: frozenset(lines) for rid, lines in found.items()}


def parse_directive(text: str) -> str | None:
    """The virtual path from a first-line `whalescan-fixture: path=...` directive, or None.

    Raises `FixtureError` for a path that is absolute or climbs out with `..`.
    """
    first = text.split("\n", 1)[0].rstrip("\r")
    m = DIRECTIVE_RE.match(first)
    if m is None:
        return None
    path = m.group("path")
    if path.endswith("-->"):
        path = path[:-3]
    if not safe_relpath(path):
        raise FixtureError(f"fixture directive path {path!r} must be relative, without '..'")
    return path


def load_sidecar(directory: str, root: str) -> dict[str, dict[str, Any]]:
    """Parse `expect.json` in `directory`: file name -> {"expect": {rule: lines}, "path": virtual path}."""
    import json

    path = os.path.join(directory, SIDECAR)
    if not os.path.lexists(path):
        return {}
    data = _read_confined(path, root, MAX_SIDECAR_BYTES)
    try:
        doc = json.loads(decode(data))
    except (ValueError, RecursionError) as exc:
        raise FixtureError(f"{SIDECAR}: invalid JSON: {exc}") from None
    if not isinstance(doc, dict):
        raise FixtureError(f"{SIDECAR}: expected an object mapping fixture file names to expectations")
    out: dict[str, dict[str, Any]] = {}
    for name, entry in doc.items():
        if not isinstance(name, str) or not name or "/" in name or "\\" in name or name in (".", ".."):
            raise FixtureError(f"{SIDECAR}: bad fixture file name {name!r}")
        if not isinstance(entry, dict):
            raise FixtureError(f"{SIDECAR}: {name}: expected an object of rule IDs to line lists")
        expect: dict[str, frozenset[int]] = {}
        virtual: str | None = None
        for key, value in entry.items():
            if key == "path":
                if not isinstance(value, str) or not safe_relpath(value):
                    raise FixtureError(f"{SIDECAR}: {name}: `path` must be a relative path without '..'")
                virtual = value
                continue
            if not RULE_ID_RE.match(key):
                raise FixtureError(f"{SIDECAR}: {name}: {key!r} is not a rule ID")
            if not isinstance(value, list) or not all(
                isinstance(n, int) and not isinstance(n, bool) and n >= 1 for n in value
            ):
                raise FixtureError(f"{SIDECAR}: {name}: {key}: expected a list of line numbers >= 1")
            expect[key] = frozenset(value)
        out[name] = {"expect": expect, "path": virtual}
    return out


# ------------------------------------------------------------------------------------------ discovery


def fixture_dir(root: str | os.PathLike[str], rule_id: str) -> str:
    if not RULE_ID_RE.match(rule_id):
        raise FixtureError(f"not a rule ID: {rule_id!r}")
    return os.path.join(os.fspath(root), rule_id)


def discover(root: str | os.PathLike[str], rule_id: str, spec: Mapping[str, Any] | None = None) -> FixtureSet:
    """Fixtures for one rule: automatic `<root>/<ID>/{pos*,neg*}.*` discovery, or the rule's explicit spec."""
    base = os.fspath(root)
    directory = fixture_dir(base, rule_id)
    problems: list[str] = []
    if not os.path.isdir(base):
        return FixtureSet(rule_id, directory, problems=(f"fixtures directory not found: {base}",))
    real_root = os.path.realpath(base)
    candidates: list[tuple[Polarity, str]] = []
    if spec is not None and isinstance(spec.get("pos"), list) and isinstance(spec.get("neg"), list):
        for polarity in ("pos", "neg"):
            for rel in spec[polarity]:
                if not isinstance(rel, str) or not safe_relpath(rel):
                    problems.append(f"fixture path {rel!r} must be relative, without '..'")
                    continue
                candidates.append((polarity, os.path.join(base, *rel.split("/"))))
    elif os.path.isdir(directory):
        candidates = _auto_candidates(directory, problems)
    else:
        problems.append(f"no fixture directory {_display(base, directory)}")
    pos: list[Fixture] = []
    neg: list[Fixture] = []
    sidecars: dict[str, dict[str, dict[str, Any]]] = {}
    for polarity, path in candidates[:MAX_FIXTURES_PER_RULE]:
        name = _display(base, path)
        parent = os.path.dirname(path)
        try:
            if parent not in sidecars:
                sidecars[parent] = load_sidecar(parent, real_root)
            data = _read_confined(path, real_root, MAX_FIXTURE_BYTES)
            fixture = _make_fixture(rule_id, polarity, path, name=name, data=data, sidecar=sidecars[parent])
        except FixtureError as exc:
            problems.append(f"{name}: {exc}")
            continue
        except OSError as exc:
            problems.append(f"{name}: cannot read: {exc.strerror or exc}")
            continue
        if polarity == "neg" and fixture.expected_lines() is not None:
            problems.append(f"{name}: a neg fixture must not carry expect annotations for {rule_id}")
        (pos if polarity == "pos" else neg).append(fixture)
    if len(candidates) > MAX_FIXTURES_PER_RULE:
        problems.append(f"more than {MAX_FIXTURES_PER_RULE} fixtures; the rest were ignored")
    if not problems or pos or neg:
        if not pos:
            problems.append(f"no pos* fixture for {rule_id}")
        if not neg:
            problems.append(f"no neg* fixture for {rule_id}")
    return FixtureSet(rule_id, directory, tuple(pos), tuple(neg), tuple(dict.fromkeys(problems)))


def _auto_candidates(directory: str, problems: list[str]) -> list[tuple[Polarity, str]]:
    out: list[tuple[Polarity, str]] = []
    try:
        with os.scandir(directory) as it:
            names = sorted(e.name for e in it)
    except OSError as exc:
        problems.append(f"cannot list {directory}: {exc.strerror or exc}")
        return out
    for name in names:
        if name.startswith(".") or name == SIDECAR:
            continue
        for polarity in ("pos", "neg"):
            if fnmatch.fnmatchcase(name, f"{polarity}*.*"):
                out.append((polarity, os.path.join(directory, name)))
    return out


def _make_fixture(
    rule_id: str,
    polarity: Polarity,
    path: str,
    *,
    name: str,
    data: bytes,
    sidecar: Mapping[str, Mapping[str, Any]],
) -> Fixture:
    text = decode(data)
    expect = {rid: set(lines) for rid, lines in parse_expectations(text).items()}
    virtual = parse_directive(text)
    entry = sidecar.get(os.path.basename(path))
    if entry is not None:
        for rid, lines in entry["expect"].items():
            expect.setdefault(rid, set()).update(lines)
        if entry["path"] is not None:
            virtual = virtual or entry["path"]
    return Fixture(
        rule_id=rule_id,
        polarity=polarity,
        path=path,
        name=name,
        virtual_path=virtual or os.path.basename(path),
        data=data,
        expect={rid: frozenset(lines) for rid, lines in expect.items()},
    )


def _display(base: str, path: str) -> str:
    return os.path.relpath(path, base).replace(os.sep, "/")


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _read_confined(path: str, real_root: str, limit: int) -> bytes:
    """Read a regular file whose real path lies inside `real_root`, capped at `limit` bytes."""
    real = os.path.realpath(path)
    if not _within(real, real_root):
        raise FixtureError("path resolves outside the fixtures directory")
    try:
        return read_regular_file(real, limit)
    except UnreadableFile as exc:
        raise FixtureError(str(exc)) from None


def check_fixture_dir(
    root: str | os.PathLike[str], rule_id: str, spec: Mapping[str, Any] | None = None
) -> list[str]:
    """The (dev) §7.3 check: problems with a rule's fixtures, empty when it has >=1 pos and >=1 neg."""
    return list(discover(root, rule_id, spec).problems)


# ------------------------------------------------------------------------------------------ evaluation


def evaluate(fixture: Fixture, hit_lines: Iterable[int], rule_id: str | None = None) -> FixtureResult:
    """Judge the rule's hit start lines on one fixture (§2.6 steps 2 and 3)."""
    rid = rule_id or fixture.rule_id
    hits = list(hit_lines)
    lines = tuple(sorted(set(hits)))
    if fixture.polarity == "neg":
        if not hits:
            return FixtureResult(fixture, rid, True, "no hits", lines)
        return FixtureResult(
            fixture, rid, False, f"expected no hits, got {len(hits)} at line(s) {_fmt(lines)}", lines
        )
    expected = fixture.expected_lines(rid)
    if expected is None:
        if fixture.expect:
            others = ", ".join(sorted(fixture.expect))
            return FixtureResult(
                fixture, rid, False, f"fixture has expect annotations ({others}) but none for {rid}", lines
            )
        if hits:
            return FixtureResult(fixture, rid, True, f"{len(hits)} hit(s)", lines)
        return FixtureResult(fixture, rid, False, "expected at least one hit, got none", lines)
    if set(lines) == expected:
        return FixtureResult(fixture, rid, True, f"hits at the expected line(s) {_fmt(lines)}", lines)
    missing = tuple(sorted(expected - set(lines)))
    extra = tuple(sorted(set(lines) - expected))
    detail = []
    if missing:
        detail.append(f"missing {_fmt(missing)}")
    if extra:
        detail.append(f"unexpected {_fmt(extra)}")
    return FixtureResult(
        fixture,
        rid,
        False,
        f"hit lines {_fmt(lines) or 'none'} != expected {_fmt(tuple(sorted(expected)))} "
        f"({'; '.join(detail)})",
        lines,
    )


def _fmt(lines: tuple[int, ...]) -> str:
    return ", ".join(str(n) for n in lines)
