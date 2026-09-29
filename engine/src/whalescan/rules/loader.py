"""Rule loading (spec §7): pack files -> schema (§7.2) -> semantic checks (§7.3) -> lint (§8.2) -> `Rule`.

Sources, in precedence order for duplicate detection:

* the built-in `bundle.json` (release-time, pre-validated, already normalized; §15.2), or in a source checkout
  without a bundle the repository's `rules/` directory, validated like any YAML pack;
* extra rule directories (`--rules-dir`, `rules.extra_dirs`) and explicit pack files: YAML packs parsed with
  `whalescan.yamlite` (imported lazily) or JSON packs. These are untrusted input and get every check.

`load()` returns a `RuleSet` holding every loaded rule; `RuleSet.select()` applies pack selectors, rule ID
globs and `rules.enable/disable`. `RuleSet` also owns the (kind, lang) applicability index and the keyword
tables that the per-file pipeline uses (§8.1 steps 1-2).
"""

from __future__ import annotations

import fnmatch
import importlib
import os
import re
import stat
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from ..errors import RuleError
from ..model import KINDS, AppliesTo, Confidence, Diagnostic, Rule, Severity

BUNDLE_SCHEMA: Final = "whalescan/rules-bundle@1"
RULE_SCHEMA_VERSION: Final = 1  # == schema.SCHEMA_VERSION; kept here so the hook path never imports schema
BUNDLE_PATH: Final = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bundle.json")
PACK_ROOTS: Final = ("appsec", "secrets", "agentsec", "domain")
SOURCE_SETS: Final = frozenset({"web", "airflow", "cli", "llm", "net", "msg", "file", "env"})
PACK_SUFFIXES: Final = (".yaml", ".yml", ".json")

MAX_RULE_FILE_BYTES: Final = 2 * 1024 * 1024  # same cap as a yamlite parse (§5.3)
MAX_RULE_FILES: Final = 2_000
MAX_RULES: Final = 10_000
MAX_DIR_DEPTH: Final = 16
MAX_ERRORS_SHOWN: Final = 50

Origin = Literal["bundle", "builtin", "extra", "file"]
YamlLoader = Callable[[str], Sequence[Any]]

# Structured matchers and the file languages they can ever produce hits on (§7.3 matcher <-> applies_to).
STRUCTURED_LANGS: Final[Mapping[str, frozenset[str]]] = {
    "yaml_path": frozenset({"yaml", "json"}),
    "hcl": frozenset({"hcl", "json"}),  # json: *.tf.json
    "py_ast": frozenset({"python"}),
}
LEAF_KINDS: Final = frozenset(
    {"regex", "multiline", "unicode", "entropy", "yaml_path", "py_ast", "hcl", "builtin"}
)

_NS_PACKS: Final[Mapping[str, frozenset[str]]] = {
    "SEC": frozenset({"secrets"}),
    "AGT": frozenset({"agentsec"}),
    **{ns: frozenset({"appsec", "domain"}) for ns in ("INJ", "ACC", "CRY", "SSRF", "DES", "WEB")},
}
_PLACEHOLDER_SRC: Final = r"(?<!\$)\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}"
_GLOB_CHARS = frozenset("*?[")


# =============================================================================================== issues


@dataclass(frozen=True, slots=True)
class RuleIssue:
    """A problem found while loading rules. Errors fail the load (`RuleError`, exit 2); warnings do not."""

    level: Literal["error", "warning"]
    code: str  # schema | lint-R1..R7 | duplicate-id | shadows-bundled | namespace | ...
    message: str
    rule_id: str | None = None
    source: str | None = None  # pack file (display path)
    where: str | None = None  # location inside the rule, e.g. `match.all[0].regex.pattern`

    def __str__(self) -> str:
        parts = [p for p in (self.source, self.rule_id, self.where) if p]
        prefix = ": ".join(parts)
        return f"{prefix}: {self.message} [{self.code}]" if prefix else f"{self.message} [{self.code}]"

    def to_diagnostic(self) -> Diagnostic:
        where = f"{self.where}: " if self.where else ""
        return Diagnostic(
            self.level, f"rule-{self.code}", where + self.message, file=self.source, rule_id=self.rule_id
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "code": self.code,
            "message": self.message,
            "rule_id": self.rule_id,
            "source": self.source,
            "where": self.where,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> RuleIssue:
        level = d["level"]
        if level not in ("error", "warning"):
            raise ValueError(f"bad issue level {level!r}")
        opt = {k: _opt_str(d.get(k)) for k in ("rule_id", "source", "where")}
        return cls(level, str(d["code"]), str(d["message"]), **opt)


class RuleLoadError(RuleError):
    """`RuleError` carrying the individual issues (exit code 2)."""

    def __init__(self, issues: Sequence[RuleIssue], headline: str | None = None) -> None:
        self.issues: tuple[RuleIssue, ...] = tuple(issues)
        errors = [i for i in self.issues if i.level == "error"] or list(self.issues)
        head = headline or f"{len(errors)} rule error{'s' if len(errors) != 1 else ''}"
        lines = [f"  - {i}" for i in errors[:MAX_ERRORS_SHOWN]]
        if len(errors) > MAX_ERRORS_SHOWN:
            lines.append(f"  … and {len(errors) - MAX_ERRORS_SHOWN} more")
        super().__init__("\n".join([head + ":", *lines]))


# =============================================================================================== sources


@dataclass(frozen=True, slots=True)
class SourceFile:
    """One rule source file. `display` is shown in messages; `key` is its stable identity in cache keys."""

    origin: Origin
    path: str
    display: str
    key: str


@dataclass(frozen=True, slots=True)
class RawRule:
    """One rule object as read from a source, before checks. `normalized` marks bundle entries."""

    data: Any
    source: str
    origin: Origin
    index: int = 0
    normalized: bool = False


def discover_sources(
    extra_dirs: Sequence[str | os.PathLike[str]] = (),
    files: Sequence[str | os.PathLike[str]] = (),
    *,
    builtin: bool = True,
    bundle_path: str | os.PathLike[str] | None = None,
    missing_dirs_ok: bool = False,
) -> tuple[list[SourceFile], list[RuleIssue]]:
    """Enumerate rule source files: the bundle (or dev rules dir), then extra dirs, then explicit files."""
    sources: list[SourceFile] = []
    issues: list[RuleIssue] = []
    if builtin:
        bundle = os.fspath(bundle_path) if bundle_path is not None else BUNDLE_PATH
        if os.path.isfile(bundle):
            sources.append(
                SourceFile("bundle", os.path.realpath(bundle), "bundle.json", "bundle:bundle.json")
            )
        elif bundle_path is not None:
            raise RuleError(f"rule bundle not found: {bundle}")
        else:
            dev = dev_rules_dir()
            if dev is not None:
                found, problems = iter_pack_files(dev)
                issues += problems
                for path in found:
                    rel = os.path.relpath(path, dev).replace(os.sep, "/")
                    sources.append(SourceFile("builtin", path, f"rules/{rel}", f"builtin:{rel}"))
    for i, raw_dir in enumerate(extra_dirs):
        d = os.fspath(raw_dir)
        if not os.path.isdir(d):
            if missing_dirs_ok and not os.path.lexists(d):
                continue
            raise RuleError(f"rules directory not found: {d}")
        found, problems = iter_pack_files(d)
        issues += problems
        for path in found:
            rel = os.path.relpath(path, os.path.realpath(d)).replace(os.sep, "/")
            shown = f"{d.rstrip('/' + os.sep)}/{rel}".replace(os.sep, "/")
            sources.append(SourceFile("extra", path, shown, f"extra{i}:{os.path.abspath(d)}:{rel}"))
    for raw_file in files:
        f = os.fspath(raw_file)
        real = os.path.realpath(f)  # an explicitly named file may be a symlink; its target is read
        sources.append(SourceFile("file", real, f.replace(os.sep, "/"), f"file:{real}"))
    return sources, issues


def dev_rules_dir() -> str | None:
    """The repository `rules/` directory when running from a source checkout that has no `bundle.json`."""
    package = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))  # .../src/whalescan
    src = os.path.dirname(package)
    engine = os.path.dirname(src)
    if os.path.basename(src) != "src" or not os.path.isfile(os.path.join(engine, "pyproject.toml")):
        return None
    rules = os.path.join(os.path.dirname(engine), "rules")
    return rules if os.path.isdir(rules) else None


def iter_pack_files(root: str) -> tuple[list[str], list[RuleIssue]]:
    """Pack files (`*.yaml`, `*.yml`, `*.json`) under `root`, sorted, skipping hidden entries.

    Symlinks are followed only when their target stays inside `root`; directory cycles are cut by a
    (st_dev, st_ino) visited set; depth and file count are capped.
    """
    real_root = os.path.realpath(root)
    issues: list[RuleIssue] = []
    out: list[str] = []
    visited: set[tuple[int, int]] = set()
    stack: list[tuple[str, int]] = [(real_root, 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            st = os.stat(directory)
            if (st.st_dev, st.st_ino) in visited:
                continue
            visited.add((st.st_dev, st.st_ino))
            with os.scandir(directory) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            issues.append(
                RuleIssue("error", "io", f"cannot read directory: {exc.strerror or exc}", source=directory)
            )
            continue
        for entry in entries:
            if entry.name.startswith("."):
                continue
            path = entry.path
            try:
                if entry.is_symlink():
                    target = os.path.realpath(path)
                    if not _within(target, real_root):
                        issues.append(
                            RuleIssue(
                                "warning",
                                "symlink-escape",
                                "symlink points outside the rules directory; skipped",
                                source=_rel_display(root, path, real_root),
                            )
                        )
                        continue
                    path = target
                    is_dir, is_file = os.path.isdir(target), os.path.isfile(target)
                else:
                    is_dir, is_file = (
                        entry.is_dir(follow_symlinks=False),
                        entry.is_file(follow_symlinks=False),
                    )
            except OSError:
                continue
            if is_dir:
                if depth + 1 > MAX_DIR_DEPTH:
                    issues.append(
                        RuleIssue(
                            "warning",
                            "too-deep",
                            f"deeper than {MAX_DIR_DEPTH} levels; skipped",
                            source=_rel_display(root, path, real_root),
                        )
                    )
                else:
                    stack.append((path, depth + 1))
            elif is_file and entry.name.endswith(PACK_SUFFIXES):
                out.append(path)
                if len(out) > MAX_RULE_FILES:
                    raise RuleError(f"{root}: more than {MAX_RULE_FILES} rule files")
    return sorted(set(out)), issues


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _rel_display(root: str, path: str, real_root: str) -> str:
    base = real_root if _within(path, real_root) else os.path.dirname(path)
    return f"{root.rstrip('/')}/{os.path.relpath(path, base)}".replace(os.sep, "/")


class UnreadableFile(ValueError):
    """A path that is not a readable regular file within the size cap (message says why)."""


def read_regular_file(
    path: str, limit: int, *, check: Callable[[os.stat_result], str | None] | None = None
) -> bytes:
    """Read at most `limit` bytes of a regular file, safely.

    The final path component is never followed if it is a symlink (`O_NOFOLLOW`), and the open is
    non-blocking so a FIFO or device cannot hang the caller; the type is checked on the open descriptor
    before anything is read. `check` may veto the file from its `stat` result (ownership, permissions).
    Raises `OSError` for I/O errors and `UnreadableFile` for type, size or `check` failures.
    """
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise UnreadableFile("not a regular file")
        if check is not None and (reason := check(st)):
            raise UnreadableFile(reason)
        if st.st_size > limit:
            raise UnreadableFile(f"larger than {limit} bytes")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > limit:
        raise UnreadableFile(f"larger than {limit} bytes")
    return data


def read_source(src: SourceFile, limit: int = MAX_RULE_FILE_BYTES) -> bytes:
    """Read a rule source (see `read_regular_file`), capped at `limit` bytes."""
    if src.origin == "bundle":
        limit = max(limit, 64 * 1024 * 1024)  # the release bundle holds every built-in rule
    try:
        return read_regular_file(src.path, limit)
    except UnreadableFile as exc:
        raise RuleError(
            f"{src.display}: rule file is {exc}" if "larger" in str(exc) else f"{src.display}: {exc}"
        ) from None
    except OSError as exc:
        raise RuleError(f"{src.display}: cannot read rule file: {exc.strerror or exc}") from None


def parse_source(src: SourceFile, data: bytes, *, yaml_loader: YamlLoader | None = None) -> list[RawRule]:
    """Decode and parse one source into raw rule objects (no validation yet)."""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise RuleError(f"{src.display}: not valid UTF-8 (byte {exc.start})") from None
    if src.origin == "bundle":
        return _bundle_raws(src, _json_load(text, src.display))
    if src.path.endswith(".json"):
        docs: Sequence[Any] = [_json_load(text, src.display)]
    else:
        docs = (yaml_loader or default_yaml_loader)(text)
    rules: list[Any] = []
    for doc in docs:
        if doc is None:
            continue
        if not isinstance(doc, list):
            raise RuleError(
                f"{src.display}: a pack file must be a sequence of rule objects, got {_json_kind(doc)}"
            )
        rules.extend(doc)
    if len(rules) > MAX_RULES:
        raise RuleError(f"{src.display}: more than {MAX_RULES} rules")
    return [RawRule(r, src.display, src.origin, i) for i, r in enumerate(rules)]


def _bundle_raws(src: SourceFile, doc: Any) -> list[RawRule]:
    if (
        not isinstance(doc, dict)
        or doc.get("schema") != BUNDLE_SCHEMA
        or not isinstance(doc.get("rules"), list)
    ):
        raise RuleError(f"{src.display}: not a {BUNDLE_SCHEMA} document")
    rules = doc["rules"]
    raw_fixtures = doc.get("fixtures")
    fixtures: dict[str, Any] = raw_fixtures if isinstance(raw_fixtures, dict) else {}
    out: list[RawRule] = []
    for i, entry in enumerate(rules):
        data = entry
        if isinstance(entry, dict) and isinstance(entry.get("id"), str) and entry["id"] in fixtures:
            data = {**entry, "fixtures": fixtures[entry["id"]]}
        out.append(RawRule(data, src.display, "bundle", i, normalized=True))
    expected = doc.get("bundle_hash")
    if isinstance(expected, str) and _raw_bundle_hash(rules) != expected:
        raise RuleError(f"{src.display}: bundle_hash mismatch (file is corrupt or was edited by hand)")
    return out


def _raw_bundle_hash(entries: list[Any]) -> str:
    """`bundle_hash` computed straight from `rule_to_dict` entries, without building `Rule` objects."""
    import hashlib

    stripped = [{k: v for k, v in e.items() if k != "source_file"} for e in entries if isinstance(e, dict)]
    if len(stripped) != len(entries) or not all(isinstance(e.get("id"), str) for e in stripped):
        return ""
    stripped.sort(key=lambda e: str(e["id"]))
    return "sha256:" + hashlib.sha256(canonical_json(stripped)).hexdigest()


def default_yaml_loader(text: str) -> list[Any]:
    """Parse a YAML stream with `whalescan.yamlite` (lazy import) and convert documents to plain values."""
    try:
        yamlite = importlib.import_module("whalescan.yamlite")
    except ImportError as exc:
        raise RuleError(f"YAML rule packs need whalescan.yamlite, which is unavailable: {exc}") from None
    try:
        docs = yamlite.load_all(text)
    except RuleError:
        raise
    except Exception as exc:  # parser errors of any type become rule errors, never crashes
        raise RuleError(f"YAML parse error: {exc}") from None
    return [to_plain(d) for d in docs]


def to_plain(value: Any, depth: int = 0) -> Any:
    """Convert parser output (plain values or node objects) to JSON-shaped Python values."""
    if depth > 64:
        raise RuleError("rule nesting deeper than 64 levels")
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, Mapping):
        return {_plain_key(k): to_plain(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_plain(v, depth + 1) for v in value]
    for attr in ("to_python", "to_plain", "plain"):
        fn = getattr(value, attr, None)
        if callable(fn):
            return to_plain(fn(), depth + 1)
    if hasattr(value, "value"):
        return to_plain(value.value, depth + 1)
    return value  # left for the schema pre-check to reject


def _plain_key(key: Any) -> Any:
    if isinstance(key, str):
        return key
    raw = getattr(key, "raw", None)
    if isinstance(raw, str):
        return raw
    val = getattr(key, "value", None)
    return val if isinstance(val, str) else key


class _DuplicateKeyError(ValueError):
    pass


def _json_load(text: str, where: str) -> Any:
    import json

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in items:
            if k in out:
                raise _DuplicateKeyError(f"duplicate key {k!r}")
            out[k] = v
        return out

    def bad_constant(name: str) -> Any:
        raise ValueError(f"invalid JSON constant {name}")

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=bad_constant)
    except RecursionError:
        raise RuleError(f"{where}: JSON nested too deeply") from None
    except ValueError as exc:
        raise RuleError(f"{where}: invalid JSON: {exc}") from None


def _json_kind(value: Any) -> str:
    from .schema import json_type

    return json_type(value)


# =============================================================================================== checks


def expr_key(expr: Mapping[str, Any]) -> str:
    """The operator key of a (schema-valid) expression: all|any|not|<leaf>."""
    for k in expr:
        if k != "near_lines":
            return str(k)
    raise ValueError("empty matcher expression")


def iter_leaves(
    expr: Mapping[str, Any], where: str = "match", depth: int = 0
) -> Iterator[tuple[str, str, Any]]:
    """(location, leaf kind, leaf spec) for every leaf matcher, including those under `not`."""
    if depth > 64:
        return
    k = expr_key(expr)
    if k in ("all", "any"):
        for i, child in enumerate(expr[k]):
            yield from iter_leaves(child, f"{where}.{k}[{i}]", depth + 1)
    elif k == "not":
        yield from iter_leaves(expr["not"], f"{where}.not", depth + 1)
    else:
        yield f"{where}.{k}", k, expr[k]


def reporting_leaves(
    expr: Mapping[str, Any], where: str = "match", depth: int = 0
) -> list[tuple[str, str, Any]]:
    """Leaves whose hits become findings: every `any` child, the first positive `all` child (§8.1)."""
    if depth > 64:
        return []
    k = expr_key(expr)
    if k == "any":
        out: list[tuple[str, str, Any]] = []
        for i, child in enumerate(expr["any"]):
            out += reporting_leaves(child, f"{where}.any[{i}]", depth + 1)
        return out
    if k == "all":
        for i, child in enumerate(expr["all"]):
            if expr_key(child) != "not":
                return reporting_leaves(child, f"{where}.all[{i}]", depth + 1)
        return []
    if k == "not":
        return []
    return [(f"{where}.{k}", k, expr[k])]


def required_langs(expr: Mapping[str, Any], depth: int = 0) -> frozenset[str] | None:
    """Languages a hit is confined to, or None when a text matcher can hit anywhere."""
    if depth > 64:
        return None
    k = expr_key(expr)
    if k == "any":
        parts = [required_langs(c, depth + 1) for c in expr["any"]]
        if any(p is None for p in parts):
            return None
        return frozenset().union(*(p for p in parts if p is not None))
    if k == "all":
        constrained = [
            p for c in expr["all"] if expr_key(c) != "not" if (p := required_langs(c, depth + 1)) is not None
        ]
        if not constrained:
            return None
        return frozenset.intersection(*constrained)
    if k == "not":
        return None
    return STRUCTURED_LANGS.get(k)


def check_rule(raw: Any, *, source: str | None = None, lint: bool = True) -> list[RuleIssue]:
    """Schema, per-rule semantic checks (§7.3) and regex lint (§8.2) for one raw rule object."""
    from .schema import validate_rule

    rid = raw.get("id") if isinstance(raw, dict) and isinstance(raw.get("id"), str) else None
    schema_issues = validate_rule(raw)
    if schema_issues:
        return [RuleIssue("error", "schema", i.message, rid, source, i.path or None) for i in schema_issues]
    issues: list[RuleIssue] = []

    def add(
        code: str, message: str, where: str | None = None, level: Literal["error", "warning"] = "error"
    ) -> None:
        issues.append(RuleIssue(level, code, message, rid, source, where))

    _check_namespace(raw, add)
    _check_expression(raw["match"], "match", None, add, 0)
    _check_applies_to(raw, add)
    _check_groups(raw, add)
    _check_paths(raw, add)
    _check_misc(raw, add)
    if lint:
        from .lint import lint_rule

        for li in lint_rule(raw):
            add(f"lint-{li.code}", li.message, li.where or None, li.level)
    return issues


_Add = Callable[..., None]


def _check_namespace(raw: Mapping[str, Any], add: _Add) -> None:
    ns = raw["id"].split("-")[1]
    root = raw["pack"].split("/", 1)[0]
    allowed = _NS_PACKS.get(ns, frozenset({"domain"}))
    if root not in allowed:
        want = " or ".join(f"{p}/*" for p in sorted(allowed))
        add("namespace", f"WS-{ns} rules belong in {want}, not {raw['pack']}", "pack")


def _check_expression(expr: Mapping[str, Any], where: str, parent: str | None, add: _Add, depth: int) -> None:
    k = expr_key(expr)
    if k == "not" and parent != "all":
        add("expr", "`not` is only allowed directly under `all`", where)
    if k == "all":
        children = expr["all"]
        if all(expr_key(c) == "not" for c in children):
            add("expr", "`all` needs at least one positive (non-`not`) child", where)
        for i, child in enumerate(children):
            _check_expression(child, f"{where}.all[{i}]", "all", add, depth + 1)
    elif k == "any":
        for i, child in enumerate(expr["any"]):
            _check_expression(child, f"{where}.any[{i}]", "any", add, depth + 1)
    elif k == "not":
        _check_expression(expr["not"], f"{where}.not", "not", add, depth + 1)


def _as_set(value: Any) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return frozenset({value})
    return frozenset(str(v) for v in value)


def _check_applies_to(raw: Mapping[str, Any], add: _Add) -> None:
    langs = _as_set(raw["applies_to"].get("lang"))
    expr = raw["match"]
    for where, kind, _spec in iter_leaves(expr):
        if kind == "builtin" and raw["pack"] != "agentsec/mcp":
            add("applies-to", "`builtin` matchers are only allowed in pack agentsec/mcp", where)
        compat = STRUCTURED_LANGS.get(kind)
        if compat is not None and langs and not (langs & compat):
            add(
                "applies-to",
                f"`{kind}` needs lang {'/'.join(sorted(compat))}, but applies_to.lang is "
                f"{'/'.join(sorted(langs))}",
                where,
            )
    need = required_langs(expr)
    if need is None:
        return
    if not need:
        add(
            "applies-to",
            "the matchers under `all` need incompatible languages; the rule can never match",
            "match",
        )
    elif langs - need:
        add(
            "applies-to",
            f"applies_to.lang {'/'.join(sorted(langs - need))} can never match: the matcher only "
            f"runs on {'/'.join(sorted(need))}",
            "applies_to.lang",
        )


def _compile(pattern: str, letters: Sequence[str], context: Literal["regex", "multiline", "sequence"]) -> Any:
    import warnings

    from .lint import compile_flags

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return re.compile(pattern, compile_flags(letters, context))
    except (re.error, RecursionError, OverflowError, ValueError):
        return None  # reported by lint R1


def _leaf_patterns(kind: str, spec: Any) -> list[Any] | None:
    """Compiled patterns of a leaf (None for a pattern that does not compile); None for non-regex leaves."""
    if kind == "regex":
        if isinstance(spec, str):
            return [_compile(spec, (), "regex")]
        return [_compile(spec["pattern"], spec.get("flags", ()), "regex")]
    if kind == "multiline":
        flags = spec.get("flags", ())
        if "pattern" in spec:
            return [_compile(spec["pattern"], flags, "multiline")]
        return [_compile(p, flags, "sequence") for p in spec["sequence"]]
    return None


def _check_groups(raw: Mapping[str, Any], add: _Add) -> None:
    for where, kind, spec in iter_leaves(raw["match"]):
        if kind not in ("regex", "multiline") or not isinstance(spec, dict):
            continue
        compiled = _leaf_patterns(kind, spec) or []
        rx = compiled[0] if compiled else None
        if rx is None:
            continue
        secret = spec.get("secret_group")
        if secret is not None and secret not in rx.groupindex:
            add(
                "group",
                f"secret_group {secret!r} is not a named group of the pattern",
                f"{where}.secret_group",
            )
        report = spec.get("report_group")
        if isinstance(report, str) and report not in rx.groupindex:
            add(
                "group",
                f"report_group {report!r} is not a named group of the pattern",
                f"{where}.report_group",
            )
        elif isinstance(report, (int, float)) and not isinstance(report, bool) and int(report) > rx.groups:
            add(
                "group",
                f"report_group {int(report)} exceeds the pattern's {rx.groups} group(s)",
                f"{where}.report_group",
            )
    names = set(re.compile(_PLACEHOLDER_SRC).findall(raw["message"]))
    if not names:
        return
    for where, kind, spec in reporting_leaves(raw["match"]):
        patterns = _leaf_patterns(kind, spec)
        if patterns is None:
            add(
                "group",
                f"message placeholder(s) {_braces(names)} need named groups, but `{kind}` has no pattern",
                where,
            )
            continue
        if any(rx is None for rx in patterns):
            continue
        available: set[str] = set()
        for rx in patterns:
            available |= set(rx.groupindex)
        missing = names - available
        if missing:
            add(
                "group",
                f"message placeholder(s) {_braces(missing)} are not named groups of the pattern",
                where,
            )


def _braces(names: Iterable[str]) -> str:
    return ", ".join("{{" + n + "}}" for n in sorted(names))


# -- paths (§8.6, §8.8) and py_ast names (§8.7) ----------------------------------------------------------

_YP_STEP_SRC: Final = (
    r"""\.?(?:(?P<dstar>\*\*)|(?P<star>\*)|"(?P<quoted>(?:[^"\\]|\\.)*)"|\{(?P<alt>[^{}]+)\}"""
    r"""|(?P<ident>[^.\[\]{}"*\s]+))|\[(?P<index>-?[0-9]+|\*)\]"""
)
_YP_ALT_ITEM_SRC: Final = r"""[^.\[\]{}"*\s,]+\Z"""
_HCL_SEG = r'(?:\*|[A-Za-z0-9_][A-Za-z0-9_-]*|"[^"\\\n]*")'
_HCL_IDX = r"(?:\[(?:[0-9]+|\*)\])*"
_HCL_BLOCK_SRC: Final = rf"[A-Za-z_][A-Za-z0-9_-]*(?:\.{_HCL_SEG})*\Z"
_HCL_ATTR_SRC: Final = rf"{_HCL_SEG}{_HCL_IDX}(?:\.{_HCL_SEG}{_HCL_IDX})*\Z"
_PY_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_PY_SEG = rf"(?:\*\*|\*|\?|\{{{_PY_IDENT}(?:,{_PY_IDENT})*\}}|{_PY_IDENT})"
_PY_DOTTED_SRC: Final = rf"{_PY_SEG}(?:\.{_PY_SEG})*\Z"
_PY_NAME_SRC: Final = rf"{_PY_IDENT}\Z"


def yaml_path_error(path: str) -> str | None:
    """Why `path` does not parse under the §8.6 grammar, or None."""
    if len(path) > 512:
        return "path longer than 512 characters"
    pos = 2 if path.startswith("$.") else 0
    if pos >= len(path):
        return "empty path"
    first = True
    while pos < len(path):
        m = re.compile(_YP_STEP_SRC).match(path, pos)
        if m is None or m.end() == pos:
            return f"unexpected {path[pos : pos + 12]!r} at offset {pos}"
        token = m.group(0)
        if first and token.startswith((".", "[")):
            return "a path must start with a key, `*` or `**`"
        if not first and not token.startswith((".", "[")):
            return f"missing '.' before {token!r} at offset {pos}"
        alt = m.group("alt")
        if alt is not None and not all(re.compile(_YP_ALT_ITEM_SRC).match(item) for item in alt.split(",")):
            return f"bad alternation {{{alt}}}"
        first = False
        pos = m.end()
    return None


def _check_paths(raw: Mapping[str, Any], add: _Add) -> None:
    for where, kind, spec in iter_leaves(raw["match"]):
        if kind == "yaml_path":
            if "each" in spec and (err := yaml_path_error(spec["each"])):
                add("path", f"bad yaml_path `each`: {err}", f"{where}.each")
            for group in ("all", "any", "none"):
                for i, cond in enumerate(spec.get(group, ())):
                    if err := yaml_path_error(cond["path"]):
                        add("path", f"bad yaml path: {err}", f"{where}.{group}[{i}].path")
        elif kind == "hcl":
            if not re.compile(_HCL_BLOCK_SRC).match(spec["block"]):
                add("path", "bad hcl block path (type, then labels or `*`, dot-separated)", f"{where}.block")
            if "each" in spec and not re.compile(_HCL_BLOCK_SRC).match(spec["each"]):
                add("path", "bad hcl `each` path (dot-separated block types)", f"{where}.each")
            for group in ("all", "any", "none"):
                for i, cond in enumerate(spec.get(group, ())):
                    here = f"{where}.{group}[{i}]"
                    if "attr" in cond and not re.compile(_HCL_ATTR_SRC).match(cond["attr"]):
                        add("path", "bad hcl attribute path", f"{here}.attr")
                    rng = cond.get("range_includes")
                    if isinstance(rng, dict):
                        for end in ("lo", "hi"):
                            if not re.compile(_HCL_ATTR_SRC).match(rng[end]):
                                add(
                                    "path",
                                    f"bad hcl attribute path in range_includes.{end}",
                                    f"{here}.range_includes",
                                )
        elif kind == "py_ast" and "call" in spec:
            _check_py_call(spec["call"], f"{where}.call", add)


def _check_py_call(call: Mapping[str, Any], where: str, add: _Add) -> None:
    for key in ("callee", "require_import"):
        value = call.get(key)
        for item in [value] if isinstance(value, str) else (value or ()):
            if not re.compile(_PY_DOTTED_SRC).match(item):
                add("path", f"bad dotted pattern {item!r} (segments: name, *, **, {{a,b}})", f"{where}.{key}")
    for item in call.get("sanitizers", ()):
        if not re.compile(_PY_DOTTED_SRC).match(item):
            add("path", f"bad sanitizer name {item!r}", f"{where}.sanitizers")
    for item in call.get("kwarg_absent", ()):
        if not re.compile(_PY_NAME_SRC).match(item):
            add("path", f"bad keyword argument name {item!r}", f"{where}.kwarg_absent")
    for item in call.get("sources", ()):
        if item in SOURCE_SETS:
            continue
        dotted = bool(re.compile(_PY_DOTTED_SRC).match(item)) and (
            "." in item or any(c in item for c in "*{")
        )
        if not dotted:
            known = ", ".join(sorted(SOURCE_SETS))
            add(
                "path",
                f"unknown source set {item!r} (known: {known}; custom sources are dotted paths)",
                f"{where}.sources",
            )


def _check_misc(raw: Mapping[str, Any], add: _Add) -> None:
    for where, kind, spec in iter_leaves(raw["match"]):
        if kind == "entropy" and spec.get("min_len", 20) > spec.get("max_len", 200):
            add("entropy", "min_len is greater than max_len", where)
    rid = raw["id"]
    if raw.get("replaced_by") == rid:
        add("ref", "replaced_by names the rule itself", "replaced_by")
    if rid in raw.get("supersedes", ()):
        add("ref", "supersedes names the rule itself", "supersedes")
    fixtures = raw.get("fixtures")
    if isinstance(fixtures, dict):
        for side in ("pos", "neg"):
            for i, p in enumerate(fixtures[side]):
                if not safe_relpath(p):
                    add(
                        "fixtures",
                        f"fixture path {p!r} must be relative, without '..'",
                        f"fixtures.{side}[{i}]",
                    )


def safe_relpath(path: str) -> bool:
    """A relative POSIX path that cannot leave its base directory (no `..`, no empty segments)."""
    if not path or "\x00" in path or "\\" in path or path.startswith("/") or len(path) > 512:
        return False
    return all(part not in ("", "..") for part in path.split("/"))


# =============================================================================================== normalize


def _plain_copy(value: Any, depth: int = 0) -> Any:
    if depth > 64:
        raise RuleError("rule nesting deeper than 64 levels")
    if isinstance(value, dict):
        return {str(k): _plain_copy(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [_plain_copy(v, depth + 1) for v in value]
    return value


def _strs(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(v) for v in value)


def to_rule(raw: Mapping[str, Any], source_file: str | None = None) -> Rule:
    """Convert a schema-valid raw rule to a `Rule` without checks (langs may be implied by the matchers)."""
    at = raw["applies_to"]
    langs = _as_set(at.get("lang"))
    if not langs:
        langs = required_langs(raw["match"]) or frozenset()
    pack = str(raw["pack"])
    max_bytes = at.get("max_bytes")
    return Rule(
        id=str(raw["id"]),
        title=str(raw["title"]),
        pack=pack,
        severity=Severity.parse(raw["severity"]),
        confidence=Confidence.parse(raw["confidence"]),
        owner=str(raw["owner"]),
        applies_to=AppliesTo(
            kinds=_as_set(at.get("kind")),
            langs=langs,
            globs=_strs(at.get("glob")),
            exclude_globs=_strs(at.get("exclude_glob")),
            tags_any=_as_set(at.get("tags_any")),
            tags_none=_as_set(at.get("tags_none")),
            include_minified=bool(at.get("include_minified", False)),
            max_bytes=None if max_bytes is None else int(max_bytes),
        ),
        match=_plain_copy(raw["match"]),
        message=str(raw["message"]),
        references=_strs(raw["references"]),
        cwe=_strs(raw.get("cwe")),
        owasp=_strs(raw.get("owasp")),
        atlas=_strs(raw.get("atlas")),
        tags=_strs(raw.get("tags")),
        fix=None if raw.get("fix") is None else str(raw["fix"]),
        keywords=_strs(raw.get("keywords")),
        keywords_case="sensitive" if raw.get("keywords_case") == "sensitive" else "insensitive",
        filters=_plain_copy(raw.get("filters") or {}),
        redact=bool(raw.get("redact", False)),
        # §10: `exposure_sensitive: false` is the default for the secrets pack.
        exposure_sensitive=bool(raw.get("exposure_sensitive", pack.split("/", 1)[0] != "secrets")),
        supersedes=_strs(raw.get("supersedes")),
        max_hits_per_file=int(raw.get("max_hits_per_file", 50)),
        enabled_by_default=bool(raw.get("enabled_by_default", True)),
        deprecated=bool(raw.get("deprecated", False)),
        replaced_by=_opt_str(raw.get("replaced_by")),
        since=_opt_str(raw.get("since")),
        source_file=source_file,
    )


def normalize(
    raw: Mapping[str, Any], *, source_file: str | None = None, validate: bool = True, lint: bool = True
) -> Rule:
    """Validate (schema, per-rule semantic checks, lint) and convert one raw rule. Raises `RuleLoadError`."""
    if validate:
        errors = [i for i in check_rule(raw, source=source_file, lint=lint) if i.level == "error"]
        if errors:
            raise RuleLoadError(errors)
    return to_rule(raw, source_file)


def _opt_str(value: Any) -> str | None:
    return None if value is None else str(value)


# -- canonical dict form (bundle, cache, hashing) ---------------------------------------------------------


def rule_to_dict(rule: Rule, *, with_source: bool = True) -> dict[str, Any]:
    """JSON-safe canonical form of a normalized rule (sets become sorted lists)."""
    at = rule.applies_to
    d: dict[str, Any] = {
        "id": rule.id,
        "title": rule.title,
        "pack": rule.pack,
        "severity": rule.severity.label,
        "confidence": rule.confidence.label,
        "owner": rule.owner,
        "applies_to": {
            "kinds": sorted(at.kinds),
            "langs": sorted(at.langs),
            "globs": list(at.globs),
            "exclude_globs": list(at.exclude_globs),
            "tags_any": sorted(at.tags_any),
            "tags_none": sorted(at.tags_none),
            "include_minified": at.include_minified,
            "max_bytes": at.max_bytes,
        },
        "match": _plain_copy(dict(rule.match)),
        "message": rule.message,
        "references": list(rule.references),
        "cwe": list(rule.cwe),
        "owasp": list(rule.owasp),
        "atlas": list(rule.atlas),
        "tags": list(rule.tags),
        "fix": rule.fix,
        "keywords": list(rule.keywords),
        "keywords_case": rule.keywords_case,
        "filters": _plain_copy(dict(rule.filters)),
        "redact": rule.redact,
        "exposure_sensitive": rule.exposure_sensitive,
        "supersedes": list(rule.supersedes),
        "max_hits_per_file": rule.max_hits_per_file,
        "enabled_by_default": rule.enabled_by_default,
        "deprecated": rule.deprecated,
        "replaced_by": rule.replaced_by,
        "since": rule.since,
    }
    if with_source:
        d["source_file"] = rule.source_file
    return d


def _req(d: Mapping[str, Any], key: str, typ: type | tuple[type, ...]) -> Any:
    value = d[key]
    if not isinstance(value, typ) or (typ is int and isinstance(value, bool)):
        raise TypeError(f"{key}: expected {typ}, got {type(value).__name__}")
    return value


def _str_list(d: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = _req(d, key, list)
    if not all(isinstance(v, str) for v in value):
        raise TypeError(f"{key}: expected a list of strings")
    return tuple(value)


def _opt(d: Mapping[str, Any], key: str, typ: type) -> Any:
    value = d.get(key)
    if value is not None and (not isinstance(value, typ) or (typ is int and isinstance(value, bool))):
        raise TypeError(f"{key}: expected {typ.__name__} or null")
    return value


def rule_from_dict(d: Any) -> Rule:
    """Inverse of `rule_to_dict`, with structural type checks (raises KeyError/TypeError/ValueError)."""
    if not isinstance(d, dict):
        raise TypeError("rule entry is not an object")
    at = _req(d, "applies_to", dict)
    case = _req(d, "keywords_case", str)
    if case not in ("insensitive", "sensitive"):
        raise ValueError(f"keywords_case: {case!r}")
    return Rule(
        id=_req(d, "id", str),
        title=_req(d, "title", str),
        pack=_req(d, "pack", str),
        severity=Severity.parse(_req(d, "severity", str)),
        confidence=Confidence.parse(_req(d, "confidence", str)),
        owner=_req(d, "owner", str),
        applies_to=AppliesTo(
            kinds=frozenset(_str_list(at, "kinds")),
            langs=frozenset(_str_list(at, "langs")),
            globs=_str_list(at, "globs"),
            exclude_globs=_str_list(at, "exclude_globs"),
            tags_any=frozenset(_str_list(at, "tags_any")),
            tags_none=frozenset(_str_list(at, "tags_none")),
            include_minified=_req(at, "include_minified", bool),
            max_bytes=_opt(at, "max_bytes", int),
        ),
        match=_req(d, "match", dict),
        message=_req(d, "message", str),
        references=_str_list(d, "references"),
        cwe=_str_list(d, "cwe"),
        owasp=_str_list(d, "owasp"),
        atlas=_str_list(d, "atlas"),
        tags=_str_list(d, "tags"),
        fix=_opt(d, "fix", str),
        keywords=_str_list(d, "keywords"),
        keywords_case=case,
        filters=_req(d, "filters", dict),
        redact=_req(d, "redact", bool),
        exposure_sensitive=_req(d, "exposure_sensitive", bool),
        supersedes=_str_list(d, "supersedes"),
        max_hits_per_file=_req(d, "max_hits_per_file", int),
        enabled_by_default=_req(d, "enabled_by_default", bool),
        deprecated=_req(d, "deprecated", bool),
        replaced_by=_opt(d, "replaced_by", str),
        since=_opt(d, "since", str),
        source_file=_opt(d, "source_file", str),
    )


def canonical_json(value: Any) -> bytes:
    import json

    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def bundle_hash(rules: Iterable[Rule]) -> str:
    """`sha256:` of the canonical JSON of the normalized rules, sorted by ID (source paths excluded)."""
    import hashlib

    ordered = sorted(rules, key=lambda r: r.id)
    return (
        "sha256:"
        + hashlib.sha256(canonical_json([rule_to_dict(r, with_source=False) for r in ordered])).hexdigest()
    )


# =============================================================================================== rule sets


@dataclass(frozen=True, slots=True)
class KeywordTable:
    """Keyword prefilter tables (§8.1 step 2); values are indices into `RuleSet.rules`."""

    insensitive: Mapping[str, tuple[int, ...]]  # casefolded keyword -> rules
    sensitive: Mapping[str, tuple[int, ...]]
    always: tuple[int, ...]  # rules without keywords

    def to_dict(self) -> dict[str, Any]:
        return {
            "insensitive": {k: list(v) for k, v in self.insensitive.items()},
            "sensitive": {k: list(v) for k, v in self.sensitive.items()},
            "always": list(self.always),
        }

    @classmethod
    def build(cls, rules: Sequence[Rule]) -> KeywordTable:
        ins: dict[str, list[int]] = {}
        sen: dict[str, list[int]] = {}
        always: list[int] = []
        for i, rule in enumerate(rules):
            if not rule.keywords:
                always.append(i)
                continue
            table, fold = (sen, False) if rule.keywords_case == "sensitive" else (ins, True)
            for kw in dict.fromkeys(k.casefold() if fold else k for k in rule.keywords):
                table.setdefault(kw, []).append(i)
        return cls(
            {k: tuple(v) for k, v in ins.items()}, {k: tuple(v) for k, v in sen.items()}, tuple(always)
        )

    @classmethod
    def from_dict(cls, d: Mapping[str, Any], n_rules: int) -> KeywordTable:
        def table(key: str) -> dict[str, tuple[int, ...]]:
            raw = _req(d, key, dict)
            return {str(k): _indices(v, n_rules) for k, v in raw.items()}

        return cls(table("insensitive"), table("sensitive"), _indices(d["always"], n_rules))


def _indices(value: Any, n: int) -> tuple[int, ...]:
    if not isinstance(value, list) or not all(
        isinstance(i, int) and not isinstance(i, bool) and 0 <= i < n for i in value
    ):
        raise ValueError("bad rule index list")
    return tuple(value)


_ANY: Final = "*"


class RuleSet:
    """An immutable, ordered set of normalized rules plus lookup structures.

    `rules` keeps load order (bundle first, then extra dirs); `by_id` maps IDs to rules. The applicability
    index answers "which rules can run on a file of this (kind, lang)"; kinds and langs left empty in a rule's
    `applies_to` match anything (unknown kinds only match rules without a kind restriction).
    """

    __slots__ = ("_hash", "_index", "_keywords", "_memo", "by_id", "fixture_specs", "rules", "warnings")

    def __init__(
        self,
        rules: Iterable[Rule],
        *,
        warnings: Iterable[RuleIssue] = (),
        fixture_specs: Mapping[str, Any] | None = None,
        index: Mapping[str, Mapping[str, tuple[int, ...]]] | None = None,
        keywords: KeywordTable | None = None,
        rules_hash: str | None = None,
    ) -> None:
        self.rules: tuple[Rule, ...] = tuple(rules)
        by_id: dict[str, Rule] = {}
        for rule in self.rules:
            if rule.id in by_id:
                raise RuleError(f"duplicate rule id {rule.id}")
            by_id[rule.id] = rule
        self.by_id: Mapping[str, Rule] = by_id
        self.warnings: tuple[RuleIssue, ...] = tuple(warnings)
        self.fixture_specs: Mapping[str, Any] = dict(fixture_specs or {})
        self._index = index
        self._keywords = keywords
        self._hash = rules_hash
        self._memo: dict[tuple[str, str], tuple[Rule, ...]] = {}

    # -- container protocol -------------------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self) -> Iterator[Rule]:
        return iter(self.rules)

    def __contains__(self, rule_id: object) -> bool:
        return rule_id in self.by_id

    def __repr__(self) -> str:
        return f"RuleSet({len(self.rules)} rules)"

    def get(self, rule_id: str) -> Rule | None:
        return self.by_id.get(rule_id)

    @property
    def bundle_hash(self) -> str:
        """`sha256:` of the canonical JSON of these rules (computed once)."""
        if self._hash is None:
            self._hash = bundle_hash(self.rules)
        return self._hash

    @property
    def packs(self) -> tuple[str, ...]:
        return tuple(sorted({r.pack for r in self.rules}))

    def counts_by_pack(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for rule in self.rules:
            out[rule.pack] = out.get(rule.pack, 0) + 1
        return dict(sorted(out.items()))

    # -- applicability ---------------------------------------------------------------------------------------

    @property
    def index(self) -> Mapping[str, Mapping[str, tuple[int, ...]]]:
        """kind -> lang -> rule indices; lang `*` holds rules without a lang restriction, kind `*` holds rules
        without a kind restriction (used for kinds outside `model.KINDS`)."""
        if self._index is None:
            building: dict[str, dict[str, list[int]]] = {k: {_ANY: []} for k in (*KINDS, _ANY)}
            for i, rule in enumerate(self.rules):
                kinds = rule.applies_to.kinds or (*KINDS, _ANY)
                for kind in kinds:
                    bucket = building.setdefault(kind, {_ANY: []})
                    for lang in sorted(rule.applies_to.langs) or (_ANY,):
                        bucket.setdefault(lang, []).append(i)
            self._index = {k: {lang: tuple(ids) for lang, ids in v.items()} for k, v in building.items()}
        return self._index

    def applicable(self, kind: str, lang: str) -> tuple[Rule, ...]:
        """Rules whose `applies_to` kind and lang admit a file of this kind and lang (memoized)."""
        key = (kind, lang)
        hit = self._memo.get(key)
        if hit is None:
            bucket = self.index.get(kind) or self.index[_ANY]
            ids = sorted(set(bucket.get(_ANY, ())) | set(bucket.get(lang, ())))
            hit = tuple(self.rules[i] for i in ids)
            self._memo[key] = hit
        return hit

    def candidates(self, kind: str, lang: str, tags: Iterable[str] = ()) -> tuple[Rule, ...]:
        """`applicable` narrowed by `tags_any` / `tags_none` (glob, size and minified checks stay with the
        pipeline, which knows the file's path and flags)."""
        tagset = frozenset(tags)
        return tuple(
            r
            for r in self.applicable(kind, lang)
            if (not r.applies_to.tags_any or r.applies_to.tags_any & tagset)
            and not (r.applies_to.tags_none & tagset)
        )

    @property
    def keyword_table(self) -> KeywordTable:
        if self._keywords is None:
            self._keywords = KeywordTable.build(self.rules)
        return self._keywords

    # -- selection -----------------------------------------------------------------------------------------

    def select(
        self,
        packs: Sequence[str] | None = None,
        rule_ids: Sequence[str] | None = None,
        *,
        exclude: Sequence[str] = (),
        enable: Sequence[str] = (),
        disable: Sequence[str] = (),
    ) -> RuleSet:
        """The active subset, in load order.

        1. Pack selectors (`appsec`, `domain/*`, `domain/k8s`, `-domain/trading`; None = every pack): positive
           selectors are unioned, then negative ones removed. Only `enabled_by_default` rules are taken.
        2. `enable` IDs/globs are forced on (even when off by default or outside the selected packs), then
           `disable` IDs/globs are removed (config `rules.enable` / `rules.disable`).
        3. `rule_ids` (`--rule`, globs) restricts the result; an exact ID is forced on even if it was off.
        4. `exclude` (`--exclude-rule`, globs) removes rules last.

        An unknown exact ID in `rule_ids` raises `RuleError`; unknown IDs elsewhere become warnings.
        """
        notes: list[RuleIssue] = []
        in_packs = self._pack_filter(packs)
        chosen = {r.id for r in self.rules if r.enabled_by_default and in_packs(r.pack)}
        chosen |= self._match_ids(enable, "rules.enable", notes)
        chosen -= self._match_ids(disable, "rules.disable", notes)
        if rule_ids is not None:
            wanted = self._match_ids(rule_ids, "--rule", notes, strict=True)
            exact = {p for p in rule_ids if p in self.by_id}
            chosen = (chosen & wanted) | exact
        chosen -= self._match_ids(exclude, "--exclude-rule", notes)
        picked = [r for r in self.rules if r.id in chosen]
        specs = {k: v for k, v in self.fixture_specs.items() if k in chosen}
        return RuleSet(picked, warnings=(*self.warnings, *notes), fixture_specs=specs)

    def _match_ids(
        self, patterns: Iterable[str], what: str, notes: list[RuleIssue], *, strict: bool = False
    ) -> set[str]:
        out: set[str] = set()
        for raw in patterns:
            pat = raw.strip()
            if not pat:
                continue
            if _GLOB_CHARS.isdisjoint(pat):
                if pat in self.by_id:
                    out.add(pat)
                elif strict:
                    raise RuleError(f"unknown rule ID: {pat}")
                else:
                    notes.append(RuleIssue("warning", "unknown-rule", f"{what}: unknown rule ID {pat}"))
                continue
            matched = {rid for rid in self.by_id if fnmatch.fnmatchcase(rid, pat)}
            if not matched:
                notes.append(RuleIssue("warning", "unknown-rule", f"{what}: {pat!r} matches no rule"))
            out |= matched
        return out

    @staticmethod
    def _pack_filter(packs: Sequence[str] | None) -> Callable[[str], bool]:
        if packs is None:
            return lambda _pack: True
        positive: list[str] = []
        negative: list[str] = []
        for raw in packs:
            sel = raw.strip()
            if not sel:
                continue
            neg = sel.startswith("-")
            pat = sel[1:].strip() if neg else sel
            _validate_pack_selector(pat, raw)
            (negative if neg else positive).append(pat)
        only_negative = not positive and bool(negative)

        def admitted(pack: str) -> bool:
            if not (only_negative or any(pack_matches(pack, p) for p in positive)):
                return False
            return not any(pack_matches(pack, p) for p in negative)

        return admitted

    # -- serialization (cache) -----------------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_hash": self.bundle_hash,
            "rules": [rule_to_dict(r) for r in self.rules],
            "index": {k: {lang: list(ids) for lang, ids in v.items()} for k, v in self.index.items()},
            "keywords": self.keyword_table.to_dict(),
            "warnings": [w.to_dict() for w in self.warnings],
            "fixtures": dict(self.fixture_specs),
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> RuleSet:
        """Rebuild from `to_dict` output; raises KeyError/TypeError/ValueError on malformed input."""
        rules = [rule_from_dict(r) for r in _req(d, "rules", list)]
        n = len(rules)
        index: dict[str, dict[str, tuple[int, ...]]] = {}
        for kind, langs in _req(d, "index", dict).items():
            if not isinstance(langs, dict):
                raise TypeError("index entry is not an object")
            index[str(kind)] = {str(lang): _indices(ids, n) for lang, ids in langs.items()}
        if _ANY not in index:
            raise ValueError("index lacks the wildcard kind")
        keywords = KeywordTable.from_dict(_req(d, "keywords", dict), n)
        warnings = [RuleIssue.from_dict(w) for w in _req(d, "warnings", list)]
        fixtures = _req(d, "fixtures", dict)
        digest = _req(d, "bundle_hash", str)
        return cls(
            rules,
            warnings=warnings,
            fixture_specs=fixtures,
            index=index,
            keywords=keywords,
            rules_hash=digest,
        )


def pack_matches(pack: str, selector: str) -> bool:
    """`appsec` matches every `appsec/*` pack; selectors with a `/` or glob characters use fnmatch."""
    if "/" not in selector:
        return fnmatch.fnmatchcase(pack.split("/", 1)[0], selector)
    return fnmatch.fnmatchcase(pack, selector)


_SELECTOR_SRC: Final = r"[a-z0-9*?\[\]-]+(?:/[a-z0-9*?\[\]-]+)?\Z"


def _validate_pack_selector(pattern: str, raw: str) -> None:
    if not re.compile(_SELECTOR_SRC).match(pattern):
        raise RuleError(f"bad pack selector {raw!r}")
    root = pattern.split("/", 1)[0]
    if not any(fnmatch.fnmatchcase(r, root) for r in PACK_ROOTS):
        raise RuleError(f"unknown pack {raw!r}; packs are {', '.join(PACK_ROOTS)}")


# =============================================================================================== building


@dataclass(frozen=True, slots=True)
class CheckReport:
    """Result of checking raw rules without raising: what `rules test` reports per rule."""

    rules: tuple[Rule, ...]
    issues: tuple[RuleIssue, ...]
    fixture_specs: Mapping[str, Any] = field(default_factory=dict)

    @property
    def errors(self) -> tuple[RuleIssue, ...]:
        return tuple(i for i in self.issues if i.level == "error")

    @property
    def warnings(self) -> tuple[RuleIssue, ...]:
        return tuple(i for i in self.issues if i.level == "warning")

    @property
    def ok(self) -> bool:
        return not self.errors

    def issues_for(self, rule_id: str) -> tuple[RuleIssue, ...]:
        return tuple(i for i in self.issues if i.rule_id == rule_id)


def check(
    raws: Iterable[RawRule], *, lint: bool = True, extra_issues: Iterable[RuleIssue] = ()
) -> CheckReport:
    """Run every load-time check over raw rules from all sources, collecting issues instead of raising."""
    issues: list[RuleIssue] = list(extra_issues)
    rules: list[Rule] = []
    fixture_specs: dict[str, Any] = {}
    first_seen: dict[str, RawRule] = {}
    for raw in raws:
        rid = (
            raw.data.get("id") if isinstance(raw.data, dict) and isinstance(raw.data.get("id"), str) else None
        )
        if rid is not None and rid in first_seen:
            prev = first_seen[rid]
            if prev.origin in ("bundle", "builtin") and raw.origin in ("extra", "file"):
                issues.append(
                    RuleIssue(
                        "error",
                        "shadows-bundled",
                        f"rule ID {rid} is already defined by a built-in rule; extra rules may not shadow it",
                        rid,
                        raw.source,
                    )
                )
            else:
                issues.append(
                    RuleIssue(
                        "error",
                        "duplicate-id",
                        f"rule ID {rid} is also defined in {prev.source}",
                        rid,
                        raw.source,
                    )
                )
            continue
        if rid is not None:
            first_seen[rid] = raw
        if raw.normalized:
            try:
                rule = rule_from_dict(raw.data)
            except (KeyError, TypeError, ValueError) as exc:
                issues.append(RuleIssue("error", "bundle", f"malformed bundle entry: {exc}", rid, raw.source))
                continue
        else:
            per_rule = check_rule(raw.data, source=raw.source, lint=lint)
            issues += per_rule
            if any(i.level == "error" for i in per_rule):
                continue
            rule = to_rule(raw.data, raw.source)
        rules.append(rule)
        spec = raw.data.get("fixtures")
        if isinstance(spec, dict):
            fixture_specs[rule.id] = _plain_copy(spec)
    known = set(first_seen)
    for rule in rules:
        if rule.replaced_by is not None and rule.replaced_by not in known:
            issues.append(
                RuleIssue(
                    "error",
                    "ref",
                    f"replaced_by names unknown rule {rule.replaced_by}",
                    rule.id,
                    rule.source_file,
                    "replaced_by",
                )
            )
        for other in rule.supersedes:
            if other not in known:
                issues.append(
                    RuleIssue(
                        "error",
                        "ref",
                        f"supersedes names unknown rule {other}",
                        rule.id,
                        rule.source_file,
                        "supersedes",
                    )
                )
    return CheckReport(tuple(rules), tuple(issues), fixture_specs)


def build(raws: Iterable[RawRule], *, lint: bool = True, extra_issues: Iterable[RuleIssue] = ()) -> RuleSet:
    """`check` and raise `RuleLoadError` on any error; warnings are kept on the returned `RuleSet`."""
    report = check(raws, lint=lint, extra_issues=extra_issues)
    if report.errors:
        raise RuleLoadError(report.issues)
    return RuleSet(report.rules, warnings=report.warnings, fixture_specs=report.fixture_specs)


def read_all(
    sources: Sequence[SourceFile], *, yaml_loader: YamlLoader | None = None
) -> tuple[list[RawRule], list[bytes]]:
    """Read and parse every source; the returned bytes are exactly what was parsed (for cache keys)."""
    raws: list[RawRule] = []
    blobs: list[bytes] = []
    for src in sources:
        data = read_source(src)
        blobs.append(data)
        raws += parse_source(src, data, yaml_loader=yaml_loader)
    if len(raws) > MAX_RULES:
        raise RuleError(f"more than {MAX_RULES} rules in total")
    return raws, blobs


def load(
    extra_dirs: Sequence[str | os.PathLike[str]] = (),
    files: Sequence[str | os.PathLike[str]] = (),
    *,
    builtin: bool = True,
    bundle_path: str | os.PathLike[str] | None = None,
    yaml_loader: YamlLoader | None = None,
    lint: bool = True,
    missing_dirs_ok: bool = False,
) -> RuleSet:
    """Load, check and normalize every rule from the bundle, extra dirs and files. Raises `RuleError`."""
    sources, issues = discover_sources(
        extra_dirs, files, builtin=builtin, bundle_path=bundle_path, missing_dirs_ok=missing_dirs_ok
    )
    raws, _ = read_all(sources, yaml_loader=yaml_loader)
    return build(raws, lint=lint, extra_issues=issues)


def load_raw_rules(
    rules: Iterable[Mapping[str, Any]], *, source: str = "<memory>", lint: bool = True
) -> RuleSet:
    """Build a `RuleSet` from in-memory rule mappings (tests, API callers) with every check applied."""
    raws = [RawRule(dict(r), source, "file", i) for i, r in enumerate(rules)]
    return build(raws, lint=lint)


def build_bundle(
    rule_dirs: Sequence[str | os.PathLike[str]], *, yaml_loader: YamlLoader | None = None
) -> dict[str, Any]:
    """The release-time `bundle.json` document for the given rule directories (fully validated)."""
    sources: list[SourceFile] = []
    issues: list[RuleIssue] = []
    for d in rule_dirs:
        base = os.fspath(d)
        found, problems = iter_pack_files(base)
        issues += problems
        for path in found:
            rel = os.path.relpath(path, os.path.realpath(base)).replace(os.sep, "/")
            sources.append(SourceFile("builtin", path, f"rules/{rel}", f"builtin:{rel}"))
    raws, _ = read_all(sources, yaml_loader=yaml_loader)
    ruleset = build(raws, extra_issues=issues)
    return {
        "schema": BUNDLE_SCHEMA,
        "bundle_hash": ruleset.bundle_hash,
        "rules": [rule_to_dict(r) for r in ruleset.rules],
        "fixtures": dict(ruleset.fixture_specs),
    }
