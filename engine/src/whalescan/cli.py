"""Lazy argparse command surface for whalescan (engine spec §2 and §17)."""

import argparse
import os
import sys

# Type-only imports without importing typing (or engine modules) on the startup path.
if getattr(sys.modules.get("typing"), "TYPE_CHECKING", False):
    from typing import Any

    from .api import Scanner
    from .config import Config
    from .model import Finding, ScanResult


SEVERITIES = ("critical", "high", "medium", "low", "info")
FORMATS = ("text", "json", "jsonl", "sarif", "markdown")


def _globals(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-c", "--config", default=argparse.SUPPRESS)
    parser.add_argument("--no-project-config", action="store_true", default=argparse.SUPPRESS)
    parser.add_argument("--root", default=argparse.SUPPRESS)
    parser.add_argument("--rules-dir", action="append", default=argparse.SUPPRESS)
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("-q", action="store_true", default=argparse.SUPPRESS)
    verbosity.add_argument("-v", action="count", default=argparse.SUPPRESS)
    parser.add_argument("--log-format", choices=("text", "json"), default=argparse.SUPPRESS)
    parser.add_argument("--color", choices=("auto", "always", "never"), default=argparse.SUPPRESS)
    parser.add_argument("--no-cache", action="store_true", default=argparse.SUPPRESS)
    parser.add_argument("--cache-dir", default=argparse.SUPPRESS)


def _scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--stdin", action="store_true")
    parser.add_argument("--stdin-filename", default="<stdin>")
    parser.add_argument("-f", "--format", choices=FORMATS)
    parser.add_argument("-o", "--output", default="-")
    parser.add_argument("--also", action="append", default=[])
    parser.add_argument("--packs")
    parser.add_argument("--rule", action="append")
    parser.add_argument("--exclude-rule", action="append", default=[])
    parser.add_argument("--fail-on", choices=(*SEVERITIES, "never"))
    parser.add_argument("--min-severity", choices=SEVERITIES)
    parser.add_argument("--min-confidence", choices=("high", "medium", "low"))
    baseline = parser.add_mutually_exclusive_group()
    baseline.add_argument("--baseline")
    baseline.add_argument("--no-baseline", action="store_true")
    parser.add_argument("--show-suppressed", action="store_true")
    diff = parser.add_mutually_exclusive_group()
    diff.add_argument("--diff")
    diff.add_argument("--staged", action="store_true")
    parser.add_argument("--diff-lines", action="store_true")
    parser.add_argument("--files-from")
    parser.add_argument("--include", action="append")
    parser.add_argument("--exclude", action="append")
    parser.add_argument("--no-gitignore", action="store_true")
    parser.add_argument("--follow-symlinks", action="store_true")
    parser.add_argument("--max-file-size")
    parser.add_argument("--max-files", type=int)
    parser.add_argument("-j", "--jobs", type=int)
    parser.add_argument("--time-budget-ms", type=int)
    parser.add_argument("--adapters")
    parser.add_argument("--adapters-strict", action="store_true")
    parser.add_argument("--deterministic", action="store_true")
    parser.add_argument("--profile", action="store_true")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="whalescan")
    _globals(parser)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("scan", "inject", "secrets"):
        command = commands.add_parser(name)
        _globals(command)
        _scan_options(command)
        if name == "inject":
            command.add_argument("--source", default="stdin")
            command.add_argument("--reveal", action=argparse.BooleanOptionalAction, default=None)
            command.add_argument("--reveal-out")
            command.add_argument("--max-bytes", type=int)
        if name == "secrets":
            command.add_argument("--git-history", action="store_true")
            command.add_argument("--since")
            command.add_argument("--max-commits", type=int, default=1000)
    baseline = commands.add_parser("baseline")
    _globals(baseline)
    actions = baseline.add_subparsers(dest="action", required=True)
    for name in ("create", "update"):
        command = actions.add_parser(name)
        _globals(command)
        _scan_options(command)
        command.add_argument("--baseline-out")
        command.add_argument("--reason", required=name == "create")
        command.add_argument("--allow-critical", action="store_true")
        if name == "create":
            command.add_argument("--force", action="store_true")
        else:
            command.add_argument("--no-prune", action="store_true")
            command.add_argument("--add-new", action="store_true")
    rules = commands.add_parser("rules")
    _globals(rules)
    actions = rules.add_subparsers(dest="action", required=True)
    listing = actions.add_parser("list")
    _globals(listing)
    listing.add_argument("--packs")
    listing.add_argument("--kind", choices=("code", "iac", "ci", "agent-config", "doc", "data"))
    listing.add_argument("--severity-min", choices=SEVERITIES)
    listing.add_argument("--tag")
    listing.add_argument("-f", "--format", choices=("table", "json", "markdown"), default="table")
    test = actions.add_parser("test")
    _globals(test)
    test.add_argument("ids", nargs="*")
    test.add_argument("--fixtures", default="tests/fixtures")
    test.add_argument("--redos", action="store_true")
    test.add_argument("--schema-only", action="store_true")
    test.add_argument("--junit")
    explain = actions.add_parser("explain")
    _globals(explain)
    explain.add_argument("id")
    explain.add_argument("-f", "--format", choices=("text", "json", "markdown"), default="text")
    explain.add_argument("--grep", action="store_true")
    version = commands.add_parser("version")
    _globals(version)
    version.add_argument("-f", "--format", choices=("text", "json"), default="text")
    version.add_argument("--probe-adapters", action="store_true")
    return parser


def _config(args: argparse.Namespace) -> "Config":
    from .config import load_config, parse_size
    from .errors import UsageError

    overrides: dict[str, object] = {}
    for key in (
        "fail_on",
        "min_severity",
        "min_confidence",
        "jobs",
        "time_budget_ms",
        "include",
        "exclude",
        "max_files",
        "baseline",
    ):
        value = getattr(args, key, None)
        if value is not None:
            overrides["scan." + key] = value
    for flag, key, value in (
        ("no_gitignore", "scan.respect_gitignore", False),
        ("follow_symlinks", "scan.follow_symlinks", True),
        ("no_baseline", "scan.baseline", ""),
        ("no_cache", "cache.enabled", False),
        ("adapters_strict", "adapters.strict", True),
        ("diff_lines", "scan.diff_lines_only", True),
    ):
        if getattr(args, flag, False):
            overrides[key] = value
    if getattr(args, "max_file_size", None) is not None:
        try:
            overrides["scan.max_file_bytes"] = parse_size(args.max_file_size)
        except ValueError:
            raise UsageError("--max-file-size expects a positive size with optional K/M/G suffix") from None
    if getattr(args, "packs", None) is not None:
        overrides["scan.packs"] = args.packs.split(",")
    if getattr(args, "cache_dir", None) is not None:
        overrides["cache.dir"] = args.cache_dir
    if getattr(args, "adapters", None) is not None:
        overrides["adapters.enabled"] = [] if args.adapters == "none" else args.adapters.split(",")
    if getattr(args, "log_format", None) is not None:
        overrides["logging.format"] = args.log_format
    if getattr(args, "q", False):
        overrides["logging.level"] = "error"
    elif getattr(args, "v", 0):
        overrides["logging.level"] = "debug" if args.v > 1 else "info"
    cfg = load_config(
        getattr(args, "root", None),
        path=getattr(args, "config", None),
        project=not getattr(args, "no_project_config", False),
        overrides=overrides,
    )
    if getattr(args, "rules_dir", None):
        cfg = cfg.with_overrides({"rules.extra_dirs": [*cfg.rules.extra_dirs, *args.rules_dir]})
    return cfg


def _logging(cfg: "Config") -> None:
    from .log import setup
    from .redact import Redactor

    setup(cfg.logging.level, cfg.logging.format, cfg.logging.file, redactor=Redactor())


def _targets(args: argparse.Namespace) -> list[str]:
    from .errors import UsageError
    from .walker import read_files_from

    paths = list(args.paths)
    if args.stdin:
        paths.append("-")
    if paths.count("-") > 1 or (args.files_from == "-" and "-" in paths):
        raise UsageError("stdin may be consumed at most once")
    if args.diff_lines and not (args.diff or args.staged):
        raise UsageError("--diff-lines requires --diff or --staged")
    if args.files_from:
        paths.extend(read_files_from(args.files_from))
    if paths.count("-") > 1 or (args.files_from == "-" and "-" in paths):
        raise UsageError("stdin may be consumed at most once")
    if not paths and args.command in ("inject", "secrets") and not sys.stdin.isatty() and not args.files_from:
        paths = ["-"]
    return paths if paths or args.files_from else ["."]


def _combine(results: list["ScanResult"], cfg: "Config") -> "ScanResult":
    from .model import ScanResult, Stats

    if not results:
        from .model import RunInfo

        return ScanResult((), (), Stats(), RunInfo(root=cfg.root))
    stats = Stats()
    for result in results:
        for key in ("files_scanned", "bytes_scanned", "rules_evaluated"):
            setattr(stats, key, getattr(stats, key) + getattr(result.stats, key))
        for key in ("files_skipped", "capped", "by_severity", "suppressed"):
            target = getattr(stats, key)
            for name, count in getattr(result.stats, key).items():
                target[name] = target.get(name, 0) + count
        stats.truncated |= result.stats.truncated
    findings = tuple(sorted((f for r in results for f in r.findings), key=lambda f: f.sort_key))
    gate = tuple(
        f for r in results for f in (r._gate_findings if r._gate_findings is not None else r.findings)
    )
    run = results[0].run
    sweeps = tuple(r.run._sweep for r in results if r.run._sweep is not None)

    def sweep(value: str) -> str:
        for finalize in sweeps:
            value = finalize(value)
        return value

    run._sweep = sweep
    profile: dict[str, tuple[float, int]] = {}
    for result in results:
        for rule_id, (elapsed, hits) in result.run._profile.items():
            previous = profile.get(rule_id, (0.0, 0))
            profile[rule_id] = (previous[0] + elapsed, previous[1] + hits)
    run._profile = profile
    run.truncated = stats.truncated
    run.duration_ms = sum(r.run.duration_ms for r in results)
    combined = ScanResult(
        findings, tuple(d for r in results for d in r.diagnostics), stats, run, _gate_findings=gate
    )
    combined.run.exit_code = combined.exit_code(cfg.scan.fail_on)
    return combined


def _injection(scanner: "Scanner", data: bytes, args: argparse.Namespace, filename: str) -> "ScanResult":
    from .errors import UsageError
    from .matchers.unicode import reveal
    from .textio import decode

    limit = scanner.cfg.inject.max_bytes if args.max_bytes is None else args.max_bytes
    if limit < 1:
        raise UsageError("--max-bytes must be positive")
    truncated = len(data) > limit
    scanned = data[: limit // 2] + b"\n" + data[-(limit - limit // 2) :] if truncated else data
    result = scanner._text(
        scanned,
        filename,
        None,
        args.time_budget_ms,
        is_inject=True,
        source_label=args.source,
        truncated=truncated,
    )
    if args.reveal_out:
        # Use the parent-run sweep, without matching or parsing the input a second time.
        text = decode(data).text
        if result.run._sweep is not None:
            text = result.run._sweep(text)
        show = scanner.cfg.inject.reveal if args.reveal is None else args.reveal
        _write(reveal(text) if show else text, args.reveal_out)
    return result


def _read_inject(limit: int, retain: int) -> tuple[bytes, bool]:
    """Drain tool output with bounded memory, retaining the real tail even above stdin caps."""
    from .errors import UsageError

    if limit < 1:
        raise UsageError("--max-bytes must be positive")
    head = bytearray()
    tail = b""
    full = bytearray()
    total = 0
    for chunk in iter(lambda: sys.stdin.buffer.read(65536), b""):
        total += len(chunk)
        if len(head) < limit // 2:
            head.extend(chunk[: limit // 2 - len(head)])
        tail = (tail + chunk)[-(limit - limit // 2) :]
        if total <= retain:
            full.extend(chunk)
        else:
            full.clear()
    if total <= retain:
        return bytes(full), False
    return bytes(head) + b"\n" + tail, True


def _scan(args: argparse.Namespace, cfg: "Config") -> "ScanResult":
    import time

    from .api import Scanner, _deadline, _expired, load_rules
    from .errors import UsageError
    from .textio import read_stream

    deadline = _deadline(cfg.scan.time_budget_ms if args.time_budget_ms is None else args.time_budget_ms)

    def remaining() -> int:
        return max(1, int((deadline - time.monotonic()) * 1000)) if deadline is not None else 0

    paths = _targets(args)
    args.resolved_paths = list(paths)
    if args.command == "baseline" and (args.diff or args.staged):
        from .walker import git_changed_files

        changed = git_changed_files(cfg.root, args.diff, staged=args.staged)
        roots = [os.path.abspath(p) for p in paths if p != "-"]
        args.resolved_paths = [
            os.path.join(cfg.root, p)
            for p in changed
            if any(
                os.path.join(cfg.root, p) == root or os.path.join(cfg.root, p).startswith(root + os.sep)
                for root in roots
            )
        ]
    packs = (
        ("agentsec",) if args.command == "inject" else (("secrets",) if args.command == "secrets" else None)
    )
    rules = load_rules(cfg, packs=packs, rule_ids=args.rule).select(exclude=args.exclude_rule)
    if args.command == "baseline":
        cfg = cfg.with_overrides(
            {"scan.baseline": "", "scan.min_severity": "info", "scan.min_confidence": "low"}
        )
    scanner = Scanner(rules, cfg, adapters=cfg.adapters.enabled)
    if args.command == "secrets" and args.git_history:
        return _history(scanner, args)
    if args.command == "secrets" and (args.since or args.max_commits != 1000):
        raise UsageError("--since/--max-commits require --git-history")
    results = []
    normal = [p for p in paths if p != "-"]
    if normal:
        if args.command == "inject":
            from .textio import read_file
            from .walker import Walker

            inject_cfg = cfg.with_overrides({"scan.max_file_bytes": cfg.scan.max_total_bytes})
            walker = Walker(inject_cfg, rule_ids=rules.by_id)
            for candidate in walker.walk(normal):
                if _expired(deadline):
                    break
                args.time_budget_ms = remaining()
                try:
                    data = read_file(candidate.abs_path or "", inject_cfg.scan.max_file_bytes)
                except OSError:
                    continue
                results.append(_injection(scanner, data, args, candidate.path))
        elif args.staged:
            from dataclasses import replace

            from .walker import git_changed_files, git_diff_hunks

            changed = git_changed_files(cfg.root, staged=True)
            roots = [os.path.abspath(p) for p in normal]
            normal = [
                os.path.join(cfg.root, p)
                for p in changed
                if any(
                    os.path.join(cfg.root, p) == root or os.path.join(cfg.root, p).startswith(root + os.sep)
                    for root in roots
                )
            ]
            result = (
                scanner.scan_paths(normal, jobs=args.jobs, time_budget_ms=args.time_budget_ms)
                if normal
                else _combine([], cfg)
            )
            if args.diff_lines:
                hunks = git_diff_hunks(cfg.root, staged=True)
                gate = result._gate_findings if result._gate_findings is not None else result.findings

                def keep(f: "Finding") -> bool:
                    return any(f.end_line >= lo and f.line <= hi for lo, hi in hunks.get(f.file, ()))

                result = replace(
                    result,
                    findings=tuple(f for f in result.findings if keep(f)),
                    _gate_findings=tuple(f for f in gate if keep(f)),
                )
            results.append(result)
        else:
            results.append(
                scanner.scan_paths(
                    normal, jobs=args.jobs, diff_ref=args.diff, time_budget_ms=args.time_budget_ms
                )
            )
    if "-" in paths:
        args.time_budget_ms = remaining()
        cap = cfg.scan.max_stdin_bytes
        if args.command == "inject":
            limit = cfg.inject.max_bytes if args.max_bytes is None else args.max_bytes
            data, truncated = _read_inject(limit, sys.maxsize if args.reveal_out else max(cap, limit))
        else:
            data, truncated = read_stream(sys.stdin.buffer, cap)
        result = (
            _injection(scanner, data, args, args.stdin_filename)
            if args.command == "inject"
            else scanner.scan_text(data, filename=args.stdin_filename, time_budget_ms=args.time_budget_ms)
        )
        if truncated:
            from dataclasses import replace

            from .model import Diagnostic

            result.stats.truncated = result.run.truncated = True
            if not any(d.code == "input-truncated" for d in result.diagnostics):
                result = replace(
                    result,
                    diagnostics=(
                        *result.diagnostics,
                        Diagnostic("warning", "input-truncated", "stdin byte cap reached"),
                    ),
                )
        results.append(result)
    combined = _combine(results, cfg)
    if _expired(deadline):
        from dataclasses import replace

        from .model import Diagnostic

        combined.stats.truncated = combined.run.truncated = True
        if not any(d.code == "time-budget-exceeded" for d in combined.diagnostics):
            combined = replace(
                combined,
                diagnostics=(
                    *combined.diagnostics,
                    Diagnostic(
                        "warning",
                        "time-budget-exceeded",
                        "time budget exceeded; partial scan (hooks fail open)",
                    ),
                ),
            )
    return combined


def _history(scanner: "Scanner", args: argparse.Namespace) -> "ScanResult":
    import subprocess
    from dataclasses import replace

    from .errors import UsageError

    if args.max_commits < 1 or (
        args.since and (args.since.startswith("-") or any(c.isspace() for c in args.since))
    ):
        raise UsageError("invalid history revision or max-commits")
    command = [
        "git",
        "-C",
        scanner.cfg.root,
        "-c",
        "core.fsmonitor=false",
        "log",
        "-p",
        "-U0",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--format=%x00%H",
        f"--max-count={args.max_commits}",
    ]
    if args.since:
        command.append(args.since + "..HEAD")
    command.append("--")
    proc = subprocess.run(command, capture_output=True, timeout=60, check=False)
    if proc.returncode:
        raise UsageError("git history could not be read")
    results: list[ScanResult] = []
    commit, filename, line = "", "", 0
    added: list[bytes] = []
    first = 1
    in_hunk = False

    def flush() -> None:
        if not added or not filename:
            added.clear()
            return
        result = scanner.scan_text(b"\n".join(added), filename=filename)

        def locate(f: "Finding") -> "Finding":
            return replace(
                f,
                line=f.line + first - 1,
                end_line=f.end_line + first - 1,
                properties={**f.properties, "commit": commit},
            )

        gate = result._gate_findings if result._gate_findings is not None else result.findings
        results.append(
            replace(
                result,
                findings=tuple(locate(f) for f in result.findings),
                _gate_findings=tuple(locate(f) for f in gate),
            )
        )
        added.clear()

    for raw in proc.stdout.split(b"\n"):
        boundary = raw.startswith((b"\0", b"@@ ", b"diff --git ")) or (
            not in_hunk and raw.startswith(b"+++ ")
        )
        if boundary:
            flush()
        if raw.startswith(b"diff --git "):
            in_hunk = False
        if raw.startswith(b"\0"):
            in_hunk = False
            commit = raw[1:].decode("ascii", "replace")
        elif not in_hunk and raw.startswith(b"+++ "):
            from .walker import _c_unquote

            name = _c_unquote(os.fsdecode(raw[4:]).rstrip("\t"))
            filename = name[2:] if name.startswith("b/") else ""
        elif raw.startswith(b"@@ "):
            from .walker import _parse_hunk_header

            parsed = _parse_hunk_header(raw)
            line = parsed[0] if parsed else 0
            in_hunk = parsed is not None
        elif in_hunk and raw.startswith(b"+"):
            if not added:
                first = line
            added.append(raw[1:])
            line += 1
        elif raw.startswith(b" "):
            flush()
            line += 1
    flush()
    return _combine(results, scanner.cfg)


def _write(text: str, path: str) -> None:
    if path == "-":
        sys.stdout.write(text)
        sys.stdout.flush()
    else:
        with open(path, "w", encoding="utf-8") as stream:
            stream.write(text)


def _reports(result: "ScanResult", args: argparse.Namespace, cfg: "Config") -> None:
    from .errors import UsageError
    from .report import json, markdown, sarif, text

    outputs = [(args.format or cfg.report.format, args.output)]
    for extra in args.also:
        fmt, separator, path = extra.partition("=")
        if not separator or fmt not in FORMATS or not path:
            raise UsageError("--also requires FORMAT=PATH")
        outputs.append((fmt, path))
    if sum(path == "-" for _, path in outputs) > 1:
        raise UsageError("only one report may be written to stdout")
    if args.deterministic:
        result.run.started_at, result.run.duration_ms = "", 0
    color = getattr(args, "color", "auto")
    colored = color == "always" or (color == "auto" and "NO_COLOR" not in os.environ and sys.stdout.isatty())
    for fmt, path in outputs:
        if fmt == "json":
            output = json.render(result, include_suppressed=args.show_suppressed)
        elif fmt == "jsonl":
            output = json.render_jsonl(result, include_suppressed=args.show_suppressed)
        elif fmt == "sarif":
            output = sarif.render(
                result,
                include_suppressed=args.show_suppressed,
                absolute_root=cfg.root if cfg.report.sarif_absolute_root else None,
            )
        elif fmt == "markdown":
            output = markdown.render(
                result, include_suppressed=args.show_suppressed, max_findings=cfg.report.markdown_max_findings
            )
        else:
            output = text.render(
                result, color=colored and path == "-", include_suppressed=args.show_suppressed
            )
        _write(output, path)


def _baseline(args: argparse.Namespace, cfg: "Config", result: "ScanResult") -> int:
    from . import __version__
    from .errors import UsageError
    from .matchers.unicode import reveal
    from .suppress import Baseline

    def clean(value: str) -> str:
        return reveal(result.run._sweep(value) if result.run._sweep is not None else value)

    reason = clean(args.reason) if args.reason is not None else None
    path = cfg.resolve_path(
        args.baseline_out or args.baseline or cfg.scan.baseline or ".whalesecurity/baseline.json"
    )
    if result.run.truncated:
        raise UsageError("refusing to write a baseline from a truncated scan")
    if args.action == "create":
        if os.path.exists(path) and not args.force:
            raise UsageError("baseline exists; use --force to overwrite")
        baseline = Baseline.create(
            result.findings,
            reason=reason or "",
            allow_critical=args.allow_critical,
            tool_version=__version__,
            rules_hash=result.run.rules_hash,
        )
        counts = (0, 0, len(baseline.entries))
    else:
        baseline = Baseline.load(path)
        roots = [os.path.abspath(p) for p in args.resolved_paths if p != "-"]

        def in_scope(entry: str) -> bool:
            full = os.path.abspath(os.path.join(cfg.root, entry))
            return any(
                full == root or (os.path.isdir(root) and full.startswith(root + os.sep)) for root in roots
            )

        counts = baseline.update(
            result.findings,
            in_scope,
            prune=not args.no_prune,
            add_new=args.add_new,
            reason=reason,
            allow_critical=args.allow_critical,
        )
    for entry in baseline.entries:
        for key, value in entry.items():
            if isinstance(value, str):
                entry[key] = clean(value)
    baseline.save(path)
    print(f"kept {counts[0]} · pruned {counts[1]} · added {counts[2]}")
    return 0


def _check_output(checks: list[tuple[str, bool, str]], junit: str | None) -> int:
    for name, ok, message in checks:
        print(f"{'PASS' if ok else 'FAIL'} {name}: {message}")
    if junit:
        from xml.etree.ElementTree import Element, SubElement, tostring

        suite = Element("testsuite", tests=str(len(checks)), failures=str(sum(not ok for _, ok, _ in checks)))
        for name, ok, message in checks:
            case = SubElement(suite, "testcase", name=name)
            if not ok:
                SubElement(case, "failure", message=message)
        _write(tostring(suite, encoding="unicode") + "\n", junit)
    return int(any(not ok for _, ok, _ in checks))


def _rules(args: argparse.Namespace, cfg: "Config") -> int:
    import json

    from .api import load_rules
    from .errors import RuleError, UsageError
    from .model import Severity
    from .rules import fixtures
    from .rules.loader import RuleLoadError, rule_to_dict

    if args.action == "test" and not args.schema_only and not os.path.isdir(args.fixtures):
        raise UsageError("fixtures directory not found")
    ids = args.ids or None if args.action == "test" else ([args.id] if args.action == "explain" else None)
    try:
        rules = load_rules(cfg, rule_ids=ids)
    except RuleLoadError as exc:
        if args.action != "test":
            raise
        return _check_output(
            [(issue.rule_id or "rules", False, issue.code) for issue in exc.issues if issue.level == "error"],
            args.junit,
        )
    if args.action == "test":
        from .api import Scanner

        checks: list[tuple[str, bool, str]] = []
        for rule in rules:
            if not args.schema_only:
                fixture_set = fixtures.discover(args.fixtures, rule.id, rules.fixture_specs.get(rule.id))
                checks.extend((rule.id, False, p) for p in fixture_set.problems)
                test_cfg = cfg.with_overrides(
                    {
                        "scan.baseline": "",
                        "scan.min_severity": "info",
                        "scan.min_confidence": "low",
                        "suppress.require_reason": True,
                    }
                )
                from .rules.loader import RuleSet

                scanner = Scanner(RuleSet([rule]), test_cfg)
                for fixture in fixture_set.all:
                    result = scanner.scan_text(fixture.data, filename=fixture.virtual_path)
                    verdict = fixtures.evaluate(fixture, [f.line for f in result.findings])
                    checks.append((fixture.name, verdict.ok, verdict.message))
            if args.redos:
                from .rules.lint import iter_patterns

                for pattern in iter_patterns(rule_to_dict(rule)):
                    checks.append(
                        (
                            rule.id + ":" + pattern.where,
                            _redos(pattern.pattern, pattern.flags),
                            "ReDoS budget",
                        )
                    )
        return _check_output(checks, args.junit)
    selected = list(rules)
    if args.action == "list":
        selected = [
            r
            for r in selected
            if (not args.kind or not r.applies_to.kinds or args.kind in r.applies_to.kinds)
            and (not args.severity_min or r.severity >= Severity.parse(args.severity_min))
            and (not args.tag or args.tag in r.tags)
        ]
        rows = [
            {"id": r.id, "title": r.title, "pack": r.pack, "severity": r.severity.label} for r in selected
        ]
        if args.format == "json":
            print(json.dumps(rows, sort_keys=True, ensure_ascii=False))
        else:
            separator = " | " if args.format == "markdown" else "\t"
            if args.format == "markdown":
                print("| ID | Severity | Pack | Title |\n| --- | --- | --- | --- |")
            for row in rows:
                print(separator.join(str(row[k]) for k in ("id", "severity", "pack", "title")))
        return 0
    if len(selected) != 1 or selected[0].id != args.id:
        raise RuleError("rules explain requires one known exact ID")
    rule = selected[0]
    doc = rule_to_dict(rule)
    fixture_set = fixtures.discover(
        os.path.join(cfg.root, "tests", "fixtures"), rule.id, rules.fixture_specs.get(rule.id)
    )
    doc["fixture_paths"] = [f.name for f in fixture_set.all]
    if args.grep:
        import shlex

        from .rules.lint import iter_patterns

        patterns = list(iter_patterns(doc))
        if "regex" not in rule.match:
            raise UsageError("--grep is available only for regex rules")
        grep_pattern = patterns[0].pattern
        letters = "".join(flag for flag in patterns[0].flags if flag in ("i", "x"))
        if letters:
            grep_pattern = f"(?{letters})" + grep_pattern
        print(
            "rg -n -P -e "
            + shlex.quote(grep_pattern)
            + " -- "
            + " ".join(shlex.quote(p) for p in rule.applies_to.globs or (".",))
        )
    elif args.format == "json":
        print(json.dumps(doc, sort_keys=True, ensure_ascii=False))
    else:
        prefix = "## " if args.format == "markdown" else ""
        print(
            f"{prefix}{rule.id}: {rule.title}\nSeverity: {rule.severity} · Pack: {rule.pack}\n"
            f"{rule.message}\nMatcher: {json.dumps(dict(rule.match), sort_keys=True)}\n"
            f"Fixtures: {', '.join(doc['fixture_paths']) or 'none'}"
        )
    return 0


def _redos(pattern: str, flags: tuple[str, ...]) -> bool:
    import json
    import subprocess

    # Pattern passed as data on stdin, never command arguments; subprocess has a hard kill.
    script = (
        "import json,re,sys,time\n"
        "p,letters=json.load(sys.stdin); bits=re.M\n"
        "for f in letters: bits |= {'i':re.I,'s':re.S,'a':re.A,'x':re.X}.get(f,0)\n"
        "rx=re.compile(p,bits); prefix=re.match(r'[A-Za-z0-9_-]+',p.lstrip('^'))\n"
        "prefix=prefix.group() if prefix else 'literal'\n"
        "classes=re.findall(r'\\[(?:\\\\.|[^\\]\\\\])+\\]',p); representatives=[]\n"
        "for cls in classes:\n"
        " for c in 'aA019bB_ /:!@\\n':\n"
        "  if re.fullmatch(cls,c,bits): representatives.append(c); break\n"
        "chars=(representatives+list('aA0 \\n!'))[:6]\n"
        "inputs=[c*100000 for c in chars]+[(prefix*100000)[:100000], 'a'*100000+'!']\n"
        "for s in inputs:\n"
        " start=time.perf_counter(); list(rx.finditer(s))\n"
        " if time.perf_counter()-start >= .05: sys.exit(1)\n"
    )
    try:
        proc = subprocess.run(
            [sys.executable, "-c", script],
            input=json.dumps([pattern, flags]).encode(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False
    return proc.returncode == 0


def _version(args: argparse.Namespace) -> int:
    import hashlib
    import json
    import platform
    from importlib.util import find_spec

    from . import __version__

    path = os.path.join(os.path.dirname(__file__), "rules", "bundle.json")
    bundle: dict[str, Any] = {"bundle_hash": "sha256:" + hashlib.sha256(b"[]").hexdigest(), "rules": []}
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as stream:
            bundle = json.load(stream)
    counts: dict[str, int] = {}
    for rule in bundle.get("rules", []):
        pack = rule["pack"]
        counts[pack] = counts.get(pack, 0) + 1
    cache = (
        getattr(args, "cache_dir", None)
        or os.environ.get("WHALESCAN_CACHE_DIR")
        or os.path.join(os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")), "whalescan")
    )
    if getattr(args, "config", None) or os.environ.get("WHALESCAN_CONFIG"):
        cache = _config(args).cache_path
    doc: dict[str, Any] = {
        "version": __version__,
        "python": platform.python_version(),
        "platform": platform.system() + " " + platform.machine(),
        "rules": {"bundle_hash": bundle.get("bundle_hash"), "counts": counts},
        "extras": [
            name
            for name, module in (("mcp", "mcp"), ("adapters", "pip_audit"))
            if find_spec(module) is not None
        ],
        "cache_dir": cache,
    }
    if args.probe_adapters:
        import shutil
        import subprocess

        versions = {}
        for name in ("semgrep", "gitleaks", "trivy", "osv-scanner"):
            binary = shutil.which(name)
            if binary:
                try:
                    proc = subprocess.run([binary, "--version"], capture_output=True, timeout=5, check=False)
                    versions[name] = proc.stdout.decode("utf-8", "replace").strip()[:200]
                except (OSError, subprocess.TimeoutExpired):
                    versions[name] = "unavailable"
        doc["adapters"] = versions
    print(
        json.dumps(doc, sort_keys=True)
        if args.format == "json"
        else (
            f"whalescan {__version__} · Python {doc['python']} · {doc['platform']}\n"
            f"rules: {sum(counts.values())} · {bundle.get('bundle_hash')}\n"
            f"extras: {', '.join(doc['extras']) or 'none'}\ncache: {cache}"
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = None
    cfg = None
    result = None
    code = 3
    try:
        args = _parser().parse_args(argv)
        if args.command == "version":
            code = 0
            return _version(args)
        cfg = _config(args)
        _logging(cfg)
        if args.command == "rules":
            code = 0
            return _rules(args, cfg)
        result = _scan(args, cfg)
        if args.command == "baseline":
            code = 0
            return _baseline(args, cfg, result)
        code = result.exit_code(cfg.scan.fail_on)
        if cfg.adapters.strict and any(
            d.code in ("adapter-missing", "adapter-failed") for d in result.diagnostics
        ):
            code = 3
        result.run.exit_code = code
        from .matchers.unicode import reveal

        result.run.argv = [
            reveal(result.run._sweep(arg) if result.run._sweep is not None else arg)
            for arg in (sys.argv[1:] if argv is None else argv)
        ]
        _reports(result, args, cfg)
        if args.profile:
            print("profile: top rules by cumulative matching time", file=sys.stderr)
            for rule_id, (elapsed, hits) in sorted(result.run._profile.items(), key=lambda item: -item[1][0])[
                :20
            ]:
                print(f"{rule_id}: {elapsed:.3f} ms · {hits} hits", file=sys.stderr)
        return code
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115 -- kept for interpreter flush
        return code
    except Exception as exc:
        from .errors import WhalescanError

        code = exc.exit_code if isinstance(exc, WhalescanError) else 3
        if (
            code == 3
            and args is not None
            and args.command in ("scan", "inject", "secrets", "baseline")
            and getattr(args, "format", None) in ("json", "sarif")
        ):
            from .config import Config
            from .model import RunInfo, ScanResult, Stats

            if result is None:
                result = getattr(exc, "partial_result", None) or ScanResult((), (), Stats(), RunInfo())
            if result.run.error is None:
                result.run.error = {"type": type(exc).__name__, "message": "operation failed (see stderr)"}
            result.run.exit_code = 3
            import contextlib

            with contextlib.suppress(OSError, WhalescanError):
                _reports(result, args, cfg or Config.default())
        # Exception strings can contain raw match text; don't print arbitrary exception messages.
        if code == 3:
            print(f"whalescan: internal error: {type(exc).__name__} (rerun with -vv)", file=sys.stderr)
            if args is not None and getattr(args, "v", 0) >= 2:
                import traceback

                print("Traceback (most recent call last):", file=sys.stderr)
                for frame in traceback.extract_tb(exc.__traceback__):
                    print(f"  File {frame.filename!r}, line {frame.lineno}, in {frame.name}", file=sys.stderr)
                print(type(exc).__name__ + ": operation failed", file=sys.stderr)
        else:
            from .matchers.unicode import reveal

            print("whalescan: " + reveal(str(exc)), file=sys.stderr)
        return code
