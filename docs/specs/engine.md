# whalescan — Engine Specification

This document specifies `whalescan`, the deterministic Python scanner behind every WhaleSecurity
surface: the CLI, the Claude Code hooks, the audit skills and agents, the GitHub Action and the
pre-commit hook. It fixes the module layout, CLI contract, configuration, file discovery and
classification, rule format, matcher semantics, finding identity, severity, suppression, output
formats, adapters, performance budgets, the public Python API, and failure behavior. The goal is
that the engine can be implemented and tested without further design decisions. The spec is
normative for v1.0. MUST, SHOULD and MAY follow RFC 2119. Deviations from `docs/DESIGN.md` are
listed in §19.

**Contents**
1. Package and module layout · 2. CLI · 3. Configuration · 4. `.whalescanignore` · 5. Walker ·
6. File classifier · 7. Rule format · 8. Matchers · 9. Dedupe and fingerprinting ·
10. Severity model · 11. Suppressions and baseline · 12. Reporters · 13. Secret redaction ·
14. Adapters · 15. Performance · 16. Public Python API · 17. Errors and exit codes ·
18. Logging · 19. Refinements to DESIGN.md

---

## 1. Package and module layout

```
engine/
├── pyproject.toml
└── src/whalescan/
    ├── __init__.py          public API re-exports (§16), __version__
    ├── __main__.py          `python -m whalescan` → cli.main()
    ├── cli.py               argparse tree, dispatch, exit-code mapping (§2, §17)
    ├── api.py               Scanner, scan_text, scan_injection, module-level cached scanner
    ├── model.py             frozen dataclasses: Rule, Hit, Finding, FileCtx, ScanResult, Diagnostic
    ├── config.py            discovery, merge, validation, trust boundary (§3)
    ├── ignore.py            gitignore-syntax compiler, shared by the walker and .whalescanignore (§4)
    ├── walker.py            file enumeration (§5)
    ├── textio.py            BOM/encoding, binary sniff, line index, offset → (line, col)
    ├── classify.py          path + content → lang, kind, tags (§6)
    ├── rules/
    │   ├── loader.py        YAML/JSON load, pack selection, semantic checks (§7.3)
    │   ├── schema.py        rule JSON Schema (§7.2) + stdlib validator for the keywords it uses
    │   ├── lint.py          regex safety lint R1–R7 (§8.2)
    │   ├── cache.py         normalized-rule cache (§15.2)
    │   └── bundle.json      pre-validated built-in rules, generated from /rules at release
    ├── matchers/
    │   ├── base.py          Matcher protocol, Hit, combinators all/any/not/near_lines (§8.1)
    │   ├── regex.py  multiline.py  unicode.py  unicode_data.py  entropy.py
    │   ├── yamlpath.py      path grammar + predicates over yamlite nodes (§8.6)
    │   ├── pyast.py         stdlib `ast`: call patterns, local taint, fastapi_route (§8.7)
    │   └── hcl.py           predicates over hcllite blocks (§8.8)
    ├── yamlite.py           YAML subset parser with source positions (no dependencies)
    ├── hcllite.py           HCL2 tokenizer + block parser, *.tf.json reader
    ├── dedupe.py            fingerprints, overlap resolution, cross-source merge (§9)
    ├── severity.py          base × reachability × exposure (§10)
    ├── suppress.py          inline suppressions + baseline file (§11)
    ├── redact.py            secret redaction, hidden-codepoint reveal, output sweep (§13)
    ├── report/
    │   ├── text.py  json.py  sarif.py  markdown.py
    │   └── schemas/         finding-1.json  report-1.json  baseline-1.json  mcp-pins-1.json
    ├── adapters/
    │   ├── base.py          Adapter protocol, sandboxed subprocess runner (§14)
    │   └── semgrep.py  gitleaks.py  trivy.py  osv.py
    ├── mcp_pin.py           mcp pin / verify (§2.5)
    ├── errors.py            exception hierarchy → exit codes (§17)
    ├── log.py               logging setup, redacting filter (§18)
    └── _vendor/tomli/       MIT, imported only on Python 3.10 (tomllib is 3.11+)
```

```toml
# engine/pyproject.toml (excerpt)
[project]
name = "whalescan"
requires-python = ">=3.10"
dependencies = []                                  # stdlib-only core, a hard CI gate
[project.optional-dependencies]
ast = []                                           # reserved for the post-v1 tree-sitter tier
adapters = ["pip-audit>=2.7"]                      # other adapters are external binaries
mcp = ["mcp>=1.2"]                                 # only for `mcp pin/verify --live`
[project.scripts]
whalescan = "whalescan.cli:main"
```

**Import discipline.** At import time `cli.py` imports only `argparse`, `os` and `sys`. Every
other module is imported inside the subcommand handler that needs it. `ast`, `json`,
`concurrent.futures` and `hashlib` load lazily. CI asserts `python -X importtime -m whalescan
version` stays under 80 ms.

---

## 2. CLI

```
whalescan [GLOBAL OPTIONS] <command> [ARGS]
  scan · inject · secrets · mcp {pin,verify} · baseline {create,update} · rules {list,test,explain} · version
```

**Global options.** These are accepted before or after the command.

| Flag | Default | Meaning |
|---|---|---|
| `-c, --config PATH` | discovered (§3.1) | Project config file |
| `--no-project-config` | off | Ignore `.whalesecurity/config.toml`. Use this for untrusted checkouts |
| `--rules-dir DIR` (repeatable) | — | Extra rule directories (YAML packs) |
| `--root DIR` | git toplevel, else cwd | Base for relative output paths and project config |
| `-q` / `-v` / `-vv` | warning | Log level error / info / debug |
| `--log-format text\|json` | text | stderr log format (§18) |
| `--color auto\|always\|never` | auto | `auto` is off when `NO_COLOR` is set or stdout is not a TTY |
| `--no-cache`, `--cache-dir DIR` | cache on | Rule cache (§15.2) |

**Scan options.** Shared by `scan`, `inject`, `secrets` and `baseline`. Size values accept `K`,
`M` and `G` suffixes (binary units).

| Flag | Default | Meaning |
|---|---|---|
| `PATHS...` | `.` | Files or directories. `-` means stdin (§2.8) |
| `--stdin`, `--stdin-filename NAME` | `<stdin>` | Read one document from stdin. NAME is the virtual path |
| `-f, --format` | `text` | `text\|json\|jsonl\|sarif\|markdown` |
| `-o, --output PATH` | stdout | Primary report destination |
| `--also FORMAT=PATH` (repeatable) | — | Extra reports from the same run, e.g. `--also sarif=out.sarif` |
| `--packs LIST` | config | Comma-separated selectors: `appsec`, `domain/*`, `-domain/trading` (removes) |
| `--rule ID`, `--exclude-rule ID` (repeatable, glob) | — | Restrict or remove rules, e.g. `--rule 'WS-K8S-*'` |
| `--fail-on SEV\|never` | `high` | Severity at or above which the run exits 1 |
| `--min-severity SEV` / `--min-confidence C` | `low` / `low` | Drop findings below these from the output |
| `--baseline PATH` / `--no-baseline` | `.whalesecurity/baseline.json` if present | §11.3 |
| `--show-suppressed` | off | Include suppressed findings, marked with `suppressed` |
| `--diff REF` / `--staged` | — | Only files changed vs REF (`git diff --name-only -z --diff-filter=ACMR REF`) or the index |
| `--diff-lines` | off | Also drop findings outside added or modified hunks |
| `--files-from PATH\|-` | — | Path list, NUL-separated if it contains `\0`, else newline-separated |
| `--include GLOB` / `--exclude GLOB` (repeatable) | — | gitignore-syntax filters on top of ignore files |
| `--no-gitignore`, `--follow-symlinks` | off | §5 |
| `--max-file-size`, `--max-files` | 1M, 50000 | §5.3 |
| `-j, --jobs N` | 0 = auto | §15.3 |
| `--time-budget-ms N` | 0 = none | Stop early and mark the run `truncated` (§15.4) |
| `--adapters LIST\|auto\|none`, `--adapters-strict` | none | §14 |
| `--deterministic` | off | Zero out timestamps and durations, for golden tests |
| `--profile` | off | Per-rule timing, top 20, printed to stderr |

### 2.1 `scan`
This command runs the configured packs (default `appsec, secrets, domain, agentsec`; agentsec
rules apply only to the kinds they declare). It is the command used by `/whale-audit`, CI and
pre-commit.

```bash
whalescan scan                                                    # repo, text, fail on high
whalescan scan services/pricing-api -f sarif -o whalescan.sarif --fail-on critical
whalescan scan --diff origin/main --diff-lines -f markdown -o pr-comment.md    # PR gate
whalescan scan infra/live deploy/k8s --packs domain/terraform,domain/k8s --also json=out/iac.json
git show HEAD:dags/etl_orders.py | whalescan scan - --stdin-filename dags/etl_orders.py -f jsonl
whalescan scan --adapters auto -j 8 .
```

### 2.2 `inject`
Scans untrusted content (web pages, MCP/tool output, docs, agent instruction files) with the
`agentsec` pack only.

- Inline suppressions are **never** honored (§11.1). Baseline and config suppressions still apply.
- `--source LABEL` is stored as `properties.source_label` on each finding (`web:<url>`,
  `mcp:<server>/<tool>`, `bash:<argv0>`, `file:<path>`, `rag:<collection>`).
- `--reveal` is on by default. Snippets show hidden code points as `[ZWSP]`, `[TAG:"…"]`,
  `[BIDI:RLO]` and so on. `--reveal-out PATH|-` writes the whole input with those markers.
- `--max-bytes N` (default `inject.max_bytes`, 2 MiB). Input above N is scanned as its first
  N/2 and last N/2 bytes. The run then gets `stats.truncated=true` and an `input-truncated`
  diagnostic, so padding cannot push a payload out of view unannounced.
- Input with no path, or with the `<stdin>` name, is classified as `kind=doc`.

```bash
curl -sL https://wiki.example.com/runbook | whalescan inject --source web:https://wiki.example.com/runbook -f json
whalescan inject CLAUDE.md AGENTS.md .claude/ docs/ --fail-on medium
whalescan inject vendor_notes.md --reveal-out -        # show where the hidden characters are
```

### 2.3 `secrets`
Runs the `secrets` pack only (provider patterns plus entropy). `--git-history [--since REV]
[--max-commits N=1000]` scans the added lines of `git log -p -U0 --no-color --no-ext-diff
--format=%x00%H REV..HEAD` and sets `properties.commit`. `.env.example`-style files are scanned at
confidence `low`.

```bash
whalescan secrets --no-gitignore                              # includes local .env files
whalescan secrets --git-history --since v1.4.0 -f sarif -o secrets.sarif
terraform show -json plan.out | whalescan secrets - --stdin-filename plan.json   # secrets in a TF plan
```

### 2.4 `baseline create | update`
```bash
whalescan baseline create [PATHS] [scan options] [--baseline-out PATH] --reason TEXT [--force] [--allow-critical]
whalescan baseline update [PATHS] [scan options] [--no-prune] [--add-new --reason TEXT]
```
- `create` refuses to overwrite an existing file unless `--force` is given (exit 2).
- `update` prunes entries that were not re-found. It only prunes entries whose `path` was inside
  the scanned scope, so a partial scan never deletes unrelated entries.
- `--add-new` adds unmatched findings.
- `critical` findings are never baselined unless `--allow-critical` is given.
- Both commands print `kept N · pruned M · added K`.

### 2.5 `mcp pin | verify`
```bash
whalescan mcp pin    [--mcp-config PATH]... [--server NAME]... [--pins PATH] [--live] [--from-json PATH|-] [--timeout-s 10]
whalescan mcp verify [same options] [-f FORMAT] [--fail-on SEV] [--strict]
```
- **Server discovery.** Reads the `mcpServers` object of each `mcp.config_files` entry (default
  `.mcp.json`, `~/.claude.json`). For `~/.claude.json` it also reads `projects["<root>"].mcpServers`.
- **Tool metadata.** `--live` (requires the `[mcp]` extra and trusted config) starts stdio
  servers or connects to http servers, then calls `initialize` and a paginated `tools/list`. Each
  server has a hard timeout. `--from-json` instead reads `{"<server>": {"tools": [<tools/list
  items>]}}`. With neither flag, only the server config is pinned and verified. This fast mode is
  what the `mcp_verify.py` SessionStart hook runs.
- **Canonical JSON.**
  `canon(x) = json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.
  No Unicode normalization is applied, so hidden code points change the hash.
- **Hashes.**
  - `config_sha256 = sha256(canon({transport, command, args, url, env_keys: sorted(env), header_keys: sorted(headers)}))`.
    Environment and header *values* are excluded because they are secrets.
  - Tool `sha256 = sha256(canon({name, title, description, inputSchema, outputSchema, annotations}))`.

```json
{"schema": "whalescan/mcp-pins@1", "updated_at": "2026-09-29T10:00:00Z",
 "servers": {"jira": {"source": ".mcp.json", "transport": "stdio", "config_sha256": "…64 hex…",
   "tools": {"get_issue": {"sha256": "…64 hex…", "description_chars": 412}}, "pinned_at": "2026-09-29T10:00:00Z"}}}
```

`verify` emits findings through `builtin: mcp_drift` rules in `rules/agentsec/mcp.yaml`. The
finding location is the server entry in the config file. The agentsec pack also runs over every
added or changed description, with `source_label=mcp:<server>/<tool>`.

| Rule | Condition | Severity |
|---|---|---|
| `WS-AGT-MCP-001` | Pinned tool's description or schema hash changed (`properties.diff`: revealed unified diff, ≤4 KiB) | high |
| `WS-AGT-MCP-002` | New tool on a pinned server | medium |
| `WS-AGT-MCP-003` | Server config hash changed (command, args, url, env keys) | high |
| `WS-AGT-MCP-004` | Server configured but not pinned | medium |
| `WS-AGT-MCP-005` | Pinned tool removed | low |

An unreachable server in `--live` mode produces an `mcp-unreachable` diagnostic. With
`--strict` it exits 3.

### 2.6 `rules list | test | explain`
```bash
whalescan rules list [--packs P] [--kind K] [--severity-min SEV] [--tag T] [-f table|json|markdown]
whalescan rules test [RULE_ID|GLOB ...] [--fixtures tests/fixtures] [--redos] [--schema-only] [--junit PATH]
whalescan rules explain RULE_ID [-f text|json|markdown] [--grep]
```

**`rules test`** checks every selected rule as follows:
1. Schema, lint (§8.2) and semantic checks (§7.3).
2. Each `tests/fixtures/<ID>/pos*.*` fixture produces at least one hit.
   - If the fixture carries `expect:` annotations, the set of hit start lines MUST equal the set
     of annotated lines. An annotation looks like `# expect: WS-INJ-003`, and is matched by
     `(?:#|//|--|<!--)[ \t]*expect:[ \t]*(?P<ids>WS-[A-Z0-9-]+(?:[ \t]*,[ \t]*WS-[A-Z0-9-]+)*)`.
   - Comment-less JSON uses a sidecar `expect.json`: `{"pos.json": {"WS-AGT-MCP-010": [4]}}`.
3. Each `neg*.*` fixture produces zero hits.

A first-line directive `# whalescan-fixture: path=.github/workflows/pr.yml` sets the fixture's
virtual path. Glob-restricted rules need it.

`--redos` runs each pattern against eight generated 100 KB adversarial strings in a subprocess
with a 2 s hard kill. The strings are runs of each character class in the pattern, the literal
prefix repeated, and `"a"*N + "!"`. Each string MUST finish in under 50 ms.

Exit codes: 0 when all rules pass, 1 when any fails, 2 for an unknown ID or missing fixtures
directory.

**`rules explain`** prints the rule's metadata, a matcher summary and its fixture paths.
`--grep` prints an equivalent ripgrep command for regex rules. The command always has the form
`rg -n -P -e <shlex-quoted pattern> -- <paths>`. `-e` and `--` keep dash-leading patterns such as
`-----BEGIN` from being parsed as flags.

### 2.7 `version`
`whalescan version [-f text|json] [--probe-adapters]` reports the version, Python, platform,
`rules.bundle_hash`, rule counts per pack, installed extras and the cache dir. With
`--probe-adapters` it also reports the adapter binary versions; this runs subprocesses and is
slow.

### 2.8 Stdin conventions
- `-` (or `--stdin`) may appear at most once. Stdin is read as bytes and decoded as in §5.5, up
  to `scan.max_stdin_bytes` (16 MiB). `inject` uses `inject.max_bytes`.
- `--stdin-filename` drives classification, `applies_to.glob`, `.whalescanignore` and the
  output `file`. With the default `<stdin>`, classification is by content sniff only and
  glob-restricted rules do not run.
- `inject` and `secrets` read stdin implicitly when PATHS is empty and stdin is not a TTY. `scan`
  never does, so it cannot hang in CI.
- `--files-from -` and `mcp … --from-json -` read their lists from stdin instead.

---

## 3. Configuration (`.whalesecurity/config.toml`)

### 3.1 Discovery, precedence, trust
- **Project config.** `--config` → `$WHALESCAN_CONFIG` → the first `.whalesecurity/config.toml`
  found walking up from cwd. The walk stops at a directory containing `.git`, at `$HOME`, or at `/`.
- **User config.** `$XDG_CONFIG_HOME/whalescan/config.toml` (default `~/.config/whalescan/`).
- **Precedence.** built-in defaults < user < project < env < CLI.
- **Merging.** Tables deep-merge. Scalars and arrays replace. Three keys merge instead:
  `rules.enable` and `rules.disable` are unioned, and `severity.overrides` is dict-updated.
- **Trust boundary.** Some keys cause code execution, network access, or writes outside the repo.
  These keys are honored **only** from user config, env or CLI: `adapters.*.bin`,
  `adapters.*.args`, `adapters.*.env`, `adapters.osv.allow_network`, `mcp.live`, `cache.dir`,
  `logging.file`. When project config sets one, the value is ignored and a
  `config-untrusted-key` diagnostic is emitted. Project config that disables rules or lowers
  severities is honored, but every such change is listed in `run.config_changes` of each report
  so auditors can see it.
- **Validation.** Type and enum errors exit 2 with a message such as
  `scan.fail_on: expected one of critical|high|medium|low|info|never`. Unknown keys produce a
  `config-unknown-key` warning. `schema` greater than the supported version exits 2.

**Env vars:** `WHALESCAN_CONFIG`, `WHALESCAN_NO_PROJECT_CONFIG=1`, `WHALESCAN_FAIL_ON`,
`WHALESCAN_PACKS`, `WHALESCAN_JOBS`, `WHALESCAN_CACHE_DIR`, `WHALESCAN_NO_CACHE=1`,
`WHALESCAN_LOG_LEVEL`, `NO_COLOR`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`.

### 3.2 Full schema with defaults
```toml
schema = 1                                   # required int

[scan]
packs            = ["appsec", "secrets", "domain", "agentsec"]
fail_on          = "high"                    # critical|high|medium|low|info|never
min_severity     = "low"
min_confidence   = "low"                     # high|medium|low
jobs             = 0                         # 0 = min(os.cpu_count(), 8)
time_budget_ms   = 0                         # 0 = unlimited
include          = []                        # globs; empty = all
exclude          = []                        # gitignore syntax, appended after .whalescanignore
walker           = "auto"                    # auto|git|fs  (§5.1)
respect_gitignore = true
follow_symlinks  = false
max_file_bytes   = 1_048_576
max_files        = 50_000
max_total_bytes  = 536_870_912
max_stdin_bytes  = 16_777_216
baseline         = ".whalesecurity/baseline.json"
diff_lines_only  = false
skip_minified    = true                      # only secrets rules run on minified files

[rules]
extra_dirs = [".whalesecurity/rules"]        # data only; relative to project root
enable     = []                              # IDs/globs forced on (incl. enabled_by_default=false)
disable    = []                              # IDs/globs

[severity]
overrides = {}                               # { "WS-DKR-003" = "low" } replaces the base severity
[severity.exposure]                          # first matching class wins, in this order
test     = ["tests/**", "test/**", "**/test_*.py", "**/*_test.py", "**/conftest.py",
            "**/fixtures/**", "examples/**", "docs/**", "**/.env.example"]
vendored = ["vendor/**", "third_party/**", "**/site-packages/**", "**/node_modules/**"]
internet = ["**/routers/**", "**/routes/**", "**/api/**", "**/webhooks/**", "**/ingress*.y*ml",
            "**/nginx/**", "**/traefik/**"]
internal = ["scripts/**", "tools/**", "ops/**", "notebooks/**"]

[classify]
rules = []   # [{ glob = "platform/manifests/**/*.yaml", kind = "iac", lang = "yaml", tags = ["k8s"] }]

[suppress]
require_reason   = true
min_reason_chars = 10
allow_file_level = true
allow_wildcard   = false                     # permit whalescan:ignore[*]
max_block_lines  = 200
report_unused    = false

[secrets]
allow_values     = []                        # regexes; a secret fully matching one is dropped
entropy_delta    = 0.0                       # added to every entropy threshold (-1.0..+1.0)

[inject]
max_bytes = 2_097_152
reveal    = true

[adapters]
enabled   = []                               # semgrep|gitleaks|trivy|osv, or ["auto"]
timeout_s = 300
strict    = false
[adapters.semgrep]   # bin = "semgrep"   args = ["--config", "p/default"]      (trusted-only)
[adapters.gitleaks]  # bin = "gitleaks"  args = []                             (trusted-only)
[adapters.trivy]     # bin = "trivy"     scanners = ["vuln", "misconfig"]
[adapters.osv]       # backend = "osv-scanner"  # osv-scanner|pip-audit|api; allow_network = false

[mcp]
pins         = ".whalesecurity/mcp-pins.json"
config_files = [".mcp.json", "~/.claude.json"]
live         = false                         # trusted-only
timeout_s    = 10

[report]
format                  = "text"
max_snippet_chars       = 240
markdown_max_findings   = 200
sarif_include_all_rules = false
sarif_absolute_root     = false              # never embed local absolute paths by default

[cache]
enabled = true
dir     = ""                                 # "" = $XDG_CACHE_HOME/whalescan (trusted-only)

[logging]
level  = "warning"
format = "text"
file   = ""                                  # trusted-only

[hooks]                                      # reserved; schema owned by the hooks spec
```

---

## 4. `.whalescanignore`

- **Syntax.** Identical to gitignore and compiled by the same `ignore.py`:
  - `#` starts a comment and `\#` escapes it. Trailing spaces are trimmed unless escaped.
  - `!` negates. A trailing `/` means directories only.
  - A pattern containing a non-trailing `/` is anchored to the ignore file's directory.
    Otherwise it matches a basename at any depth.
  - `*` compiles to `[^/]*`, `?` to `[^/]`, `[…]` is a character class, `**/` matches any
    leading directories, `/**` everything inside, and `/**/` zero or more directories.
  - The last matching pattern wins. Ignore files are applied from the root down to the deepest
    directory.
  - A file under an excluded directory cannot be re-included; this matches git.
- **Location.** `.whalescanignore` files may appear in any directory and apply to that subtree.
- **Rule-scoped sections (extension).** A line `#!rules WS-AGT-*,WS-SEC-GEN-*` starts a section
  whose patterns apply only to the listed rule IDs or globs. `#!rules *` returns to all rules.
  The directive is a comment to git and other tools.
- **Differences from `.gitignore`.**
  1. `.whalescanignore` applies to **explicit** paths and to `--stdin-filename`, so the
     `scan_edit.py` hook stays quiet on `tests/fixtures/`. `.gitignore` applies only during
     directory traversal; an explicitly named file is scanned even if gitignored.
  2. `.git/` is always excluded and cannot be negated.
- **Built-in excludes** (lowest priority, negatable):
  `node_modules/ .venv/ venv/ __pycache__/ .tox/ .mypy_cache/ .ruff_cache/ .terraform/
  .terragrunt-cache/ dist/ build/ target/ .idea/ *.min.js.map`.

```gitignore
# repo root: self-scan must be clean (DESIGN §9 gate 4)
rules/
tests/fixtures/
evals/corpus/
evals/injection-corpus/
#!rules WS-SEC-*
docs/examples/**/*.env
#!rules *
```

---

## 5. Walker

### 5.1 Enumeration
```python
def walk(roots, cfg, ign) -> Iterator[Candidate]:
    for root in dedupe_preserving_order(roots):
        if root == STDIN: yield stdin_candidate(cfg); continue
        st = os.lstat(root)                                 # FileNotFoundError → UsageError (exit 2)
        if stat.S_ISREG(st.st_mode):                        # explicit file: .gitignore not applied
            if not ign.whalescanignored(rel(root)): yield file_candidate(root, st)
            continue
        if stat.S_ISLNK(st.st_mode): yield from symlink_policy(root, roots, cfg); continue
        rels = git_ls_files(root) if use_git(root, cfg) else fs_walk(root, ign)
        for r in rels:
            if ign.ignored(r) or not cfg.included(r): continue
            yield from caps_and_candidate(r)                # §5.3; stops at max_files

def fs_walk(top, ign):                                      # used when walker="fs" or git unavailable
    stack = [top]
    while stack:
        d = stack.pop()
        with os.scandir(d) as it:
            entries = sorted(it, key=lambda e: e.name.encode("utf-8", "surrogateescape"))
        for e in reversed(entries):                         # LIFO → lexicographic visit order
            if e.name == ".git": continue
            if e.is_symlink(): yield from symlink_policy(e.path, ...); continue
            if e.is_dir(follow_symlinks=False):
                if not ign.ignored(rel(e.path), is_dir=True): stack.append(e.path)
            elif e.is_file(follow_symlinks=False):
                yield rel(e.path)                           # FIFOs, sockets, devices never yielded
```

`walker="auto"` uses `git ls-files --cached --others --exclude-standard -z` (one subprocess,
which honors global and `info/exclude` rules) when the root is inside a work tree, `git` is on
PATH, and `respect_gitignore` is true. Otherwise it uses `fs_walk` with the built-in gitignore
compiler. Submodule gitlinks are skipped and logged at info level. Paths are POSIX, relative to
`--root`. Explicit paths outside the root are reported as absolute paths.

### 5.2 Symlink policy
- **Default.** Symlinks, both file and directory, are not followed. They are counted as
  `skipped.symlink`.
- **`--follow-symlinks`.** A link is followed only if `os.path.realpath(target)` lies inside one
  of the scan roots. Directory cycles are prevented by a `(st_dev, st_ino)` visited set.
- **Escaping links** are always skipped with a `symlink-escape` warning. An example is
  `config -> ~/.aws/credentials` in a cloned repo. The scanner MUST NOT read outside its roots,
  because redaction is a second line of defense, not the first.

### 5.3 Size caps and special files
| Cap | Default | On exceed |
|---|---|---|
| Regular files only (`S_ISREG` after `lstat`) | — | Other types are skipped silently. Opening a FIFO would hang the hook |
| `max_file_bytes` | 1 MiB | Skip, `skipped.too_large` + info diagnostic |
| `max_files` | 50 000 | Stop enumeration, `truncated=true`, `max-files-reached` warning |
| `max_total_bytes` | 512 MiB | Same as `max_files` |
| py_ast parse | 512 KiB | py_ast rules skip the file; text rules still run |
| yamlite parse | 2 MiB, depth 64, 200k nodes, 10k alias expansions | `parse-error`; structured rules skip the file |

Files are opened with `O_RDONLY | O_NOFOLLOW` (where available) and read in one `read()` call,
capped at `max_file_bytes + 1`.

### 5.4 Binary detection
```python
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz", ".bz2",
              ".xz", ".zst", ".7z", ".jar", ".war", ".class", ".whl", ".so", ".dylib", ".dll", ".exe",
              ".o", ".a", ".pyc", ".parquet", ".orc", ".avro", ".npy", ".npz", ".pkl", ".onnx",
              ".safetensors", ".pt", ".db", ".sqlite", ".p12", ".pfx", ".jks", ".woff", ".woff2"}

def sniff(head: bytes, name: str) -> tuple[bool, str | None]:        # (is_binary, bom_encoding)
    if suffix(name) in BINARY_EXT: return True, None
    for bom, enc in BOMS: 
        if head.startswith(bom): return False, enc                    # UTF-16/32 contain NULs
    if b"\x00" in head: return True, None
    ctrl = sum(1 for b in head if b < 0x09 or 0x0E <= b < 0x20 and b != 0x1B or b == 0x7F)
    return (len(head) > 0 and ctrl / len(head) > 0.30), None          # head = first 8 KiB
```

### 5.5 Encoding and BOM handling
| BOM bytes (checked in this order) | Codec | Note |
|---|---|---|
| `00 00 FE FF` | utf-32-be | |
| `FF FE 00 00` | utf-32-le | Must be tested before UTF-16 LE |
| `EF BB BF` | utf-8 | BOM stripped, `bom="utf-8"` |
| `FE FF` / `FF FE` | utf-16-be / utf-16-le | Common in Windows-exported SQL and PowerShell |

1. If there is a BOM, it is stripped and the rest is decoded with that codec and
   `errors="replace"`. Any U+FFFD produced adds a `decode-replaced` diagnostic.
2. With no BOM, strict UTF-8 is tried.
3. If that fails, the file is decoded as latin-1, which is lossless and one char per byte. The
   file gets the `encoding_fallback` flag and a `decode-fallback-latin1` diagnostic. The
   `unicode` matcher is disabled for that file, because its code points are meaningless.

Text is never newline-normalized: CRLF files keep their `\r`, and matchers see the exact content.
Only `\n` is a line break for positions. `\r\n` works naturally. A lone `\r`, U+2028 and U+0085
are not line breaks (unlike `str.splitlines`), so line numbers agree with editors, git and SARIF
viewers.

### 5.6 Positions
```python
line_starts = [0] + [i + 1 for i, ch in enumerate(text) if ch == "\n"]     # built with str.find loop
def pos(off):                                  # 1-based (line, col); col counts Unicode code points
    i = bisect_right(line_starts, off) - 1
    return i + 1, off - line_starts[i] + 1
def end_pos(end):                              # exclusive end → column after the last char
    line, col = pos(end - 1)
    return line, col + 1
```
Columns count **code points**, not UTF-16 units. SARIF declares `columnKind:
"unicodeCodePoints"`.

### 5.7 File flags
- `generated`: the first 5 lines match `(?i)@generated\b|\bDO NOT EDIT\b|\bauto-?generated\b`.
- `minified`: size > 20 KiB and mean line length > 1000, or the name matches `\.min\.(?:js|css)$`.
- `test`: the path matches
  `(?:^|/)(?:tests?|__tests__|spec|specs|fixtures?|testdata)/|(?:^|/)(?:test_[^/]*\.py|[^/]*_test\.(?:py|go)|conftest\.py|[^/]*\.(?:spec|test)\.[jt]sx?)$`.

---

## 6. File classifier

`classify(path, head_text) -> (lang, kind, tags)`, where kind is one of `code | iac | ci |
agent-config | doc | data`. Steps run in order:

1. `[classify].rules` from config (first match).
2. Path table A.
3. Extension table B.
4. Content sniff C, over the first 64 KiB.
5. Fallback `text`/`data`.

The first decisive step sets `lang` and `kind`. Tags accumulate from every step, plus the §5.7
flags. For multi-document YAML the highest kind wins: `ci > iac > agent-config > code > doc > data`.

| A · Path pattern | lang | kind | tags |
|---|---|---|---|
| `.github/workflows/*.{yml,yaml}` | yaml | ci | gha |
| `**/action.{yml,yaml}` | yaml | ci | gha-action |
| `.tekton/**/*.{yml,yaml}` | yaml | ci | tekton |
| `.gitlab-ci.yml`, `.circleci/config.yml`, `azure-pipelines.yml`, `bitbucket-pipelines.yml`, `Jenkinsfile` | yaml / groovy | ci | ci-other |
| `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `**/SKILL.md`, `.claude/{commands,agents}/**/*.md`, `.cursorrules`, `.cursor/rules/**`, `.windsurfrules`, `.clinerules` | markdown | agent-config | agent-instructions |
| `.mcp.json`, `**/mcp.json`, `.vscode/mcp.json` | json | agent-config | mcp |
| `.claude/settings*.json`, `.claude-plugin/*.json`, `**/hooks/hooks.json` | json | agent-config | agent-settings |
| `Dockerfile`, `Dockerfile.*`, `*.Dockerfile`, `Containerfile` | dockerfile | iac | docker |
| `{docker-compose,compose}*.{yml,yaml}` | yaml | iac | compose |
| `**/Chart.yaml`; `values*.yaml` and `templates/**` beside a `Chart.yaml` | yaml | iac | helm, helm-template |
| `terragrunt.hcl` | hcl | iac | terragrunt |
| `kustomization.{yml,yaml}` | yaml | iac | k8s, kustomize |
| `**/{playbooks,roles,group_vars,host_vars}/**/*.{yml,yaml}`, `site.yml`, `playbook*.yml`, `ansible.cfg` | yaml / ini | iac | ansible |
| `nginx.conf`, `**/nginx/**/*.conf`, `**/{sites-available,sites-enabled,conf.d}/*` | nginx | iac | nginx |
| `traefik.{yml,yaml,toml}`, `**/traefik/**/*.{yml,yaml,toml}` | yaml / toml | iac | traefik |
| `dags/**/*.py`, `**/airflow/**/*.py` | python | code | airflow-dag |
| `.env`, `.env.*`, `*.env` | dotenv | data | env (+ `example` for `.example/.sample/.template/.dist`) |
| `requirements*.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `go.sum`, `Cargo.lock` | varies | data | lockfile |

| B · Extension | lang | kind |
|---|---|---|
| `.py .pyi` / `.ipynb` | python / json (+notebook) | code |
| `.scala .sc .sbt` · `.java .kt .go .rs .rb .php .cs` | scala · per extension | code |
| `.js .mjs .cjs .jsx` / `.ts .tsx` | javascript / typescript | code |
| `.sql` · `.sh .bash .zsh .ksh` · `.ps1` | sql · shell · powershell | code |
| `.j2 .jinja .jinja2 .tpl` | jinja | code (template) |
| `.tf` · `.tf.json` · `.tfvars` · `.hcl` | hcl · json · hcl · hcl | iac (+terraform) |
| `.yml .yaml` · `.json` · `.toml` · `.ini .cfg .conf .properties` · `.xml` · `.csv .tsv` | yaml · json · toml · ini · xml · csv | data (then sniff) |
| `.pem .key .crt .asc` | text (+key-material) | data |
| `.md .mdx .markdown` · `.rst .adoc .txt` · `.html .htm .xhtml .svg` | markdown · rst/text · html/xml | doc |

| C · Content sniff (first 64 KiB) | Effect |
|---|---|
| YAML doc with `^apiVersion:` and `^kind:` | iac + k8s. `tekton.dev/` → ci + tekton. `*.toolkit.fluxcd.io/` → ci + flux. `kind: (Cluster)?Role(Binding)?\|CustomResourceDefinition` adds k8s-rbac / k8s-crd |
| YAML with top-level `on:` and `jobs:` (outside `.github/workflows/`) | ci + gha |
| YAML with top-level `services:` whose children have `image:` or `build:` | iac + compose |
| YAML whose top level is a sequence with `hosts:` / `tasks:` | iac + ansible |
| JSON with top-level `"mcpServers"` | agent-config + mcp |
| JSON/YAML with `AWSTemplateFormatVersion` or `Type: AWS::…` resources | iac + cloudformation |
| JSON with `"format_version"` and `"terraform_version"` | data + terraform-plan |
| Python `^[ \t]*(?:from\|import)[ \t]+(?:fastapi\|starlette)\b` / `airflow\b` / `pyspark\b` | + fastapi / airflow-dag / spark |
| Python importing `boto3` with `bedrock-runtime`, `vertexai`, `google.cloud.aiplatform`, `langchain*`, `llama_index` | + llm |
| Python importing `pinecone`, `qdrant_client`, `weaviate`, `chromadb`, `pymilvus`, `pgvector` | + vectordb |
| Python importing `ccxt`, `alpaca`, `ib_insync`, `binance`, `kopf` | + trading (`kopf`: + k8s-operator) |
| Scala `import org.apache.spark` | + spark |
| No extension + shebang `python*` / `(ba\|z)?sh` | python / shell, code |

---

## 7. Rule format

### 7.1 Pack files and examples
A pack file (`rules/<pack>/<name>.yaml`) is a YAML sequence of rule objects. Built-in packs ship
pre-validated in `bundle.json`. `--rules-dir` and `rules.extra_dirs` are parsed with `yamlite`.

```yaml
- id: WS-SEC-DB-002
  title: Database URL with inline password
  pack: secrets/generic
  severity: high
  confidence: high
  owner: "@whalesecurity/secrets"
  cwe: [CWE-798]
  owasp: [A07]
  applies_to: { kind: [code, iac, ci, data, doc] }
  keywords: ["://"]
  match:
    regex:
      pattern: '(?P<scheme>postgres(?:ql)?|mysql|mariadb|singlestore|memsql|mongodb(?:\+srv)?|rediss?|amqps?)://(?P<user>[^:/\s@]{1,128}):(?P<secret>[^@\s/]{1,256})@'
      secret_group: secret
  filters: { line_not_regex: '://[^:\s]{1,128}:(?:\$\{[^}]{1,64}\}|\{\{[^}]{1,64}\}\}|<[^>]{1,64}>|\*{3,})@' }
  message: "{{scheme}} connection string for user {{user}} embeds a password."
  fix: Read the DSN from Secrets Manager / Vault / a k8s Secret; rotate this credential.
  references: ["https://cwe.mitre.org/data/definitions/798.html"]

- id: WS-K8S-001
  title: Privileged container
  pack: domain/k8s
  severity: high
  confidence: high
  owner: "@whalesecurity/platform"
  cwe: [CWE-250]
  applies_to: { kind: iac, tags_any: [k8s, helm] }
  match:
    yaml_path:
      each: "**.{containers,initContainers,ephemeralContainers}[*]"
      all:
        - { path: "securityContext.privileged", equals: true }
  message: Container runs privileged, with full host device and kernel access.
  fix: Remove privileged; grant only the specific capabilities needed (securityContext.capabilities.add).
  references: ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"]
```

### 7.2 JSON Schema (draft 2020-12)
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:whalescan:schema:rule:1",
  "title": "whalescan rule (one item of a pack file's top-level sequence)",
  "type": "object",
  "additionalProperties": false,
  "required": ["id", "title", "pack", "severity", "confidence", "owner", "applies_to", "match", "message", "references"],
  "properties": {
    "id": {"type": "string", "pattern": "^WS-(INJ|ACC|CRY|SSRF|DES|WEB|SEC|AGT|GHA|K8S|TF|DKR|AIR|SPK|API|LLM|TRD)(-[A-Z0-9]{2,10})?-[0-9]{3}$"},
    "title": {"type": "string", "minLength": 8, "maxLength": 120},
    "pack": {"type": "string", "pattern": "^(appsec|secrets|agentsec|domain)/[a-z0-9][a-z0-9-]{0,40}$"},
    "severity": {"$ref": "#/$defs/severity"},
    "confidence": {"$ref": "#/$defs/confidence"},
    "cwe": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^CWE-[1-9][0-9]{0,4}$"}},
    "owasp": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^(A(0[1-9]|10)(:20(17|21|25))?|API([1-9]|10)(:2023)?|LLM(0[1-9]|10)(:2025)?|CICD-SEC-([1-9]|10)|K(0[1-9]|10))$"}},
    "atlas": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^AML\\.T[0-9]{4}(\\.[0-9]{3})?$"}},
    "tags": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,31}$"}},
    "owner": {"type": "string", "pattern": "^@[A-Za-z0-9][A-Za-z0-9-]{0,38}(/[A-Za-z0-9._-]{1,64})?$"},
    "since": {"type": "string", "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$"},
    "deprecated": {"type": "boolean", "default": false},
    "replaced_by": {"type": "string", "pattern": "^WS-[A-Z0-9-]+$"},
    "enabled_by_default": {"type": "boolean", "default": true},
    "applies_to": {"$ref": "#/$defs/applies_to"},
    "keywords": {"type": "array", "maxItems": 32, "items": {"type": "string", "minLength": 2, "maxLength": 64}},
    "keywords_case": {"enum": ["insensitive", "sensitive"], "default": "insensitive"},
    "match": {"$ref": "#/$defs/expr"},
    "filters": {"$ref": "#/$defs/filters"},
    "redact": {"type": "boolean", "default": false},
    "exposure_sensitive": {"type": "boolean", "default": true},
    "supersedes": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^WS-[A-Z0-9-]+$"}},
    "max_hits_per_file": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 50},
    "message": {"type": "string", "minLength": 10, "maxLength": 600},
    "fix": {"type": "string", "maxLength": 1200},
    "references": {"type": "array", "minItems": 1, "items": {"type": "string", "pattern": "^https://\\S+$"}},
    "fixtures": {"default": "auto", "oneOf": [{"const": "auto"},
      {"type": "object", "additionalProperties": false, "required": ["pos", "neg"],
       "properties": {"pos": {"$ref": "#/$defs/paths"}, "neg": {"$ref": "#/$defs/paths"}}}]}
  },
  "$defs": {
    "severity": {"enum": ["critical", "high", "medium", "low", "info"]},
    "confidence": {"enum": ["high", "medium", "low"]},
    "kind": {"enum": ["code", "iac", "ci", "agent-config", "doc", "data"]},
    "scalar": {"type": ["string", "number", "boolean", "null"]},
    "paths": {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1}},
    "globs": {"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 256}},
    "strs": {"type": "array", "items": {"type": "string", "minLength": 1}},
    "one_or_many": {"oneOf": [{"type": "string"}, {"type": "array", "minItems": 1, "items": {"type": "string"}}]},
    "pattern": {"type": "string", "minLength": 1, "maxLength": 4096},
    "applies_to": {"type": "object", "additionalProperties": false, "minProperties": 1, "properties": {
      "kind": {"oneOf": [{"$ref": "#/$defs/kind"}, {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/kind"}}]},
      "lang": {"$ref": "#/$defs/one_or_many"},
      "glob": {"$ref": "#/$defs/globs"},
      "exclude_glob": {"$ref": "#/$defs/globs"},
      "tags_any": {"$ref": "#/$defs/strs"},
      "tags_none": {"$ref": "#/$defs/strs"},
      "include_minified": {"type": "boolean", "default": false},
      "max_bytes": {"type": "integer", "minimum": 1}}},
    "filters": {"type": "object", "additionalProperties": false, "properties": {
      "file_regex": {"$ref": "#/$defs/pattern"},
      "file_not_regex": {"$ref": "#/$defs/pattern"},
      "line_not_regex": {"$ref": "#/$defs/pattern"},
      "path_not_glob": {"$ref": "#/$defs/globs"}}},
    "expr": {"oneOf": [
      {"type": "object", "additionalProperties": false, "required": ["all"], "properties": {
        "all": {"type": "array", "minItems": 2, "items": {"$ref": "#/$defs/expr"}},
        "near_lines": {"type": "integer", "minimum": 0, "maximum": 500}}},
      {"type": "object", "additionalProperties": false, "required": ["any"], "properties": {"any": {"type": "array", "minItems": 2, "items": {"$ref": "#/$defs/expr"}}}},
      {"type": "object", "additionalProperties": false, "required": ["not"], "properties": {"not": {"$ref": "#/$defs/expr"}}},
      {"type": "object", "additionalProperties": false, "required": ["regex"], "properties": {"regex": {"$ref": "#/$defs/regex"}}},
      {"type": "object", "additionalProperties": false, "required": ["multiline"], "properties": {"multiline": {"$ref": "#/$defs/multiline"}}},
      {"type": "object", "additionalProperties": false, "required": ["unicode"], "properties": {"unicode": {"$ref": "#/$defs/unicode"}}},
      {"type": "object", "additionalProperties": false, "required": ["entropy"], "properties": {"entropy": {"$ref": "#/$defs/entropy"}}},
      {"type": "object", "additionalProperties": false, "required": ["yaml_path"], "properties": {"yaml_path": {"$ref": "#/$defs/yaml_path"}}},
      {"type": "object", "additionalProperties": false, "required": ["py_ast"], "properties": {"py_ast": {"$ref": "#/$defs/py_ast"}}},
      {"type": "object", "additionalProperties": false, "required": ["hcl"], "properties": {"hcl": {"$ref": "#/$defs/hcl"}}},
      {"type": "object", "additionalProperties": false, "required": ["builtin"], "properties": {"builtin": {"enum": ["mcp_drift"]}}}]},
    "regex": {"oneOf": [{"$ref": "#/$defs/pattern"},
      {"type": "object", "additionalProperties": false, "required": ["pattern"], "properties": {
        "pattern": {"$ref": "#/$defs/pattern"},
        "flags": {"type": "array", "uniqueItems": true, "items": {"enum": ["i", "x", "a"]}},
        "report_group": {"oneOf": [{"type": "integer", "minimum": 0}, {"type": "string"}], "default": 0},
        "secret_group": {"type": "string", "pattern": "^[A-Za-z_][A-Za-z0-9_]*$"}}}]},
    "multiline": {"oneOf": [
      {"type": "object", "additionalProperties": false, "required": ["pattern"], "properties": {
        "pattern": {"$ref": "#/$defs/pattern"},
        "flags": {"type": "array", "uniqueItems": true, "items": {"enum": ["i", "x", "a", "s"]}},
        "max_span_lines": {"type": "integer", "minimum": 1, "maximum": 200, "default": 30},
        "secret_group": {"type": "string", "pattern": "^[A-Za-z_][A-Za-z0-9_]*$"}}},
      {"type": "object", "additionalProperties": false, "required": ["sequence", "within_lines"], "properties": {
        "sequence": {"type": "array", "minItems": 2, "maxItems": 5, "items": {"$ref": "#/$defs/pattern"}},
        "within_lines": {"type": "integer", "minimum": 1, "maximum": 200},
        "flags": {"type": "array", "uniqueItems": true, "items": {"enum": ["i", "x", "a"]}}}}]},
    "unicode": {"type": "object", "additionalProperties": false, "required": ["classes"], "properties": {
      "classes": {"type": "array", "minItems": 1, "uniqueItems": true, "items": {"enum": ["ZW", "BIDI", "TAG", "VS", "PUA", "CTRL", "HOMOGLYPH"]}},
      "min_run": {"type": "integer", "minimum": 1, "maximum": 64, "default": 1},
      "bidi_unbalanced_only": {"type": "boolean", "default": false},
      "allow_emoji_sequences": {"type": "boolean", "default": true}}},
    "entropy": {"type": "object", "additionalProperties": false, "required": ["charset"], "properties": {
      "charset": {"enum": ["hex", "base64", "base64url", "alnum"]},
      "min_len": {"type": "integer", "minimum": 12, "maximum": 256, "default": 20},
      "max_len": {"type": "integer", "minimum": 16, "maximum": 1024, "default": 200},
      "threshold": {"type": "number", "minimum": 1.0, "maximum": 6.0},
      "scope": {"enum": ["values", "anywhere"], "default": "values"},
      "min_classes": {"type": "integer", "minimum": 1, "maximum": 3, "default": 2},
      "context": {"type": "object", "additionalProperties": false, "properties": {
        "keywords": {"$ref": "#/$defs/strs"},
        "required": {"type": "boolean", "default": false},
        "window_chars": {"type": "integer", "minimum": 8, "maximum": 400, "default": 80}}},
      "exclude_regex": {"type": "array", "items": {"$ref": "#/$defs/pattern"}}}},
    "predicates": {"type": "object", "properties": {
      "exists": {"type": "boolean"},
      "equals": {"$ref": "#/$defs/scalar"},
      "not_equals": {"$ref": "#/$defs/scalar"},
      "in": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/scalar"}},
      "not_in": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/scalar"}},
      "regex": {"$ref": "#/$defs/pattern"},
      "not_regex": {"$ref": "#/$defs/pattern"},
      "type": {"enum": ["str", "int", "float", "bool", "null", "map", "seq"]},
      "contains": {"type": ["string", "number", "boolean"]},
      "quantifier": {"enum": ["any", "all"], "default": "any"}}},
    "yaml_cond": {"allOf": [{"$ref": "#/$defs/predicates"},
      {"type": "object", "required": ["path"], "minProperties": 2, "properties": {
        "path": {"type": "string", "minLength": 1, "maxLength": 512},
        "promote": {"type": "boolean", "default": true}}}], "unevaluatedProperties": false},
    "yaml_conds": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/yaml_cond"}},
    "yaml_path": {"type": "object", "additionalProperties": false,
      "anyOf": [{"required": ["all"]}, {"required": ["any"]}, {"required": ["none"]}],
      "properties": {
        "each": {"type": "string", "minLength": 1, "maxLength": 512},
        "schema": {"enum": ["auto", "yaml11", "yaml12"], "default": "auto"},
        "all": {"$ref": "#/$defs/yaml_conds"}, "any": {"$ref": "#/$defs/yaml_conds"}, "none": {"$ref": "#/$defs/yaml_conds"}}},
    "arg_cond": {"type": "object", "additionalProperties": false, "minProperties": 1, "properties": {
      "tainted": {"type": "boolean"},
      "dynamic_string": {"type": "boolean"},
      "constant": {"type": "boolean"},
      "equals": {"$ref": "#/$defs/scalar"},
      "not_equals": {"$ref": "#/$defs/scalar"},
      "regex": {"$ref": "#/$defs/pattern"}}},
    "py_ast": {"oneOf": [
      {"type": "object", "additionalProperties": false, "required": ["call"], "properties": {"call": {
        "type": "object", "additionalProperties": false, "required": ["callee"], "properties": {
          "callee": {"$ref": "#/$defs/one_or_many"},
          "args": {"type": "object", "propertyNames": {"pattern": "^([0-9]{1,2}|\\*)$"}, "additionalProperties": {"$ref": "#/$defs/arg_cond"}},
          "kwargs": {"type": "object", "propertyNames": {"pattern": "^[A-Za-z_][A-Za-z0-9_]*$"}, "additionalProperties": {"$ref": "#/$defs/arg_cond"}},
          "kwarg_absent": {"$ref": "#/$defs/strs"},
          "sources": {"$ref": "#/$defs/strs"},
          "sanitizers": {"$ref": "#/$defs/strs"},
          "require_import": {"$ref": "#/$defs/one_or_many"}}}}},
      {"type": "object", "additionalProperties": false, "required": ["fastapi_route"], "properties": {"fastapi_route": {
        "type": "object", "additionalProperties": false, "properties": {
          "methods": {"type": "array", "items": {"enum": ["get", "post", "put", "patch", "delete", "api_route", "websocket"]}},
          "auth_regex": {"$ref": "#/$defs/pattern"},
          "ignore_paths_regex": {"$ref": "#/$defs/pattern"}}}}}]},
    "hcl_cond": {"allOf": [{"$ref": "#/$defs/predicates"},
      {"type": "object", "anyOf": [{"required": ["attr"]}, {"required": ["range_includes"]}], "properties": {
        "attr": {"type": "string", "minLength": 1, "maxLength": 256},
        "range_includes": {"type": "object", "additionalProperties": false, "required": ["lo", "hi", "any"], "properties": {
          "lo": {"type": "string"}, "hi": {"type": "string"},
          "any": {"type": "array", "minItems": 1, "items": {"type": "integer", "minimum": 0, "maximum": 65535}}}}}}],
      "unevaluatedProperties": false},
    "hcl_conds": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/hcl_cond"}},
    "hcl": {"type": "object", "additionalProperties": false, "required": ["block"], "properties": {
      "block": {"type": "string", "minLength": 1, "maxLength": 256},
      "each": {"type": "string", "minLength": 1, "maxLength": 256},
      "all": {"$ref": "#/$defs/hcl_conds"}, "any": {"$ref": "#/$defs/hcl_conds"}, "none": {"$ref": "#/$defs/hcl_conds"},
      "on_unknown": {"enum": ["nomatch", "match"], "default": "nomatch"}}}
  }
}
```

### 7.3 Semantic checks (loader, beyond the schema)
Every failure below is a `RuleError` and exits 2. Checks marked (dev) run only in `rules test`.

| Check | Rule |
|---|---|
| Unique IDs | Across all loaded packs, bundle and extra dirs. An extra-dir rule may not shadow a bundled ID |
| Namespace ↔ pack | `WS-SEC` → `secrets/*`. `WS-AGT` → `agentsec/*`. `WS-INJ\|ACC\|CRY\|SSRF\|DES\|WEB` → `appsec/*` or `domain/*`. All other namespaces → `domain/*` |
| Matcher ↔ applies_to | `yaml_path` needs lang yaml/json. `hcl` needs hcl or `.tf.json`. `py_ast` needs python. `builtin` needs `agentsec/mcp` |
| Regex lint | R1–R7 (§8.2) on every pattern, including filters and predicates |
| Group names | `secret_group`, `report_group` and `{{name}}` placeholders in `message` must exist in the pattern |
| Paths | `yaml_path`/`hcl` paths parse (§8.6, §8.8). `py_ast.sources` name a known source set or a dotted path |
| Cross refs | `replaced_by` and `supersedes` IDs exist. A `not` expression appears only directly under `all` |
| Fixtures (dev) | `tests/fixtures/<ID>/` has ≥1 `pos*` and ≥1 `neg*` file |

The stdlib validator in `schema.py` implements exactly the keywords used above. CI also validates
every pack with the reference `jsonschema` package, to catch drift between the two validators.

---

## 8. Matchers

### 8.1 Common contract and pipeline
```python
@dataclass(slots=True)
class Hit:
    start: int; end: int                          # code-point offsets in ctx.text; end exclusive
    line: int; col: int; end_line: int; end_col: int
    captures: dict[str, str]                      # named groups, raw (redacted before output)
    secret_spans: list[tuple[int, int]]
    reachability: str = "unknown"                 # tainted | unknown | constant
    confidence_delta: int = 0                     # -1 = one step lower than rule.confidence
    props: dict[str, Any] = field(default_factory=dict)   # trace, reveal, decoded, entropy …
```

**Per-file pipeline**, cheapest step first:
1. `applies_to` index lookup on (kind, lang, tags, glob).
2. Keyword prefilter: one pass of a combined `re.escape`d alternation of every candidate rule's
   keywords over the text (casefolded when insensitive). A rule is active if any of its keywords
   occurred, or if it has no keywords.
3. `filters.file_regex` and `file_not_regex`.
4. Text matchers: `regex`, `multiline`, `unicode`, `entropy`.
5. Parse on demand, once per file, shared by all rules: yamlite, hcllite, `ast`.
6. Structured matchers.
7. `line_not_regex` and `path_not_glob`.
8. `max_hits_per_file` cap. Excess hits are counted in `stats.capped[rule_id]`.

**Combinators.**
- `any` is the union of its children's hits.
- `all` requires every positive child to hit and every `not` child to produce nothing. Its
  reported hits are those of the first positive child.
- With `near_lines: N`, a first-child hit is kept only if every other positive child has a hit
  within N lines of it and no `not` child has one.
- Children are evaluated in order, and `all` short-circuits on the first empty child.

### 8.2 `regex` (all hits, line and column)
```python
def run_regex(ctx, spec, rule):
    pat = spec.compiled()                     # lazy; flags = re.MULTILINE | user flags (i, x, a)
    for n, m in enumerate(pat.finditer(ctx.text)):   # ALL non-overlapping hits, not re.search
        if n >= rule.max_hits_per_file: ctx.cap(rule.id); break
        s, e = m.span(spec.report_group)
        if s == e: continue                   # defensive; R4 forbids empty-width patterns
        yield Hit(s, e, *ctx.pos(s), *ctx.end_pos(e), m.groupdict(),
                  [m.span(spec.secret_group)] if spec.secret_group and m.group(spec.secret_group) else [])
```
`^` and `$` are line anchors, and `.` never matches `\n`. Cross-line matching is the job of
`multiline`. The DESIGN "`--` semantics" requirement has two parts. Patterns never pass through
argv, so a leading `-` is always literal (a regression test covers `-----BEGIN OPENSSH PRIVATE
KEY-----`). Every exporter (`rules explain --grep`) emits `-e PATTERN --`.

**Regex lint** (`rules/lint.py`, run at load time and in CI):

| # | Rule | Severity |
|---|---|---|
| R1 | Compiles with Python `re` | error |
| R2 | No nested unbounded repeats (a `MAX_REPEAT`/`MIN_REPEAT` with max `MAXREPEAT` containing another). Checked on the `re._parser` AST (`sre_parse` on 3.10) | error |
| R3 | No unbounded repeat of `.`, `\s`, `\S` or a negated class as the first element, since it makes finditer quadratic on long lines. Anchor on a literal or use `{0,N}` | error |
| R4 | Minimum width > 0 (`parse(p).getwidth()[0] > 0`) | error |
| R5 | `(?s)` / DOTALL is forbidden in `regex` (use `multiline`) | error |
| R6 | Unbounded `*`/`+` on `.` or a negated class anywhere should be `{0,N}` with N ≤ 4096 | warning |
| R7 | Alternation inside an unbounded repeat whose branches share a first character | error |

### 8.3 `multiline`
- **`pattern` form.** Runs `finditer` over the whole text with `re.M`, plus `re.S` if flag `s`
  is set. A hit is dropped when `end_line - line + 1 > max_span_lines` (default 30). An example
  is a PEM private key: `-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[A-Za-z0-9+/=\s]{64,8192}-----END`.
- **`sequence` form.** Ordered line-proximity matching, which is ReDoS-safe:
```python
def run_sequence(ctx, spec):
    hits = [list(p.finditer(ctx.text)) for p in spec.compiled_seq()]   # each list sorted by start
    for h0 in hits[0]:
        prev, limit = h0, ctx.line_of(h0.start()) + spec.within_lines
        for later in hits[1:]:
            nxt = first(m for m in later if m.start() >= prev.end())    # bisect on starts
            if nxt is None or ctx.line_of(nxt.start()) > limit: break
            prev = nxt
        else:
            yield Hit(h0.start(), prev.end(), ...)                      # spans first → last
```
Example (Airflow template injection): `sequence: ['\bBashOperator\(', 'bash_command\s*=\s*f?["'']',
'\{\{\s*(?:dag_run\.conf|params)\b']`, `within_lines: 12`.

### 8.4 `unicode` (code-point classes)
If `ctx.text.isascii()` (a C fast path), nothing runs. Otherwise one compiled class regex finds
runs:
`[­؜᠎​-‏‪-‮⁠-⁤⁦-⁩﻿︀-️\U000e0000-\U000e007f\U000e0100-\U000e01ef]+`.
PUA, CTRL and HOMOGLYPH use their own scanners. Each run becomes one hit.

| Class | Code points | Reveal marker | Precision exemptions |
|---|---|---|---|
| ZW | U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+2060 WJ, U+2061–2064, U+FEFF (not at offset 0), U+180E, U+00AD SHY | `[ZWSP]` `[ZWNJ]` `[ZWJ]` `[WJ]` `[ZWNBSP]` `[SHY]` `[U+2061]` | ZWJ between two Extended_Pictographic chars (emoji). ZWNJ between two Arabic (U+0600–06FF) or Indic (U+0900–0DFF) letters |
| BIDI | U+202A LRE, 202B RLE, 202C PDF, 202D LRO, 202E RLO, 2066 LRI, 2067 RLI, 2068 FSI, 2069 PDI, 200E LRM, 200F RLM, 061C ALM | `[BIDI:RLO]` … | None. `props.bidi_unbalanced` is true when openers (LRE, RLE, LRO, RLO, LRI, RLI, FSI) outnumber closers (PDF, PDI) on the line, which is the Trojan Source pattern (CVE-2021-42574) |
| TAG | U+E0000–E007F | `[TAG:"<decoded>"]`, decoded = `chr(cp - 0xE0000)` for E0020–E007E | None. Always flagged; the decoded ASCII goes in `props.decoded` |
| VS | U+FE00–FE0F, U+E0100–E01EF | `[VS:n]` | U+FE0F after an emoji or keycap. FE00–FE0E single occurrences. Runs of ≥2 are decoded as bytes (FE00–FE0F → 0–15, E0100–E01EF → 16–255) into `props.decoded_bytes_hex` |
| PUA | U+E000–F8FF, U+F0000–FFFFD, U+100000–10FFFD | `[PUA:U+E123]` | Files tagged `font` or `icons` |
| CTRL | U+0000–0008, 000B, 000E–001F (includes ESC 0x1B, the terminal-escape vector), 007F, 0080–009F | `[CTRL:U+001B]` | `\t`, `\n`, `\r`, `\f` |
| HOMOGLYPH | A word (`[^\W_]+`) containing ≥1 ASCII letter **and** ≥1 code point from the Cyrillic/Greek confusables table (~45 entries in `unicode_data.py`, e.g. U+0430 а, U+0435 е, U+043E о, U+0440 р, U+0441 с, U+0445 х, U+0456 і, U+03BF ο, U+0391 Α) | `[U+0430→a]` | All-Cyrillic or all-Greek words (legitimate text). An all-confusable word on an otherwise-ASCII line is flagged at `confidence_delta=-1` |

`min_run` applies per class. `bidi_unbalanced_only` keeps only unbalanced BIDI hits. Reveal
markers are used in every snippet, message and report (§13), so a finding never re-carries its
own hidden payload into the agent's context.

### 8.5 `entropy` (Shannon)
For a candidate token `s` of length L with character counts `n_c`:

```
H(s) = − Σ_c (n_c / L) · log2(n_c / L)            # bits per character, 0 ≤ H ≤ log2(min(L, |Σ|))
```
```python
def shannon(s: str) -> float:
    L = len(s); return -sum((n / L) * math.log2(n / L) for n in Counter(s).values())
```

**Candidate extraction.**
- `scope: values` (the default) applies the charset regex only inside the value group of
  `(?<![A-Za-z0-9_.-])(?P<key>[A-Za-z_][A-Za-z0-9_.-]{0,63})["']?[ \t]{0,8}(?::=|=>|[:=])[ \t]{0,8}(?P<q>["'\x60]?)(?P<val>[^\s"'\x60,;]{8,256})`,
  and inside quoted string literals.
- `scope: anywhere` applies it to the whole text.

| charset | Token regex | Max H | Threshold for L = 16–23 / 24–39 / ≥40 |
|---|---|---|---|
| hex | `(?<![0-9A-Fa-f])[0-9A-Fa-f]{16,128}(?![0-9A-Fa-f])` | 4.0 | 3.0 / 3.2 / 3.4 |
| base64 | `(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,200}={0,2}(?![A-Za-z0-9+/=])` | 6.0 | 3.8 / 4.2 / 4.5 |
| base64url | `(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{16,200}(?![A-Za-z0-9_-])` | 6.0 | 3.8 / 4.2 / 4.5 |
| alnum | `(?<![A-Za-z0-9])[A-Za-z0-9]{16,200}(?![A-Za-z0-9])` | 5.95 | 3.6 / 4.0 / 4.3 |

`threshold`, when set, replaces the bucket values. `secrets.entropy_delta` is added to every
threshold.

**A token becomes a hit when all of these hold:**
1. `min_len ≤ L ≤ max_len`.
2. `H ≥ threshold(L)`.
3. The token has ≥ `min_classes` of {upper, lower, digit}. For hex, ≥1 digit and ≥1 letter.
4. It is not a placeholder:
   `(?i)^(?:x{6,}|\*{4,}|<[^>]{1,64}>|\$\{[^}]{1,64}\}|\{\{[^}]{1,64}\}\}|(?:your|my|example|sample|dummy|fake|test|changeme|placeholder|redacted|replace)[_-]?[a-z0-9_-]{0,40})$`.
5. It is not a run: `(.)\1{5,}`, applied to the token only.
6. It is not a sequential run (`0123456789`, `abcdef`).
7. It is not a UUID (`^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$`) unless the
   keyword context matched.
8. It is not a 40- or 64-hex digest when the key or line matches
   `(?i)\b(?:sha|commit|rev|ref|digest|checksum|integrity|uses)\b`.
9. It is not in a `lockfile`-tagged file.
10. It is not an `exclude_regex` match.

**Context and confidence.**
- `context.keywords` defaults to `secret token passwd password pwd api_key apikey access_key
  private credential auth bearer signature client_secret dsn conn webhook hmac`.
- Keywords are searched case-insensitively in the `key` group, or in the `window_chars` before
  the token on the same line.
- Confidence is `high` if a keyword is present and `H ≥ threshold + 0.3`. It is `medium` if a
  keyword is present. It is `low` without a keyword; with `context.required: true`, a token
  without a keyword is dropped instead.
- `props = {entropy: round(H, 2), charset, length}`.

### 8.6 `yaml_path`
**Parser.** `yamlite` is used rather than PyYAML, because the core has no dependencies and every
node needs a source span.
- **Supported:** block and flow mappings and sequences, plain, quoted and block scalars (`|`,
  `>`, chomping and indent indicators), comments, `---`/`...` multi-document streams, anchors,
  aliases, and `<<` merge keys (expanded at parse time, explicit keys win). Tags such as `!Ref`
  and `!!str` are kept on the node.
- **Unsupported:** complex `?` keys and `%TAG` directives. They cause a `parse-error` for that
  document only.
- **JSON** is parsed by the same code as YAML 1.2 flow, so `yaml_path` also works on
  `.mcp.json`, `.tf.json` and CloudFormation JSON.
- **Helm templates** get lenient mode first. Lines that are pure template control, matching
  `^[ \t]*\{\{-?[ \t]*(?:if|else|end|range|with|define|template|include|/\*)\b.*\}\}[ \t]*$`,
  are blanked, and inline `{{ … }}` stays as string scalars.

**Keys are never type-resolved.** The PyYAML/YAML 1.1 pitfall is that `yaml.safe_load("on:
push")` returns `{True: "push"}`, so a lookup of `"on"` silently finds nothing and every GHA
trigger rule misses. yamlite keeps each key as its unquoted source text: `on`, `"on"` and `'on'`
are all the key `on`, and `true:` is the key `true`, never `on`. Regression fixtures cover all
four forms. Only **values** are resolved, for `equals`, `in` and `type`, using a schema chosen per
file:

| Plain scalar | yaml12 (core) | yaml11 |
|---|---|---|
| `true True TRUE false False FALSE` | bool | bool |
| `yes Yes YES no No NO on On ON off Off OFF y Y n N` | str | bool |
| `null Null NULL ~` (empty) | null | null |
| `0o17` / `017` / `0x1F` / `1_000` | int / int (17) / int / str | str / int (octal 15) / int / int |
| `22:22` (compose port) | str | int 1342 (sexagesimal) |

`schema: auto` picks yaml11 for tags {k8s, helm, ansible, kustomize, tekton, flux}, because their
consumers use YAML 1.1 bool semantics. It picks yaml12 for everything else (gha, compose,
traefik, JSON).

**Path grammar.**
```
path    = [ "$." ] step { ( "." step ) | index }
step    = "**" | "*" | ident | quoted | alt
ident   = 1*( any char except . [ ] { } " * and whitespace )
quoted  = '"' *( [^"\\] | "\\" char ) '"'               ; keys containing dots: annotations."kubernetes.io/ingress.class"
alt     = "{" ident *( "," ident ) "}"                   ; {containers,initContainers}
index   = "[" ( ["-"] 1*DIGIT | "*" ) "]"
```
Tokenizer (applied with `re.match` at a moving position; paths are ≤512 chars):
`\.?(?:(?P<dstar>\*\*)|(?P<star>\*)|"(?P<quoted>(?:[^"\\]|\\.)*)"|\{(?P<alt>[^{}]+)\}|(?P<ident>[^.\[\]{}"*\s]+))|\[(?P<index>-?[0-9]+|\*)\]`

```python
def resolve(nodes, steps, promote=True):
    for st in steps:
        out = []
        for n in nodes:
            if st.kind in ("key", "alt"):
                keys = st.keys                                        # raw-text comparison
                if n.is_map: out += [v for k, v in n.items if k.raw in keys]
                elif promote and n.is_scalar and n.raw in keys: out.append(Virtual(n))  # on: pull_request_target
                elif promote and n.is_seq: out += [Virtual(i) for i in n.items if i.is_scalar and i.raw in keys]  # on: [push, pull_request_target]
            elif st.kind == "star":  out += n.values() if n.is_map else n.items if n.is_seq else []
            elif st.kind == "dstar": out += [n, *n.descendants()]     # pre-order, zero or more levels
            elif st.kind == "index" and n.is_seq: out += n.items if st.i is STAR else n.items[st.i:st.i + 1 or None]
        nodes = unique_by_identity(out)
    return nodes
```
Promotion lets `on.pull_request_target` match the scalar, sequence and mapping forms of `on:`,
as DESIGN §4 requires. A `Virtual` node exists with value null at the scalar's span. Promotion
never applies after `*`, `**` or an index, and it can be turned off per condition with
`promote: false`.

**Predicates.** They apply to the nodes returned by `resolve`.
- `exists: true` holds when the result is non-empty. `exists: false` holds when it is empty.
- Value predicates use `quantifier: any` (default: at least one node satisfies) or `all` (at
  least one node, and every node satisfies).
- A missing path makes every value predicate **false**, including the negative ones:
  `not_equals`, `not_in`, `not_regex`. Rule authors write `exists: false` for absence.
- `equals` and `in` compare resolved typed values. `regex` and `not_regex` use `re.search` on the
  scalar's unquoted source text; block scalars are compared after folding.
- `contains` holds when a sequence has a scalar item equal to the value.
- `type` compares the node type.

**Evaluation and location.**
```python
for doc in docs:
    anchors = resolve([doc.root], parse(spec.each)) if spec.each else [doc.root]
    for a in anchors:
        base = lambda c: doc.root if c.path.startswith("$.") else a
        if all(ev(c, base(c)) for c in spec.all) and (not spec.any or any(ev(c, base(c)) for c in spec.any)) \
           and not any(ev(c, base(c)) for c in spec.none):
            yield from locate(a, spec)
```
`locate` emits one hit per node satisfying the **first positive value condition**. If there is
none, it uses the first `exists: true` condition. If there is none of those either, it uses the
anchor's key span. For DESIGN's GHA-001 example, which has no `each`, this yields one hit per
matching `with.ref` step. Rule for unpinned MCP servers in `.mcp.json`:

```yaml
match:
  yaml_path:
    each: "mcpServers.*"
    all:
      - { path: "command", in: [npx, bunx, pnpx, uvx] }
      - { path: "args[*]", regex: '^(?:@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$' }   # package spec with no @version
```

### 8.7 `py_ast` (stdlib `ast`, function-local taint)
The file is parsed once with `ast.parse`. A `SyntaxError` produces a `parse-error` diagnostic and
py_ast rules skip the file, which happens with syntax newer than the running interpreter.

**Name resolution.** An alias map is built from `import x as y` and `from m import n as k`.
`qualname(expr)` turns an `Attribute`/`Name` chain into a dotted string through that map. An
unresolvable receiver (a call result, a subscript) becomes the segment `?`.

**Callee patterns** are dotted:
- `*` matches one segment, including `?`.
- `**` matches any number of segments.
- `{a,b}` is alternation.
- Examples: `subprocess.{run,call,check_call,check_output,Popen}`, `os.{system,popen}`,
  `pickle.{load,loads}`, `yaml.load`, `**.execute`, `**.sql` (`spark.sql`,
  `SparkSession.builder.getOrCreate().sql`), `sqlalchemy.text`, `jinja2.Template`, `{eval,exec}`.

**Argument conditions.**
- `tainted`: reached by a source (below).
- `dynamic_string`: the argument is one of the following, after resolving a local `Name` one
  step to its last assignment:
  - an f-string with ≥1 `FormattedValue`,
  - a `+` whose operands are not all constants,
  - a `%` with a constant format and non-constant arguments,
  - `.format(...)` or `str.join` with non-constant arguments.
- `constant`: every leaf is an `ast.Constant`.
- `equals` / `regex` apply to the literal value, or to the dotted name for names (e.g.
  `Loader=yaml.SafeLoader`).
- `kwarg_absent` handles cases like `yaml.load(x)` with no `Loader`.
- Arg key `"*"` means any positional argument.

**Source sets** (`sources:` entries may also be dotted patterns):

| Set | Expressions |
|---|---|
| `web` | Parameters of FastAPI/Starlette route handlers, except `Depends(...)`/`Security(...)` defaults and params annotated `int float bool UUID date datetime Decimal Literal[...]`. `request.{query_params,path_params,headers,cookies,form,json,body,url}` (including `await request.json()`). Flask `request.{args,form,values,json,data,files,headers,cookies}` and `request.get_json()` |
| `airflow` | `dag_run.conf`, `context["dag_run"].conf`, `kwargs["dag_run"].conf`, task `params`, `ti.xcom_pull(...)` |
| `cli` | `sys.argv`, `input()`, attributes of `argparse` `parse_args()` results |
| `llm` | Results of `**.{invoke,ainvoke,converse,converse_stream,invoke_model,generate,generate_content,predict,complete,chat}` in files tagged `llm` |
| `net` | `requests.*(...)` / `httpx.*(...)` `.text`, `.content`, `.json()`; `urlopen(...).read()` |
| `msg` | Kafka/SQS/PubSub payloads: `**.poll()`, `msg.value()`, `record.value`, `message.data`. Used for trading signal and order paths |
| `file` / `env` | `open(...).read()`, `Path(...).read_text()`, `json.load(...)` / `os.environ[...]`, `os.getenv(...)`. Only when a rule opts in |

Default sanitizers are `int float bool uuid.UUID shlex.quote html.escape markupsafe.escape
re.escape ipaddress.ip_address urllib.parse.quote os.path.basename`. A rule's `sanitizers:` list
extends them.

```python
def analyze_function(fn, rule):                        # module body is analyzed as one pseudo-function
    tainted: dict[str, TaintOrigin] = seed_params(fn, rule.sources)   # route params, Request objects
    for _ in range(3):                                 # fixpoint for loops; monotone (no kills), recall-first
        before = len(tainted)
        for stmt in in_source_order(fn.body):
            match stmt:
                case Assign | AnnAssign | AugAssign if (o := origin(stmt.value)): bind(targets(stmt), o)
                case For(target, iter) | comprehension if (o := origin(iter)):     bind([target], o)
                case With(items) if any(o := origin(i.context_expr) for i in items):   bind(as_names(items), o)
        if len(tainted) == before: break
    for call in calls_in(fn):
        if matches(rule.callee, qualname(call.func)) and constraints_hold(call, rule, origin):
            yield hit(call, reachability=reach(call), props={"trace": trace_of(call)})

def origin(e):                                          # → TaintOrigin | None
    Name → tainted.get(e.id) or source_match(e);  Attribute/Subscript → origin(e.value) or source_match(e)
    Call → None if sanitizer(qualname(e.func)) else (source_match(e) or origin(receiver(e))
            or first(origin(a) for a in e.args + kw_values(e)))   # unknown calls propagate taint
    JoinedStr/BinOp/BoolOp/IfExp/List/Tuple/Set/Dict/Starred/Await → first origin among children
    Constant → None
```
`reach(call)` is `tainted` if the constrained argument has an origin. It is `constant` if the
argument is constant. Otherwise it is `unknown`. `trace` is a list of `{line, name, via}` records
from source to sink, capped at 8. SARIF renders it as a `codeFlow`.

**`fastapi_route`.** Handles FastAPI routes that lack an auth dependency.
1. Find decorators `<recv>.<method>(path, ...)` where `recv` was assigned `FastAPI(...)` or
   `APIRouter(...)` in the module.
2. Collect auth evidence. Any one of these counts:
   - a parameter default `Depends(X)` or `Security(X)`;
   - an `Annotated[..., Depends(X)]` parameter;
   - the decorator's `dependencies=[Depends(X)]`;
   - `dependencies=` on the router or app constructor;
   - `app.include_router(router, dependencies=[...])` in the same module.
3. Evidence counts only when `qualname(X)` matches `auth_regex`. The default is
   `(?i)(auth|current_?user|verify|token|jwt|oauth|api_?key|security|permission|require|login|principal|session)`.
4. A route with methods in `methods` (default `post put patch delete`), no evidence, and a path
   not matching `ignore_paths_regex` (default `^/(?:health|healthz|livez|readyz|metrics)$`) is a
   hit. The hit lands on the decorator with `confidence_delta=-1`, because auth may be attached
   in another module. `finding-verifier` checks that case.

### 8.8 `hcl` (hcl-lite)
**Tokenizer (`hcllite.py`).**
- Comments: `(?:#|//)[^\n]*|/\*(?s:.*?)\*/`.
- Numbers: `-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?`.
- Identifiers: `[A-Za-z_][A-Za-z0-9_-]*`.
- Heredocs: `<<(?P<strip>-?)(?P<tag>[A-Za-z_][A-Za-z0-9_]*)[ \t]*\n`, running until a line whose
  stripped text equals the tag.
- Strings are scanned by a state machine, not a regex. It tracks `${`/`%{` nesting so that
  `"${lookup(var.m, "k")}"` stays one token.
- Punctuation.

**Grammar.**
```
body  = { attribute | block }
attr  = IDENT "=" expr NEWLINE                ; expr: literal (string w/o interpolation, number, bool, null,
block = IDENT { STRING | IDENT } "{" body "}" ;       list/object of literals) else Expr(raw text to depth-0 newline)
```
`*.tf.json` is mapped onto the same `Block(type, labels, attrs, blocks)` model.

**References.** `var.x` resolves to a literal `default` of `variable "x"`, and `local.y` to a
literal in `locals {}`. Both are looked up in the same directory, from a per-directory symbol
table built once. Anything else stays `Unknown`.

**Paths.**
- `block` matches type then labels, with `*` for one label: `resource.aws_security_group.*`,
  `module.*`, `remote_state`.
- `each` iterates nested blocks, e.g. `ingress`.
- `attr` paths walk nested blocks and object keys: `metadata_options.http_tokens`,
  `config.encrypt`.

**Predicates.** They are those of §8.6 plus `range_includes: {lo, hi, any}`, which is true if
some port p in `any` satisfies `lo ≤ p ≤ hi`. Each predicate is tri-state: an `Unknown` value
gives *unknown*. `on_unknown: nomatch` (the default) treats unknown as false. `match` treats it
as true, with `confidence_delta=-1` and `props.unresolved=[attr…]`.

```yaml
match:
  hcl:
    block: "resource.aws_security_group.*"
    each: "ingress"
    all:
      - { attr: cidr_blocks, contains: "0.0.0.0/0" }
      - { range_includes: { lo: from_port, hi: to_port, any: [22, 3389, 5432, 3306, 6379, 9200] } }
```

---

## 9. Dedupe and fingerprinting

**Normalized snippet.**
1. Take the lines `line … min(end_line, line + 2)`.
2. Replace every secret span with `<SECRET:sha256hex>` if the secret is ≥16 chars, else
   `<SECRET:len=N>`.
3. Collapse `\s+` to a single space and strip.

Unicode is **not** normalized, because hidden code points are the finding.

```python
fp      = "sha256:" + sha256("\x1f".join([rule_id, path, norm, str(occ)]).encode("utf-8", "surrogatepass")).hexdigest()
content = "sha256:" + sha256("\x1f".join([rule_id, norm, str(occ)]).encode(...)).hexdigest()   # path-free
```
`occ` is the 0-based index among findings in the same file with the same (rule_id, norm), in
position order. It keeps two identical `privileged: true` lines distinct. Fingerprints ignore
line numbers, so they survive code moving within a file. `content_fingerprint` lets a baseline
follow a renamed file (§11.3).

**Dedupe order.**
1. **Exact:** hits with the same (rule_id, path, line, col, end_line, end_col) are kept once.
2. **Same rule, overlapping spans:** the earliest start wins, then the longest span.
3. **Cross-rule overlap on the same secret span:** keep the rule with the highest (not tagged
   `generic`, listed in the other's `supersedes`, severity score, confidence). For example,
   `WS-SEC-AWS-001` beats the entropy rule `WS-SEC-GEN-001`. Losers go into the winner's
   `properties.related`.
4. **Cross-source:** an adapter finding on the same file and line, with intersecting CWE (or both
   secrets), is merged into the engine finding as `also_reported_by: ["semgrep:<id>"]`.

---

## 10. Severity model

```
score = min(10, BASE[rule.severity or override] × R[reachability] × E[exposure])
final = band(score)
```

| Base | Score | Reachability R | × | Exposure E | × | Band | Score range |
|---|---|---|---|---|---|---|---|
| critical | 10.0 | tainted (py_ast proved source→sink) | 1.25 | internet (routers, webhooks, ingress, public proxy config) | 1.1 | critical | ≥ 9.0 |
| high | 7.5 | unknown (pattern match; default) | 1.0 | default | 1.0 | high | 7.0 – 8.99 |
| medium | 5.0 | constant (sink argument is literal) | 0.6 | internal (scripts, tools, ops) | 0.8 | medium | 4.0 – 6.99 |
| low | 2.5 | | | vendored | 0.5 | low | 1.0 – 3.99 |
| info | 0.5 | | | test (tests, fixtures, examples, docs) | 0.4 | info | < 1.0 |

- **Exposure** is the first matching class of `severity.exposure` (§3.2). Files tagged `test`
  default to `test`, and routes found by `fastapi_route` default to `internet`.
- **`exposure_sensitive: false`** fixes E = 1.0. This is the default for the `secrets` pack,
  because a live key in `tests/` is still leaked. `inject` input always uses E = 1.0.
- Findings keep `base_severity`, `score`, `reachability` and `exposure`. `--fail-on` and
  `--min-severity` compare against the **final** band.
- **Ordering** in reports is by `score × W[confidence]` (high 1.0, medium 0.8, low 0.5)
  descending, then path, line and rule.

| Example | Calculation | Final |
|---|---|---|
| `WS-INJ-003` `subprocess.run(cmd, shell=True)` with `cmd` from a route param in `app/routers/orders.py` | 7.5 × 1.25 × 1.1 = 10.3 → 10 | critical |
| Same pattern in `scripts/backfill.py`, `cmd` origin unknown | 7.5 × 1.0 × 0.8 | medium (6.0) |
| `WS-SPK-001` `spark.sql(f"... {TABLE}")` where `TABLE` is a module constant | 7.5 × 0.6 × 1.0 | medium (4.5) |
| `WS-K8S-001` privileged container in `tests/fixtures/` | 7.5 × 1.0 × 0.4 | low (3.0) |
| `WS-SEC-TRD-001` exchange API secret in `tests/test_orders.py` | 10 × 1.0 × 1.0 (not exposure-sensitive) | critical |

---

## 11. Suppressions and baseline

### 11.1 Inline syntax
```python
# marker (one per line):
MARKER = re.compile(r"(?:#|//|--|/\*|<!--|;|\{#)\s*whalescan:ignore(?P<scope>-next-line|-file|-start|-end)?"
                    r"(?:\[(?P<ids>[A-Za-z0-9*,\s-]{1,200})\])?(?P<tail>[^\n]{0,400})")
KV = re.compile(r'''(?P<k>reason|until|ticket)=(?:"(?P<q>(?:[^"\\\n]|\\.){0,300})"|(?P<v>[^\s"]{1,120}))''')
```
```python
subprocess.run(argv, shell=True)  # whalescan:ignore[WS-INJ-003] reason="argv is a fixed tuple" until=2026-12-31
```
```yaml
# whalescan:ignore-next-line[WS-K8S-001] reason="node-exporter needs host access" ticket=PLAT-412
      privileged: true
```

| Form | Scope |
|---|---|
| `whalescan:ignore[IDS]` | The finding's start line. If the comment is alone on its line, the next non-blank line |
| `whalescan:ignore-next-line[IDS]` | The next non-blank line |
| `whalescan:ignore-file[IDS]` | The whole file. Must appear in the first 20 lines (`allow_file_level`) |
| `whalescan:ignore-start[IDS]` … `whalescan:ignore-end` | The enclosed lines, at most `max_block_lines` (200) |

**IDs** are exact IDs or prefix globs (`WS-SEC-*`). A bare `*` requires `allow_wildcard`.

**Validity.**
- A reason must be present and at least `min_reason_chars` long, otherwise the suppression is
  invalid and the finding stays visible. An invalid suppression adds a `suppression-invalid`
  diagnostic.
- A marker whose `until` date has passed is inactive and adds `suppression-expired`.
- With `report_unused`, an unused marker adds `suppression-unused`.

**Hard exclusions.** Inline markers are ignored in two cases, because the content is
attacker-controlled and would suppress itself:
1. every `inject` input, and
2. `WS-AGT-*` findings in `agent-config` and `doc` files during `scan`.

Only baseline and config suppressions apply there. The `scan_edit.py` hook reports any newly
added `whalescan:ignore` marker to the agent, so an agent adding one is visible.

### 11.2 Config suppression
`rules.disable` and `severity.overrides` apply here. Every entry from project config is echoed in
`run.config_changes`.

### 11.3 Baseline file (`.whalesecurity/baseline.json`)
```json
{
  "schema": "whalescan/baseline@1",
  "tool_version": "1.0.0",
  "rules_hash": "sha256:…",
  "created_at": "2026-09-29T10:00:00Z",
  "updated_at": "2026-09-29T10:00:00Z",
  "entries": [
    {"fingerprint": "sha256:…", "content_fingerprint": "sha256:…", "rule_id": "WS-K8S-004",
     "path": "deploy/k8s/pricing-api.yaml", "line": 42, "severity": "medium",
     "reason": "limits set by LimitRange in ns; PLAT-377", "added_at": "2026-09-29", "expires": null}
  ]
}
```
- Entries are sorted by (path, rule_id, fingerprint) so diffs are stable. No snippet is stored,
  so the baseline can never hold a secret. `line` is informational only.
- **Matching** tries `fingerprint` first. If that fails, and the entry's `path` is absent from
  the current file set, it tries `content_fingerprint`, which handles moved files.
- An expired entry (past `expires`) no longer suppresses and adds a diagnostic.
- Baseline-suppressed findings are counted in `stats.suppressed.baseline`.

---

## 12. Reporters

Every reporter consumes the same sorted `ScanResult`, and every string passes through
`redact.sweep` (§13).

### 12.1 Text
```
CRITICAL  WS-GHA-001  .github/workflows/pr-preview.yml:31:18  pull_request_target checks out PR head code
          │ ref: ${{ github.event.pull_request.head.sha }}
          fix: Use pull_request for untrusted code, or split into a privileged workflow_run job.
HIGH      WS-SEC-DB-002  airflow/dags/etl_orders.py:12:14  Database URL with inline password
          │ URI = "singlestore://etl:…[REDACTED len=11]@s2.internal:3306/orders"

2 findings (1 critical, 1 high) · 1,204 files · 0.91 s · 7 suppressed (baseline 5, inline 2) · fail-on high → exit 1
```
Colors are red for critical, magenta for high, yellow for medium, and cyan for low and info.

### 12.2 JSON: `json` and `jsonl`
- **`-f json`** writes one envelope: `{"schema": "whalescan/report@1", "tool": {name, version,
  rules_hash}, "run": {started_at, duration_ms, root, argv, packs, config_sources,
  config_changes, fail_on, exit_code, truncated, error}, "stats": {files_scanned, files_skipped:
  {binary, too_large, ignored, symlink}, rules_evaluated, capped, by_severity, suppressed:
  {inline, baseline, config}}, "findings": [finding@1…], "diagnostics": [{level, code, message,
  file?, line?, rule_id?}]}`.
- **`-f jsonl`** writes one finding@1 per line and no envelope. It is streamable, and hooks use
  it.
- Output is byte-identical across runs for the same input with `--deterministic`: sorted keys,
  `ensure_ascii=False`, and hidden characters already revealed.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:whalescan:schema:finding:1",
  "title": "whalescan finding",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema", "rule_id", "title", "severity", "base_severity", "score", "confidence", "reachability", "exposure",
               "file", "line", "col", "end_line", "end_col", "snippet", "cwe", "owasp", "message", "fingerprint",
               "content_fingerprint", "source"],
  "properties": {
    "schema": {"const": "whalescan/finding@1"},
    "rule_id": {"type": "string", "pattern": "^(WS-[A-Z0-9]+(-[A-Z0-9]+)*-[0-9]{3}|(semgrep|gitleaks|trivy|osv|llm):\\S{1,200})$"},
    "title": {"type": "string", "minLength": 1, "maxLength": 200},
    "severity": {"$ref": "#/$defs/severity"},
    "base_severity": {"$ref": "#/$defs/severity"},
    "score": {"type": "number", "minimum": 0, "maximum": 10},
    "confidence": {"enum": ["high", "medium", "low"]},
    "reachability": {"enum": ["tainted", "unknown", "constant"]},
    "exposure": {"enum": ["internet", "default", "internal", "vendored", "test"]},
    "pack": {"type": "string"},
    "file": {"type": "string", "minLength": 1},
    "file_kind": {"enum": ["code", "iac", "ci", "agent-config", "doc", "data"]},
    "line": {"type": "integer", "minimum": 1},
    "col": {"type": "integer", "minimum": 1},
    "end_line": {"type": "integer", "minimum": 1},
    "end_col": {"type": "integer", "minimum": 1, "description": "exclusive, code points"},
    "snippet": {"type": "string", "maxLength": 2000, "description": "redacted and revealed"},
    "cwe": {"type": "array", "items": {"type": "string", "pattern": "^CWE-[0-9]+$"}},
    "owasp": {"type": "array", "items": {"type": "string"}},
    "atlas": {"type": "array", "items": {"type": "string"}},
    "message": {"type": "string", "minLength": 1},
    "fix": {"type": ["string", "null"]},
    "references": {"type": "array", "items": {"type": "string"}},
    "fingerprint": {"$ref": "#/$defs/sha"},
    "content_fingerprint": {"$ref": "#/$defs/sha"},
    "source": {"enum": ["engine", "semgrep", "gitleaks", "trivy", "osv", "llm"]},
    "also_reported_by": {"type": "array", "items": {"type": "string"}},
    "suppressed": {"oneOf": [{"type": "null"}, {"type": "object", "additionalProperties": false, "required": ["kind"], "properties": {
      "kind": {"enum": ["inline", "baseline", "config"]},
      "reason": {"type": "string"}, "until": {"type": "string", "format": "date"},
      "ticket": {"type": "string"}, "marker_line": {"type": "integer", "minimum": 1}}}]},
    "verification": {"type": "object", "additionalProperties": false, "required": ["status", "by"], "properties": {
      "status": {"enum": ["confirmed", "false_positive", "needs_review"]},
      "by": {"type": "string"}, "note": {"type": "string", "maxLength": 2000}}},
    "properties": {"type": "object", "properties": {
      "trace": {"type": "array", "maxItems": 8, "items": {"type": "object", "required": ["line"], "properties": {
        "line": {"type": "integer"}, "name": {"type": "string"}, "via": {"type": "string"}}}},
      "source_label": {"type": "string"}, "decoded": {"type": "string"}, "decoded_bytes_hex": {"type": "string"},
      "bidi_unbalanced": {"type": "boolean"}, "entropy": {"type": "number"}, "commit": {"type": "string"},
      "diff": {"type": "string", "maxLength": 4096}, "unresolved": {"type": "array", "items": {"type": "string"}},
      "related": {"type": "array", "items": {"type": "string"}}}}
  },
  "$defs": {
    "severity": {"enum": ["critical", "high", "medium", "low", "info"]},
    "sha": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
  }
}
```

### 12.3 SARIF 2.1.0
| SARIF field | Source |
|---|---|
| `$schema`, `version` | `https://json.schemastore.org/sarif-2.1.0.json`, `"2.1.0"` |
| `runs[0].tool.driver` | `name: "whalescan"`, `version`, `semanticVersion`, `informationUri` (project URL) |
| `runs[0].tool.extensions[]` | One `toolComponent` per adapter that ran (`name`, `version`) |
| `driver.rules[]` | One `reportingDescriptor` per rule with ≥1 result, or per selected rule with `sarif_include_all_rules` |
| `rule.id` / `rule.name` | `rule_id` / title in PascalCase ASCII (`PullRequestTargetChecksOutPrHead`) |
| `rule.shortDescription.text` / `fullDescription.text` | `title` / static `message` with placeholders removed |
| `rule.help.text` / `help.markdown` / `helpUri` | `fix` + references / same as Markdown / `references[0]` |
| `rule.defaultConfiguration.level` | critical, high → `error`. medium → `warning`. low, info → `note` |
| `rule.properties.tags` | `["security", pack, "external/cwe/cwe-94", "owasp/A03", …rule tags]` |
| `rule.properties["security-severity"]` | Base: critical `"9.5"`, high `"8.0"`, medium `"5.5"`, low `"3.0"` (omitted for info) |
| `rule.properties.precision` | Confidence high/medium/low → `"high"`/`"medium"`/`"low"` |
| `results[].ruleId`, `ruleIndex`, `level` | `rule_id`, index into `rules[]`, level from the **final** severity |
| `results[].message.text` | Redacted and revealed `message` |
| `…physicalLocation.artifactLocation` | `uri`: `file`, POSIX and percent-encoded. `uriBaseId: "%SRCROOT%"` |
| `…physicalLocation.region` | `startLine=line`, `startColumn=col`, `endLine=end_line`, `endColumn=end_col` (both exclusive), `snippet.text=snippet` |
| `results[].partialFingerprints` | `{"whalescan/v1": fingerprint, "whalescan/content/v1": content_fingerprint}` |
| `results[].properties` | `severity, base_severity, score, confidence, reachability, exposure, source, pack, cwe, owasp` |
| `results[].codeFlows` | From `properties.trace`: one `threadFlow`, with `locations[].location` per step |
| `results[].suppressions` | With `--show-suppressed`: inline → `{kind: "inSource"}`, baseline or config → `{kind: "external"}`, `status: "accepted"`, `justification: reason` |
| `runs[0].columnKind` | `"unicodeCodePoints"` |
| `runs[0].originalUriBaseIds` | `{"%SRCROOT%": {"uri": "file:///abs/root/"}}` only with `sarif_absolute_root` |
| `runs[0].automationDetails.id` | `"whalescan/<sorted packs joined by +>/"`. The stable category lets GitHub track results per pack set |
| `runs[0].invocations[0]` | `executionSuccessful` (exit ≠ 3), `exitCode`, and `toolExecutionNotifications` from diagnostics (level, `descriptor.id` = code) |

Adapter results go into the same single run with prefixed rule IDs. Their rules come from adapter
metadata, and `extensions` credits the tools. This avoids multi-run category collisions in code
scanning.

### 12.4 Markdown (PR comments, `/whale-audit`)
1. A heading with counts: `## whalescan: 1 critical · 2 high · 4 medium`.
2. A summary table `| Sev | Rule | Location | Title |`.
3. For critical and high findings, a `####` section each, containing:
   - `` `file:line` `` · CWE · OWASP · confidence;
   - a fenced snippet whose fence is longer than any backtick run in it;
   - `**Fix:**` and the references.
4. Medium, low and info findings in a `<details>` table. The whole report is capped at
   `markdown_max_findings`.

Escaping: `|` becomes `\|` in tables, and `<`, `>`, `&` are HTML-escaped outside fences, so a
finding cannot inject HTML or mentions into a PR comment. Hidden code points are always revealed.

---

## 13. Secret redaction

- **Which spans are secret.**
  - Every hit of a `secrets/*` rule, using the named group from `secret_group`, or else the whole
    match.
  - Every hit of a rule with `redact: true`.
  - Every entropy token.
  - Adapter secret findings, re-located in our own file text. Adapter-provided secret text is
    never trusted or printed.
- **Format.**
  - For a secret with L ≥ 16: `prefix + "…[sha256:" + sha256(secret)[:8] + "]"`, where `prefix`
    is the first `min(4, L // 4)` characters (`AKIA…[sha256:1f3a9c0e]`).
  - For L < 16 (passwords): `…[REDACTED len=L]` with no hash, so short secrets cannot be
    dictionary-checked.
  - A multi-line private key keeps its `-----BEGIN … KEY-----` header. Its body becomes
    `…[sha256:xxxxxxxx]`.
- **Where it applies.** Snippets, `message` interpolations (`{{secret}}` is always redacted),
  `properties`, all four reporters, logs, and adapter raw fields. `baseline.json` stores no text.
- **Sweep.** The run keeps an in-memory set of raw secret values, which is never serialized.
  Every output string passes through `sweep(text)`, a single alternation regex of those values,
  longest first, as a second line of defense. CI asserts that no reporter output for the fixtures
  contains any `pos` fixture secret, in any format.
- **Reveal.** After redaction, hidden code points (§8.4) are replaced by their markers in every
  output string, including `--format json`.

---

## 14. Adapters

```python
class Adapter(Protocol):
    name: str                                            # "semgrep" | "gitleaks" | "trivy" | "osv"
    def probe(self, cfg) -> AdapterInfo | None: ...      # shutil.which + version; cached per process
    def command(self, targets: list[str], cfg) -> list[str]: ...
    def ok_exit(self, rc: int) -> bool: ...
    def parse(self, stdout: bytes, report_file: Path | None) -> Iterable[dict]: ...
    def normalize(self, raw: dict, ctx: NormCtx) -> Finding | None: ...
```

**Runner.**
- argv list only, never `shell=True`.
- `cwd=root`.
- `timeout=adapters.timeout_s`.
- Environment reduced to `PATH HOME LANG LC_ALL TMPDIR`, plus per-tool opt-outs
  (`SEMGREP_SEND_METRICS=off`).
- stdout capped at 256 MiB.
- Report files go in a 0700 temp dir under the cache dir and are deleted afterwards.

**Failures.** A missing binary gives `adapter-missing` (info). A timeout, a bad exit code or
unparseable output gives `adapter-failed` (warning). None of these change the exit code unless
`--adapters-strict` is set, which makes them exit 3.

| Adapter | Command | Findings → `whalescan/finding@1` |
|---|---|---|
| semgrep | `semgrep scan --json --quiet --metrics=off --disable-version-check <args> -- <targets>`. OK exits: 0, 1 | `results[]`: `rule_id=semgrep:<check_id>`, `path`, `start.line/col`, `end.line/col`. `extra.severity` ERROR→high, WARNING→medium, INFO→low; CRITICAL/HIGH/MEDIUM/LOW map directly. `cwe` from `extra.metadata.cwe` via `\bCWE-([0-9]{1,5})\b`. `owasp` via `\b(A(?:0[1-9]\|10)):(20[0-9]{2})\b`. Confidence from `metadata.confidence`, default medium. `fix` from `extra.fix` |
| gitleaks | `gitleaks dir <target> --no-banner --redact --report-format json --report-path <tmp> --exit-code 42`, or `gitleaks git --log-opts=<range>` for history. OK exits: 0, 42 | `rule_id=gitleaks:<RuleID>`, `File`, `StartLine..EndLine`, `Commit`. The secret is re-located by re-running the rule span over our decoded line (column hints only), then redacted by §13. Severity high (`adapters.gitleaks.severity_map` overrides). `cwe=[CWE-798]`. Confidence medium |
| trivy | `trivy fs --format json --quiet --exit-code 0 --scanners <scanners> <root>`. OK exit: 0 | `Results[].Vulnerabilities[]` → `trivy:<VulnerabilityID>` at `Target` (line = first line containing `PkgName`), message `"<pkg> <installed>: <id>; fixed in <FixedVersion>"`, `cwe` from `CweIDs`. `Misconfigurations[]` with `Status=="FAIL"` → `trivy:<ID>` at `CauseMetadata.StartLine..EndLine`. Severity CRITICAL/HIGH/MEDIUM/LOW maps directly; UNKNOWN→low. `Secrets[]` are dropped when the secrets pack ran |
| osv | `osv-scanner scan source --format json -r <root>` (OK exits: 0, 1, 128), or `pip-audit -f json --progress-spinner off -r <req>`, or `api` (POST `https://api.osv.dev/v1/querybatch`, requires trusted `allow_network`) | `results[].packages[].vulnerabilities[]` → `osv:<id>`, with `aliases` in properties, at `source.path` (line of the package). Severity from `groups[].max_severity` (CVSS score → §10 bands), else `database_specific.severity` (MODERATE→medium), else medium. `cwe` from `database_specific.cwe_ids` |

**Normalization rules** apply to every adapter.
- Paths become root-relative POSIX. Missing `line` or `col` become 1.
- `end_*` defaults to the start position plus the end of that line.
- Fingerprints are recomputed with §9, using **our** file text, never the adapter's snippet.
- `exposure` is applied as for engine findings; `reachability` is `unknown`.
- Messages are redacted and revealed.
- Unknown severities map to `medium`, and unknown confidences to `low`.

---

## 15. Performance

### 15.1 Budgets (CI benchmark on a 4-vCPU runner; a regression greater than 20% fails)
| Scenario | Budget |
|---|---|
| `whalescan version` cold start | < 80 ms |
| Hook: `scan_text` on one ≤100 KB file, warm cache (`scan_edit.py`) | engine < 120 ms, hook p95 < 200 ms |
| Hook: `scan_injection` on 1 MiB of tool output | < 150 ms |
| Regex tier, single core, 8 KB average files | ≥ 2 000 files/s |
| py_ast tier | ≥ 300 files/s |
| Each regex vs 100 KB adversarial input | < 50 ms |
| RSS on a 50 000-file repo | < 300 MB |

### 15.2 Rule cache
- **What is cached.** The expensive part is YAML parsing, schema validation and linting, not
  `re.compile`. The cache stores the normalized, validated rule set, the applicability index and
  the keyword tables as **JSON**, not pickle, because a writable cache dir must never become a
  code-execution vector.
- **Key.** `sha256(engine_version | schema_version | sorted (relpath, sha256(file)) of every
  rule source | rule-affecting config)`.
- **File.** `<cache>/rules-<key[:16]>.json`, written atomically (tmp + `os.replace`), mode 0600
  in a 0700 directory. Only the newest 5 are kept.
- **Built-in rules** load from the release-time `bundle.json`, so no YAML is parsed on the hook
  path.
- **Regex compilation.** Patterns compile lazily per process, on the first file where the rule is
  active. `re.Pattern` objects pickle as source anyway. A single-file hook therefore compiles
  only the ~20–40 applicable rules.

### 15.3 Parallelism
- **Threshold.** A single process is used below 200 files or 4 MiB total. Above it, a
  `ProcessPoolExecutor` with `jobs` workers runs (default `min(cpu_count, 8)`).
- **Start method.** `forkserver` on Linux, `spawn` elsewhere.
- **Workers** load the rule cache in the initializer.
- **Batches.** Files are batched about 64 files or 2 MiB per task, largest files first, to
  reduce tail latency.
- **Deterministic output.** Results are merged and then sorted, so output does not depend on
  scheduling.
- **Threads** are not used for matching, because of the GIL. Free-threaded builds are
  re-evaluated post-v1.
- **Adapters** run concurrently with the engine in a thread (they are subprocesses).

### 15.4 Time budget
`time_budget_ms` is checked between files and between rules within a file. When it is exceeded,
the run stops, sets `run.truncated=true`, and adds a `time-budget-exceeded` diagnostic. The exit
code is computed on the partial result. Hooks treat a truncated run as fail-open and say so.
Python `re` has no per-match timeout, so ReDoS safety comes from lint (§8.2) and CI (§2.6
`--redos`).

---

## 16. Public Python API

```python
from whalescan import (__version__, load_config, load_rules, Scanner, scan_text, scan_injection,
                       Finding, ScanResult, Severity, Confidence, Diagnostic, Baseline,
                       mcp_pin, mcp_verify, reveal, redact,
                       WhalescanError, UsageError, ConfigError, RuleError)

def load_config(root: str | os.PathLike[str] | None = None, *, path: str | None = None,
                project: bool = True, overrides: Mapping[str, Any] | None = None) -> Config: ...
def load_rules(cfg: Config, *, packs: Sequence[str] | None = None,
               rule_ids: Sequence[str] | None = None) -> RuleSet: ...

class Scanner:                                     # immutable after construction; thread-safe
    def __init__(self, rules: RuleSet, cfg: Config, *, adapters: Sequence[str] = ()) -> None: ...
    def scan_paths(self, paths: Sequence[str | os.PathLike[str]], *, jobs: int | None = None,
                   diff_ref: str | None = None, time_budget_ms: int | None = None) -> ScanResult: ...
    def scan_text(self, text: str | bytes, *, filename: str = "<stdin>",
                  line_ranges: Sequence[tuple[int, int]] | None = None,      # keep hits intersecting these
                  time_budget_ms: int | None = None) -> ScanResult: ...

# module-level conveniences for hooks: lazily build and cache a process-wide Scanner
def scan_text(text: str | bytes, *, filename: str, packs: Sequence[str] = ("appsec", "secrets", "domain"),
              line_ranges=None, time_budget_ms: int = 150, root: str | None = None) -> ScanResult: ...
def scan_injection(text: str | bytes, *, source_label: str, reveal: bool = True,
                   max_bytes: int | None = None, time_budget_ms: int = 150) -> ScanResult: ...

@dataclass(frozen=True, slots=True)
class ScanResult:
    findings: tuple[Finding, ...]; diagnostics: tuple[Diagnostic, ...]; stats: Stats; run: RunInfo
    def exit_code(self, fail_on: str = "high") -> int: ...   # 0|1 (3 is decided by the CLI)
    def to_json(self) -> str: ...;  def to_jsonl(self) -> str: ...;  def to_sarif(self) -> str: ...
    def to_markdown(self) -> str: ...;  def to_text(self, color: bool = False) -> str: ...

@dataclass(frozen=True, slots=True)
class Finding:                                     # fields mirror finding@1 (§12.2)
    rule_id: str; title: str; severity: Severity; base_severity: Severity; score: float
    confidence: Confidence; reachability: str; exposure: str; pack: str
    file: str; file_kind: str; line: int; col: int; end_line: int; end_col: int
    snippet: str; cwe: tuple[str, ...]; owasp: tuple[str, ...]; message: str; fix: str | None
    references: tuple[str, ...]; fingerprint: str; content_fingerprint: str; source: str
    also_reported_by: tuple[str, ...] = (); suppressed: Suppression | None = None
    properties: Mapping[str, Any] = field(default_factory=dict)
    def to_dict(self) -> dict[str, Any]: ...

class Severity(IntEnum): INFO = 0; LOW = 1; MEDIUM = 2; HIGH = 3; CRITICAL = 4
```
```python
# scan_edit.py hook, abridged
res = whalescan.scan_text(new_content, filename=rel_path, line_ranges=edited_ranges)
if any(f.severity >= Severity.HIGH for f in res.findings): emit_additional_context(res.to_markdown())
```
**Stability.** Names exported from `whalescan/__init__.py` follow semver from 1.0. Modules and
names starting with `_`, and `whalescan.matchers.*`, `whalescan.rules.*` and
`whalescan.adapters.*` internals, are private. The API never prints; logging goes to the
`whalescan` logger.

---

## 17. Errors and exit codes

```
WhalescanError                 → 3
├── UsageError                 → 2   bad flags, missing path, conflicting options, baseline exists w/o --force
├── ConfigError                → 2   TOML syntax, type/enum errors, unsupported schema version
├── RuleError                  → 2   schema, lint or semantic failure; unknown rule ID
├── AdapterError               → diagnostic, or 3 with --adapters-strict
└── InternalError              → 3   any unexpected exception
```

| Command | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| `scan` / `inject` / `secrets` | No unsuppressed finding ≥ `--fail-on` (or `never`) | ≥1 such finding | Usage, config or rule error | Internal error; strict adapter failure |
| `mcp verify` | No drift finding ≥ `--fail-on` | Drift ≥ `--fail-on` | Unreadable pins or MCP config | Internal error; `--strict` and a server unreachable |
| `mcp pin`, `baseline create/update` | Written | — | Usage (exists without `--force`, critical without `--allow-critical`) | Internal / I/O error on write |
| `rules test` | All pass | ≥1 rule fails | Unknown ID, missing fixtures dir | Internal error |
| `rules list/explain`, `version` | OK | — | Unknown ID / bad flag | Internal error |

- **Exit code evaluation.** `fail_on` is evaluated on unsuppressed findings that pass
  `min_confidence` and `--diff-lines`, **before** `min_severity` output filtering.
- **Per-file problems never abort a run.** These are read errors, `decode-*`, `parse-error`,
  `too-large`, `symlink-*` and `rule-capped`. They become diagnostics.
- **On exit 3 with `-f json`/`sarif`,** the reporter still writes a valid document. For JSON,
  `run.error = {type, message}` holds the partial findings. For SARIF,
  `executionSuccessful=false`. Hooks parse this and fail open, loudly.
- **Signals.** `KeyboardInterrupt` exits 130 with no traceback. On `BrokenPipeError` stdout is
  redirected to devnull and the computed code is used. A traceback is printed only at `-vv`.
  Otherwise stderr gets one line: `whalescan: internal error: <Type>: <msg> (rerun with -vv)`.

---

## 18. Logging

- **Setup.** Standard library `logging`, with the logger hierarchy `whalescan`,
  `whalescan.walker`, `.rules`, `.matchers.<type>`, `.adapters.<name>` and `.mcp`. Logs go to
  **stderr only**; stdout is reserved for reports.
- **Levels.** `-q` gives ERROR, the default is WARNING, `-v` INFO, `-vv` DEBUG. The env override
  is `WHALESCAN_LOG_LEVEL`. `logging.file` (trusted-only) adds a `RotatingFileHandler`
  (5 MiB × 3).
- **`--log-format json`** writes one object per line: `{"ts", "level", "logger", "msg", "file",
  "rule_id", "elapsed_ms"}`.
- **Content.** DEBUG logs rule IDs, file paths, spans and timings, and **never** match text for
  rules with `redact` or `secrets/*` packs. A `RedactingFilter` attached to the root handler
  applies `redact.sweep` and reveal to every formatted record as a second line of defense.
- **`--profile`** prints a table of the top 20 rules by cumulative time and hits, plus parse
  times per structured parser. The perf benchmark uses it to enforce §15.1.

---

## 19. Refinements to DESIGN.md

1. **"Stdlib-only core"** means zero install-time dependencies. The core ships its own `yamlite`
   parser (with positions and raw keys, which is what fixes the `on:` pitfall) and vendors
   `tomli` for Python 3.10 only.
2. **Rule cache format** is JSON of normalized rules, not a pickle of compiled rules. Regexes
   compile lazily per process (§15.2).
3. **Fingerprint** is `sha256(rule_id␟path␟normalized_snippet␟occurrence)` with U+001F
   separators. A path-free `content_fingerprint` is added for moved files (§9).
4. **Report envelope.** `-f json` wraps finding@1 objects in a `whalescan/report@1` envelope.
   `jsonl` emits bare findings. The finding gains `title`, `base_severity`, `score`,
   `reachability`, `exposure`, `pack`, `file_kind`, `end_col` (exclusive, code points),
   `content_fingerprint`, `suppressed`, `verification` and `properties`. The `source` enum adds
   `trivy` and `osv`.
5. **Rule ID grammar** allows an optional sub-namespace, `WS-SEC-AWS-001`, which DESIGN §8
   already uses.
6. **New rule fields:** `owner` (required, per DESIGN §11), `keywords`, `filters`, `redact`,
   `exposure_sensitive`, `supersedes`, `max_hits_per_file` and `enabled_by_default`. There is
   also a `builtin: mcp_drift` matcher for `WS-AGT-MCP-*`.
7. **Inline suppressions** are ignored for `inject` input and for `WS-AGT-*` findings in
   agent-config and doc files, and they support `until=`.
8. **Trusted-only config keys** (adapter binaries and args, network, live MCP, cache and log
   paths) are ignored in project config.
9. **Modules added** to the DESIGN §3 layout: `api.py`, `model.py`, `config.py`, `ignore.py`,
   `textio.py`, `yamlite.py`, `hcllite.py`, `dedupe.py`, `redact.py`, `errors.py`, `log.py`,
   `rules/{schema,lint,cache}.py`. Baseline handling lives in `suppress.py` as DESIGN states.
10. **Extras.** The `[ast]` extra is reserved for the post-v1 tree-sitter tier; v1 `py_ast`
    uses stdlib `ast`. The `[adapters]` extra carries `pip-audit` for the osv adapter.
