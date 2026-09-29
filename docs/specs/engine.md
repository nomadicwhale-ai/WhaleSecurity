# whalescan — Engine Specification

This document specifies `whalescan`, the deterministic Python scanner behind every WhaleSecurity surface: the CLI,
the Claude Code hooks, the audit skills and agents, the GitHub Action and pre-commit. It fixes the module layout, CLI
contract, configuration, file discovery and classification, rule format, matcher semantics, finding identity,
severity, suppression, output formats, adapters, performance budgets, public Python API and failure behavior, so the
engine can be built and tested without further design decisions. It is normative for v1.0 (MUST/SHOULD/MAY per
RFC 2119). Deviations from `docs/DESIGN.md` are listed in §19.

**Contents:** 1 Layout · 2 CLI · 3 Configuration · 4 `.whalescanignore` · 5 Walker · 6 Classifier · 7 Rule format ·
8 Matchers · 9 Dedupe and fingerprints · 10 Severity · 11 Suppressions and baseline · 12 Reporters · 13 Redaction ·
14 Adapters · 15 Performance · 16 Python API · 17 Errors and exit codes · 18 Logging · 19 Refinements to DESIGN.md

---

## 1. Package and module layout

```
engine/
├── pyproject.toml
└── src/whalescan/
    ├── __init__.py  __main__.py   public API re-exports (§16), __version__; `python -m whalescan`
    ├── cli.py               argparse tree, dispatch, exit-code mapping (§2, §17)
    ├── api.py               Scanner, module-level scan_text / scan_injection with a cached scanner
    ├── model.py             frozen dataclasses: Rule, Hit, Finding, FileCtx, ScanResult, Diagnostic
    ├── config.py            discovery, merge, validation, trust boundary (§3)
    ├── ignore.py            gitignore-syntax compiler shared by walker and .whalescanignore (§4)
    ├── walker.py            file enumeration (§5)
    ├── textio.py            BOM/encoding, binary sniff, line index, offset → (line, col)
    ├── classify.py          path + content → lang, kind, tags (§6)
    ├── rules/
    │   ├── loader.py        YAML/JSON load, pack selection, semantic checks (§7.3)
    │   ├── schema.py        rule JSON Schema (§7.2) + stdlib validator for the keywords it uses
    │   ├── lint.py          regex safety lint R1–R7 (§8.2)
    │   ├── cache.py         normalized-rule cache (§15.2)
    │   └── bundle.json      pre-validated built-in rules, generated from /rules at release
    ├── matchers/            base.py (registry, combinators) regex.py multiline.py unicode.py unicode_data.py
    │                        entropy.py yamlpath.py pyast.py hcl.py builtin.py (mcp_drift)
    ├── yamlite.py           YAML subset parser with source positions and raw keys (no deps)
    ├── hcllite.py           HCL2 tokenizer + block parser, *.tf.json reader
    ├── dedupe.py            fingerprints, overlap resolution, cross-source merge (§9)
    ├── severity.py          base × reachability × exposure (§10)
    ├── suppress.py          inline suppressions + baseline file (§11)
    ├── redact.py            secret redaction, hidden-codepoint reveal, output sweep (§13)
    ├── report/              text.py json.py sarif.py markdown.py
    │   └── schemas/         finding-1.json report-1.json baseline-1.json mcp-pins-1.json
    ├── adapters/            base.py (protocol, sandboxed runner) semgrep.py gitleaks.py trivy.py osv.py
    ├── mcp_pin.py           mcp pin / verify (§2.5)
    ├── errors.py  log.py    exception hierarchy (§17); logging + redacting filter (§18)
    └── _vendor/tomli/       MIT; imported only on Python 3.10 (tomllib is 3.11+)
```

**`engine/pyproject.toml`:** `name = "whalescan"`, `requires-python = ">=3.10"`, `dependencies = []` (stdlib-only
core, a hard CI gate), extras `adapters = ["pip-audit>=2.7"]` (other adapters are external binaries),
`mcp = ["mcp>=1.2"]` (only for `mcp pin/verify --live`) and `dev` (pytest, ruff, mypy, PyYAML, jsonschema); the
`ast` extra named in DESIGN is reserved for the post-v1 tree-sitter tier and not declared in v1. Entry point:
`whalescan = "whalescan.cli:main"`; package data: `rules/bundle.json`, `report/schemas/*.json`, `py.typed`.

**Import discipline.** `cli.py` imports only `argparse`, `os` and `sys` at module load. Everything else (`ast`,
`json`, `hashlib`, `concurrent.futures`, matchers, reporters) is imported inside the handler that needs it. CI
asserts that `python -X importtime -m whalescan version` stays under 80 ms.

---

## 2. CLI

```
whalescan [GLOBAL OPTIONS] <command> [ARGS]
  scan · inject · secrets · mcp {pin,verify} · baseline {create,update} · rules {list,test,explain} · version
```

| Global option (before or after the command) | Default | Meaning |
|---|---|---|
| `-c, --config PATH` / `--no-project-config` | discovered (§3.1) | Project config file / ignore it (untrusted checkouts) |
| `--rules-dir DIR` (repeatable) | — | Extra YAML rule packs |
| `--root DIR` | git toplevel, else cwd | Base for relative output paths and project config |
| `-q` / `-v` / `-vv`, `--log-format text\|json` | warning, text | stderr logging (§18) |
| `--color auto\|always\|never` | auto | `auto` is off when `NO_COLOR` is set or stdout is not a TTY |
| `--no-cache`, `--cache-dir DIR` | on | Rule cache (§15.2) |

| Scan option (`scan`, `inject`, `secrets`, `baseline`) | Default | Meaning |
|---|---|---|
| `PATHS...` | `.` | Files or directories; `-` is stdin (§2.7) |
| `--stdin`, `--stdin-filename NAME` | `<stdin>` | Read one document from stdin; NAME is its virtual path |
| `-f, --format` / `-o, --output PATH` | text / stdout | `text\|json\|jsonl\|sarif\|markdown` |
| `--also FORMAT=PATH` (repeatable) | — | Extra reports from the same run, e.g. `--also sarif=out.sarif` |
| `--packs LIST` | config | Selectors: `appsec`, `domain/*`, `-domain/trading` (removes) |
| `--rule ID`, `--exclude-rule ID` (repeatable, glob) | — | Restrict or remove rules, e.g. `--rule 'WS-K8S-*'` |
| `--fail-on SEV\|never` | `high` | Exit 1 when an unsuppressed finding is at or above SEV |
| `--min-severity SEV`, `--min-confidence C` | low, low | Drop findings below these from the output |
| `--baseline PATH` / `--no-baseline`, `--show-suppressed` | `.whalesecurity/baseline.json` if present | §11.3 |
| `--diff REF` / `--staged`, `--diff-lines` | — | Only files changed vs REF (`git diff --name-only -z --diff-filter=ACMR REF`) or the index; `--diff-lines` also drops findings outside added hunks |
| `--files-from PATH\|-` | — | Path list, NUL-separated if it contains `\0`, else newline-separated |
| `--include GLOB`, `--exclude GLOB` (repeatable) | — | gitignore-syntax filters on top of ignore files |
| `--no-gitignore`, `--follow-symlinks`, `--max-file-size`, `--max-files` | off, off, 1M, 50000 | §5. Sizes accept `K`/`M`/`G` |
| `-j, --jobs N`, `--time-budget-ms N` | 0 = auto, 0 = none | §15.3, §15.4 |
| `--adapters LIST\|auto\|none`, `--adapters-strict` | none | §14 |
| `--deterministic`, `--profile` | off | Zero timestamps/durations for golden tests; per-rule timing to stderr |

### 2.1 `scan`
Runs the configured packs (default `appsec, secrets, domain, agentsec`; agentsec rules only touch the kinds they
declare). It is the command behind `/whale-audit`, CI and pre-commit.
```bash
whalescan scan                                                         # repo, text, fail on high
whalescan scan services/pricing-api -f sarif -o whalescan.sarif --fail-on critical
whalescan scan --diff origin/main --diff-lines -f markdown -o pr-comment.md         # PR gate
whalescan scan infra/live deploy/k8s --packs domain/terraform,domain/k8s --also json=out/iac.json
git show HEAD:dags/etl_orders.py | whalescan scan - --stdin-filename dags/etl_orders.py -f jsonl
```

### 2.2 `inject`
Scans untrusted content (web pages, MCP/tool output, docs, agent instruction files) with the `agentsec` pack only.
Inline suppressions are **never** honored (§11.1). `--source LABEL` is stored as `properties.source_label`
(`web:<url>`, `mcp:<server>/<tool>`, `bash:<argv0>`, `rag:<collection>`). `--reveal` (on by default) renders hidden
code points in snippets as `[ZWSP]`, `[TAG:"…"]`, `[BIDI:RLO]`; `--reveal-out PATH|-` writes the whole input with
those markers. `--max-bytes N` (default `inject.max_bytes`, 2 MiB): larger input is scanned as its first N/2 and
last N/2 bytes, with `stats.truncated=true` and an `input-truncated` diagnostic, so padding cannot silently push a
payload out of view. Input with no filename is classified as `kind=doc`.
```bash
curl -sL https://wiki.example.com/runbook | whalescan inject --source web:https://wiki.example.com/runbook -f json
whalescan inject CLAUDE.md AGENTS.md .claude/ docs/ --fail-on medium
whalescan inject vendor_notes.md --reveal-out -             # show where hidden characters are
```

### 2.3 `secrets`
Runs the `secrets` pack only (provider patterns plus entropy). `--git-history [--since REV] [--max-commits N=1000]`
scans the added lines of `git log -p -U0 --no-color --no-ext-diff --format=%x00%H REV..HEAD` and sets
`properties.commit`. Files tagged `example` (`.env.example`) are reported at confidence `low`.
```bash
whalescan secrets --no-gitignore                                   # includes local .env files
whalescan secrets --git-history --since v1.4.0 -f sarif -o secrets.sarif
terraform show -json plan.out | whalescan secrets - --stdin-filename plan.json
```

### 2.4 `baseline create | update`
```bash
whalescan baseline create [PATHS] [scan options] [--baseline-out PATH] --reason TEXT [--force] [--allow-critical]
whalescan baseline update [PATHS] [scan options] [--no-prune] [--add-new --reason TEXT]
```
`create` refuses to overwrite an existing file without `--force` (exit 2). `update` prunes entries that were not
re-found, but only entries whose `path` lies inside the scanned scope, so a partial scan never deletes unrelated
entries. `--add-new` adds unmatched findings. `critical` findings are never baselined without `--allow-critical`.
Both print `kept N · pruned M · added K`.

### 2.5 `mcp pin | verify`
```bash
whalescan mcp pin    [--mcp-config PATH]... [--server NAME]... [--pins PATH] [--live] [--from-json PATH|-] [--timeout-s 10]
whalescan mcp verify [same options] [-f FORMAT] [--fail-on SEV] [--strict]
```
- **Servers** come from the `mcpServers` object of each `mcp.config_files` entry (default `.mcp.json`,
  `~/.claude.json`, where `projects["<root>"].mcpServers` is also read).
- **Tool metadata.** `--live` (needs the `[mcp]` extra and trusted config) starts stdio servers or connects to http
  servers, then calls `initialize` and a paginated `tools/list`, with a hard timeout per server. `--from-json` reads
  `{"<server>": {"tools": [<tools/list items>]}}`. With neither, only server configs are pinned and verified: this
  fast mode is what the `mcp_verify.py` SessionStart hook runs.
- **Hashes.** `canon(x) = json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`, with no Unicode
  normalization, so hidden code points change the hash.
  `config_sha256 = sha256(canon({transport, command, args, url, env_keys: sorted(env), header_keys: sorted(headers)}))`
  excludes env and header *values* (secrets). Per tool,
  `sha256 = sha256(canon({name, title, description, inputSchema, outputSchema, annotations}))`.

```json
{"schema": "whalescan/mcp-pins@1", "updated_at": "2026-09-29T10:00:00Z",
 "servers": {"jira": {"source": ".mcp.json", "transport": "stdio", "config_sha256": "<64 hex>",
   "tools": {"get_issue": {"sha256": "<64 hex>", "description_chars": 412}}, "pinned_at": "2026-09-29T10:00:00Z"}}}
```
`verify` reports through `builtin: mcp_drift` rules in `rules/agentsec/mcp.yaml`, located at the server entry in the
config file. It also runs the agentsec pack over every added or changed description (`source_label=mcp:<server>/<tool>`).
An unreachable server in `--live` mode yields an `mcp-unreachable` diagnostic, or exit 3 with `--strict`.

| Rule | Condition | Severity |
|---|---|---|
| `WS-AGT-MCP-001` | Pinned tool's description or schema changed (`properties.diff`: revealed unified diff, ≤4 KiB) | high |
| `WS-AGT-MCP-002` / `-005` | Tool added to / removed from a pinned server | medium / low |
| `WS-AGT-MCP-003` | Server config changed (command, args, url, env keys) | high |
| `WS-AGT-MCP-004` | Server configured but not pinned | medium |

### 2.6 `rules list | test | explain`
```bash
whalescan rules list [--packs P] [--kind K] [--severity-min SEV] [--tag T] [-f table|json|markdown]
whalescan rules test [RULE_ID|GLOB ...] [--fixtures tests/fixtures] [--redos] [--schema-only] [--junit PATH]
whalescan rules explain RULE_ID [-f text|json|markdown] [--grep]
```
**`rules test`** checks each selected rule: (1) schema, lint (§8.2) and semantic checks (§7.3); (2) every
`tests/fixtures/<ID>/pos*.*` produces ≥1 hit, and when the fixture has `expect:` annotations the set of hit start
lines MUST equal the annotated lines, where annotations match
`(?:#|//|--|<!--)[ \t]*expect:[ \t]*(?P<ids>WS-[A-Z0-9-]+(?:[ \t]*,[ \t]*WS-[A-Z0-9-]+)*)` (comment-less JSON uses a
sidecar `expect.json`: `{"pos.json": {"WS-AGT-MCP-010": [4]}}`); (3) every `neg*.*` produces 0 hits. A first-line
directive `# whalescan-fixture: path=.github/workflows/pr.yml` sets a virtual path for glob-restricted rules.
`--redos` runs each pattern in a subprocess (2 s hard kill) against eight 100 KB adversarial strings (runs of each
character class in the pattern, the literal prefix repeated, `"a"*N + "!"`); each MUST finish in under 50 ms. Exit
codes: 0 all pass, 1 any failure, 2 unknown ID or missing fixtures dir.

**`rules explain`** prints the metadata, a matcher summary and fixture paths. `--grep` prints an equivalent search
for regex rules, always as `rg -n -P -e <shlex-quoted pattern> -- <paths>`: `-e` and `--` keep dash-leading
patterns such as `-----BEGIN` from being parsed as flags.

**`version [-f text|json] [--probe-adapters]`** reports version, Python, platform, `rules.bundle_hash`, rule counts per
pack, installed extras and cache dir; `--probe-adapters` adds adapter binary versions (slow).

### 2.7 Stdin conventions
`-` (or `--stdin`) may appear at most once. Stdin is read as bytes, decoded as in §5.5, capped at
`scan.max_stdin_bytes` (16 MiB; `inject` uses `inject.max_bytes`). `--stdin-filename` drives classification,
`applies_to.glob`, `.whalescanignore` and the output `file`; with the default `<stdin>` only content sniffing
classifies it and glob-restricted rules do not run. `inject` and `secrets` read stdin implicitly when PATHS is
empty and stdin is not a TTY; `scan` never does, so it cannot hang in CI. `--files-from -` and
`mcp … --from-json -` read their lists from stdin.

---

## 3. Configuration (`.whalesecurity/config.toml`)

### 3.1 Discovery, precedence, trust
- **Project config:** `--config` → `$WHALESCAN_CONFIG` → first `.whalesecurity/config.toml` walking up from cwd,
  stopping at a directory containing `.git`, at `$HOME` or at `/`. **User config:**
  `$XDG_CONFIG_HOME/whalescan/config.toml` (default `~/.config/whalescan/`).
- **Precedence:** built-in defaults < user < project < env < CLI. Tables deep-merge; scalars and arrays replace,
  except `rules.enable`/`rules.disable` (union) and `severity.overrides` (dict update).
- **Trust boundary.** Keys that execute code, reach the network, or write outside the repo are honored **only**
  from user config, env or CLI: `adapters.*.bin`, `adapters.*.args`, `adapters.*.env`, `adapters.osv.allow_network`,
  `mcp.live`, `cache.dir`, `logging.file`. Project config that sets them is ignored with a `config-untrusted-key`
  diagnostic (a cloned repo must not be able to set `adapters.semgrep.bin = "./x.sh"`). Project config that
  disables rules or lowers severities is honored, but each such change is listed in `run.config_changes` of every
  report so auditors see it.
- **Validation:** type and enum errors exit 2 (`scan.fail_on: expected one of critical|high|medium|low|info|never`);
  unknown keys give a `config-unknown-key` warning; a `schema` newer than supported exits 2.
- **Env vars:** `WHALESCAN_CONFIG`, `WHALESCAN_NO_PROJECT_CONFIG=1`, `WHALESCAN_FAIL_ON`, `WHALESCAN_PACKS`,
  `WHALESCAN_JOBS`, `WHALESCAN_CACHE_DIR`, `WHALESCAN_NO_CACHE=1`, `WHALESCAN_LOG_LEVEL`, `NO_COLOR`,
  `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`.

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
exclude          = []                        # gitignore syntax, applied after .whalescanignore
walker           = "auto"                    # auto|git|fs (§5.1)
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
enable     = []                              # IDs/globs forced on (incl. enabled_by_default = false)
disable    = []                              # IDs/globs
[severity]
overrides = {}                               # { "WS-DKR-003" = "low" } replaces the base severity
[severity.exposure]                          # first matching class wins, in this order
test     = ["tests/**", "test/**", "**/test_*.py", "**/*_test.py", "**/conftest.py", "**/fixtures/**",
            "examples/**", "docs/**", "**/.env.example"]
vendored = ["vendor/**", "third_party/**", "**/site-packages/**", "**/node_modules/**"]
internet = ["**/routers/**", "**/routes/**", "**/api/**", "**/webhooks/**", "**/ingress*.y*ml",
            "**/nginx/**", "**/traefik/**"]
internal = ["scripts/**", "tools/**", "ops/**", "notebooks/**"]
[classify]
rules = []        # [{ glob = "platform/manifests/**/*.yaml", kind = "iac", lang = "yaml", tags = ["k8s"] }]
[suppress]
require_reason   = true
min_reason_chars = 10
allow_file_level = true
allow_wildcard   = false                     # permit whalescan:ignore[*]
max_block_lines  = 200
report_unused    = false
[secrets]
allow_values  = []                           # regexes; a secret value fully matching one is dropped
entropy_delta = 0.0                          # added to every entropy threshold (-1.0 .. +1.0)
[inject]
max_bytes = 2_097_152
reveal    = true
[adapters]
enabled   = []                               # semgrep|gitleaks|trivy|osv, or ["auto"]
timeout_s = 300
strict    = false
semgrep   = { bin = "semgrep", args = ["--config", "p/default"] }        # bin/args/env: trusted-only
gitleaks  = { bin = "gitleaks", args = [], severity_map = {} }
trivy     = { bin = "trivy", scanners = ["vuln", "misconfig"] }
osv       = { backend = "osv-scanner", allow_network = false }          # osv-scanner|pip-audit|api
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

**Syntax** is exactly gitignore, compiled by the shared `ignore.py`: `#` comments (`\#` escapes), trailing spaces
trimmed unless escaped, `!` negates, trailing `/` = directories only, a pattern with a non-trailing `/` is anchored to
the ignore file's directory (otherwise it matches a basename at any depth), `*` → `[^/]*`, `?` → `[^/]`, `[…]`
classes, `**/` any leading directories, `/**` everything inside, `/**/` zero or more directories. The last matching
pattern wins; ignore files apply from the root down to the deepest directory; as in git, a file under an excluded
directory cannot be re-included. Files may appear in any directory and cover that subtree.

**Extension: rule-scoped sections.** A line `#!rules WS-AGT-*,WS-SEC-GEN-*` starts a section whose patterns apply
only to those rule IDs/globs; `#!rules *` returns to all rules. To git and other tools the directive is a comment.

**Differences from `.gitignore`:** (1) `.whalescanignore` also applies to **explicit** paths and to
`--stdin-filename`, so the `scan_edit.py` hook stays quiet on `tests/fixtures/`, while `.gitignore` applies only
during traversal (an explicitly named file is scanned even if gitignored); (2) `.git/` is always excluded and cannot
be negated. **Built-in excludes** (lowest priority, negatable): `node_modules/ .venv/ venv/ __pycache__/ .tox/
.mypy_cache/ .ruff_cache/ .terraform/ .terragrunt-cache/ dist/ build/ target/ .idea/ *.min.js.map`.

```gitignore
# repo root: the self-scan must be clean (DESIGN §9, gate 4)
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
        st = os.lstat(root)                                   # FileNotFoundError → UsageError (exit 2)
        if stat.S_ISREG(st.st_mode):                          # explicit file: .gitignore not applied
            if not ign.whalescanignored(rel(root)): yield file_candidate(root, st)
            continue
        if stat.S_ISLNK(st.st_mode): yield from symlink_policy(root, roots, cfg); continue
        for r in (git_ls_files(root) if use_git(root, cfg) else fs_walk(root, ign)):
            if not ign.ignored(r) and cfg.included(r):
                yield from caps_and_candidate(r)              # §5.3; stops at max_files

def fs_walk(top, ign):                                        # walker="fs", or git unavailable
    stack = [top]
    while stack:
        d = stack.pop()
        with os.scandir(d) as it:
            entries = sorted(it, key=lambda e: e.name.encode("utf-8", "surrogateescape"))
        for e in reversed(entries):                           # LIFO → lexicographic visit order
            if e.name == ".git": continue
            if e.is_symlink(): yield from symlink_policy(e.path, ...); continue
            if e.is_dir(follow_symlinks=False):
                if not ign.ignored(rel(e.path), is_dir=True): stack.append(e.path)
            elif e.is_file(follow_symlinks=False):
                yield rel(e.path)                             # FIFOs, sockets, devices: never yielded
```
`walker="auto"` uses `git ls-files --cached --others --exclude-standard -z` (one subprocess; honors global and
`info/exclude` rules) when the root is inside a work tree, `git` is on PATH and `respect_gitignore` is true; otherwise
`fs_walk` with the built-in gitignore compiler. Submodule gitlinks are skipped (info log). Output paths are POSIX
relative to `--root`; explicit paths outside the root are reported absolute.

### 5.2 Symlink policy
Default: symlinks (file or directory) are not followed and are counted as `skipped.symlink`. With
`--follow-symlinks`, a link is followed only if `os.path.realpath(target)` lies inside one of the scan roots;
directory cycles are cut by a `(st_dev, st_ino)` visited set. Links escaping the roots (a cloned repo's
`config -> ~/.aws/credentials`) are always skipped with a `symlink-escape` warning: the scanner MUST NOT read outside
its roots, since redaction is the second line of defense, not the first.

### 5.3 Size caps and special files
| Cap | Default | On exceed |
|---|---|---|
| Regular files only (`S_ISREG` after `lstat`) | — | Other types skipped silently; opening a FIFO would hang a hook |
| `max_file_bytes` | 1 MiB | Skip; `skipped.too_large` + info diagnostic |
| `max_files` / `max_total_bytes` | 50 000 / 512 MiB | Stop enumeration; `truncated=true`; `max-files-reached` warning |
| py_ast parse | 512 KiB | py_ast rules skip the file; text rules still run |
| yamlite parse | 2 MiB, depth 64, 200k nodes, 10k alias expansions | `parse-error`; structured rules skip the file |

Files are opened with `O_RDONLY | O_NOFOLLOW` where available and read in one call capped at `max_file_bytes + 1`.

### 5.4 Binary detection
`BINARY_EXT`: images (`.png .jpg .jpeg .gif .webp .ico`), `.pdf`, archives (`.zip .gz .tgz .bz2 .xz .zst .7z .jar
.war .whl`), native and bytecode (`.class .so .dylib .dll .exe .o .a .pyc`), data and models (`.parquet .orc .avro
.npy .npz .pkl .onnx .safetensors .pt .db .sqlite`), keystores (`.p12 .pfx .jks`), fonts (`.woff .woff2`).
```python
def sniff(head: bytes, name: str) -> tuple[bool, str | None]:          # (is_binary, bom_codec); head = first 8 KiB
    if suffix(name) in BINARY_EXT: return True, None
    for bom, codec in BOMS:
        if head.startswith(bom): return False, codec                    # UTF-16/32 text contains NULs
    if b"\x00" in head: return True, None
    ctrl = sum(1 for b in head if b < 0x09 or (0x0E <= b < 0x20 and b != 0x1B) or b == 0x7F)
    return (len(head) > 0 and ctrl / len(head) > 0.30), None
```

### 5.5 Encoding and BOM handling
| BOM bytes (checked in this order) | Codec | Note |
|---|---|---|
| `00 00 FE FF` / `FF FE 00 00` | utf-32-be / utf-32-le | UTF-32 LE MUST be tested before UTF-16 LE |
| `EF BB BF` | utf-8 | BOM stripped; `bom="utf-8"` |
| `FE FF` / `FF FE` | utf-16-be / utf-16-le | Common in Windows-exported SQL and PowerShell |

With a BOM: strip it and decode with that codec and `errors="replace"` (any U+FFFD adds `decode-replaced`). Without:
strict UTF-8, else latin-1 (lossless, one char per byte) with an `encoding_fallback` flag and a
`decode-fallback-latin1` diagnostic; the `unicode` matcher is disabled for such files because their code points are
meaningless. Text is never newline-normalized (CRLF keeps its `\r`). Only `\n` breaks lines for positions: a lone
`\r`, U+2028 and U+0085 do not (unlike `str.splitlines`), so line numbers agree with editors, git and SARIF viewers.

### 5.6 Positions and file flags
```python
line_starts = [0] + [i + 1 for i in find_all(text, "\n")]       # str.find loop
def pos(off):                                  # 1-based (line, col); col counts Unicode code points
    i = bisect_right(line_starts, off) - 1
    return i + 1, off - line_starts[i] + 1
def end_pos(end):                              # exclusive end → column after the last char
    line, col = pos(end - 1)
    return line, col + 1
```
Columns count **code points**, not UTF-16 units; SARIF declares `columnKind: "unicodeCodePoints"`. Flags:
`generated` if the first 5 lines match `(?i)@generated\b|\bDO NOT EDIT\b|\bauto-?generated\b`; `minified` if
size > 20 KiB and mean line length > 1000, or the name matches `\.min\.(?:js|css)$`; `test` if the path matches
`(?:^|/)(?:tests?|__tests__|spec|specs|fixtures?|testdata)/|(?:^|/)(?:test_[^/]*\.py|[^/]*_test\.(?:py|go)|conftest\.py|[^/]*\.(?:spec|test)\.[jt]sx?)$`.

---

## 6. File classifier

`classify(path, head_text) -> (lang, kind, tags)`, kind ∈ `code | iac | ci | agent-config | doc | data`. Steps, in
order: (1) `[classify].rules` from config; (2) path table A; (3) extension table B; (4) content sniff C over the first
64 KiB; (5) fallback `text`/`data`. The first decisive step sets `lang` and `kind`; tags accumulate from all steps plus
the §5.6 flags. For multi-document YAML the highest kind wins: `ci > iac > agent-config > code > doc > data`.

| A · Path pattern | lang | kind | tags |
|---|---|---|---|
| `.github/workflows/*.{yml,yaml}` / `**/action.{yml,yaml}` | yaml | ci | gha / gha-action |
| `.tekton/**/*.{yml,yaml}` | yaml | ci | tekton |
| `.gitlab-ci.yml`, `.circleci/config.yml`, `azure-pipelines.yml`, `bitbucket-pipelines.yml`, `Jenkinsfile` | yaml / groovy | ci | ci-other |
| `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `**/SKILL.md`, `.claude/{commands,agents}/**/*.md`, `.cursorrules`, `.cursor/rules/**`, `.windsurfrules`, `.clinerules` | markdown | agent-config | agent-instructions |
| `.mcp.json`, `**/mcp.json`, `.vscode/mcp.json` | json | agent-config | mcp |
| `.claude/settings*.json`, `.claude-plugin/*.json`, `**/hooks/hooks.json` | json | agent-config | agent-settings |
| `Dockerfile`, `Dockerfile.*`, `*.Dockerfile`, `Containerfile` | dockerfile | iac | docker |
| `{docker-compose,compose}*.{yml,yaml}` | yaml | iac | compose |
| `**/Chart.yaml`; `values*.yaml` and `templates/**` beside a `Chart.yaml` | yaml | iac | helm (+helm-template) |
| `terragrunt.hcl` / `kustomization.{yml,yaml}` | hcl / yaml | iac | terragrunt / k8s, kustomize |
| `**/{playbooks,roles,group_vars,host_vars}/**/*.{yml,yaml}`, `site.yml`, `playbook*.yml`, `ansible.cfg` | yaml / ini | iac | ansible |
| `nginx.conf`, `**/nginx/**/*.conf`, `**/{sites-available,sites-enabled,conf.d}/*` | nginx | iac | nginx |
| `traefik.{yml,yaml,toml}`, `**/traefik/**/*.{yml,yaml,toml}` | yaml / toml | iac | traefik |
| `dags/**/*.py`, `**/airflow/**/*.py` | python | code | airflow-dag |
| `.env`, `.env.*`, `*.env` | dotenv | data | env (+example for `.example/.sample/.template/.dist`) |
| `requirements*.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `go.sum`, `Cargo.lock` | varies | data | lockfile |

| B · Extension | lang | kind |
|---|---|---|
| `.py .pyi` · `.ipynb` | python · json (+notebook) | code |
| `.scala .sc .sbt` · `.java .kt .go .rs .rb .php .cs` · `.js .mjs .cjs .jsx` · `.ts .tsx` | per extension | code |
| `.sql` · `.sh .bash .zsh .ksh` · `.ps1` · `.j2 .jinja .jinja2 .tpl` | sql · shell · powershell · jinja | code |
| `.tf` · `.tf.json` · `.tfvars` · `.hcl` | hcl · json · hcl · hcl | iac (+terraform) |
| `.yml .yaml` · `.json` · `.toml` · `.ini .cfg .conf .properties` · `.xml` · `.csv .tsv` | per extension | data (then sniff C) |
| `.pem .key .crt .asc` | text (+key-material) | data |
| `.md .mdx .markdown` · `.rst .adoc .txt` · `.html .htm .xhtml .svg` | markdown · rst/text · html/xml | doc |

| C · Content sniff (first 64 KiB) | Effect |
|---|---|
| YAML doc with `^apiVersion:` and `^kind:` | iac + k8s; `tekton.dev/` → ci + tekton; `*.toolkit.fluxcd.io/` → ci + flux; RBAC kinds / CRDs add k8s-rbac / k8s-crd |
| YAML with top-level `on:` and `jobs:` outside `.github/workflows/` | ci + gha |
| YAML with top-level `services:` whose children have `image:`/`build:` · top-level sequence with `hosts:`/`tasks:` | iac + compose · iac + ansible |
| JSON with top-level `"mcpServers"` | agent-config + mcp |
| `AWSTemplateFormatVersion` or `Type: AWS::…` resources · JSON with `format_version` + `terraform_version` | iac + cloudformation · data + terraform-plan |
| Python `^[ \t]*(?:from\|import)[ \t]+(?:fastapi\|starlette)\b` (likewise `airflow\b`, `pyspark\b`) | + fastapi / airflow-dag / spark |
| Python importing `boto3` with `bedrock-runtime`, `vertexai`, `google.cloud.aiplatform`, `langchain*`, `llama_index` | + llm |
| Python importing `pinecone`, `qdrant_client`, `weaviate`, `chromadb`, `pymilvus`, `pgvector` | + vectordb |
| Python importing `ccxt`, `alpaca`, `ib_insync`, `binance` · `kopf` | + trading · + k8s-operator |
| Scala `import org.apache.spark` · no extension + shebang `python*` / `(ba\|z)?sh` | + spark · python / shell, code |

---

## 7. Rule format

### 7.1 Pack files and examples
A pack file `rules/<pack>/<name>.yaml` is a YAML sequence of rule objects. Built-in packs ship pre-validated in
`bundle.json`; `--rules-dir` and `rules.extra_dirs` are parsed with `yamlite`.
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
  fix: Read the DSN from Secrets Manager, Vault or a k8s Secret, and rotate this credential.
  references: ["https://cwe.mitre.org/data/definitions/798.html"]
```
Structured examples: WS-K8S-001 and `.mcp.json` pinning (§8.6), open security groups (§8.8).

### 7.2 JSON Schema (draft 2020-12)
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:whalescan:schema:rule:1",
  "title": "whalescan rule (one item of a pack file's top-level sequence)",
  "type": "object", "additionalProperties": false,
  "required": ["id", "title", "pack", "severity", "confidence", "owner", "applies_to", "match", "message", "references"],
  "properties": {
    "id": {"type": "string", "pattern": "^WS-(INJ|ACC|CRY|SSRF|DES|WEB|SEC|AGT|GHA|K8S|TF|DKR|AIR|SPK|API|LLM|TRD)(-[A-Z0-9]{2,10})?-[0-9]{3}$"},
    "title": {"type": "string", "minLength": 8, "maxLength": 120},
    "pack": {"type": "string", "pattern": "^(appsec|secrets|agentsec|domain)/[a-z0-9][a-z0-9-]{0,40}$"},
    "severity": {"$ref": "#/$defs/severity"},
    "confidence": {"$ref": "#/$defs/confidence"},
    "cwe": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^CWE-[1-9][0-9]{0,4}$"}},
    "owasp": {"type": "array", "uniqueItems": true, "items": {"type": "string",
      "pattern": "^(A(0[1-9]|10)(:20(17|21|25))?|API([1-9]|10)(:2023)?|LLM(0[1-9]|10)(:2025)?|CICD-SEC-([1-9]|10)|K(0[1-9]|10))$"}},
    "atlas": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^AML\\.T[0-9]{4}(\\.[0-9]{3})?$"}},
    "tags": {"type": "array", "uniqueItems": true, "items": {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,31}$"}},
    "owner": {"type": "string", "pattern": "^@[A-Za-z0-9][A-Za-z0-9-]{0,38}(/[A-Za-z0-9._-]{1,64})?$"},
    "since": {"type": "string", "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$"},
    "deprecated": {"type": "boolean", "default": false},
    "replaced_by": {"$ref": "#/$defs/rule_ref"},
    "enabled_by_default": {"type": "boolean", "default": true},
    "applies_to": {"$ref": "#/$defs/applies_to"},
    "keywords": {"type": "array", "maxItems": 32, "items": {"type": "string", "minLength": 2, "maxLength": 64}},
    "keywords_case": {"enum": ["insensitive", "sensitive"], "default": "insensitive"},
    "match": {"$ref": "#/$defs/expr"},
    "filters": {"type": "object", "additionalProperties": false, "properties": {
      "file_regex": {"$ref": "#/$defs/pattern"}, "file_not_regex": {"$ref": "#/$defs/pattern"},
      "line_not_regex": {"$ref": "#/$defs/pattern"}, "path_not_glob": {"$ref": "#/$defs/strs"}}},
    "redact": {"type": "boolean", "default": false},
    "exposure_sensitive": {"type": "boolean", "default": true},
    "supersedes": {"type": "array", "uniqueItems": true, "items": {"$ref": "#/$defs/rule_ref"}},
    "max_hits_per_file": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 50},
    "message": {"type": "string", "minLength": 10, "maxLength": 600},
    "fix": {"type": "string", "maxLength": 1200},
    "references": {"type": "array", "minItems": 1, "items": {"type": "string", "pattern": "^https://\\S+$"}},
    "fixtures": {"default": "auto", "oneOf": [{"const": "auto"}, {"type": "object", "additionalProperties": false,
      "required": ["pos", "neg"], "properties": {"pos": {"$ref": "#/$defs/strs1"}, "neg": {"$ref": "#/$defs/strs1"}}}]}
  },
  "$defs": {
    "severity": {"enum": ["critical", "high", "medium", "low", "info"]},
    "confidence": {"enum": ["high", "medium", "low"]},
    "kind": {"enum": ["code", "iac", "ci", "agent-config", "doc", "data"]},
    "rule_ref": {"type": "string", "pattern": "^WS-[A-Z0-9-]+$"},
    "scalar": {"type": ["string", "number", "boolean", "null"]},
    "strs": {"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 256}},
    "strs1": {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1, "maxLength": 256}},
    "one_or_many": {"oneOf": [{"type": "string", "minLength": 1}, {"$ref": "#/$defs/strs1"}]},
    "pattern": {"type": "string", "minLength": 1, "maxLength": 4096},
    "group": {"type": "string", "pattern": "^[A-Za-z_][A-Za-z0-9_]*$"},
    "applies_to": {"type": "object", "additionalProperties": false, "minProperties": 1, "properties": {
      "kind": {"oneOf": [{"$ref": "#/$defs/kind"}, {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/kind"}}]},
      "lang": {"$ref": "#/$defs/one_or_many"}, "glob": {"$ref": "#/$defs/strs"}, "exclude_glob": {"$ref": "#/$defs/strs"},
      "tags_any": {"$ref": "#/$defs/strs"}, "tags_none": {"$ref": "#/$defs/strs"},
      "include_minified": {"type": "boolean", "default": false}, "max_bytes": {"type": "integer", "minimum": 1}}},
    "expr": {"oneOf": [
      {"type": "object", "additionalProperties": false, "required": ["all"], "properties": {
        "all": {"type": "array", "minItems": 2, "items": {"$ref": "#/$defs/expr"}},
        "near_lines": {"type": "integer", "minimum": 0, "maximum": 500}}},
      {"type": "object", "additionalProperties": false, "required": ["any"], "properties": {
        "any": {"type": "array", "minItems": 2, "items": {"$ref": "#/$defs/expr"}}}},
      {"type": "object", "additionalProperties": false, "required": ["not"], "properties": {"not": {"$ref": "#/$defs/expr"}}},
      {"type": "object", "additionalProperties": false, "minProperties": 1, "maxProperties": 1, "properties": {
        "regex": {"$ref": "#/$defs/regex"}, "multiline": {"$ref": "#/$defs/multiline"}, "unicode": {"$ref": "#/$defs/unicode"},
        "entropy": {"$ref": "#/$defs/entropy"}, "yaml_path": {"$ref": "#/$defs/yaml_path"}, "py_ast": {"$ref": "#/$defs/py_ast"},
        "hcl": {"$ref": "#/$defs/hcl"}, "builtin": {"enum": ["mcp_drift"]}}}]},
    "regex": {"oneOf": [{"$ref": "#/$defs/pattern"}, {"type": "object", "additionalProperties": false, "required": ["pattern"],
      "properties": {"pattern": {"$ref": "#/$defs/pattern"},
        "flags": {"type": "array", "uniqueItems": true, "items": {"enum": ["i", "x", "a"]}},
        "report_group": {"oneOf": [{"type": "integer", "minimum": 0}, {"$ref": "#/$defs/group"}], "default": 0},
        "secret_group": {"$ref": "#/$defs/group"}}}]},
    "multiline": {"oneOf": [
      {"type": "object", "additionalProperties": false, "required": ["pattern"], "properties": {
        "pattern": {"$ref": "#/$defs/pattern"},
        "flags": {"type": "array", "uniqueItems": true, "items": {"enum": ["i", "x", "a", "s"]}},
        "max_span_lines": {"type": "integer", "minimum": 1, "maximum": 200, "default": 30},
        "secret_group": {"$ref": "#/$defs/group"}}},
      {"type": "object", "additionalProperties": false, "required": ["sequence", "within_lines"], "properties": {
        "sequence": {"type": "array", "minItems": 2, "maxItems": 5, "items": {"$ref": "#/$defs/pattern"}},
        "within_lines": {"type": "integer", "minimum": 1, "maximum": 200},
        "flags": {"type": "array", "uniqueItems": true, "items": {"enum": ["i", "x", "a"]}}}}]},
    "unicode": {"type": "object", "additionalProperties": false, "required": ["classes"], "properties": {
      "classes": {"type": "array", "minItems": 1, "uniqueItems": true,
        "items": {"enum": ["ZW", "BIDI", "TAG", "VS", "PUA", "CTRL", "HOMOGLYPH"]}},
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
        "keywords": {"$ref": "#/$defs/strs"}, "required": {"type": "boolean", "default": false},
        "window_chars": {"type": "integer", "minimum": 8, "maximum": 400, "default": 80}}},
      "exclude_regex": {"type": "array", "items": {"$ref": "#/$defs/pattern"}}}},
    "predicates": {"type": "object", "properties": {
      "exists": {"type": "boolean"}, "equals": {"$ref": "#/$defs/scalar"}, "not_equals": {"$ref": "#/$defs/scalar"},
      "in": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/scalar"}},
      "not_in": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/scalar"}},
      "regex": {"$ref": "#/$defs/pattern"}, "not_regex": {"$ref": "#/$defs/pattern"},
      "type": {"enum": ["str", "int", "float", "bool", "null", "map", "seq"]},
      "contains": {"type": ["string", "number", "boolean"]},
      "quantifier": {"enum": ["any", "all"], "default": "any"}}},
    "yaml_cond": {"allOf": [{"$ref": "#/$defs/predicates"}, {"type": "object", "required": ["path"], "minProperties": 2,
      "properties": {"path": {"type": "string", "minLength": 1, "maxLength": 512}, "promote": {"type": "boolean", "default": true}}}],
      "unevaluatedProperties": false},
    "yaml_conds": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/yaml_cond"}},
    "yaml_path": {"type": "object", "additionalProperties": false,
      "anyOf": [{"required": ["all"]}, {"required": ["any"]}, {"required": ["none"]}],
      "properties": {"each": {"type": "string", "minLength": 1, "maxLength": 512},
        "schema": {"enum": ["auto", "yaml11", "yaml12"], "default": "auto"},
        "all": {"$ref": "#/$defs/yaml_conds"}, "any": {"$ref": "#/$defs/yaml_conds"}, "none": {"$ref": "#/$defs/yaml_conds"}}},
    "arg_cond": {"type": "object", "additionalProperties": false, "minProperties": 1, "properties": {
      "tainted": {"type": "boolean"}, "dynamic_string": {"type": "boolean"}, "constant": {"type": "boolean"},
      "equals": {"$ref": "#/$defs/scalar"}, "not_equals": {"$ref": "#/$defs/scalar"}, "regex": {"$ref": "#/$defs/pattern"}}},
    "py_ast": {"oneOf": [
      {"type": "object", "additionalProperties": false, "required": ["call"], "properties": {"call": {
        "type": "object", "additionalProperties": false, "required": ["callee"], "properties": {
          "callee": {"$ref": "#/$defs/one_or_many"},
          "args": {"type": "object", "propertyNames": {"pattern": "^([0-9]{1,2}|\\*)$"}, "additionalProperties": {"$ref": "#/$defs/arg_cond"}},
          "kwargs": {"type": "object", "propertyNames": {"$ref": "#/$defs/group"}, "additionalProperties": {"$ref": "#/$defs/arg_cond"}},
          "kwarg_absent": {"$ref": "#/$defs/strs"}, "sources": {"$ref": "#/$defs/strs"},
          "sanitizers": {"$ref": "#/$defs/strs"}, "require_import": {"$ref": "#/$defs/one_or_many"}}}}},
      {"type": "object", "additionalProperties": false, "required": ["fastapi_route"], "properties": {"fastapi_route": {
        "type": "object", "additionalProperties": false, "properties": {
          "methods": {"type": "array", "items": {"enum": ["get", "post", "put", "patch", "delete", "api_route", "websocket"]}},
          "auth_regex": {"$ref": "#/$defs/pattern"}, "ignore_paths_regex": {"$ref": "#/$defs/pattern"}}}}}]},
    "hcl_cond": {"allOf": [{"$ref": "#/$defs/predicates"}, {"type": "object",
      "anyOf": [{"required": ["attr"]}, {"required": ["range_includes"]}],
      "properties": {"attr": {"type": "string", "minLength": 1, "maxLength": 256},
        "range_includes": {"type": "object", "additionalProperties": false, "required": ["lo", "hi", "any"], "properties": {
          "lo": {"type": "string"}, "hi": {"type": "string"},
          "any": {"type": "array", "minItems": 1, "items": {"type": "integer", "minimum": 0, "maximum": 65535}}}}}}],
      "unevaluatedProperties": false},
    "hcl_conds": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/hcl_cond"}},
    "hcl": {"type": "object", "additionalProperties": false, "required": ["block"], "properties": {
      "block": {"type": "string", "minLength": 1, "maxLength": 256}, "each": {"type": "string", "minLength": 1, "maxLength": 256},
      "all": {"$ref": "#/$defs/hcl_conds"}, "any": {"$ref": "#/$defs/hcl_conds"}, "none": {"$ref": "#/$defs/hcl_conds"},
      "on_unknown": {"enum": ["nomatch", "match"], "default": "nomatch"}}}
  }
}
```

### 7.3 Semantic checks (loader, beyond the schema)
Each failure is a `RuleError` (exit 2); (dev) checks run only in `rules test`.

| Check | Rule |
|---|---|
| Unique IDs | Across bundle, packs and extra dirs; an extra-dir rule may not shadow a bundled ID |
| Namespace ↔ pack | `WS-SEC` → `secrets/*`; `WS-AGT` → `agentsec/*`; `WS-INJ\|ACC\|CRY\|SSRF\|DES\|WEB` → `appsec/*` or `domain/*`; all others → `domain/*` |
| Matcher ↔ applies_to | `yaml_path` needs lang yaml/json; `hcl` needs hcl or `.tf.json`; `py_ast` needs python; `builtin` needs `agentsec/mcp` |
| Regex lint | R1–R7 (§8.2) on every pattern, including filters and predicates |
| Group names | `secret_group`, `report_group` and `{{name}}` placeholders in `message` exist in the pattern |
| Paths and refs | `yaml_path`/`hcl` paths parse; `py_ast.sources` name a known set or dotted path; `replaced_by`/`supersedes` exist; `not` appears only directly under `all` |
| Fixtures (dev) | `tests/fixtures/<ID>/` has ≥1 `pos*` and ≥1 `neg*` file |

The stdlib validator in `schema.py` implements exactly the keywords used above; CI also validates every pack with
the reference `jsonschema` package to catch drift between the two.

---

## 8. Matchers

### 8.1 Common contract, pipeline, combinators
```python
@dataclass(slots=True)
class Hit:                     # offsets are code points into ctx.text, end exclusive; positions per §5.6
    start: int; end: int; line: int; col: int; end_line: int; end_col: int
    captures: dict[str, str]; secret_spans: list[tuple[int, int]]      # raw; redacted before any output
    reachability: str = "unknown"; confidence_delta: int = 0            # tainted|unknown|constant; -1 = one step lower
    props: dict[str, Any] = field(default_factory=dict)                 # trace, decoded, entropy, unresolved …
```
**Per-file pipeline**, cheapest first: (1) `applies_to` index lookup on (kind, lang, tags, glob); (2) keyword
prefilter: one pass of a combined `re.escape`d alternation of all candidate rules' keywords (casefolded when
insensitive), and a rule is active if any keyword occurred or it has none; (3) `filters.file_regex` /
`file_not_regex`; (4) text matchers `regex`, `multiline`, `unicode`, `entropy`; (5) on-demand parse, once per file and
shared: yamlite, hcllite, `ast`; (6) structured matchers; (7) `line_not_regex`, `path_not_glob`;
(8) `max_hits_per_file`, with the overflow counted in `stats.capped[rule_id]`.

**Combinators.** `any` is the union of child hits. `all` requires every positive child to hit and every `not` child
to be empty; its hits are the first positive child's. With `near_lines: N`, a first-child hit survives only if every
other positive child hits within N lines of it and no `not` child does. Children run in order; `all` short-circuits
on the first empty child.

### 8.2 `regex` (all hits, line and column)
```python
def run_regex(ctx, spec, rule):
    pat = spec.compiled()                                # lazy; re.MULTILINE | flags (i, x, a)
    for n, m in enumerate(pat.finditer(ctx.text)):      # ALL non-overlapping hits, never re.search
        if n >= rule.max_hits_per_file: ctx.cap(rule.id); break
        s, e = m.span(spec.report_group)
        if s == e: continue                              # defensive; R4 forbids zero-width patterns
        secret = [m.span(spec.secret_group)] if spec.secret_group and m.group(spec.secret_group) else []
        yield Hit(s, e, *ctx.pos(s), *ctx.end_pos(e), m.groupdict(), secret)
```
`^`/`$` are line anchors and `.` never matches `\n`; cross-line matching belongs to `multiline`. DESIGN's "`--`
semantics" has two halves: patterns never pass through argv, so a leading `-` is literal (a regression test covers
`-----BEGIN OPENSSH PRIVATE KEY-----`), and every exporter (`rules explain --grep`) emits `-e PATTERN --`.

| Lint | Rule (run at load and in CI) | Level |
|---|---|---|
| R1 | Compiles with Python `re` | error |
| R2 | No nested unbounded repeats (`MAX_REPEAT`/`MIN_REPEAT` with max `MAXREPEAT` inside another), checked on the `re._parser` AST (`sre_parse` on 3.10) | error |
| R3 | The first element is not an unbounded repeat of `.`, `\s`, `\S` or a negated class (quadratic finditer on long lines): anchor on a literal or use `{0,N}` | error |
| R4 | Minimum width > 0 (`parse(p).getwidth()[0] > 0`) | error |
| R5 | No `(?s)`/DOTALL in `regex` (use `multiline`) | error |
| R6 | Unbounded `*`/`+` on `.` or a negated class anywhere should be `{0,N}`, N ≤ 4096 | warning |
| R7 | No alternation inside an unbounded repeat whose branches share a first character | error |

### 8.3 `multiline`
**`pattern` form:** `finditer` over the whole text with `re.M` (plus `re.S` if flag `s`); a hit is dropped if
`end_line - line + 1 > max_span_lines` (default 30). Example (private key):
`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[A-Za-z0-9+/=\s]{64,8192}-----END`.
**`sequence` form:** ordered line-proximity matching, ReDoS-safe by construction.
```python
def run_sequence(ctx, spec):
    hits = [list(p.finditer(ctx.text)) for p in spec.compiled_seq()]      # each list sorted by start
    for h0 in hits[0]:
        prev, limit = h0, ctx.line_of(h0.start()) + spec.within_lines
        for later in hits[1:]:
            nxt = first(m for m in later if m.start() >= prev.end())     # bisect on starts
            if nxt is None or ctx.line_of(nxt.start()) > limit: break
            prev = nxt
        else:
            yield Hit(h0.start(), prev.end(), ...)                        # spans first → last
```
Example (Airflow template injection): `sequence: ['\bBashOperator\(', 'bash_command\s*=\s*f?["'']',
'\{\{\s*(?:dag_run\.conf|params)\b']`, `within_lines: 12`.

### 8.4 `unicode` (code-point classes)
If `ctx.text.isascii()` (a C fast path) nothing runs. Otherwise one compiled class regex finds runs,
`[­؜᠎​-‏‪-‮⁠-⁤⁦-⁩﻿︀-️\U000e0000-\U000e007f\U000e0100-\U000e01ef]+`,
and PUA, CTRL and HOMOGLYPH use their own scanners. Each run is one hit.

| Class | Code points | Reveal marker | Precision exemptions / extras |
|---|---|---|---|
| ZW | U+200B ZWSP, 200C ZWNJ, 200D ZWJ, 2060 WJ, 2061–2064, FEFF (not at offset 0), 180E, 00AD SHY | `[ZWSP]` `[ZWNJ]` `[ZWJ]` `[WJ]` `[ZWNBSP]` `[SHY]` `[U+2061]` | ZWJ between two Extended_Pictographic chars (emoji); ZWNJ between Arabic (U+0600–06FF) or Indic (U+0900–0DFF) letters |
| BIDI | U+202A LRE, 202B RLE, 202C PDF, 202D LRO, 202E RLO, 2066 LRI, 2067 RLI, 2068 FSI, 2069 PDI, 200E LRM, 200F RLM, 061C ALM | `[BIDI:RLO]` … | `props.bidi_unbalanced` when openers outnumber closers (PDF, PDI) on a line: Trojan Source, CVE-2021-42574 |
| TAG | U+E0000–E007F | `[TAG:"<decoded>"]` | Always flagged; `props.decoded` = `chr(cp - 0xE0000)` over E0020–E007E |
| VS | U+FE00–FE0F, U+E0100–E01EF | `[VS:n]` | FE0F after an emoji/keycap and single FE00–FE0E are exempt; runs ≥2 decode as bytes (FE00–FE0F → 0–15, E0100–E01EF → 16–255) into `props.decoded_bytes_hex` |
| PUA | U+E000–F8FF, F0000–FFFFD, 100000–10FFFD | `[PUA:U+E123]` | Files tagged `font` or `icons` |
| CTRL | U+0000–0008, 000B, 000E–001F (incl. ESC 0x1B, the terminal-escape vector), 007F, 0080–009F | `[CTRL:U+001B]` | `\t \n \r \f` |
| HOMOGLYPH | A word `[^\W_]+` with ≥1 ASCII letter **and** ≥1 entry of the Cyrillic/Greek confusables table (~45 in `unicode_data.py`: U+0430 а, 0435 е, 043E о, 0440 р, 0441 с, 0445 х, 0456 і, 03BF ο, 0391 Α …) | `[U+0430→a]` | All-Cyrillic/all-Greek words are exempt; an all-confusable word on an otherwise-ASCII line gets `confidence_delta=-1` |

`min_run` applies per class; `bidi_unbalanced_only` keeps only unbalanced BIDI hits. Reveal markers are used in
every snippet, message and report (§13), so a finding never carries its hidden payload back into an agent's context.

### 8.5 `entropy` (Shannon)
For a token `s` of length L with character counts `n_c`:
`H(s) = − Σ_c (n_c / L) · log2(n_c / L)` bits per character, `0 ≤ H ≤ log2(min(L, |charset|))`.
```python
def shannon(s: str) -> float:
    L = len(s); return -sum((n / L) * math.log2(n / L) for n in Counter(s).values())
```
**Candidates.** `scope: values` (default) applies the charset regex only inside quoted string literals and the `val`
group of `(?<![A-Za-z0-9_.-])(?P<key>[A-Za-z_][A-Za-z0-9_.-]{0,63})["']?[ \t]{0,8}(?::=|=>|[:=])[ \t]{0,8}(?P<q>["'\x60]?)(?P<val>[^\s"'\x60,;]{8,256})`;
`scope: anywhere` applies it to the whole text.

| charset | Token regex | Max H | Threshold for L = 16–23 / 24–39 / ≥40 |
|---|---|---|---|
| hex | `(?<![0-9A-Fa-f])[0-9A-Fa-f]{16,128}(?![0-9A-Fa-f])` | 4.0 | 3.0 / 3.2 / 3.4 |
| base64 | `(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,200}={0,2}(?![A-Za-z0-9+/=])` | 6.0 | 3.8 / 4.2 / 4.5 |
| base64url | `(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{16,200}(?![A-Za-z0-9_-])` | 6.0 | 3.8 / 4.2 / 4.5 |
| alnum | `(?<![A-Za-z0-9])[A-Za-z0-9]{16,200}(?![A-Za-z0-9])` | 5.95 | 3.6 / 4.0 / 4.3 |

A rule's `threshold` replaces the bucket values; `secrets.entropy_delta` is added to all thresholds. A token is a hit
iff: `min_len ≤ L ≤ max_len`; `H ≥ threshold(L)`; it has ≥ `min_classes` of {upper, lower, digit} (hex: ≥1 digit
and ≥1 letter); it is not a placeholder,
`(?i)^(?:x{6,}|\*{4,}|<[^>]{1,64}>|\$\{[^}]{1,64}\}|\{\{[^}]{1,64}\}\}|(?:your|my|example|sample|dummy|fake|test|changeme|placeholder|redacted|replace)[_-]?[a-z0-9_-]{0,40})$`;
not a run `(.)\1{5,}` (applied to the token only) or a sequential run (`0123456789`, `abcdef`); not a UUID
(`^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$`) unless keyword context matched; not a 40- or 64-hex digest
when the key or line matches `(?i)\b(?:sha|commit|rev|ref|digest|checksum|integrity|uses)\b`; not in a
`lockfile`-tagged file; and not matched by `exclude_regex`.

**Context and confidence.** `context.keywords` default: `secret token passwd password pwd api_key apikey access_key
private credential auth bearer signature client_secret dsn conn webhook hmac`, searched case-insensitively in the
`key` group or the `window_chars` before the token on its line. Confidence: `high` with a keyword and
`H ≥ threshold + 0.3`; `medium` with a keyword; `low` without (dropped if `context.required`).
`props = {entropy: round(H, 2), charset, length}`.

### 8.6 `yaml_path`
**Parser: `yamlite`, not PyYAML.** The core has no dependencies, and every node needs a source span. It supports
block and flow collections, plain/quoted/block scalars (`|`, `>`, chomping and indent indicators), comments, `---`/`...`
multi-document streams, anchors, aliases and `<<` merge keys (expanded at parse time; explicit keys win); tags
(`!Ref`, `!!str`) are kept on the node. Complex `?` keys and `%TAG` directives give a `parse-error` for that document
only. JSON parses as YAML 1.2 flow, so `yaml_path` also covers `.mcp.json`, `.tf.json` and CloudFormation JSON. Helm
templates get lenient mode first: lines that are pure template control,
`^[ \t]*\{\{-?[ \t]*(?:if|else|end|range|with|define|template|include|/\*)\b.*\}\}[ \t]*$`, are blanked, and inline
`{{ … }}` stays a string scalar.

**Keys are never type-resolved (the `on:` pitfall).** `yaml.safe_load("on: push")` returns `{True: "push"}` under
YAML 1.1, so a lookup of `"on"` silently finds nothing and every GHA trigger rule misses. yamlite keeps each key as
its unquoted source text: `on`, `"on"` and `'on'` are all key `on`, and `true:` is key `true`, never `on`. Regression
fixtures cover all four. Only **values** are resolved (for `equals`, `in`, `type`), with a per-file schema:

| Plain scalar | yaml12 (core) | yaml11 |
|---|---|---|
| `true True TRUE false False FALSE` | bool | bool |
| `yes Yes YES no No NO on On ON off Off OFF y Y n N` | str | bool |
| `null Null NULL ~`, empty | null | null |
| `0o17` · `017` · `0x1F` · `1_000` | int · int 17 · int · str | str · int 15 (octal) · int · int |
| `22:22` (compose port) | str | int 1342 (sexagesimal) |

`schema: auto` picks yaml11 for tags {k8s, helm, ansible, kustomize, tekton, flux}, whose consumers apply YAML 1.1
bools, and yaml12 for everything else (gha, compose, traefik, JSON).

**Path grammar** (paths ≤ 512 chars):
```
path   = [ "$." ] step { ( "." step ) | index }
step   = "**" | "*" | ident | quoted | alt
ident  = 1*( any char except . [ ] { } " * and whitespace )
quoted = '"' *( [^"\\] | "\\" char ) '"'          ; dotted keys: metadata.annotations."kubernetes.io/ingress.class"
alt    = "{" ident *( "," ident ) "}"              ; **.{containers,initContainers}[*]
index  = "[" ( ["-"] 1*DIGIT | "*" ) "]"           ; rules[-1], jobs.*.steps[*]
```
Tokenizer, applied with `re.match` at a moving position:
`\.?(?:(?P<dstar>\*\*)|(?P<star>\*)|"(?P<quoted>(?:[^"\\]|\\.)*)"|\{(?P<alt>[^{}]+)\}|(?P<ident>[^.\[\]{}"*\s]+))|\[(?P<index>-?[0-9]+|\*)\]`
```python
def resolve(nodes, steps, promote=True):
    for st in steps:
        out = []
        for n in nodes:
            if st.kind in ("key", "alt"):                                    # raw-text key comparison
                if n.is_map: out += [v for k, v in n.items if k.raw in st.keys]
                elif promote and n.is_scalar and n.raw in st.keys: out.append(Virtual(n))      # on: pull_request_target
                elif promote and n.is_seq: out += [Virtual(i) for i in n.items if i.is_scalar and i.raw in st.keys]
            elif st.kind == "star":  out += n.values() if n.is_map else n.items if n.is_seq else []
            elif st.kind == "dstar": out += [n, *n.descendants()]           # pre-order, zero or more levels
            elif st.kind == "index" and n.is_seq:
                out += n.items if st.i is STAR else n.items[st.i:st.i + 1 or None]
        nodes = unique_by_identity(out)
    return nodes
```
Promotion lets `on.pull_request_target` match the scalar, sequence (`on: [push, pull_request_target]`) and mapping
forms, as DESIGN §4 requires; the `Virtual` node is a null at the scalar's span. Promotion never applies after `*`,
`**` or an index, and `promote: false` turns it off per condition.

**Predicates** apply to the resolved nodes. `exists: true|false` tests non-empty/empty. Value predicates use
`quantifier: any` (default: ≥1 node satisfies) or `all` (≥1 node and all satisfy). A missing path makes **every**
value predicate false, including `not_equals`, `not_in` and `not_regex`; absence is written `exists: false`. `equals`
and `in` compare resolved values; `regex`/`not_regex` use `re.search` on the unquoted source text (block scalars after
folding); `contains` tests a sequence for an equal scalar item; `type` tests the node type.

**Evaluation and location.** Paths starting with `$.` are absolute; others are relative to the `each` anchor.
```python
for doc in docs:
    for a in (resolve([doc.root], parse(spec.each)) if spec.each else [doc.root]):
        ev_ = lambda c: ev(c, doc.root if c.path.startswith("$.") else a)
        if all(map(ev_, spec.all)) and (not spec.any or any(map(ev_, spec.any))) and not any(map(ev_, spec.none)):
            yield from locate(a, spec)
```
`locate` emits one hit per node satisfying the **first positive value condition**, else the first `exists: true`
condition, else the anchor's key span. DESIGN's WS-GHA-001 (no `each`) therefore yields one hit per offending
`with.ref`. Two more (rule excerpts):
```yaml
- id: WS-K8S-001                      # privileged container: any workload kind, any nesting depth (yaml11 bools)
  match:
    yaml_path:
      each: "**.{containers,initContainers,ephemeralContainers}[*]"
      all: [ { path: "securityContext.privileged", equals: true } ]
- id: WS-AGT-MCP-010                  # .mcp.json server launched from an unpinned package
  match:
    yaml_path:
      each: "mcpServers.*"
      all:
        - { path: "command", in: [npx, bunx, pnpx, uvx] }
        - { path: "args[*]", regex: '^(?:@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$' }   # package spec with no @version
```

### 8.7 `py_ast` (stdlib `ast`, function-local taint)
The file is parsed once with `ast.parse`; a `SyntaxError` (e.g. syntax newer than the running interpreter) gives
`parse-error` and py_ast rules skip the file. **Name resolution:** an alias map from `import x as y` /
`from m import n as k`; `qualname(expr)` turns `Attribute`/`Name` chains into dotted strings through it, and an
unresolvable receiver (call result, subscript) becomes the segment `?`. **Callee patterns:** dotted, `*` = one
segment (including `?`), `**` = any number, `{a,b}` = alternation, e.g.
`subprocess.{run,call,check_call,check_output,Popen}`, `os.{system,popen}`, `pickle.{load,loads}`, `yaml.load`,
`**.execute`, `**.sql` (matches `spark.sql` and `SparkSession.builder.getOrCreate().sql`), `sqlalchemy.text`,
`jinja2.Template`, `{eval,exec}`.

**Argument conditions** (`args` keys are positions or `"*"` for any; `kwargs` by name): `tainted` = reached by a
source; `dynamic_string` = after resolving a local `Name` one step to its last assignment, the argument is an
f-string with ≥1 `FormattedValue`, a `+` with non-constant operands, a `%` with non-constant arguments, or
`.format(...)`/`str.join` with non-constant arguments; `constant` = every leaf is `ast.Constant`; `equals`/`regex`
test the literal, or the dotted name for names (`Loader=yaml.SafeLoader`). `kwarg_absent: [Loader]` covers
`yaml.load(x)`.

| Source set | Expressions |
|---|---|
| `web` | Parameters of FastAPI/Starlette route handlers, except `Depends(...)`/`Security(...)` defaults and params annotated `int float bool UUID date datetime Decimal Literal[...]`; `request.{query_params,path_params,headers,cookies,form,json,body,url}` incl. `await request.json()`; Flask `request.{args,form,values,json,data,files,headers,cookies}`, `request.get_json()` |
| `airflow` | `dag_run.conf`, `context["dag_run"].conf`, `kwargs["dag_run"].conf`, task `params`, `ti.xcom_pull(...)` |
| `cli` | `sys.argv`, `input()`, attributes of `argparse` `parse_args()` results |
| `llm` | Results of `**.{invoke,ainvoke,converse,converse_stream,invoke_model,generate,generate_content,predict,complete,chat}` in files tagged `llm` |
| `net` | `.text`, `.content`, `.json()` of `requests.*(...)` / `httpx.*(...)`; `urlopen(...).read()` |
| `msg` | Kafka/SQS/PubSub payloads (`**.poll()`, `msg.value()`, `record.value`, `message.data`): trading signal and order paths |
| `file`, `env` (opt-in only) | `open(...).read()`, `Path(...).read_text()`, `json.load(...)`; `os.environ[...]`, `os.getenv(...)` |

Default sanitizers: `int float bool uuid.UUID shlex.quote html.escape markupsafe.escape re.escape
ipaddress.ip_address urllib.parse.quote os.path.basename`; a rule's `sanitizers` extends them.
```python
def analyze_function(fn, rule):                         # the module body is analyzed as one pseudo-function
    tainted: dict[str, Origin] = seed_params(fn, rule.sources)          # route params, Request objects
    for _ in range(3):                                  # fixpoint for loops; monotone (no kills) = recall-first
        before = len(tainted)
        for stmt in in_source_order(fn.body):
            if isinstance(stmt, (Assign, AnnAssign, AugAssign)) and (o := origin(stmt.value)): bind(targets(stmt), o)
            elif isinstance(stmt, (For, comprehension)) and (o := origin(stmt.iter)):          bind([stmt.target], o)
            elif isinstance(stmt, With):
                for item in stmt.items:
                    if (o := origin(item.context_expr)) and item.optional_vars: bind([item.optional_vars], o)
        if len(tainted) == before: break
    for call in calls_in(fn):
        if matches(rule.callee, qualname(call.func)) and constraints_hold(call, rule, origin):
            yield hit(call, reachability=reach(call), props={"trace": trace_of(call)})

def origin(e) -> Origin | None:
    # Name → tainted.get(e.id) or source_match(e);  Attribute / Subscript → origin(e.value) or source_match(e)
    # Call → None if sanitizer(qualname(e.func)) else source_match(e) or origin(receiver(e))
    #          or first(origin(a) for a in e.args + kw_values(e))       # unknown calls propagate taint
    # JoinedStr / BinOp / BoolOp / IfExp / List / Tuple / Set / Dict / Starred / Await → first child origin
    # Constant → None
    ...
```
`reach(call)` is `tainted` when the constrained argument has an origin, `constant` when it is constant, else
`unknown`. `trace` lists up to 8 `{line, name, via}` steps from source to sink; SARIF renders it as a `codeFlow`.

**`fastapi_route`.** (1) Find decorators `<recv>.<method>(path, ...)` whose `recv` was assigned `FastAPI(...)` or
`APIRouter(...)` in the module. (2) Auth evidence is any of: a parameter default `Depends(X)`/`Security(X)`; an
`Annotated[..., Depends(X)]` parameter; the decorator's `dependencies=[Depends(X)]`; `dependencies=` on the router or
app constructor; `app.include_router(router, dependencies=[...])` in the same module. It counts only when
`qualname(X)` matches `auth_regex`, default
`(?i)(auth|current_?user|verify|token|jwt|oauth|api_?key|security|permission|require|login|principal|session)`.
(3) A route whose method is in `methods` (default `post put patch delete`), with no evidence and a path not matching
`ignore_paths_regex` (default `^/(?:health|healthz|livez|readyz|metrics)$`), is a hit on the decorator with
`confidence_delta=-1`, because auth may be attached in another module; `finding-verifier` checks that case.

### 8.8 `hcl` (hcl-lite)
**Tokenizer (`hcllite.py`):** comments `(?:#|//)[^\n]*|/\*(?s:.*?)\*/`; numbers
`-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?`; identifiers `[A-Za-z_][A-Za-z0-9_-]*`; heredocs
`<<(?P<strip>-?)(?P<tag>[A-Za-z_][A-Za-z0-9_]*)[ \t]*\n` up to a line whose stripped text equals the tag; strings via a
state machine (not a regex) that tracks `${`/`%{` nesting, so `"${lookup(var.m, "k")}"` stays one token; punctuation.
```
body  = { attr | block }
attr  = IDENT "=" expr NEWLINE     ; expr = literal (string without interpolation, number, bool, null,
block = IDENT { STRING | IDENT } "{" body "}"    ;  list/object of literals), else Expr(raw text to depth-0 newline)
```
`*.tf.json` maps onto the same `Block(type, labels, attrs, blocks)` model. **References:** `var.x` resolves to the
literal `default` of `variable "x"` and `local.y` to a literal in `locals {}`, both from a per-directory symbol table
built once; anything else stays `Unknown`. **Paths:** `block` matches type then labels, `*` = any one label
(`resource.aws_security_group.*`, `module.*`, `remote_state`); `each` iterates nested blocks (`ingress`); `attr`
walks nested blocks and object keys (`metadata_options.http_tokens`, `config.encrypt`). **Predicates** are §8.6's
plus `range_includes: {lo, hi, any}`, true when some port p in `any` has `lo ≤ p ≤ hi`. They are tri-state: an
`Unknown` value is *unknown*, treated as false under `on_unknown: nomatch` (default) or as true under `match` with
`confidence_delta=-1` and `props.unresolved=[attr…]`.
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

**Normalized snippet:** lines `line … min(end_line, line + 2)`; every secret span replaced by `<SECRET:sha256hex>`
(secret ≥16 chars) or `<SECRET:len=N>`; `\s+` collapsed to one space; stripped. Unicode is **not** normalized:
hidden code points are the finding.
```python
fp      = "sha256:" + sha256("\x1f".join([rule_id, path, norm, str(occ)]).encode("utf-8", "surrogatepass")).hexdigest()
content = "sha256:" + sha256("\x1f".join([rule_id, norm, str(occ)]).encode("utf-8", "surrogatepass")).hexdigest()
```
`occ` is the 0-based index, in position order, among findings in the same file with the same (rule_id, norm), which
keeps two identical `privileged: true` lines distinct. No line numbers are hashed, so fingerprints survive code
moving within a file; the path-free `content_fingerprint` lets a baseline follow a renamed file (§11.3).

**Dedupe**, in order: (1) exact: same (rule_id, path, line, col, end_line, end_col), keep one; (2) same rule,
overlapping spans: earliest start, then longest span; (3) cross-rule overlap on the same secret span: keep the rule
ranking highest on (not tagged `generic`, listed in the other's `supersedes`, severity score, confidence), e.g.
`WS-SEC-AWS-001` over the entropy rule `WS-SEC-GEN-001`, with losers kept in `properties.related`; (4) cross-source:
an adapter finding on the same file and line with intersecting CWE (or both secrets) merges into the engine finding
as `also_reported_by: ["semgrep:<id>"]`.

---

## 10. Severity model

```
score = min(10, BASE[override or rule.severity] × R[reachability] × E[exposure]);   final = band(score)
```

| Base | Score | Reachability | R | Exposure | E | Band | Score range |
|---|---|---|---|---|---|---|---|
| critical | 10.0 | tainted (py_ast proved source→sink) | 1.25 | internet (routers, webhooks, ingress, public proxy config) | 1.1 | critical | ≥ 9.0 |
| high | 7.5 | unknown (pattern match; default) | 1.0 | default | 1.0 | high | 7.0 – 8.99 |
| medium | 5.0 | constant (sink argument is a literal) | 0.6 | internal (scripts, tools, ops) | 0.8 | medium | 4.0 – 6.99 |
| low | 2.5 | | | vendored | 0.5 | low | 1.0 – 3.99 |
| info | 0.5 | | | test (tests, fixtures, examples, docs) | 0.4 | info | < 1.0 |

Exposure is the first matching class of `severity.exposure` (§3.2); files tagged `test` default to `test`, and routes
found by `fastapi_route` to `internet`. `exposure_sensitive: false` pins E = 1.0; it is the `secrets` pack default,
because a live key in `tests/` is still leaked, and `inject` input always uses E = 1.0. Findings keep
`base_severity`, `score`, `reachability` and `exposure`; `--fail-on` and `--min-severity` compare the **final** band.
Reports order by `score × W[confidence]` (high 1.0, medium 0.8, low 0.5) descending, then path, line, rule.

| Example | Calculation | Final |
|---|---|---|
| `WS-INJ-003` `subprocess.run(cmd, shell=True)`, `cmd` from a route param in `app/routers/orders.py` | 7.5 × 1.25 × 1.1 = 10.3 → 10 | critical |
| Same pattern in `scripts/backfill.py`, `cmd` origin unknown | 7.5 × 1.0 × 0.8 = 6.0 | medium |
| `WS-SPK-001` `spark.sql(f"... {TABLE}")` where `TABLE` is a module constant | 7.5 × 0.6 × 1.0 = 4.5 | medium |
| `WS-K8S-001` privileged container in `tests/fixtures/` | 7.5 × 1.0 × 0.4 = 3.0 | low |
| `WS-SEC-TRD-001` exchange API secret in `tests/test_orders.py` | 10 × 1.0 × 1.0 (not exposure-sensitive) | critical |

---

## 11. Suppressions and baseline

### 11.1 Inline syntax
```python
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
| `whalescan:ignore[IDS]` | The finding's start line; if the comment is alone on its line, the next non-blank line |
| `whalescan:ignore-next-line[IDS]` | The next non-blank line |
| `whalescan:ignore-file[IDS]` | Whole file; must be in the first 20 lines (`allow_file_level`) |
| `whalescan:ignore-start[IDS]` … `whalescan:ignore-end` | Enclosed lines, at most `max_block_lines` (200) |

IDs are exact or prefix globs (`WS-SEC-*`); a bare `*` needs `allow_wildcard`. A missing reason, or one shorter than
`min_reason_chars`, makes the marker invalid: the finding stays visible and a `suppression-invalid` diagnostic is
added. A past `until` makes it inactive (`suppression-expired`); with `report_unused`, unused markers add
`suppression-unused`. **Hard exclusions:** inline markers are ignored for all `inject` input and for `WS-AGT-*`
findings in `agent-config` and `doc` files during `scan`, because that content is attacker-controlled and would
suppress itself; only baseline and config suppressions apply there. `scan_edit.py` reports any newly added
`whalescan:ignore` marker, so an agent adding one is visible.

### 11.2 Config suppression
`rules.disable` and `severity.overrides`; every entry that came from project config is echoed in `run.config_changes`.

### 11.3 Baseline file (`.whalesecurity/baseline.json`)
```json
{
  "schema": "whalescan/baseline@1", "tool_version": "1.0.0", "rules_hash": "sha256:<64 hex>",
  "created_at": "2026-09-29T10:00:00Z", "updated_at": "2026-09-29T10:00:00Z",
  "entries": [
    {"fingerprint": "sha256:<64 hex>", "content_fingerprint": "sha256:<64 hex>", "rule_id": "WS-K8S-004",
     "path": "deploy/k8s/pricing-api.yaml", "line": 42, "severity": "medium",
     "reason": "limits set by LimitRange in the namespace; PLAT-377", "added_at": "2026-09-29", "expires": null}
  ]
}
```
Entries are sorted by (path, rule_id, fingerprint) for stable diffs. No snippet is stored, so a baseline never holds
a secret; `line` is informational. Matching tries `fingerprint`, then `content_fingerprint` when the entry's `path` is
absent from the current file set (moved file). Entries past `expires` stop suppressing and add a diagnostic. Matches
are counted in `stats.suppressed.baseline`.

---

## 12. Reporters

All reporters consume the same sorted `ScanResult`, and every output string passes through `redact.sweep` (§13).

### 12.1 Text
```
CRITICAL  WS-GHA-001  .github/workflows/pr-preview.yml:31:18  pull_request_target checks out PR head code
          │ ref: ${{ github.event.pull_request.head.sha }}
          fix: Use pull_request for untrusted code, or split into a privileged workflow_run job.
HIGH      WS-SEC-DB-002  airflow/dags/etl_orders.py:12:14  Database URL with inline password
          │ URI = "singlestore://etl:…[REDACTED len=11]@s2.internal:3306/orders"

2 findings (1 critical, 1 high) · 1,204 files · 0.91 s · 7 suppressed (baseline 5, inline 2) · fail-on high → exit 1
```
Colors: critical red, high magenta, medium yellow, low and info cyan.

### 12.2 JSON (`json`, `jsonl`)
`-f json` writes one envelope `{"schema": "whalescan/report@1", "tool": {name, version, rules_hash}, "run":
{started_at, duration_ms, root, argv, packs, config_sources, config_changes, fail_on, exit_code, truncated, error},
"stats": {files_scanned, files_skipped: {binary, too_large, ignored, symlink}, bytes_scanned, rules_evaluated, capped,
by_severity, suppressed: {inline, baseline, config}, truncated}, "findings": [finding@1 …], "diagnostics": [{level, code, message, file?,
line?, rule_id?}]}`. `-f jsonl` writes one finding@1 per line and no envelope; it streams, and hooks use it. With
`--deterministic`, output is byte-identical across runs (sorted keys, `ensure_ascii=False`, hidden characters already
revealed).
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:whalescan:schema:finding:1",
  "title": "whalescan finding", "type": "object", "additionalProperties": false,
  "required": ["schema", "rule_id", "title", "severity", "base_severity", "score", "confidence", "reachability", "exposure",
    "file", "line", "col", "end_line", "end_col", "snippet", "cwe", "owasp", "message", "fingerprint", "content_fingerprint", "source"],
  "properties": {
    "schema": {"const": "whalescan/finding@1"},
    "rule_id": {"type": "string", "pattern": "^(WS-[A-Z0-9]+(-[A-Z0-9]+)*-[0-9]{3}|(semgrep|gitleaks|trivy|osv|llm):\\S{1,200})$"},
    "title": {"type": "string", "minLength": 1, "maxLength": 200},
    "severity": {"$ref": "#/$defs/severity"}, "base_severity": {"$ref": "#/$defs/severity"},
    "score": {"type": "number", "minimum": 0, "maximum": 10},
    "confidence": {"enum": ["high", "medium", "low"]},
    "reachability": {"enum": ["tainted", "unknown", "constant"]},
    "exposure": {"enum": ["internet", "default", "internal", "vendored", "test"]},
    "pack": {"type": "string"},
    "file": {"type": "string", "minLength": 1},
    "file_kind": {"enum": ["code", "iac", "ci", "agent-config", "doc", "data"]},
    "line": {"type": "integer", "minimum": 1}, "col": {"type": "integer", "minimum": 1},
    "end_line": {"type": "integer", "minimum": 1},
    "end_col": {"type": "integer", "minimum": 1, "description": "exclusive, in code points"},
    "snippet": {"type": "string", "maxLength": 2000, "description": "redacted and revealed"},
    "cwe": {"type": "array", "items": {"type": "string", "pattern": "^CWE-[0-9]+$"}},
    "owasp": {"type": "array", "items": {"type": "string"}},
    "atlas": {"type": "array", "items": {"type": "string"}},
    "message": {"type": "string", "minLength": 1},
    "fix": {"type": ["string", "null"]},
    "references": {"type": "array", "items": {"type": "string"}},
    "fingerprint": {"$ref": "#/$defs/sha"}, "content_fingerprint": {"$ref": "#/$defs/sha"},
    "source": {"enum": ["engine", "semgrep", "gitleaks", "trivy", "osv", "llm"]},
    "also_reported_by": {"type": "array", "items": {"type": "string"}},
    "suppressed": {"oneOf": [{"type": "null"}, {"type": "object", "additionalProperties": false, "required": ["kind"], "properties": {
      "kind": {"enum": ["inline", "baseline", "config"]}, "reason": {"type": "string"},
      "until": {"type": "string", "format": "date"}, "ticket": {"type": "string"}, "marker_line": {"type": "integer", "minimum": 1}}}]},
    "verification": {"type": "object", "additionalProperties": false, "required": ["status", "by"], "properties": {
      "status": {"enum": ["confirmed", "false_positive", "needs_review"]}, "by": {"type": "string"},
      "note": {"type": "string", "maxLength": 2000}}},
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
| `runs[0].tool.driver` / `.extensions[]` | `name: "whalescan"`, `version`, `semanticVersion`, `informationUri` / one `toolComponent` per adapter that ran |
| `driver.rules[]` | One `reportingDescriptor` per rule with ≥1 result (all selected rules with `sarif_include_all_rules`) |
| `rule.id` / `rule.name` | `rule_id` / title as PascalCase ASCII (`PullRequestTargetChecksOutPrHead`) |
| `rule.shortDescription` / `fullDescription` / `help` / `helpUri` | `title` / static `message` / `fix` + references (text and markdown) / `references[0]` |
| `rule.defaultConfiguration.level` | critical, high → `error`; medium → `warning`; low, info → `note` |
| `rule.properties.tags` | `["security", pack, "external/cwe/cwe-94", "owasp/A03", …rule tags]` |
| `rule.properties["security-severity"]`, `.precision` | Base: critical `"9.5"`, high `"8.0"`, medium `"5.5"`, low `"3.0"` (omitted for info); confidence as `"high"`/`"medium"`/`"low"` |
| `results[].ruleId`, `ruleIndex`, `level`, `message.text` | `rule_id`, index into `rules[]`, level from the **final** severity, redacted and revealed `message` |
| `…physicalLocation.artifactLocation` | `uri` = `file` (POSIX, percent-encoded), `uriBaseId: "%SRCROOT%"` |
| `…physicalLocation.region` | `startLine`, `startColumn`, `endLine`, `endColumn` (both exclusive) from `line`/`col`/`end_line`/`end_col`; `snippet.text` |
| `results[].partialFingerprints` | `{"whalescan/v1": fingerprint, "whalescan/content/v1": content_fingerprint}` |
| `results[].properties` / `codeFlows` | severity, base_severity, score, confidence, reachability, exposure, source, pack, cwe, owasp / one `threadFlow` from `properties.trace` |
| `results[].suppressions` | With `--show-suppressed`: inline → `inSource`, baseline or config → `external`; `status: "accepted"`, `justification: reason` |
| `runs[0].columnKind`, `originalUriBaseIds` | `"unicodeCodePoints"`; `%SRCROOT%` → `file:///abs/root/` only with `sarif_absolute_root` |
| `runs[0].automationDetails.id` | `"whalescan/<sorted packs joined by +>/"`: a stable category per pack set |
| `runs[0].invocations[0]` | `executionSuccessful` (exit ≠ 3), `exitCode`, `toolExecutionNotifications` from diagnostics (`descriptor.id` = code) |

Adapter results go into the same single run with prefixed rule IDs; their descriptors come from adapter metadata, and
`extensions` credits the tools. This avoids multi-run category collisions in GitHub code scanning.

### 12.4 Markdown (PR comments, `/whale-audit`)
A heading with counts (`## whalescan: 1 critical · 2 high · 4 medium`); a summary table `| Sev | Rule | Location |
Title |`; one `####` section per critical/high finding with `` `file:line` `` · CWE · OWASP · confidence, a fenced
snippet (fence longer than any backtick run inside it), `**Fix:**` and references; then medium, low and info in a
`<details>` table, all capped at `markdown_max_findings`. `|` becomes `\|` in tables and `< > &` are HTML-escaped
outside fences, so a finding cannot inject HTML or mentions into a PR comment. Hidden code points are always revealed.

---

## 13. Secret redaction

- **Secret spans:** every hit of a `secrets/*` rule (the `secret_group`, else the whole match), every hit of a
  `redact: true` rule, every entropy token, and adapter secret findings re-located in our own file text (secret text
  supplied by an adapter is never trusted or printed).
- **Format:** L ≥ 16 → `prefix + "…[sha256:" + sha256(secret)[:8] + "]"`, where `prefix` is the first
  `min(4, L // 4)` chars (`AKIA…[sha256:1f3a9c0e]`). L < 16 (typically a password) → `…[REDACTED len=L]` with no
  hash, so short secrets cannot be dictionary-checked. A multi-line private key keeps its `-----BEGIN … KEY-----`
  header and its body becomes `…[sha256:xxxxxxxx]`.
- **Applies to:** snippets, `message` interpolation (`{{secret}}` is always redacted), `properties`, all four
  reporters, logs and adapter raw fields. `baseline.json` stores no text at all.
- **Sweep:** the run keeps an in-memory set of raw secret values, never serialized. Every output string passes
  through `sweep(text)`, one alternation regex over those values, longest first, as a second line of defense. CI
  asserts that no reporter output, in any format, contains any `pos` fixture secret.
- **Reveal:** after redaction, hidden code points (§8.4) are replaced by their markers in every output string,
  including `-f json`.

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
**Runner:** argv list only (never `shell=True`); `cwd=root`; `timeout=adapters.timeout_s`; environment reduced to
`PATH HOME LANG LC_ALL TMPDIR` plus per-tool opt-outs (`SEMGREP_SEND_METRICS=off`); stdout capped at 256 MiB; report
files go in a 0700 temp dir under the cache dir and are deleted afterwards. **Failures:** a missing binary →
`adapter-missing` (info); timeout, unexpected exit or unparseable output → `adapter-failed` (warning). Neither changes
the exit code unless `--adapters-strict` (then exit 3).

| Adapter | Command (OK exits) | Mapping to `whalescan/finding@1` |
|---|---|---|
| semgrep | `semgrep scan --json --quiet --metrics=off --disable-version-check <args> -- <targets>` (0, 1) | `results[]`: `semgrep:<check_id>`, `path`, `start.line/col`, `end.line/col`; `extra.severity` ERROR→high, WARNING→medium, INFO→low, and CRITICAL/HIGH/MEDIUM/LOW map directly; `cwe` from `extra.metadata.cwe` via `\bCWE-([0-9]{1,5})\b`; `owasp` via `\b(A(?:0[1-9]\|10)):(20[0-9]{2})\b`; confidence from `metadata.confidence` (default medium); `fix` from `extra.fix` |
| gitleaks | `gitleaks dir <target> --no-banner --redact --report-format json --report-path <tmp> --exit-code 42`; history: `gitleaks git --log-opts=<range>` (0, 42) | `gitleaks:<RuleID>`, `File`, `StartLine..EndLine`, `Commit`. The secret is re-located by re-matching the reported line range in our decoded text (columns are hints only), then redacted per §13. Severity high (`severity_map` overrides); `cwe=[CWE-798]`; confidence medium |
| trivy | `trivy fs --format json --quiet --exit-code 0 --scanners <scanners> <root>` (0) | `Vulnerabilities[]` → `trivy:<VulnerabilityID>` at `Target`, line of the first `PkgName` occurrence, message `"<pkg> <installed>: <id>; fixed in <FixedVersion>"`, `cwe` from `CweIDs`. `Misconfigurations[]` with `Status=="FAIL"` → `trivy:<ID>` at `CauseMetadata.StartLine..EndLine`. Severities map directly, UNKNOWN→low. `Secrets[]` are dropped when the secrets pack ran |
| osv | `osv-scanner scan source --format json -r <root>` (0, 1, 128), or `pip-audit -f json --progress-spinner off -r <req>`, or `api` (POST `https://api.osv.dev/v1/querybatch`; needs trusted `allow_network`) | `packages[].vulnerabilities[]` → `osv:<id>` at `source.path` (the package's line), `aliases` in properties; severity from `groups[].max_severity` (CVSS score → §10 bands), else `database_specific.severity` (MODERATE→medium), else medium; `cwe` from `database_specific.cwe_ids` |

**Normalization, all adapters:** root-relative POSIX paths; missing `line`/`col` → 1, missing `end_*` → end of that
line; fingerprints recomputed per §9 from **our** file text, never the adapter's snippet; `exposure` applied and
`reachability=unknown`; messages redacted and revealed; unknown severity → medium, unknown confidence → low.

---

## 15. Performance

### 15.1 Budgets (CI benchmark on a 4-vCPU runner; a >20% regression fails)
| Scenario | Budget |
|---|---|
| `whalescan version` cold start | < 80 ms |
| Hook `scan_text`, one file ≤100 KB, warm cache (`scan_edit.py`) | engine < 120 ms; hook p95 < 200 ms |
| Hook `scan_injection` on 1 MiB of tool output | < 150 ms |
| Regex tier, single core, 8 KB average files / py_ast tier | ≥ 2 000 files/s / ≥ 300 files/s |
| Each regex vs 100 KB adversarial input | < 50 ms |
| RSS, 50 000-file repo | < 300 MB |

### 15.2 Rule cache
The expensive part is YAML parsing, schema validation and lint, not `re.compile`. The cache therefore stores the
normalized, validated rule set, the applicability index and the keyword tables as **JSON**, never pickle: a writable
cache dir must not become a code-execution vector. Key: `sha256(engine_version | schema_version | sorted (relpath,
sha256(file)) of every rule source | rule-affecting config)`. File: `<cache>/rules-<key[:16]>.json`, written
atomically (tmp + `os.replace`), mode 0600 in a 0700 dir; the newest 5 are kept. Built-in rules load from the
release-time `bundle.json`, so the hook path never parses YAML. Regexes compile lazily per process on the first file
where the rule is active (`re.Pattern` pickles as source anyway), so a single-file hook compiles only its ~20–40
applicable rules.

### 15.3 Parallelism
Below 200 files or 4 MiB total, everything runs in one process. Above, a `ProcessPoolExecutor` with `jobs` workers
(default `min(cpu_count, 8)`; start method `forkserver` on Linux, `spawn` elsewhere) loads the rule cache in its
initializer and processes batches of about 64 files or 2 MiB, largest first to cut tail latency. Results are merged,
then sorted, so output never depends on scheduling. Threads are not used for matching (GIL; free-threaded builds are
re-evaluated post-v1). Adapters are subprocesses and run concurrently with the engine from a thread.

### 15.4 Time budget
`time_budget_ms` is checked between files and between rules within a file. When exceeded, the run stops, sets
`run.truncated=true`, adds `time-budget-exceeded`, and computes the exit code on the partial result; hooks treat a
truncated run as fail-open and say so. Python `re` has no per-match timeout, so ReDoS safety comes from lint (§8.2)
and the CI `--redos` gate (§2.6).

---

## 16. Public Python API

```python
from whalescan import (__version__, load_config, load_rules, Scanner, scan_text, scan_injection, Finding, ScanResult,
                       Severity, Confidence, Diagnostic, Baseline, mcp_pin, mcp_verify, reveal, redact,
                       WhalescanError, UsageError, ConfigError, RuleError)

def load_config(root: str | os.PathLike[str] | None = None, *, path: str | None = None, project: bool = True,
                overrides: Mapping[str, Any] | None = None) -> Config: ...
def load_rules(cfg: Config, *, packs: Sequence[str] | None = None, rule_ids: Sequence[str] | None = None) -> RuleSet: ...

class Scanner:                                     # immutable after construction; thread-safe
    def __init__(self, rules: RuleSet, cfg: Config, *, adapters: Sequence[str] = ()) -> None: ...
    def scan_paths(self, paths: Sequence[str | os.PathLike[str]], *, jobs: int | None = None,
                   diff_ref: str | None = None, time_budget_ms: int | None = None) -> ScanResult: ...
    def scan_text(self, text: str | bytes, *, filename: str = "<stdin>",
                  line_ranges: Sequence[tuple[int, int]] | None = None,     # keep hits intersecting these
                  time_budget_ms: int | None = None) -> ScanResult: ...

# Module-level conveniences for hooks; they build and cache one process-wide Scanner lazily.
def scan_text(text: str | bytes, *, filename: str, packs: Sequence[str] = ("appsec", "secrets", "domain"),
              line_ranges: Sequence[tuple[int, int]] | None = None, time_budget_ms: int = 150,
              root: str | None = None) -> ScanResult: ...
def scan_injection(text: str | bytes, *, source_label: str, reveal: bool = True, max_bytes: int | None = None,
                   time_budget_ms: int = 150) -> ScanResult: ...

@dataclass(frozen=True, slots=True)
class ScanResult:
    findings: tuple[Finding, ...]; diagnostics: tuple[Diagnostic, ...]; stats: Stats; run: RunInfo
    def exit_code(self, fail_on: str = "high") -> int: ...    # 0|1; 3 is decided by the CLI
    # to_json() / to_jsonl() / to_sarif() / to_markdown() -> str;  to_text(color: bool = False) -> str

# Finding: frozen, slotted dataclass whose fields mirror finding@1 (§12.2) one-to-one; tuples replace arrays,
# Severity/Confidence are IntEnums (INFO=0 … CRITICAL=4; LOW=0 … HIGH=2); to_dict() emits finding@1.
```
```python
# How the scan_edit.py hook calls it (shortened)
res = whalescan.scan_text(new_content, filename=rel_path, line_ranges=edited_ranges)
if any(f.severity >= Severity.HIGH for f in res.findings):
    emit_additional_context(res.to_markdown())
```
**Stability:** names exported from `whalescan/__init__.py` follow semver from 1.0. Anything starting with `_`, and the
internals of `whalescan.matchers`, `whalescan.rules` and `whalescan.adapters`, are private. The API never prints; it
logs to the `whalescan` logger.

---

## 17. Errors and exit codes

```
WhalescanError                 → 3
├── UsageError                 → 2   bad flags, missing path, conflicting options, baseline exists without --force
├── ConfigError                → 2   TOML syntax, type/enum errors, unsupported schema version
├── RuleError                  → 2   schema, lint or semantic failure; unknown rule ID
├── AdapterError               → diagnostic, or 3 with --adapters-strict
└── InternalError              → 3   any unexpected exception
```

| Command | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| `scan`, `inject`, `secrets` | No unsuppressed finding ≥ `--fail-on` (or `never`) | ≥1 such finding | Usage, config or rule error | Internal error; strict adapter failure |
| `mcp verify` | No drift finding ≥ `--fail-on` | Drift ≥ `--fail-on` | Unreadable pins or MCP config | Internal error; `--strict` with an unreachable server |
| `mcp pin`, `baseline create/update` | Written | — | Exists without `--force`; critical without `--allow-critical` | Internal or write I/O error |
| `rules test` | All pass | ≥1 rule fails | Unknown ID; missing fixtures dir | Internal error |
| `rules list`, `rules explain`, `version` | OK | — | Unknown ID; bad flag | Internal error |

`fail_on` is evaluated over unsuppressed findings that pass `min_confidence` and `--diff-lines`, **before** the
`min_severity` output filter. Per-file problems (read errors, `decode-*`, `parse-error`, `too-large`, `symlink-*`,
`rule-capped`) never abort a run; they become diagnostics. On exit 3 with `-f json` or `sarif`, the reporter still
writes a valid document: JSON carries `run.error = {type, message}` and the partial findings, SARIF sets
`executionSuccessful=false`. Hooks parse it and fail open, loudly. `KeyboardInterrupt` exits 130 without a traceback;
on `BrokenPipeError`, stdout is redirected to devnull and the computed code is kept. Tracebacks appear only with
`-vv`; otherwise stderr gets one line: `whalescan: internal error: <Type>: <msg> (rerun with -vv)`.

---

## 18. Logging

Standard library `logging` with the hierarchy `whalescan`, `whalescan.walker`, `.rules`, `.matchers.<type>`,
`.adapters.<name>`, `.mcp`, writing to **stderr only** (stdout is reserved for reports). Levels: `-q` ERROR, default
WARNING, `-v` INFO, `-vv` DEBUG; env override `WHALESCAN_LOG_LEVEL`. `logging.file` (trusted-only) adds a
`RotatingFileHandler` (5 MiB × 3). `--log-format json` writes one object per line: `{"ts", "level", "logger", "msg",
"file", "rule_id", "elapsed_ms"}`. DEBUG logs rule IDs, paths, spans and timings, and **never** match text for
`redact` rules or `secrets/*` packs; a `RedactingFilter` on the root handler also applies `redact.sweep` and reveal
to every record. `--profile` prints the top 20 rules by cumulative time and hits, plus parse time per structured
parser; the perf benchmark uses it to enforce §15.1.

---

## 19. Refinements to DESIGN.md

1. **Stdlib-only** means zero install-time dependencies. The core ships its own `yamlite` (positions and raw keys,
   which is what fixes the `on:` pitfall) and vendors `tomli` for Python 3.10 only.
2. **Rule cache** is JSON of normalized rules, not a pickle of compiled rules; regexes compile lazily (§15.2).
3. **Fingerprint** is `sha256(rule_id␟path␟normalized_snippet␟occurrence)` with U+001F separators, plus a path-free
   `content_fingerprint` for moved files (§9).
4. **Output:** `-f json` wraps finding@1 in a `whalescan/report@1` envelope and `jsonl` emits bare findings. The
   finding adds `title`, `base_severity`, `score`, `reachability`, `exposure`, `pack`, `file_kind`, `end_col`
   (exclusive, code points), `content_fingerprint`, `suppressed`, `verification` and `properties`; `source` adds
   `trivy` and `osv`.
5. **Rule IDs** allow an optional sub-namespace (`WS-SEC-AWS-001`, already used in DESIGN §8).
6. **New rule fields:** `owner` (required, per DESIGN §11), `keywords`, `filters`, `redact`, `exposure_sensitive`,
   `supersedes`, `max_hits_per_file`, `enabled_by_default`, and a `builtin: mcp_drift` matcher for `WS-AGT-MCP-*`.
7. **Inline suppressions** support `until=`, and are ignored for `inject` input and for `WS-AGT-*` findings in
   agent-config and doc files.
8. **Trusted-only config keys** (adapter binaries and args, network, live MCP, cache and log paths) are ignored when
   set in project config.
9. **Modules added** to the DESIGN §3 layout: `api.py`, `model.py`, `config.py`, `ignore.py`, `textio.py`,
   `yamlite.py`, `hcllite.py`, `dedupe.py`, `redact.py`, `errors.py`, `log.py`, `rules/{schema,lint,cache}.py`.
   Baseline handling stays in `suppress.py`, as DESIGN states.
10. **Extras:** `[ast]` is reserved for the post-v1 tree-sitter tier and not declared in v1 (v1 `py_ast` uses stdlib
    `ast`); `[adapters]` carries `pip-audit` for the osv adapter.
