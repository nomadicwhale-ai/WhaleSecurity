# WhaleSecurity — Status & Next Steps

Last updated: 2026-09-29. Use this file to pick up work: finish the items in order, tick them off and keep it up to date.

## Status snapshot

### Done
- **Design:** [docs/DESIGN.md](docs/DESIGN.md) covers architecture, repo layout, rule schema, hooks, quality gates and roadmap.
- **Specs (drafts, not yet reviewed):**
  - [docs/specs/engine.md](docs/specs/engine.md): engine, normative for v1.0.
  - [docs/specs/rules-appsec-secrets.md](docs/specs/rules-appsec-secrets.md): appsec + secrets rule catalog.
  - [docs/specs/rules-infra-domain.md](docs/specs/rules-infra-domain.md): k8s, Docker, Terraform, CI/CD, proxies, FastAPI, Airflow, Spark, LLM and trading rule catalog.
  - [docs/specs/quality-and-release.md](docs/specs/quality-and-release.md): tests, evals, CI and release.
- **Engine `whalescan`:** under `engine/src/whalescan`, stdlib-only, **1,826 unit tests passing**, ruff clean.
  - Contract: `model.py`, `errors.py`, `matchers/base.py`. Base provides combinators `all`, `any`, `not` and `near_lines`.
  - Config: `config.py` with discovery, precedence, the trust boundary for untrusted project config, and validation. It vendors `_vendor/tomli` for Python 3.10.
  - File handling:
    - `textio.py`: BOM and encoding handling, binary sniff, positions.
    - `ignore.py`: gitignore semantics plus rule-scoped `#!rules` sections.
    - `walker.py`: git or filesystem walk, symlink policy, size caps.
    - `classify.py`: path, extension and content-sniff tables.
  - Rules:
    - `schema.py`: a stdlib JSON-Schema validator.
    - `lint.py`: ReDoS lint rules R1–R7.
    - `loader.py`: normalization, semantic checks, pack selection, applicability index.
    - `cache.py`: a JSON cache (not pickle).
    - `fixtures.py`: `pos*`/`neg*` fixtures, `# expect:` annotations and sidecar files.
  - `yamlite.py`: a YAML subset parser with source positions and raw keys, so `on:` stays the string `on`. Alias bombs are capped. It is differentially tested against PyYAML.
  - Text matchers:
    - `regex.py`: all hits per file, with report and secret groups.
    - `multiline.py`: pattern and sequence forms.
    - `unicode.py`: ZW, BIDI, TAG, VS, PUA, CTRL and HOMOGLYPH detection, reveal markers, TAG decoding.
    - `entropy.py`: Shannon entropy with context and placeholder guards.

### Incomplete
- [docs/specs/agentsec.md](docs/specs/agentsec.md): the draft stops mid-way (look for `<!-- CONTINUE -->`).
- `docs/specs/claude-plugin.md`: not written. The verified Claude Code plugin, skill, agent and hook format facts are summarized under P1 below.
- Engine: `mypy src` reports 10 errors, all in `model.py`. They come from the lazy calls to `whalescan.report.*`, which don't exist yet. The P0 items below fix this.

## Dev setup

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e 'engine[dev]'
cd engine && ruff check src tests && mypy src && pytest -q
```

## Next TODOs (in order)

### P0: finish the engine core (target v0.1)
- [ ] **P0-1 Pipeline modules** (spec §9, §10, §11, §13, §18):
  - `severity.py`: BASE × reachability × exposure, bands, ordering.
  - `dedupe.py`: normalized snippet, `fingerprint` and `content_fingerprint`, occurrence index, the 4-step dedupe.
  - `suppress.py`: inline markers with a required reason and `until=`; the baseline file with create, update and prune; hard exclusions for `inject` and `WS-AGT` in agent-config and doc files.
  - `redact.py`: redaction formats by length, keeping the PEM header, a sweep of known secrets, then reveal.
  - `log.py`: logging with a redacting filter.
- [ ] **P0-2 Reporters** (spec §12): `report/text.py`, `json.py` (report envelope and jsonl), `sarif.py` (follow the SARIF 2.1.0 mapping table exactly), `markdown.py` (escaping, fence length), and `report/schemas/*.json`. Validate the output against the schemas in tests. This also clears the mypy errors in `model.py`.
- [ ] **P0-3 API** (spec §16): `api.py` with a `Scanner` that runs walker → classify → applicability index → keyword prefilter → `evaluate` → filters → findings → dedupe → suppress → sort. Also module-level cached `scan_text` and `scan_injection` for hooks. Add a process pool above 200 files (§15.3) and the time budget (§15.4).
- [ ] **P0-4 CLI** (spec §2, §17):
  - Commands: `scan`, `inject`, `secrets`, `baseline create/update`, `rules list/test/explain` (including `--redos`) and `version`.
  - Wiring: stdin conventions, `--also FORMAT=PATH`, `--fail-on`.
  - Exit codes 0/1/2/3 and 130. `cli.py` imports only `argparse`, `os` and `sys` at module level.
- [ ] **P0-5 Seed rules:** `tools/build_bundle.py` compiles `rules/**/*.yaml` into `rules/bundle.json`. Start with about 12 seed rules, each with fixtures in `tests/fixtures/<ID>/`, taken from the rule catalogs:
  - `subprocess` with `shell=True`, `eval` on request data, SQL string formatting, `yaml.load`, `verify=False`, `pickle.loads`;
  - an AWS access key, a GitHub token, a private key block (the pattern starts with dashes), a DB URL with a password, a generic entropy rule;
  - zero-width characters, TAG smuggling, bidi controls, and an override phrase.
- [ ] **P0-6 End-to-end and regression tests:**
  - CLI runs on a temp repo producing JSON, SARIF and Markdown, with the expected exit codes.
  - A baseline round-trip, inline suppression with and without a reason, and stdin mode.
  - Regressions: a dash-leading pattern, ZWSP and TAG detection, every hit reported per file, no raw secret in any output.
- [ ] **P0-7 CI:** `.github/workflows/ci.yml` running ruff, mypy, pytest on Python 3.10–3.13, `rules test --redos`, and a self-scan. Pin actions by SHA and use `permissions: read-all`.

### Specs: finish and review (cheap, can run in parallel with P0)
- [ ] Finish `docs/specs/agentsec.md`: the rest of the WS-AGT catalog, `mcp_verify` hashing and storage, and 15 or more red-team scenarios.
- [ ] Write `docs/specs/claude-plugin.md` using the format facts in P1.
- [ ] Compile and test every regex in the three rule catalogs: each must have a positive and a near-miss negative sample, and run in under 50 ms on 100 KB of adversarial input.
- [ ] Write `docs/ROADMAP.md` from the specs: an issue-ready backlog with IDs, dependencies and acceptance criteria.

### P1: Claude Code plugin and CI surface (target v0.5)
- [ ] `.claude-plugin/plugin.json`:
  - Only `name` (kebab-case) is required. Optional fields include `version`, `description`, `author{name,email,url}`, `homepage`, `repository`, `license` and `keywords`.
  - Components are discovered from `skills/<name>/SKILL.md`, `agents/*.md` and `hooks/hooks.json`.
  - Also add `.claude-plugin/marketplace.json`.
- [ ] Skills: `whale-appsec` and `whale-agentsec` (discipline, auto-loaded); `whale-audit`, `whale-inject-audit` and `whale-threat-model` (slash commands).
  - Each is a SKILL.md with frontmatter `name`, `description` and `argument-hint`, uses `$ARGUMENTS`, and puts detail in `references/`.
- [ ] Agents: `appsec-auditor`, `injection-auditor` and `finding-verifier`.
  - Use real tool names: `Read, Grep, Glob, Bash`. `Shell` and `Delete` are not valid tool names.
  - Read-only behavior is enforced by the hook allowlist, not by the prompt.
- [ ] `action.yml`: a composite GitHub Action that runs the scan and uploads SARIF. Also `.pre-commit-hooks.yaml`.

### P2: enforcement hooks (target v0.8)
- [ ] `hooks/hooks.json` using `${CLAUDE_PLUGIN_ROOT}`:
  - `guard_read.py` (PreToolUse on Read, Grep and Glob) denies secret paths.
  - `guard_bash.py` (PreToolUse on Bash):
    - denies `curl|sh`, `rm -rf /` and reads of secret paths;
    - asks before a force-push, `--no-verify`, `sudo`, and `terraform apply` or `kubectl delete`.
  - `scan_tool_output.py` (PostToolUse on WebFetch, WebSearch, `mcp__.*` and Bash) adds `additionalContext` with a defanged, revealed warning.
  - `scan_edit.py` (PostToolUse on Edit, Write and MultiEdit) runs appsec on the changed lines.
  - `mcp_verify.py` (SessionStart) detects MCP tool-description drift.
- [ ] Hook output: PreToolUse returns `hookSpecificOutput.permissionDecision` (`allow`, `deny` or `ask`) with a reason. The hooks fail open, except that the secret-path denials fail closed.
- [ ] Hook contract tests: feed fixed JSON on stdin and assert the decision.

### P3: depth (target v0.9)
- [ ] Matchers: `yamlpath.py` (path grammar, promotion for `on:`, predicates, yaml11 vs yaml12 values), `pyast.py` (function-local taint, source sets, `fastapi_route`), and `hcl.py` with `hcllite.py`.
- [ ] Rule packs: implement the full catalogs (about 150 rules), each with pos/neg fixtures.
- [ ] `mcp pin/verify`.
- [ ] Adapters: semgrep, gitleaks, trivy and osv.

### P4: evals and v1.0
- [ ] Eval corpus pinned by SHA (Juice Shop, NodeGoat, WebGoat, DVWA, TerraGoat, Kubernetes Goat, CI/CD Goat), clean repos to measure false positives, and an in-house injection corpus.
- [ ] Per-rule precision, recall and F1 report. Release when recall ≥ 95%, false positives < 5%, and hook p95 < 200 ms.
- [ ] `release.yml`: PyPI trusted publishing, sigstore signing and an SBOM. Also CHANGELOG, SECURITY.md, CONTRIBUTING.md, and tag v1.0.0.
