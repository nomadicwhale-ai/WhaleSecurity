# WhaleSecurity — Design Plan (v0 → v1.0)

> **One repo, two shields:** **AppSec** protects the *code* the agent writes and reviews.
> **AgentSec** protects the *agent* from prompt injection in the content it reads.
> Both run on one deterministic, tested engine, and hooks enforce the rules instead of prose.

The v1.0 target is built from first principles: every detection must be backed by tests, hooks
must enforce rules instead of only describing them, and every output format must be machine-readable.
This is a design contract, not a claim that the plugin or all rules already ship; §10 records delivery status.
Last updated: **2026-10-12**. [ROADMAP.md](ROADMAP.md) owns delivery scope, dependencies and acceptance criteria;
the detailed [specs](specs/) define engine/rule semantics and unchanged per-pack quality gates.

---

## 1. Goals / Non-goals

**Goals**
- G1 — A **deterministic scanner** (`whalescan`) with rules stored as data. Every rule has a positive and a negative fixture, and CI proves each rule fires.
- G2 — A **Claude Code plugin** with discipline skills, audit slash-commands, read-only auditor agents, and **hooks** that actually block or warn.
- G3 — **Machine-first output:** text, JSON, SARIF 2.1.0 and Markdown. Also baselines, inline suppressions that require a reason, and severity-gated exit codes.
- G4 — **Core first, domain packs in v1.x:** v1.0 covers Python appsec, secrets, AgentSec and GitHub Actions; FastAPI-specific, Airflow/Spark, k8s/Helm, Docker, Terraform/HCL, proxies, Tekton/Flux/GitLab, LLM-app and trading packs follow.
- G5 — Measured quality: per-rule precision and recall on a corpus, published on every release.

**Non-goals**
- Replacing Semgrep, CodeQL, Gitleaks or Trivy. Optional Semgrep/Gitleaks/Trivy/OSV adapters are v1.x, not dependencies of the v1.0 core.
- Runtime WAF or network egress control.
- Full inter-procedural taint analysis in v1. Python AST taint is local to one function; we go deeper later.

---

## 2. Architecture

**Target architecture across v1.0 and v1.x, not current delivery.** HCL/domain matchers and optional adapters
below are deferred; [ROADMAP §2](ROADMAP.md#2-release-scope) defines the v1.0 core.

```
            ┌──────────────────────── Claude Code plugin ────────────────────────┐
            │ skills/  whale-appsec  whale-agentsec  (discipline, auto-load)     │
            │          whale-audit   whale-inject-audit  whale-threat-model (/cmd)│
            │ agents/  appsec-auditor  injection-auditor  finding-verifier (RO)  │
            │ hooks/   PreToolUse guards · PostToolUse injection scan ·          │
            │          PostToolUse(Edit|Write) scan · SessionStart MCP verify   │
            └───────────────┬────────────────────────────────────────────────────┘
                            │ JSON findings (stable schema)
            ┌───────────────▼──────────────── whalescan engine (Python) ─────────┐
            │ walker ─► file classifier ─► matchers ─► dedupe/severity ─► report │
            │ matchers: regex(all hits) · multiline · unicode · entropy ·         │
            │           yaml-path (k8s/GHA/compose) · python-ast · hcl-lite       │
            │ adapters (optional): semgrep · gitleaks · trivy · pip-audit · osv   │
            │ mcp: pin / verify tool-description hashes                           │
            └───────────────┬────────────────────────────────────────────────────┘
                            │
                 rules/*.yaml  +  tests/fixtures/<rule-id>/{pos,neg}.*
```

**Division of labor.** The engine is tuned for recall and is reproducible: same input, same
output, fast enough to run in a hook. The LLM `finding-verifier` agent is tuned for precision. It
traces each source back to its sink, checks reachability, and marks false positives. The agent
never adds new findings unless it labels them `source: llm`, which keeps provenance clear.

### Key decisions

| Decision | Choice | Why |
|---|---|---|
| Engine language | **Python ≥3.10**, core uses **stdlib only** | Your main language. Zero deps means fast startup in hooks (<150 ms) and easy vendoring. Extras: `[adapters]`, `[mcp]`; `[ast]` is reserved for post-v1. |
| Rule format | YAML, one file per pack | Diff-friendly and reviewable. Non-Python contributors can add rules. |
| Detection tiers | regex → multiline/yaml-path → Python AST | Covers ~80% of cases cheaply first and adds precision where it pays off. |
| Report schema | Our own JSON + SARIF 2.1.0 export | GitHub code scanning, IDEs and the agent all consume it. |
| Secrets in output | Always redacted (`AKIA…[sha256:8]`) | A scanner report must never become the leak. |
| Distribution | `pip install whalescan`, a Claude plugin marketplace entry, a composite GitHub Action, a pre-commit hook | Meets users wherever they run checks. |
| License | MIT (see repository `LICENSE`) | Open source. |

---

## 3. Repository layout

**Target v1.0/v1.x layout, not a current file inventory.** The engine/API/CLI, CI and docs are present on `main`;
production seed packs are in progress. Plugin, hooks, evals and remaining contract paths below are planned.
Existing unit tests live in `engine/tests/unit/`; [ROADMAP.md](ROADMAP.md) is the detailed backlog,
§10 is its summary and [TODO.md](../TODO.md) is the short next-actions list.

```
WhaleSecurity/
├── .claude-plugin/
│   ├── plugin.json
│   └── marketplace.json
├── skills/
│   ├── whale-appsec/            SKILL.md + references/ (sinks, languages, iac, secrets, threat-model)
│   ├── whale-agentsec/          SKILL.md + references/ (trust labels, lethal trifecta, red flags, refusals)
│   ├── whale-audit/             SKILL.md  (/whale-audit  → runs engine, dispatches appsec-auditor)
│   ├── whale-inject-audit/      SKILL.md  (/whale-inject-audit → engine agentsec pack + injection-auditor)
│   └── whale-threat-model/      SKILL.md  (/whale-threat-model → STRIDE + 10-question model on a design/PR)
├── agents/
│   ├── appsec-auditor.md        tools: Read, Grep, Glob, Bash   (Bash restricted by hook allowlist)
│   ├── injection-auditor.md
│   └── finding-verifier.md
├── hooks/
│   ├── hooks.json
│   ├── guard_bash.py            PreToolUse(Bash)
│   ├── guard_read.py            PreToolUse(Read|Grep|Glob)
│   ├── guard_egress.py          PreToolUse(WebFetch|mcp__.*), session trifecta gate
│   ├── scan_tool_output.py      PostToolUse(WebFetch|WebSearch|mcp__.*|Bash|Read|Grep|Glob|Task)
│   ├── scan_edit.py             PostToolUse(Edit|Write|MultiEdit)
│   └── mcp_verify.py            SessionStart: config pins + instruction-file scan
├── engine/
│   ├── pyproject.toml
│   └── src/whalescan/
│       ├── cli.py               scan | inject | secrets | mcp pin/verify | baseline | rules test
│       ├── walker.py            gitignore-aware, size caps, binary skip, .whalescanignore
│       ├── classify.py          file → {lang, kind: code|iac|ci|agent-config|doc|data}
│       ├── rules/loader.py      schema validation, pack selection
│       ├── matchers/            regex.py multiline.py unicode.py entropy.py yamlpath.py pyast.py hcl.py
│       ├── severity.py          base × reachability × exposure
│       ├── suppress.py          inline `whalescan:ignore[RULE] reason=...`, baseline file
│       ├── report/              text.py json.py sarif.py markdown.py
│       ├── adapters/            semgrep.py gitleaks.py trivy.py osv.py
│       └── mcp_pin.py
├── rules/
│   ├── appsec/                  injection.yaml access.yaml crypto.yaml ssrf.yaml deser.yaml web.yaml
│   ├── secrets/                 cloud.yaml vcs.yaml ai.yaml payments.yaml saas.yaml trading.yaml generic.yaml
│   ├── agentsec/                override.yaml tokens.yaml unicode.yaml hidden.yaml exfil.yaml execute.yaml
│   │                           repo-poison.yaml mcp.yaml
│   └── domain/                  fastapi.yaml airflow.yaml spark.yaml k8s.yaml terraform.yaml
│                                gha.yaml tekton-flux.yaml gitlab.yaml proxy.yaml docker.yaml llm-rag.yaml trading.yaml
├── tests/
│   ├── fixtures/<RULE-ID>/{pos.*,neg.*}
│   ├── test_rules.py            auto-parametrized: every rule × {pos must hit, neg must not}
│   ├── test_redos.py            every regex vs 100 KB pathological input < 50 ms
│   ├── test_regressions.py      scanner pitfalls (dash-leading patterns, ZWSP/tag chars, multi-hit per file, multiline YAML keys)
│   └── hooks/                  feed hook JSON on stdin, assert decision; bench_hooks.py
├── evals/
│   ├── corpus/                  vulnerable apps + clean popular repos (pinned SHAs, fetched by script)
│   ├── injection-corpus/        hidden-CSS pages, ZW/tag payloads, poisoned CLAUDE.md, rug-pull MCP
│   ├── run_eval.py              precision / recall / F1 per rule → evals/report.md
│   └── plugin/                  skill-trigger + agent behavior evals (claude plugin eval)
├── action.yml                   composite GitHub Action (SARIF upload)
├── .pre-commit-hooks.yaml
├── .github/workflows/ci.yml     lint · typecheck · tests · self-scan · eval smoke (actions pinned by SHA)
├── docs/                        DESIGN.md  ROADMAP.md  specs/
├── README.md  LICENSE  CHANGELOG.md  CONTRIBUTING.md  SECURITY.md
```

---

## 4. Rule schema

```yaml
# rules/domain/gha.yaml
- id: WS-GHA-001
  title: pull_request_target checks out PR head code
  pack: domain/gha
  severity: critical
  confidence: high
  cwe: [CWE-94]
  owasp: [CICD-SEC-4]
  applies_to: { kind: ci, glob: [".github/workflows/*.y*ml"] }
  match:
    yaml_path:
      all:
        - path: "on.pull_request_target"          # handles both `on: pull_request_target` and the mapping form
          exists: true
        - path: "jobs.*.steps[*].with.ref"
          regex: "github\\.event\\.pull_request\\.head\\.(sha|ref)"
  message: >
    Workflow runs with a write token and secrets, but checks out untrusted fork code.
  fix: >
    Use `pull_request` for untrusted code, or split into a privileged workflow_run job
    that never executes PR code.
  references: ["https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"]
  fixtures: auto        # tests/fixtures/WS-GHA-001/{pos.yml,neg.yml} required by CI
```

Matcher types: `regex` (all hits, line and column, always passed with `--` semantics),
`multiline`, `unicode` (codepoint classes: ZW, TAG, BIDI, and mixed-script homoglyphs),
`entropy` (Shannon threshold + charset + keyword context), `yaml_path`, `py_ast` (call patterns with
local taint: `subprocess.*(shell=True, <tainted>)`, `pickle.loads(<request.*>)`, and FastAPI routes
without an auth `Depends`), and `hcl` (lite block/attribute matcher for Terraform).

**Rule ID namespaces:** `WS-INJ`, `WS-ACC`, `WS-CRY`, `WS-SSRF`, `WS-DES`, `WS-WEB`, `WS-SEC` (secrets),
`WS-AGT` (agentsec), `WS-GHA`, `WS-K8S`, `WS-TF`, `WS-DKR`, `WS-AIR`, `WS-SPK`, `WS-API` (FastAPI),
`WS-LLM`, `WS-TRD`.

---

## 5. Rule packs and bounded v1.0 scope

**v1.0 delivers 121 selected catalog IDs; the full 302-ID inventory is not its release denominator.**
[ROADMAP §2.1](ROADMAP.md#21-core-count-121-catalog-ids) records the definition-row counting method and subpack totals.

| Pack | v1.0 IDs | Selection / later scope |
|---|---|---|
| Python appsec | 29 | Appsec definition rows whose language includes `py`; non-Python IDs/branches defer |
| Secrets | 37 | All credential formats, including exchange/broker keys; no trading business-logic pack |
| AgentSec | 41 | All WS-AGT IDs, bounded views, repo/MCP protection; unsupported OCR remains visibly not scanned |
| GitHub Actions | 14 | WS-GHA-001–016 excluding the two `† ext` entries 004/006 |
| Domain packs / other CI/CD | 0 | k8s/Helm, Docker, Terraform/HCL, proxies, FastAPI-specific, Airflow/Spark, LLM-app, trading, Tekton/Flux/GitLab and GHA extensions: v1.x |
| **Total** | **121** | **29 + 37 + 41 + 14** |

Counts come from distinct concrete IDs in the three rule-definition catalogs, excluding examples/references.
The original catalog inventory remains 81 appsec/secrets + 180 infra/domain + 41 AgentSec = 302 IDs;
181 IDs and non-Python branches of mixed-language rules are deferred, not removed or redefined.
Every shipped pack retains its quality bar and annotated positive/negative/guard fixtures.

---

## 6. Hooks: the enforcement layer

| Hook | Matcher | Behavior |
|---|---|---|
| `guard_read.py` | PreToolUse `Read\|Grep\|Glob` | **Deny** paths under `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `.env*` (except `.env.example`), `*.pem`, `*.key`, `id_*`, `.netrc`, `.npmrc`, `.pypirc`, `kubeconfig` |
| `guard_bash.py` | PreToolUse `Bash` | **Deny** `curl/wget … \| sh`, `rm -rf /` and `~`, writes to `authorized_keys`, `base64 -d \| sh`, and `cat` of the secret paths above. **Ask** for `git push --force`, `--no-verify`, `sudo`, package installs from URLs, and `terraform apply`/`kubectl delete` against non-local contexts |
| `guard_egress.py` | PreToolUse `WebFetch\|mcp__.*` | Apply AgentSec's session trifecta gate: ask after external exposure + private reads, ask for exposed money movement, deny secret-bearing hostile egress |
| `scan_tool_output.py` | PostToolUse `WebFetch\|WebSearch\|mcp__.*\|Bash\|Read\|Grep\|Glob\|Task` | Scan/label source trust; high/critical hits add redacted, revealed, defanged `additionalContext`. It never blocks an already-completed read |
| `scan_edit.py` | PostToolUse `Edit\|Write\|MultiEdit` | Run appsec, secrets and domain packs on the changed file only (<200 ms budget). Feed findings back so the agent fixes them in the same turn |
| `mcp_verify.py` | SessionStart | Verify config pins without launching servers; scan auto-loaded project guidance. Trusted live/captured listings enable tool-description drift checks; hashes alone cannot reconstruct a diff |

Every hook fails **open, and says so loudly**: if the engine crashes, the hook logs the error and
allows the action. A broken scanner must never brick the user's session. The one exception is the
secret-path denials, which are pure path checks and fail **closed**.

Config lives in `.whalesecurity/config.toml`, with user config owning trust, private-tool and egress policy.
In untrusted projects, hooks MUST ignore AgentSec loosening, including ignore/baseline suppression; owner-run CLI
audits retain engine config semantics. See [agentsec.md](specs/agentsec.md) §3, §4, §10 and §11 for exact decisions.

---

## 7. Skills & agents

- **`whale-appsec`** (auto-load when writing or reviewing code): source→sink thinking, auth on every
  state-changing path, secrets treated as already leaked, fail closed, a severity calibration
  table, and a "when writing" checklist. Keep SKILL.md **under 250 lines**. Detail lives in
  `references/`, loaded on demand.
- **`whale-agentsec`** (auto-load when handling external content): provenance labels, the lethal
  trifecta, plan-before-read, "who proposed this tool call?", and a surface-never-comply-silently
  refusal format.
- **`/whale-audit [path|diff|PR]`**
  1. `whalescan scan --format json` on the scope.
  2. Optional adapters (semgrep, gitleaks, trivy) if installed, from v1.x; v1.0 uses native findings.
  3. `finding-verifier` triages each finding (reachability, sanitizers, test/fixture context).
  4. `appsec-auditor` writes the final report: summary table, then only Critical/High in full
     (file:line, CWE/OWASP, verbatim code, concrete exploit, patched code), then a table of
     Medium/Low. It ends with a verdict and the top three fixes.
- **`/whale-inject-audit [path|url|mcp-server]`**: engine agentsec pack plus `injection-auditor`,
  with hidden characters shown in the report (`[ZWSP]`, `[TAG:x]`, `[BIDI:RLO]`).
- **`/whale-threat-model [design doc|PR]`**: STRIDE plus the 10-question checklist. Output is a
  table of threats, mitigations and residual risk.
- Agents use real tool names (`Read, Grep, Glob, Bash`). Omit auditor Bash until the enforced allowlist ships
  in v0.8. Thereafter `guard_bash.py` in "auditor mode" limits it to `git diff/log/blame`, `rg`, `find`, `wc`,
  `xxd`, `whalescan`, and the optional adapter commands when those ship in v1.x.

---

## 8. Output contract

```json
{
  "schema": "whalescan/finding@1",
  "rule_id": "WS-SEC-AWS-001",
  "severity": "critical", "confidence": "high",
  "file": "src/settings.py", "line": 12, "col": 9, "end_line": 12,
  "snippet": "AWS_KEY = \"AKIA…[sha256:1f3a9c0e]\"",
  "cwe": ["CWE-798"], "owasp": ["A07"],
  "message": "Hardcoded AWS access key", "fix": "Move to Secrets Manager; rotate the key now.",
  "fingerprint": "sha256(rule_id␟path␟normalized_snippet␟occurrence)",
  "source": "engine"            // engine | semgrep | gitleaks | llm
}
```

- This is an abbreviated finding example; engine §12.2 defines the full `finding@1` schema and `report@1` envelope.
- Fingerprints use U+001F separators and an occurrence index; a path-free `content_fingerprint` follows renames.
- Exit codes: `0` clean, `1` findings ≥ `--fail-on` (default `high`), `2` usage error, `3` internal error.

---

## 9. Quality gates (CI)

1. `ruff`, `mypy --strict` on the engine, and `pytest` with the engine at ≥90% coverage.
2. **Rule contract test:** every rule has pos/neg fixtures, pos hits ≥1 (at the exact expected
   lines if annotated `# expect: WS-XXX`), and neg hits 0.
3. **ReDoS test:** every regex runs on adversarial 100 KB inputs in under 50 ms.
4. **Self-scan:** `whalescan scan .` must be clean, with `rules/`, `tests/fixtures/` and
   `evals/` excluded through `.whalescanignore`. This proves the ignore mechanism works.
5. **Eval smoke:** a precision/recall run on a small corpus fails if any rule regresses by more
   than 5 points.
6. **Hook tests:** fixed JSON events go to stdin, and the tests assert allow/deny/ask plus the
   `additionalContext` text.
7. All GitHub Actions are pinned by SHA with workflow `permissions: {}` and per-job minimum grants.
   We use our own rules against ourselves.

**Release metrics are gates, not achieved results.** [ROADMAP §2/§3](ROADMAP.md#2-release-scope) defines their
shipped-scope denominators; quality-and-release §5 owns the full contract, including throughput ≥2k files/s
single-core regex tier and hook p95 <200 ms. Current versus remaining CI gates are recorded in §10.

---

## 10. Roadmap

**Current as of 2026-10-12; phases advance on evidence, not weeks.** P0-1–4 are merged (#1–3, #7),
and #6 parser/Windows hardening is merged. P0-5 seed rules are **in progress** in a parallel PR; at audited
`main` SHA `7c9bd54c971b85579ef052d6edc6e53277f29c08`, no production rules ship.

P0-7 is largely delivered by #5: Linux Python 3.10–3.14, Windows/macOS, lint/types/coverage,
wheel/sdist + strict Twine + smoke, stdlib-only 3.10/3.12 and `ci-ok`. Self-scan, ReDoS and bundle freshness
remain. [ROADMAP.md](ROADMAP.md) owns the detailed backlog, exit metrics and risks; TODO is the short pickup list.

| Milestone / status | Scope | Exit evidence (summary; ROADMAP §3 is authoritative) |
|---|---|---|
| **v0.1 — In progress** | First detecting release: P0-5 + P0-6 + remaining P0-7 | ≥12 seed IDs across appsec/secrets/AgentSec; all fixtures and installed-wheel E2E/no-leak tests pass; required self-scan/ReDoS/freshness feed green `ci-ok` |
| **E0 — Planned, immediately after v0.1** | Small pinned corpus and per-rule baseline harness | ≥2 vulnerable apps + ≥2 clean repos + ≥48 injection/benign cases; reviewed labels; TP/FP/FN, P/R and Wilson intervals; reproducible published baseline and continuous gate |
| **v0.5 / P1 — Planned** | Claude plugin, five skills, three agents, Action/pre-commit | Clean install, verified sample audit and SARIF integration; plugin/CI corpus increment; frozen E0 slice does not regress |
| **v0.8 / P2 — Planned** | Six hooks, trust/state and enforced auditor allowlist | ≥60 contract cases plus 26 red-team scenarios; fail-open/secret-path fail-closed and no-leak evidence; each hook/class p95 <200 ms; corpus increment/non-regression |
| **v0.9 / P3 — Planned** | 121-ID core, yaml-path/Python AST, AgentSec views and MCP pin/verify | 100% selected-rule/guard fixtures; independent per-rule variants; per-pack holdout/FDR gates and baseline non-regression |
| **v1.0 / P4 — Planned** | Complete eval/plugin/perf evidence and signed core release | All shipped-scope quality gates, independent holdouts, reproducible reports and signed assets/SBOM/verified L2 provenance |
| **v1.x — Deferred** | Domain packs/HCL, non-Python appsec, adapters, SLSA L3 | Unchanged per-pack quality gates, corpus expansion and preserved core baseline; see ROADMAP §2.2 |

### Measurable v1.0 exit metrics

**Quality is unchanged; the denominator is the 121-ID selection in §5, not every catalog pack.**
Holdout recall remains ≥95% per shipped pack; clean FDR <5% (<3% secrets, <1% vendor secrets),
high+ FP/KLOC ≤0.02, benign injection over-severity ≤2%, reveal accuracy 100%, plugin canary ASR ≤2%
and each hook/class p95 <200 ms. Deferred packs meet these gates when they ship, not by weakening them.

[ROADMAP §3.2](ROADMAP.md#32-v10-quality-bar-unchanged-thresholds-bounded-scope) lists the complete core gates;
[quality-and-release §5](specs/quality-and-release.md#5-metrics-and-gates) owns definitions and measurement methods.
Publish counts, pinned revisions, 95% Wilson intervals and missing coverage as `n/a`, not success.
E0 begins measurement early; every later milestone extends the corpus and proves frozen-baseline non-regression.

---

## 11. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Too many false positives, so users disable the tool | `confidence` field; the verifier agent; baselines; default `--fail-on high`; FP rate is a tracked release metric |
| Hook latency slows the agent loop | Stdlib-only core, per-file scope, a warm JSON cache of normalized rules keyed by source/config hash (never pickle), a 200 ms budget with a timeout that fails open |
| The scanner itself leaks secrets | Redaction in every reporter; test that no reporter emits a raw fixture secret |
| Injection strings in our own repo confuse agents working on it | `.whalescanignore` plus a repo `CLAUDE.md` that marks `rules/`, `tests/fixtures/`, `evals/` as attack-sample data |
| Regex rules rot as ecosystems change | Every rule has a `references` URL and an owner; a quarterly review issue template |
