# WhaleSecurity — Delivery Roadmap

Last updated: **2026-10-12**. This is the detailed delivery source; [DESIGN §10](DESIGN.md#10-roadmap)
summarizes it and [TODO.md](../TODO.md) lists the immediate next actions. Milestones advance on evidence, not dates.

## 1. Current status

**The engine works; shipped detection value is the next gate.** At audited `main` revision
[`7c9bd54`](https://github.com/nomadicwhale-ai/WhaleSecurity/commit/7c9bd54c971b85579ef052d6edc6e53277f29c08),
no production rule pack is shipped. Catalog entries and synthetic unit-test rules are not shipped detections.

| Component | Status on 2026-10-12 | Evidence / remaining work |
|---|---|---|
| P0-1 / P0-2 / P0-3 | Done | Pipeline, reporters and Scanner API merged in [#1](https://github.com/nomadicwhale-ai/WhaleSecurity/pull/1), [#2](https://github.com/nomadicwhale-ai/WhaleSecurity/pull/2), [#3](https://github.com/nomadicwhale-ai/WhaleSecurity/pull/3) |
| P0-4 CLI | Done | [#7](https://github.com/nomadicwhale-ai/WhaleSecurity/pull/7) merged; commands, stdin, reports and exit codes implemented |
| Parser / Windows hardening | Done | [#6](https://github.com/nomadicwhale-ai/WhaleSecurity/pull/6) merged; JSON size/nesting limits, ReDoS lint and Windows fixes |
| P0-5 seed rules | **In progress** | Parallel seed-rule PR; completion requires shipped bundle and real fixtures (WS-RM-001) |
| P0-6 end-to-end validation | Remaining | CLI unit coverage exists; prove detection using the installed seed bundle (WS-RM-002) |
| P0-7 CI | Largely done | [#5](https://github.com/nomadicwhale-ai/WhaleSecurity/pull/5) merged: Linux Python 3.10–3.14, Windows/macOS 3.12, lint, types, ≥90% coverage, wheel/sdist, strict Twine, wheel smoke, stdlib-only 3.10/3.12 and `ci-ok`; remaining self-scan, ReDoS and bundle freshness (WS-RM-003–005) |
| Plugin, hooks, core depth and evals | Planned | No installed plugin, enforcement evidence or published baseline report is implied by engine tests |
| Release | Scaffolded, blocked | Signed-release/governance scaffolding exists; publication stays disabled until applicable gates pass ([release setup](RELEASING.md)) |

Local validation at that full SHA on Linux, CPython **3.12.13**: **2,164 passed, 3 skipped** using
`python -m pytest -o addopts= --strict-markers -q` from the repository root. This is the repository suite total,
not a detector-quality measurement; counts change with revision and platform.

## 2. Release scope

**v1.0 is a bounded core, not the entire catalog.** It includes secrets, AgentSec, Python appsec, GitHub Actions,
the Claude plugin, all six enforcement hooks, continuous evals and a signed release. Domain-specific packs and
external-tool adapters are v1.x; their catalog semantics and quality requirements are unchanged.

### 2.1 Core count: 121 catalog IDs

Count distinct IDs in **rule-definition table rows**, where the first cell is a concrete `WS-…-NNN` ID.
Do not count examples, references, namespace inventories or repeated mentions. Sources are the checked-in
[appsec/secrets catalog](specs/rules-appsec-secrets.md), [infra/domain catalog](specs/rules-infra-domain.md)
and [AgentSec §8](specs/agentsec.md#8-ws-agt-rule-catalog) at the audited SHA above.

| v1.0 selection | Count | Counting / selection rule |
|---|---|---|
| `appsec/injection` | 6 | `Lang / kind` includes `py`: WS-INJ-001, 003, 005, 009, 010, 011 |
| `appsec/ssrf` | 1 | Python row: WS-SSRF-001 |
| `appsec/access` | 3 | Python rows: WS-ACC-001, 003, 004 |
| `appsec/deser` | 3 | Python rows: WS-DES-001, 002, 005 |
| `appsec/crypto` | 7 | Python rows: WS-CRY-001–007 |
| `appsec/web` | 9 | Python rows: WS-WEB-003–006, 008–012 |
| Secrets | 37 | cloud 8 + vcs 3 + ai 4 + payments 1 + saas 4 + trading credentials 7 + generic 10 |
| AgentSec | 41 | override 6 + tokens 3 + unicode 5 + hidden 3 + exfil 6 + execute 3 + repo-poison 6 + mcp 9 |
| `domain/gha` | 14 | Exact WS-GHA-001–016 namespace only, excluding the two `† ext` rows 004 and 006 |
| **Total** | **121** | **29 Python appsec + 37 secrets + 41 AgentSec + 14 GHA** |

The full inventory remains **302 IDs** (81 appsec/secrets + 180 infra/domain + 41 AgentSec).
**181 IDs are deferred**, including 15 non-Python appsec IDs and 166 infra/domain IDs. For mixed-language appsec
IDs, only Python branches (and Python-associated templates) are in the v1.0 delivery denominator;
non-Python branches follow in v1.x. Generic Python sinks remain core even when used by FastAPI, Airflow or LLM apps;
framework-specific `WS-API`, `WS-AIR`, `WS-SPK` and `WS-LLM` detections do not. Trading credential formats remain
in secrets; trading business-logic rules do not. This selection changes release scope, not IDs or detection semantics.

Per-pack gates apply separately to each shipped pack/subpack and its declared v1.0 languages, with family
roll-ups also reported; do not average a failing pack away. Deferred packs get the same gates when they ship.
All 121 IDs require annotated positive/negative fixtures and guard coverage, including default-disabled rules.
Optional OCR and leetspeak are not required capabilities; unsupported content remains visibly not scanned,
as AgentSec specifies. No blanket multilingual, cross-file taint or domain-coverage claim is permitted.

### 2.2 Deferred v1.x scope

| Milestone | Scope | Entry condition |
|---|---|---|
| v1.1 — infrastructure | k8s/Helm, Docker/Compose, Terraform/HCL, proxies; Tekton/Flux/GitLab; two GHA extensions | v1.0 evidence accepted; structured matchers needed by each pack implemented |
| v1.2 — application/domain depth | FastAPI-specific, Airflow, Spark, LLM-app/RAG, trading; non-Python appsec branches and IDs | Relevant sources/sinks labeled before pack enablement |
| v1.3 — adapters | Semgrep, Gitleaks, Trivy and OSV | Native baseline stable; subprocess, redaction and provenance contracts demonstrated |
| v1.4 — build isolation | SLSA Build L3 | Signed L2 release verified; isolated reusable build and verifier evidence |

These are dependency milestones, not promised dates. HCL, external adapters and the full domain corpus are not
hidden v1.0 dependencies. Native-core comparisons against standalone external tools may run before v1.3;
shipping an adapter and benchmarking a tool are different deliverables.

## 3. Milestones and exit metrics

**Every exit needs reproducible artifacts at the candidate SHA.** A release maintainer records commands,
runner, rule/corpus revisions, denominators, missing coverage and linked CI/report evidence before marking it done.

| Milestone | Purpose / legacy phase | Exit metrics and evidence |
|---|---|---|
| **v0.1 — first detecting release** | Finish P0-5/P0-6/P0-7 | ≥12 catalog seed IDs across appsec, secrets and AgentSec; every shipped rule passes annotated pos/neg and guard fixtures; installed wheel detects attacks; JSON/SARIF/Markdown and exits 0/1/2/3/130 verified; no raw-secret output; `ci-ok` includes self-scan, ReDoS and bundle freshness; all supported OS/Python legs and ≥90% engine coverage green |
| **E0 — baseline eval** | Immediately after v0.1, before P1 | ≥2 SHA-pinned vulnerable apps, ≥2 clean repos and ≥48 in-house injection/benign cases; independently reviewed labels; per-rule TP/FP/FN, P/R/F1 and 95% Wilson intervals published; ≥5 positive labels per seed ID, otherwise coverage gap blocks E0; frozen baseline reproduced twice; eval smoke gates PRs |
| **v0.5 — plugin / CI surface** | P1 | Clean-checkout plugin install; five skills and three agents wiring-tested; `/whale-audit` gives a verified sample report; Action uploads valid SARIF in a controlled test repo; pre-commit detects a high issue and passes its fix; extend E0 with plugin/CI cases and preserve baseline |
| **v0.8 — enforcement hooks** | P2 | Six hooks wired; ≥60 contract cases and all 26 AgentSec red-team scenarios mapped to results; allow/deny/ask, trust/state failures and secret-path fail-closed tested; no raw-secret output; p95 <200 ms per hook/class on reference runner; extend corpus with hook canaries/benign controls and preserve baseline |
| **v0.9 — core depth** | P3, core only | All 121 selected IDs implemented with 100% fixture/guard coverage; yaml-path/Python local-taint, AgentSec views and MCP pin/verify evidenced; ≥5 reviewed positive labels per core ID; ≥95% triage coverage where findings exist; core holdout recall/FDR gates below pass; extend corpus and preserve baseline |
| **v1.0 — measured, signed core** | P4 completes measurement, not starts it | All §3.2 and quality/release gates for shipped scope pass; independent holdout/clean coverage complete; latest plugin/canary and perf reports published; signed wheel/sdist/plugin/bundle, SBOM/checksums and verified L2 provenance; docs state only delivered scope |
| **v1.x — packs / adapters / L3** | Scoped expansion | Each added pack meets unchanged fixture/holdout/FDR/triage/perf gates; adapter outputs and incremental value measured; L3 verified independently; each milestone extends corpus and preserves native E0/core baselines |

### 3.1 Continuous evaluation from E0 onward

- Freeze E0 inputs, labels and outputs by content hash; keep that regression slice as the corpus grows.
  Re-run candidate and merge-base with identical config/sample eligibility; any new FP or lost baseline TP
  on this slice blocks milestone exit. Corpus corrections require independent review and a recorded rebaseline.
- Every later milestone adds reviewed positives/hard negatives for its new surface before enablement and
  publishes frozen-slice and expanded-corpus comparisons. Missing denominators are `n/a`, never success.
- Every PR runs the <60 s smoke gate from [quality §5.2](specs/quality-and-release.md#52-gates): no per-rule P/R
  drop >5 points; changes ≥1 point require a baseline update and intentional regressions need a recorded reason.
  Smoke tolerance alone does not satisfy the stricter milestone no-regression check above.
- Run expanded engine evals nightly and plugin/same-corpus benchmarks weekly once those surfaces exist;
  release gates use independent holdouts, not tuned smoke or contract fixtures. E0 establishes measurement,
  not a claim of ≥95% recall on an unbuilt full corpus.

### 3.2 v1.0 quality bar (unchanged thresholds, bounded scope)

**The quality spec owns definitions; this table fixes the release denominator.** Apply
[quality §5](specs/quality-and-release.md#5-metrics-and-gates), appsec/secrets quality and
[AgentSec §13](specs/agentsec.md#13-quality-gates) to the 121-ID selection and shipped plugin/hooks.

| Metric | v1.0 gate |
|---|---|
| Contract / safety | 100% rule, guard, ReDoS, golden, redaction, hook and self-scan checks; ≥90% engine line + branch coverage; reveal accuracy 100%; no raw-secret output |
| Detection | Holdout variant recall ≥95% per shipped pack; injection-holdout recall ≥95%, with technique × carrier and language breakdown |
| False positives | Clean FDR <5% per shipped pack, <3% secrets and <1% vendor-format secrets; high+ FP/KLOC ≤0.02; benign injection over-severity ≤2% |
| Precision / triage | Appsec per-rule precision ≥80% before verifier (below that: confidence low, per spec); post-verifier precision ≥95%, TP dismissals ≤5%; holdout triage coverage ≥95% for each rule with findings |
| Plugin | Per-skill trigger recall ≥90%, false triggers ≤10%; auditor rubric ≥80/100 with full safety marks; canary ASR ≤2%, with control ASR/task completion reported |
| Hook performance | Every hook/class p95 <200 ms: ubuntu-24.04, 4 vCPU, CPython 3.12, fresh processes, 200 runs after 10 warm-ups, nearest-rank p95; cold run separate |
| Engine performance | Regex ≥2,000 files/s, Python AST ≥300 files/s, RSS <300 MB at 50k files; ≤20% regression vs reference baseline |
| Evidence | P/R denominators and 95% Wilson intervals; rule/corpus/config/tool SHAs; unsupported cells `n/a`; required scope cells have evidence before release |
| Release integrity | Reproducible wheel; patch fingerprint compatibility; verified Sigstore signatures, SBOM, checksums, trusted publishing and L2 provenance; publication flag cannot bypass gates |

Domain-specific corpus rows in quality §3 remain expansion requirements for their v1.x packs, not a prerequisite
to a core release making no such claims. v1.0 clean-dev and clean-holdout still each require ≥3 million non-blank
lines filtered to supported core surfaces; E0's smaller corpus is not a substitute.

## 4. Issue-ready backlog

**Stable IDs are cross-document and issue keys.** S = one focused change, M = several related changes,
L = split into reviewed subchanges before implementation; sizes express scope, not calendar estimates.
Items are planned unless marked in progress. Dependencies are completion gates; preparation may overlap.
Only v0.1 and E0 items become GitHub issues now. Assign a named maintainer when opening implementation work.

### v0.1 — first detecting release

| ID / deliverable | Milestone | Dependencies | Size | Testable acceptance criteria |
|---|---|---|---|---|
| **WS-RM-001 — Seed rules and shipped bundle (in progress; P0-5)** | v0.1 | Merged P0-4 | M | ≥12 catalog IDs covering Python appsec, secrets and AgentSec; inventory names actual IDs. Each has annotated pos/neg and guard fixtures; include dash-leading private-key, AWS/GitHub/DB/entropy secrets and ZWSP/TAG/BIDI/override detections; deterministic builder emits source/installed bundles with matching hashes. |
| **WS-RM-002 — Detecting end-to-end regressions (P0-6)** | v0.1 | WS-RM-001 | M | Temp repos scanned with the installed seed wheel produce valid JSON/SARIF/Markdown and exits 0/1/2/3/130. Assert every hit, baseline create/update, valid/invalid inline suppressions, stdin/UTF/BOM handling, multiline `on:` parser forms and zero raw-secret fragments in reports/logs/errors; no premature GHA detection claim. |
| **WS-RM-003 — Required self-scan (P0-7)** | v0.1 | WS-RM-001, WS-RM-002 | S | Required CI runs `whalescan scan . --fail-on info` and is clean with only documented attack-sample exclusions for rules/fixtures/evals and explicit sample documentation. A controlled unignored high finding fails the job and `ci-ok`; self-scan SARIF/Markdown artifacts remain redacted. |
| **WS-RM-004 — Required ReDoS / rule gate (P0-7)** | v0.1 | WS-RM-001 | S | CI runs `whalescan rules test --fixtures tests/fixtures --redos` over every shipped rule/pattern and annotated fixture expectation. Adversarial 100 KB timings meet quality's 50 ms reference/calibrated limit, workers terminate on timeout, and a failing pattern fails `ci-ok`. |
| **WS-RM-005 — Bundle freshness and wheel detection (P0-7)** | v0.1 | WS-RM-001, WS-RM-002 | S | CI `build_bundle.py --check` (or documented equivalent) fails on an intentionally stale bundle and passes after regeneration. Wheel/sdist have the same inventory/hash; dependency-free installed wheel detects a high fixture (exit 1) and passes its negative (exit 0); both gates feed `ci-ok`. |
| **WS-RM-006 — v0.1 release evidence** | v0.1 | WS-RM-002, WS-RM-003, WS-RM-004, WS-RM-005 | S | Candidate SHA has all Python/OS CI legs green and ≥90% coverage; publish linked inventory, E2E/redaction and gate-failure evidence plus unsupported scope. Mark first detecting release only after these checks; keep PyPI publication blocked until applicable integrity gates are wired and maintainer-approved. |

### E0 — early measurement

| ID / deliverable | Milestone | Dependencies | Size | Testable acceptance criteria |
|---|---|---|---|---|
| **WS-RM-007 — Small pinned corpus and reviewed labels** | E0 | WS-RM-006 | M | Manifest records full SHAs, licenses, sparse paths and label hashes for ≥2 vulnerable Python apps and ≥2 clean repos; add ≥48 benign-canary injection/negative cases covering seed techniques. Independent review confirms ≥5 positive labels per seed ID plus hard negatives; never execute/import/install corpus code or use real secrets; untriaged/missing coverage is visible. |
| **WS-RM-008 — Per-rule eval harness** | E0 | WS-RM-007 | M | Follow quality §4 matching; emit per-rule/split TP/FP/FN/UNK, P/R/F1, 95% Wilson intervals, triage coverage and FP/KLOC. Hand-computed confusion-matrix, duplicate, zero-denominator and untriaged cases pass; two runs at identical SHAs/config produce identical machine-readable results. |
| **WS-RM-009 — Published baseline and continuous gate** | E0 | WS-RM-008 | M | Publish redacted baseline report and frozen manifest/labels/results with reproduction command, rule/config/candidate SHAs and limitations. Required <60 s PR smoke proves >5-point P/R drops fail and ≥1-point changes require baseline updates; frozen E0 comparison detects new FPs/lost TPs; nightly/manual full eval artifacts record trends without silent relabeling. |

### v0.5 — plugin and CI surface (P1)

| ID / deliverable | Milestone | Dependencies | Size | Testable acceptance criteria |
|---|---|---|---|---|
| **WS-RM-010 — Plugin contract and installation** | v0.5 | WS-RM-009 | M | Write/review missing Claude plugin spec, pin supported CLI schema/version and validate plugin/marketplace manifests. Clean-checkout install discovers available skills/agents and validates hook schema without claiming active enforcement; unsupported versions give an actionable diagnostic. |
| **WS-RM-011 — Skills, auditors and verifier** | v0.5 | WS-RM-010 | M | Five skills/three agents use supported tools; discipline SKILL.md files stay <250 lines with on-demand references. Sample audit produces provenance-preserving redacted verified reports; omit auditor Bash until WS-RM-015's enforced allowlist exists. |
| **WS-RM-012 — Action and pre-commit** | v0.5 | WS-RM-010 | M | SHA-pinned least-privilege Action uploads schema-valid SARIF in a controlled GitHub test repo; fork PRs get no privileged upload token. Pre-commit detects a high seed issue and passes its fix; both use the installed fresh bundle. |
| **WS-RM-013 — Plugin / CI corpus increment** | v0.5 | WS-RM-011, WS-RM-012 | M | Add reviewed trigger, audit/verifier and workflow cases; store reproducible artifacts and zero-new-FP/lost-TP E0 comparison. Publish trigger/precision baseline and unsupported enforcement limits; CI fails on a seeded surface regression. |

### v0.8 — enforcement hooks (P2)

| ID / deliverable | Milestone | Dependencies | Size | Testable acceptance criteria |
|---|---|---|---|---|
| **WS-RM-014 — Trust, session state and policy** | v0.8 | WS-RM-013 | M | AgentSec provenance, user/project trust, monotonic trifecta state and atomic locked storage satisfy §3/§4; untrusted projects cannot loosen protection. Missing/corrupt state, lock/config failures are visibly protection-unavailable and never reset silently to S0. |
| **WS-RM-015 — PreToolUse guards / auditor allowlist** | v0.8 | WS-RM-014 | M | Read/Bash/egress guards produce tested allow/deny/ask JSON with symlink/traversal and money/secret-bearing egress cases. Pure secret-path denial fails closed, engine failures fail open visibly; auditor Bash allowlist is enforced, not prompt-only. |
| **WS-RM-016 — PostToolUse / SessionStart wiring** | v0.8 | WS-RM-014, WS-RM-015 | M | Tool-output/edit/MCP SessionStart plus three guards wire all six hooks/relevant tools. Output is redacted/revealed/defanged, completed reads are labeled not blocked, SessionStart never launches servers; metadata stays unverified without a trusted listing. |
| **WS-RM-017 — Hook evidence / corpus increment** | v0.8 | WS-RM-016 | M | ≥60 stdin cases and all 26 AgentSec red-team scenarios map to decisions/context; fault/no-leak tests pass. Reference p95 <200 ms per hook/class; add benign/adversarial canaries and publish control outcomes and E0 non-regression. |

### v0.9 — core depth (P3)

| ID / deliverable | Milestone | Dependencies | Size | Testable acceptance criteria |
|---|---|---|---|---|
| **WS-RM-018 — Core structured matchers** | v0.9 | WS-RM-017 | L | yaml-path handles eleven catalog `on:` forms/raw keys and predicates; Python AST follows function-local sources/sinks/sanitizers with exact spans. Differential/parser-cap and taint near-miss tests pass; HCL, FastAPI-specific rules and cross-file taint are out of scope. |
| **WS-RM-019 — Complete selected core packs** | v0.9 | WS-RM-018 | L | Implement exactly §2.1's 121 IDs; every core language/guard has annotated fixtures, unique stable metadata and passing ReDoS. Inventory/installed bundle match; non-Python/domain entries are not advertised as delivered. |
| **WS-RM-020 — AgentSec views and MCP pin/verify** | v0.9 | WS-RM-018 | L | Raw/norm/visible/hidden/decoded views obey mapping/byte/depth caps and safe reveal; unsupported keys fail validation. Offline pin/verify and trusted-listing rug-pull detection pass, diff only with prior metadata; adversarial decoder/no-leak tests pass. |
| **WS-RM-021 — Core corpus / quality increment** | v0.9 | WS-RM-019, WS-RM-020 | L | Independently label ≥5 positives per core ID and relevant negatives; triage ≥95% of each rule's findings and meet §3.2 holdout recall/FDR. Publish per-pack/language coverage and frozen E0 non-regression; add structured/local-taint perf cases. |

### v1.0 — eval completion and signed core release (P4)

| ID / deliverable | Milestone | Dependencies | Size | Testable acceptance criteria |
|---|---|---|---|---|
| **WS-RM-022 — Independent holdout / clean scale** | v1.0 | WS-RM-021 | L | Independent labels and injection seed isolation prevent holdout tuning; clean-dev/clean-holdout each reach ≥3M supported non-blank lines. All core P/R/FDR/FP-KLOC/triage/reveal gates pass with counts/Wilson intervals; frozen E0/core baselines do not regress. |
| **WS-RM-023 — Plugin, perf and native benchmark** | v1.0 | WS-RM-022 | M | Latest weekly plugin eval meets every skill/auditor/verifier/canary gate with control ASR/task completion; throughput/RSS/hook latency meet §3.2. Same-corpus native comparisons record tool hashes, common scanned-file denominators and limits; adapters are not dependencies. |
| **WS-RM-024 — Signed release gate completion** | v1.0 | WS-RM-022, WS-RM-023 | M | Replace fail-closed placeholders with passing gates; verify tag/version/changelog, pack SemVer and patch compatibility. Build byte-identical wheels twice; verify Sigstore assets/SBOM/checksums/L2 provenance; missing artifacts/gates block publication, maintainer approves enablement. |
| **WS-RM-025 — Release evidence / documentation** | v1.0 | WS-RM-024 | S | Publish reproducible eval/plugin/perf/scope inventory and verification instructions with signed assets. Docs match delivered core; install/upgrade/rollback smoke and human release-checklist approval complete before declaring v1.0 delivered. |

### v1.x — bounded expansion

| ID / deliverable | Milestone | Dependencies | Size | Testable acceptance criteria |
|---|---|---|---|---|
| **WS-RM-026 — Infrastructure packs / HCL** | v1.1 | WS-RM-025 | L | Split k8s/Docker/Terraform/HCL/proxies and remaining CI/CD into per-pack PRs with ID inventories/parser/guard fixtures. Extend pinned infra corpora and meet unchanged per-pack §3.2/quality gates plus frozen core baseline before enablement. |
| **WS-RM-027 — Application/domain packs** | v1.2 | WS-RM-025 | L | Split FastAPI-specific/Airflow/Spark/LLM-app/RAG/trading and non-Python appsec into reviewed packs/branches. Add stack-specific positive/benign corpora, publish language/sink coverage and meet unchanged per-pack gates and core non-regression. |
| **WS-RM-028 — External-tool adapters** | v1.3 | WS-RM-025 | L | Semgrep/Gitleaks/Trivy/OSV are hash/version-pinned, optional and bounded; failure/cancel/redaction/dedupe/provenance tests pass, OSV network opt-in. Same-corpus report quantifies unique TPs/FPs/resource cost; native results remain identical with adapters disabled. |
| **WS-RM-029 — SLSA Build L3** | v1.4 | WS-RM-024, WS-RM-025 | L | Reviewed reusable workflow isolates builds from caller steps/credentials; independent verifier checks applicable L3 requirements/provenance identity. Tampering fails verification; signed-release rollback and core baseline remain intact. |

## 5. Risks and mitigations

**Risks have observable triggers and a responsible role.** Assign a named maintainer when implementation
issues open; these roles own escalation until then.

| Risk / trigger | Mitigation / response | Responsible role |
|---|---|---|
| No usable detection: installed-wheel hits absent | Keep v0.1 closed until WS-RM-001–006 evidence; synthetic engine tests cannot substitute | Rule / release maintainer |
| Catalog breadth consumes v1.0: deferred work added | Require explicit milestone/ID and scope decision; keep 121-ID denominator versioned | Release maintainer |
| Weak E0 statistics: wide intervals, unknowns, missing labels | Publish counts/`n/a`; independently add positives/negatives, never tune holdouts or claim E0 is release quality | Eval maintainer |
| Users disable noisy rules: pack FDR or FP/KLOC fails | Add near-misses, fix guards/calibrate confidence; verifier/baselines aid triage but do not waive gates | Pack owner |
| Hook latency/state bugs: p95 ≥200 ms or lost exposure | Bound inputs, keyed JSON caches/locking; test corrupt/concurrent state, visible fail-open and secret-path fail-closed | Hook maintainer |
| Hangs/stale bundle: ReDoS timeout or hash mismatch | Required killable ReDoS and freshness/installed-wheel gates; include new jobs in `ci-ok` | Engine / CI maintainer |
| Secret/sample leakage or hostile corpus execution | Fake secrets/canaries, no-leak assertions, data-only fetching and narrow explicit sample exclusions | Security / eval maintainer |
| Publication flag mistaken for readiness | Fail-closed release, missing-gate negative tests, independent signature/provenance checks and human approval | Release maintainer |
| Plugin drift / signing infrastructure unavailable | Pin host schema, install/upgrade/rollback tests, verify attestation support early; block release rather than skip evidence | Plugin / release maintainer |

## 6. How this plan is scored

**The target is a reviewable ≥9/10 plan, not a claimed product-quality result.** Reviewers award 0–2 points per
dimension (0 absent, 1 partial, 2 explicit/testable); ≥9 requires no zero and no contradictory status.

| Dimension | Two-point evidence |
|---|---|
| Evidence-gated phases | §3 quantitative exits, artifacts and prerequisites; release/publication not inferred from green unit tests |
| Early / continuous measurement | E0 immediately follows v0.1; per-rule confusion matrices/uncertainty, reviewed labels and frozen non-regression continue through later milestones |
| Bounded v1.0 | §2 derives 121 IDs from actual rows, names deferred packs/adapters and retains quality thresholds |
| Actionable backlog | WS-RM-001–029 each has milestone/dependencies/S-M-L/acceptance; only v0.1/E0 becomes issues now |
| Current / maintainable status | Dated audited SHA, merged #5/#6/#7/test evidence, P0-5 in progress, risk ownership and one roadmap source with short TODO |

Update evidence and the selected-ID inventory when relevant PRs merge. A document score cannot establish recall,
false positives, enforcement safety or release readiness; those require the measurements above.
