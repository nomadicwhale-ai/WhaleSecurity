# WhaleSecurity — Status & Next Steps

Last updated: **2026-10-12**. This is the short pickup list; [docs/ROADMAP.md](docs/ROADMAP.md) owns milestone
scope, dependencies, acceptance criteria and risks. [DESIGN §10](docs/DESIGN.md#10-roadmap) is the summary.

## Status snapshot

**The engine/API/CLI and most CI are merged; production seed rules are in progress.**

- **Done:** P0-1 pipeline (#1), P0-2 reporters (#2), P0-3 API (#3), P0-4 CLI (#7), parser/Windows hardening (#6).
- **CI largely done (#5):** Linux Python 3.10–3.14, Windows/macOS 3.12, lint/types, ≥90% coverage,
  wheel/sdist + strict Twine + wheel smoke, stdlib-only 3.10/3.12 and `ci-ok`; self-scan, ReDoS and bundle freshness remain.
- **Validated snapshot:** **2,164 passed, 3 skipped**, Linux CPython 3.12.13, audited `main`
  [`7c9bd54`](https://github.com/nomadicwhale-ai/WhaleSecurity/commit/7c9bd54c971b85579ef052d6edc6e53277f29c08).
  This is the repository suite count, not measured detection quality; [ROADMAP §1](docs/ROADMAP.md#1-current-status) records the command.
- **Specs/design:** engine, rule catalogs, AgentSec and quality/release contracts exist; implementation evidence
  is separate. The detailed roadmap is now present; the Claude plugin format spec remains to be written (WS-RM-010).
- **Planned:** plugin, six hooks, core-depth and eval evidence; signed-release scaffolding is not a completed release.
  Publication stays blocked pending applicable gates and maintainer approval ([release follow-ups](docs/RELEASING.md)).

## Dev setup

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e 'engine[dev]'
cd engine && ruff check src tests && mypy src && pytest -q
```

## Next actions (dependency order)

**v0.1 is the first detecting release; E0 measures it before plugin expansion.** Acceptance criteria live only
in [ROADMAP §4](docs/ROADMAP.md#4-issue-ready-backlog); tick these off only when the linked evidence is accepted.

- [ ] **WS-RM-001 / P0-5 — In progress:** finish catalog seed rules, annotated fixtures and the shipped bundle (parallel PR).
- [ ] **WS-RM-002 / P0-6:** verify installed-wheel detection, report/exit-code, baseline/suppression/stdin and no-leak regressions.
- [ ] **WS-RM-003–005 / remaining P0-7:** make self-scan, `rules test --redos` and bundle freshness/wheel detection required by `ci-ok`.
- [ ] **WS-RM-006:** record v0.1 exit evidence; do not infer release readiness from scaffolding.
- [ ] **WS-RM-007 / E0:** pin a small vulnerable/clean/injection corpus and independently review labels.
- [ ] **WS-RM-008 / E0:** implement per-rule TP/FP/FN and precision/recall with Wilson intervals.
- [ ] **WS-RM-009 / E0:** publish the reproducible baseline and enable continuous eval/non-regression gates.

## Following milestones

**v1.0 is the 121-ID core, not all 302 catalog IDs.** The [scope/count derivation](docs/ROADMAP.md#21-core-count-121-catalog-ids)
selects secrets, AgentSec, Python appsec and non-extension GitHub Actions; per-pack quality gates are unchanged.

- **v0.5 / P1:** plugin format spec, skills/agents, Action/pre-commit and corpus increment (WS-RM-010–013).
- **v0.8 / P2:** six enforcement hooks, trust/state, measured safety/latency and corpus increment (WS-RM-014–017).
- **v0.9 / P3:** selected core rules, yaml-path/Python AST, AgentSec views/MCP and corpus increment (WS-RM-018–021).
- **v1.0 / P4:** complete independent eval/perf/plugin evidence and signed core release (WS-RM-022–025).
- **v1.x:** domain packs/HCL, non-Python appsec, adapters and SLSA L3 (WS-RM-026–029); no delivery dates implied.
