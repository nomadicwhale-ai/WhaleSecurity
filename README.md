# WhaleSecurity

Security and prompt-injection scanning for the code AI agents write and the content they read.

[![CI](https://github.com/nomadicwhale-ai/WhaleSecurity/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/nomadicwhale-ai/WhaleSecurity/actions/workflows/ci.yml)
![Python 3.10–3.14](https://img.shields.io/badge/python-3.10%E2%80%933.14-blue)
[![MIT license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
![Zero runtime dependencies](https://img.shields.io/badge/runtime_dependencies-0-brightgreen)

## Why WhaleSecurity

- **AppSec:** flag risky Python code and exposed credentials in what an agent writes or reviews.
- **AgentSec:** detect instruction overrides and hidden Unicode in what an agent reads.
- **Deterministic engine:** `whalescan` runs locally with the Python standard library; no model calls or required runtime dependencies.

## Status

**As of 2026-10-12, the engine detects 15 shipped seed rules; this is not the full planned product.**

| Works today | Planned, with milestone |
| --- | --- |
| Scanner Python API and CLI | Claude Code plugin, five skills and three agents — v0.5 |
| Text, JSON, JSONL, SARIF and Markdown reporters | Six enforcement hooks — v0.8 |
| 15 rules with positive and near-miss fixtures | Full 121-rule core — v0.9; measured release — v1.0 |
| CI: Linux Python 3.10–3.14; macOS and Windows Python 3.12 | Baseline evals — E0; continuous measurement thereafter |
| Source installation with bundled rules | PyPI publication and signed release — gated; v1.0 |

The installed version is pre-release (`0.1.0.dev0`). Detection is not enforcement, and passing fixtures is not a measured recall claim.
See the [delivery roadmap](docs/ROADMAP.md) for release gates and [TODO](TODO.md) for next actions.
Framework-specific FastAPI, Airflow/Spark, Kubernetes, Terraform, LLM/RAG and trading packs, plus external-tool adapters, are **v1.x**, not shipped coverage.

## Install from source

**Requires Python 3.10–3.14 on Linux, macOS or Windows.** PyPI installation is planned, not available as a supported release yet.
Create a virtual environment with `python -m venv .venv`; the default install has no runtime dependencies (optional extras are separate).
Activate with `source .venv/bin/activate` on Linux/macOS, or `.venv\Scripts\Activate.ps1` in Windows PowerShell, then install:

```sh
python -m pip install "git+https://github.com/nomadicwhale-ai/WhaleSecurity.git#subdirectory=engine"
whalescan version
```

For a local checkout, the equivalent is `python -m pip install ./engine`, **not** the repository root.
The wheel includes `whalescan/rules/bundle.json`: no separate rule download or YAML dependency is needed.

## Quickstart

**Scan a project, credentials or untrusted text with the same installed CLI.** Replace the example filenames with your own paths.
These excerpts are from real runs in a three-file temporary demo: risky Python, a synthetic database credential on `example.invalid`, and zero-width text. No live credentials were used; output is trimmed.

```console
$ whalescan scan .
HIGH      WS-INJ-003  app.py:2:1  OS command injection (Python subprocess with shell=True)
HIGH      WS-SEC-DB-002  credentials.txt:1:1  Credentials embedded in a connection URI
MEDIUM    WS-AGT-UNI-002  notes.txt:1:8  Zero-width characters in text
$ whalescan secrets credentials.txt
HIGH      WS-SEC-DB-002  credentials.txt:1:1  Credentials embedded in a connection URI
$ whalescan inject notes.txt
MEDIUM    WS-AGT-UNI-002  notes.txt:1:8  Zero-width characters in text
          │ Release[ZWSP] notes.
```

The redacted password excerpt is `46d4…[sha256:5b5938d6]`, not the full value. `scan` and `secrets` exited **1**; `inject` exited **0** because the default failure threshold is `high`, not `medium`.
For stdin, use `whalescan inject -` (for example, `cat notes.txt | whalescan inject -`). Hidden characters are revealed as visible markers.

## What it detects today

**These 15 IDs are the installed bundle, not the full catalog.** This table is generated from `whalescan rules list --format json`; severities are rule defaults, and context can affect findings.

| Rule ID | Pack | What it catches | Default severity |
| --- | --- | --- | --- |
| `WS-AGT-OVR-001` | `agentsec/override` | Instruction override phrase | high |
| `WS-AGT-UNI-001` | `agentsec/unicode` | Unicode TAG character smuggling | high |
| `WS-AGT-UNI-002` | `agentsec/unicode` | Zero-width characters in text | medium |
| `WS-AGT-UNI-003` | `agentsec/unicode` | Bidirectional text controls | medium |
| `WS-CRY-005` | `appsec/crypto` | TLS certificate or hostname verification disabled | high |
| `WS-DES-001` | `appsec/deser` | Unsafe Python deserialization (pickle family) | high |
| `WS-DES-002` | `appsec/deser` | PyYAML or ruamel unsafe load | high |
| `WS-INJ-001` | `appsec/injection` | SQL built by string formatting (Python DB-API) | high |
| `WS-INJ-003` | `appsec/injection` | OS command injection (Python subprocess with shell=True) | high |
| `WS-INJ-009` | `appsec/injection` | Dynamic code evaluation of non-constant input | critical |
| `WS-SEC-AWS-001` | `secrets/cloud` | AWS access key ID | critical |
| `WS-SEC-DB-002` | `secrets/generic` | Credentials embedded in a connection URI | high |
| `WS-SEC-GEN-001` | `secrets/generic` | Generic secret assignment of a high-entropy literal | high |
| `WS-SEC-GH-001` | `secrets/vcs` | GitHub token (classic PAT, OAuth, app or refresh) | critical |
| `WS-SEC-PK-001` | `secrets/generic` | Private key block (PEM, OpenSSH, PKCS#8, PGP or PuTTY) | critical |

The [appsec/secrets](docs/specs/rules-appsec-secrets.md), [infra/domain](docs/specs/rules-infra-domain.md) and [AgentSec](docs/specs/agentsec.md#8-ws-agt-rule-catalog) catalogs describe the larger **planned** set.

## CLI reference

**Use `whalescan --help` or a command's `--help` for the complete implemented flag surface.**

| Command | Purpose |
| --- | --- |
| `scan PATHS...` | Scan a project with configured packs |
| `secrets PATHS...` | Scan only secret rules |
| `inject PATHS...` or `inject -` | Scan only AgentSec rules; reveal hidden Unicode |
| `baseline create PATHS... --reason TEXT` | Record reviewed findings as fingerprints, not snippets |
| `baseline update PATHS...` | Prune resolved entries in scanned scope; add new entries only with `--add-new --reason TEXT` |
| `rules list`, `rules explain ID` | Inspect installed rules and a rule's metadata |
| `rules test --fixtures tests/fixtures --redos` | Run fixtures and adversarial regex timing checks from a checkout |
| `version` | Show engine, Python, platform and rule-bundle information |

- Scan formats: `--format text|json|jsonl|sarif|markdown`; `--output PATH` writes a file (default: stdout).
- Add reports from the same run with repeatable `--also FORMAT=PATH`, e.g. `--also sarif=whalescan.sarif`.
- Gate with `--fail-on critical|high|medium|low|info|never` (default: `high`). `--deterministic` removes timestamps and durations for reproducible reports.
- Baselines default to `.whalesecurity/baseline.json`; use `--baseline PATH`, `--no-baseline` or `--show-suppressed`. Critical entries require explicit `--allow-critical`.

| Exit code | Meaning |
| --- | --- |
| `0` | Scan below failure threshold, or successful non-scan command |
| `1` | Unsuppressed finding at/above threshold; for `rules test`, a failed rule check |
| `2` | Usage, configuration or rule error |
| `3` | Internal/I/O error, or strict adapter failure |
| `130` | Interrupted (Ctrl+C) |

**Inline suppressions require a reason by default.** For a reviewed exception, a Python comment can precede the affected statement:

```python
# whalescan:ignore[WS-INJ-003] reason="Reviewed local-only command; input is allowlisted"
```

The reasonless form `whalescan:ignore[WS-INJ-003]` inside a Python `#` comment is invalid unless `suppress.require_reason=false` is configured.
Prefer a specific ID and a reason. Inline markers cannot suppress `inject` input, or AgentSec findings in docs/agent-config files.
See the [CLI contract](docs/specs/engine.md#2-cli) and [suppression contract](docs/specs/engine.md#11-suppressions-and-baseline) for scope and trust details; MCP commands are planned, not implemented.

## Python API

**Use `Scanner` for explicit configuration and reusable scans.** This example was executed with the source-installed bundle:

```python
from whalescan import Scanner, load_config, load_rules

cfg = load_config(project=False)
scanner = Scanner(load_rules(cfg), cfg)
result = scanner.scan_text("import subprocess\nsubprocess.run(command, shell=True)\n", filename="app.py")
print([(f.rule_id, f.severity.label, f.line) for f in result.findings])
print(result.exit_code())
```

```text
[('WS-INJ-003', 'high', 2)]
1
```

`ScanResult` contains `findings`, `diagnostics`, `stats` and `run`; findings include file/span, severity, confidence and fingerprints.
Use `result.to_json()` or `result.to_sarif()` for serialization. The convenience `scan_text` function is also available; see the [public API](docs/specs/engine.md#16-public-python-api).

## GitHub Actions

**Run the scanner directly today; a packaged Action and pre-commit hook are planned for v0.5.**
This push-only workflow avoids privileged fork-PR uploads, disables checkout credentials and ignores untrusted project configuration.
Actions and the scanner source are pinned; review and update the pins deliberately. Code scanning must be enabled for SARIF upload.

```yaml
name: WhaleSecurity
on: push
permissions: {}
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5
        with:
          persist-credentials: false
      - uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6
        with:
          python-version: "3.12"
      - run: python -m pip install "git+https://github.com/nomadicwhale-ai/WhaleSecurity.git@9eac7b3dfab2f85e4dfa2b6dfe0916e19f03dcab#subdirectory=engine"
      - id: scan
        run: whalescan scan . --format sarif --output whalescan.sarif --no-project-config
      - uses: github/codeql-action/upload-sarif@f3c49fd1ef3281abc41069b3dd22807a60c963f6 # v4
        if: ${{ always() && steps.scan.outcome != 'skipped' && hashFiles('whalescan.sarif') != '' }}
        with:
          sarif_file: whalescan.sarif
```

Findings at or above `high` fail the scan step; SARIF is still uploaded when a report exists. Review diagnostics for skipped or unsupported input, not just the exit code.

## Design principles

**Local, reproducible scans treat project content as untrusted input.**

- Stable finding order and fingerprints; `--deterministic` also removes run-time metadata.
- Matched secrets are never printed in full: redaction runs before reports and diagnostics, retaining only safe prefixes/hashes for triage.
- Project config cannot set trusted-only executable, network or logging paths; use `--no-project-config` when scanning an untrusted checkout.
- Every shipped rule has positive and near-miss fixtures; patterns are linted and ReDoS-checked (regular-expression denial of service).
- Stdlib-only core, bounded input processing and visible diagnostics; no claim of exhaustive detection or active hook enforcement.

## Roadmap

**Milestones advance on evidence, not dates.** See the [roadmap](docs/ROADMAP.md) for quantitative gates and the 121-ID core selection.

| Milestone | Scope / next evidence |
| --- | --- |
| v0.1 | First detecting release: installed seed bundle, end-to-end/redaction and required CI gates |
| E0 | Baseline eval immediately after v0.1; pinned vulnerable/clean corpora and published per-rule metrics |
| v0.5 | Claude Code plugin, skills/agents, packaged Action and pre-commit |
| v0.8 | Six enforcement hooks with contract, canary and performance evidence |
| v0.9 | Complete 121-rule core, structured/local-taint matchers and MCP pin/verify |
| v1.0 | Measured, signed core release with independent holdout and provenance gates |
| v1.x | Infrastructure/domain packs, non-Python appsec, adapters and isolated builds |

## Documentation and participation

**Specifications describe both delivered contracts and future work; the shipped inventory above defines today's coverage.**

- [Design](docs/DESIGN.md) — architecture and rationale.
- [Roadmap](docs/ROADMAP.md) and [TODO](TODO.md) — delivery gates and immediate work.
- [Engine spec](docs/specs/engine.md) — CLI, configuration, API, reporting and suppressions.
- Rule catalogs: [appsec/secrets](docs/specs/rules-appsec-secrets.md), [infra/domain](docs/specs/rules-infra-domain.md), [AgentSec](docs/specs/agentsec.md).
- [Quality and release spec](docs/specs/quality-and-release.md) and [Releasing](docs/RELEASING.md) — evaluation and publication requirements.
- [Contributing](CONTRIBUTING.md) — development and rule-fixture workflow.
- [Security policy](SECURITY.md) — report vulnerabilities privately; never post live credentials.
- [MIT license](LICENSE).
