# WhaleSecurity

[![CI](https://github.com/nomadicwhale-ai/WhaleSecurity/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/nomadicwhale-ai/WhaleSecurity/actions/workflows/ci.yml)

Open-source security and prompt-injection scanning for AI coding agents.

- **AppSec** protects the code the agent writes and reviews: injection, access control, crypto, secrets, IaC, CI/CD, and domain packs for FastAPI, Airflow/Spark, k8s, Terraform, LLM/RAG and trading systems.
- **AgentSec** protects the agent from what it reads: prompt injection, hidden Unicode, exfiltration constructs, repo-poisoning files, and MCP rug pulls.

It is built on a deterministic, tested engine (`whalescan`). Planned Claude Code skills, agents and **hooks** will enforce rules instead of only describing them.

> **Status (2026-10-12):** engine/API/CLI and most CI merged; seed rules in progress. v0.1 is the first detecting
> release, followed immediately by E0 baseline evals. v1.0 targets the 121-ID secrets/AgentSec/Python appsec/GitHub
> Actions core, plugin/hooks and signed release; domain packs and adapters follow in v1.x.
> See [TODO.md](TODO.md) for next actions and [ROADMAP.md](docs/ROADMAP.md) for scope and exit evidence.

## Documentation
- [docs/DESIGN.md](docs/DESIGN.md): architecture, status-based roadmap and measurable release gates
- [docs/specs/engine.md](docs/specs/engine.md): engine specification
- [docs/specs/rules-appsec-secrets.md](docs/specs/rules-appsec-secrets.md) and [docs/specs/rules-infra-domain.md](docs/specs/rules-infra-domain.md): rule catalogs
- [docs/specs/agentsec.md](docs/specs/agentsec.md): complete v1.0 prompt-injection defense specification (implementation planned)
- [docs/specs/quality-and-release.md](docs/specs/quality-and-release.md): testing, evals and release
