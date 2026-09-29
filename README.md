# WhaleSecurity

Open-source security and prompt-injection scanning for AI coding agents.

- **AppSec** protects the code the agent writes and reviews: injection, access control, crypto, secrets, IaC, CI/CD, and domain packs for FastAPI, Airflow/Spark, k8s, Terraform, LLM/RAG and trading systems.
- **AgentSec** protects the agent from what it reads: prompt injection, hidden Unicode, exfiltration constructs, repo-poisoning files, and MCP rug pulls.

It is built on a deterministic, tested engine (`whalescan`). Claude Code skills, agents and **hooks** use it to enforce rules instead of only describing them.

> **Status:** engine core in progress (1,921 unit tests passing). See [TODO.md](TODO.md) for what's done and what's next.

## Documentation
- [docs/DESIGN.md](docs/DESIGN.md): architecture and roadmap
- [docs/specs/engine.md](docs/specs/engine.md): engine specification
- [docs/specs/rules-appsec-secrets.md](docs/specs/rules-appsec-secrets.md) and [docs/specs/rules-infra-domain.md](docs/specs/rules-infra-domain.md): rule catalogs
- [docs/specs/agentsec.md](docs/specs/agentsec.md): prompt-injection defense (draft)
- [docs/specs/quality-and-release.md](docs/specs/quality-and-release.md): testing, evals and release
