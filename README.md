# WhaleSecurity

Open-source security and prompt-injection scanning for AI coding agents.

- **AppSec** protects the code the agent writes and reviews: injection, access control, crypto, secrets, IaC, CI/CD, and domain packs for FastAPI, Airflow/Spark, k8s, Terraform, LLM/RAG and trading systems.
- **AgentSec** protects the agent from what it reads: prompt injection, hidden Unicode, exfiltration constructs, repo-poisoning files, and MCP rug pulls.

It is built on a deterministic, tested engine (`whalescan`). Claude Code skills, agents and **hooks** use it to enforce rules instead of only describing them.

> Status: design phase. See [docs/DESIGN.md](docs/DESIGN.md) for the architecture and roadmap, and
> [docs/REVIEW-bridge-repos.md](docs/REVIEW-bridge-repos.md) for the prior-art review that shaped it.
