# Security Policy

## Reporting
Report privately via [GitHub Security → Report a vulnerability](https://github.com/nomadicwhale-ai/WhaleSecurity/security/advisories/new), never in a public issue, pull request or discussion. Include:
- The output of `whalescan version -f json` (or installed package version while the CLI is unfinished), and which component is affected.
- A minimal reproduction using only fake secrets and canary payloads.
- The impact you observed.

If private reporting is unavailable, contact [@ganbayard](https://github.com/ganbayard) to arrange a private channel without disclosing details publicly.

## Scope
In scope:
- Engine: crashes, hangs or unbounded memory on crafted input; reads outside scan roots; raw secrets in outputs or logs; code execution through config, rules, cache or adapters; HTML, mention or terminal-escape injection into reports.
- Hooks: bypassing a `deny` from `guard_read.py` or `guard_bash.py`; scanned content suppressing its own findings; a hook failing closed on attacker input.
- Agents: an auditor executing, fetching or exfiltrating content it scans.
- Supply chain: release pipeline, signatures, provenance, PyPI project and GitHub Action.
- New, unpublished injection techniques evading the agentsec pack. We add detection before disclosure.

Out of scope (use the issue templates):
- False positives.
- Detection gaps for publicly known techniques that bypass no enforcing hook.
- Intentionally vulnerable samples in `tests/fixtures/` and `evals/`.
- Bugs in Semgrep, Gitleaks, Trivy or other adapted tools; report those upstream.

## Timeline
- Acknowledgement: within 3 business days.
- Triage, with a CVSS 4.0 score: within 7 days.
- Fix: within 14 days for critical issues, 30 for high, 60 for medium and 90 for low.
- Advisory: a GHSA (with a CVE through GitHub's CNA) and reporter credit, published with the fix and no later than 90 days after the report.

## Supported versions
- Latest MINOR: all fixes.
- Previous MINOR: critical fixes for 90 days.
- Last MINOR of the previous MAJOR: critical and high fixes for 6 months.
- 0.x: no fixes/backport guarantees; report issues anyway so maintainers can fix forward. The engine is currently pre-release.

## Safe harbor
Good-faith research within this policy is authorized, and we will not take legal action over it. Test only systems you own, never use real third-party credentials, and do no more than needed to demonstrate the issue.

## Verifying releases
Sigstore bundles, GitHub attestations and `SHA256SUMS`: see [release verification](docs/RELEASING.md) and [spec §9.4](docs/specs/quality-and-release.md#94-signing-sbom-provenance-and-verification). Publication remains disabled until release prerequisites are complete.
