# Release and repository administration

## Current boundary
**CI is enforced now; publication deliberately fails closed until the full release gates exist.** The source of truth is [quality-and-release §§8–10](specs/quality-and-release.md).

- `ci.yml` runs lint, strict typing, Linux Python 3.10–3.14, macOS/Windows 3.12, ≥90% branch-inclusive coverage excluding vendored code, dependency/pin checks, and isolated wheel/sdist smoke imports. Only Python 3.14 is temporarily advisory because the deep-JSON fixture segfaults CPython; it becomes required once W4's bounded-nesting preflight fix merges.
- `release.yml` verifies tag/version/changelog/main ancestry, reruns tests, builds a byte-identical wheel twice, generates checksums, and prepares Sigstore signatures and GitHub provenance on tag pushes. No publication is initiated by this PR or this agent.
- `PYPI_PUBLISH_ENABLED` is absent/false by default. Even if set true, `release-gates` currently fails intentionally; replace it only after implementing all normative release gates below. A PyPI publisher registration alone is insufficient.

## Maintainer setup (manual, not done by this PR)
**Enable trusted publishing without storing a PyPI API token.**

- In PyPI, create/configure the `whalescan` project's trusted publisher: GitHub owner `nomadicwhale-ai`, repository `WhaleSecurity`, workflow `release.yml`, environment `pypi`. Maintainers must use 2FA.
- Create GitHub environment `pypi`: require maintainer approval, prevent self-review, and allow deployments only from protected `v*` tags. OIDC write permission is scoped to publishing/signing jobs.
- Add a `main` ruleset requiring a PR, one CODEOWNERS approval, dismissal of stale approvals, `ci-ok`, linear history, and no force-pushes/deletion. Make `main` the default branch; it is not currently the default.
- Add a `v*` tag ruleset restricting creation to maintainers and blocking update/deletion. Require signed tags as the release policy.
- Keep default Actions token read-only; disable Actions PR approvals; require approval for fork workflows; restrict allowed actions to §8.1's allowlist.
- Enable private vulnerability reporting, secret scanning with push protection, Dependabot alerts, and Python CodeQL default setup. Enable Discussions for the issue-template link.
- Future `evals` environment: deploy from `main` only and hold the evaluation credential privately. Never expose it to fork PRs.
- GitHub artifact attestation availability depends on repository visibility/plan; validate support before release. Do not silently skip provenance if unsupported.

## Completion checklist before opting into publication
**The TODO jobs are not release-ready gates.** A maintainer must approve the completion PR before setting `PYPI_PUBLISH_ENABLED=true`.

- Implement `tools/release.py`/changelog preparation, synchronized plugin/marketplace/Action versions, `rules/packs.toml`, and minimum engine/pack SemVer checks against the previous release.
- Implement full holdout/clean/injection evals, patch fingerprint compatibility, metrics/triage gates, performance/RSS, hook latency and latest plugin skill/safety results (§5.2). Wire these into `release-gates`; no unconditional success or skipped release gates.
- Build the plugin archive and rule bundle. Generate and validate CycloneDX 1.6 SBOM including vendored tomli, packs, plugin and optional extras; bind an SBOM attestation to the wheel. Sign every §9.4 artifact and include all in `SHA256SUMS`.
- Enable GitHub release creation with signed assets, assembled changelog and full evaluation report after successful PyPI publishing. Keep the signed and unsigned artifact channels immutable.
- Enable §8 CI rules/metadata/contract/ReDoS, schema differential mutations, golden/redaction/hook tests, CLI import-time (<80 ms), self-scan/SARIF, bundle regeneration and smoke-regression baselines when their implementations land. Generate CODEOWNERS from rule ownership.
- Enable the disabled nightly/weekly/quarterly evaluation workflow only after its corpora, benchmark/plugin harness and regression/owner-review reporter exist.
- Finish full-engine formatting cleanup and changelog-fragment enforcement. Routine CI does not alter engine source.

## Cutting a release
**A human reviews, merges and signs the tag; automation never merges or creates a publication tag here.**

1. Prepare a `release/vX.Y.Z` branch from `main`: synchronized versions, required pack bumps, dated Keep a Changelog section, no unassembled fragments, fresh bundle and full eval report.
2. Review a release PR against `main`, including plugin results and open eval regressions, then merge it manually after green `ci-ok` and CODEOWNERS approval.
3. Create and push a signed tag `vX.Y.Z` (or `vX.Y.ZrcN`) on the approved main commit. Only these strict formats pass verification; `v*` is deliberately broad so malformed tags fail visibly.
4. Approve the protected `pypi` deployment after verify/build/sign/full release gates pass. RCs are PEP 440 pre-releases, installed with `--pre`.
5. Verify a clean installation and provenance, open the next milestone. Yank a broken release; do not delete it, and fix forward with a PATCH.

## Consumer verification
**Verify both provenance and identity before trusting artifacts.** Replace `<version>` with the exact release version and download its signed assets.

- `python -m pip download whalescan==<version> --no-deps -d dl`
- `gh attestation verify dl/whalescan-<version>-py3-none-any.whl --repo nomadicwhale-ai/WhaleSecurity`
- `python -m sigstore verify identity <artifact> --bundle <artifact>.sigstore.json --cert-identity https://github.com/nomadicwhale-ai/WhaleSecurity/.github/workflows/release.yml@refs/tags/v<version> --cert-oidc-issuer https://token.actions.githubusercontent.com`
- From the downloaded asset directory: `sha256sum -c SHA256SUMS --ignore-missing`.

GitHub-hosted build provenance targets SLSA Build L2; reusable isolated build workflows for L3 are a post-v1 follow-up. See the normative spec §9.4 for the complete artifact matrix.
