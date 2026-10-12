# Contributing

## Development setup
**Branch from `main`, not the repository's currently stale default branch.** Use CPython 3.10–3.14 (CI also runs 3.12 on macOS and Windows).

Create a virtual environment with `python -m venv .venv`. Activate it with `source .venv/bin/activate` on POSIX or `.venv\Scripts\Activate.ps1` on Windows. Install hash-locked tooling with `python -m pip install --require-hashes --no-deps -r requirements/ci.txt`, then `python -m pip install --no-deps --no-build-isolation -e engine`.

## Checks
- `ruff check engine/src engine/tests tools tests`
- `ruff format --check tools tests engine/tests/conftest.py` (existing engine formatting cleanup is deferred).
- `cd engine && mypy --strict` (return to the repository root afterward).
- `mypy --strict --ignore-missing-imports tools`
- `HYPOTHESIS_PROFILE=ci python -m pytest engine/tests tests --cov=whalescan --cov-branch --cov-fail-under=90` (on Windows set the environment variable in your shell first).
- `python tools/check_stdlib_only.py` and `python tools/check_pins.py`.
- `python -m build --no-isolation --sdist --wheel --outdir dist engine`, `python -m twine check --strict dist/*` and `python tools/check_dist.py dist` after installing `requirements/release.txt` with hashes.

The core MUST remain stdlib-only: `engine/pyproject.toml` declares `dependencies = []`. Development tooling and optional extras must never become core runtime dependencies. Coverage excludes `_vendor/` and gates combined line/branch coverage at 90%.

Hypothesis profiles are `dev` (100 examples), `ci` (200 derandomized examples, 500 ms deadline) and `nightly` (5,000 examples, no deadline). Mark genuine POSIX-only tests `posix`; those skip on Windows, never entire modules by default.

## Pull requests
Open a focused draft PR against `main`; include the reason and checks actually run. Request @ganbayard's CODEOWNERS review. `ci-ok` is the required check; never bypass it or claim a disabled gate has passed. The Python 3.14 leg is temporarily advisory until W4's bounded JSON-nesting fix merges; all other matrix legs remain required. Resolve review comments before asking a maintainer to merge.

Changes to engine source, rules, hooks, skills, agents or the public Action need a `changelog.d/<ref>.<type>.md` fragment per [spec §9.2](docs/specs/quality-and-release.md#92-changelog). Changelog automation is deferred until release preparation tooling exists.

## Rule-change process
Start with the rule-change issue form and use the [rule PR checklist](.github/PULL_REQUEST_TEMPLATE/rule.md). The normative contract is [quality-and-release §§1–5 and 10](docs/specs/quality-and-release.md).

- Reserve a unique next ID in the correct namespace; never reuse an ID in `rules/RETIRED`.
- Supply owner, HTTPS references, taxonomy, next-version `since`, concrete remediation, and pattern keywords. Use the owners map in `.github/owners.toml`.
- Annotate every positive hit line. Add a negative fixture per false-positive guard and positive coverage for every claimed language. Fixtures must retain their exact bytes.
- Use fabricated credentials only, `WSCANARY-` injection canaries and `.invalid` hosts; never real credentials, customer data or executable malicious payloads.
- Validate schema, R1–R7 lint, ReDoS budget, cross-hits and smoke baseline. Explain cross-hit changes and metric regressions; request an independent holdout variant.
- Record confidence below target as `low`. Apply pack SemVer; broader detection is MINOR, ID retirement is MAJOR, and narrower detection is PATCH.
- Deprecate before removal: one MINOR's notice and at least six months for rules/CLI/config, with removal only in a MAJOR. Keep old IDs tombstoned.

The CLI, bundled rules, evaluation, hooks and plugin gates are not yet implemented. Record blockers rather than fabricating successful validation; publication cannot be enabled until the release gates are complete.

## Dependency updates
On Python 3.12, use `python tools/lock_requirements.py` (requires `uv`) to regenerate `requirements/{test,ci,release}.txt` from declared engine dev/build requirements and CI-only tools via universal hash-locked resolution. Install with `--require-hashes --no-deps`. Dependabot opens weekly Actions and pip updates against `main`; reviewers regenerate related locks and run the complete matrix before merging.

## Security and conduct
Report vulnerabilities privately following [SECURITY.md](SECURITY.md), not through public bug templates. Be respectful, constructive and inclusive; contact @ganbayard privately about conduct concerns. The normative spec does not require a separate code-of-conduct file.

Maintainer release and repository-settings prerequisites are documented in [RELEASING.md](docs/RELEASING.md).
