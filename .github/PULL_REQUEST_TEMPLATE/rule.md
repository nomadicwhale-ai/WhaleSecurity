## Rule change: WS-___-___
- [ ] ID is the next free number in its namespace, and is not in `rules/RETIRED`.
- [ ] Schema-valid; `owner`, HTTPS `references`, CWE/OWASP (ATLAS for agentsec); `since` = next version.
- [ ] Lint R1–R7 clean; ReDoS budget met: `pytest tests/test_redos.py -m slow -k <ID>`.
- [ ] Every `pos*` hit line annotated; one `neg_<guard>` fixture per documented FP guard.
- [ ] Multi-language rules: a `pos*` fixture for every language in `applies_to.lang`.
- [ ] Fake values only (`tools/fake_secret.py`); injection samples use `WSCANARY-` and `.invalid` hosts.
- [ ] `keywords` taken from pattern literals; `message` states flaw and impact; `fix` is concrete.
- [ ] `_crosshits.json` diff explained; smoke baseline regenerated.
- [ ] Dev precision ≥ pack target, otherwise `confidence: low`.
- [ ] Holdout variant requested from a second contributor (`evals/holdout/<ID>/`).
- [ ] Changelog fragment `rules-added`, `rules-changed` or `rules-fixed`.

<!-- Tooling not yet shipped must be recorded as blocked, never claimed as validated. -->
