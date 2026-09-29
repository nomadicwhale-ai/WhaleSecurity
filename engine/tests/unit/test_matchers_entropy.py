"""Tests for whalescan.matchers.entropy (spec §8.5).

Secret-looking fixtures are assembled from short fragments, so this file holds no contiguous candidate
token and stays clean under the repository's own secret scan.
"""

from __future__ import annotations

import math
import time
from collections import Counter
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from whalescan.errors import RuleError
from whalescan.matchers.base import REGISTRY, evaluate
from whalescan.matchers.entropy import (
    CHARSETS,
    DEFAULT_KEYWORDS,
    ENTROPY_DELTA_KEY,
    match_entropy,
    shannon,
    threshold_for,
)
from whalescan.matchers.regex import CAPPED_KEY
from whalescan.model import AppliesTo, Confidence, FileCtx, Hit, Rule, Severity


def j(*parts: str) -> str:
    return "".join(parts)


R40 = j("Zx9Q3kLm", "2VbN8rT5", "yW1pA7sD", "4fG6hJ0u", "I3oPqRsT")      # H = 5.17
R32 = R40[:32]                                                          # H = 5.00
R20 = R40[:20]                                                          # H = 4.32
AKIA = j("AKIA", "IOSFODNN", "7EXAMPLE")                                # AWS docs key id, H = 3.68
AWS_DOC_SECRET = j("wJalrXUtn", "FEMI/K7MD", "ENG/bPxRf", "iCYEXAMPL", "EKEY")  # H = 4.66
HEX32 = j("9f86d081", "884c7d65", "9a2feaa0", "c55ad015")               # H = 3.64
HEX40 = j("8e5e7e5a", "b8b370d6", "c329ec48", "0221332a", "da57f0ab")   # H = 3.83
HEX64 = j("e3b0c442", "98fc1c14", "9afbf4c8", "996fb924", "27ae41e4", "649b934c", "a495991b", "7852b855")
UUID = j("f47ac10b", "-58cc-4372-", "a567-0e02", "b2c3d479")           # H = 3.89
LOWER32 = j("qzmxncbv", "lakjshdg", "fpoiuytr", "ewqmnbvc")            # one class only


def make_rule(match: Any = None, *, max_hits: int = 50, confidence: Confidence = Confidence.MEDIUM) -> Rule:
    return Rule(
        id="WS-SEC-GEN-001",
        title="generic secret test rule",
        pack="secrets/generic",
        severity=Severity.HIGH,
        confidence=confidence,
        owner="@whalesecurity/test",
        applies_to=AppliesTo(),
        match=match if match is not None else {"entropy": {"charset": "base64"}},
        message="test message here",
        references=("https://example.com/ref",),
        max_hits_per_file=max_hits,
    )


def run(
    text: str,
    charset: str = "base64",
    *,
    max_hits: int = 50,
    confidence: Confidence = Confidence.MEDIUM,
    tags: frozenset[str] = frozenset(),
    cache: dict[str, Any] | None = None,
    **spec: Any,
) -> tuple[list[Hit], FileCtx]:
    full = {"charset": charset, **spec}
    ctx = FileCtx(path="settings.py", text=text, tags=tags, cache=dict(cache or {}))
    rule = make_rule({"entropy": full}, max_hits=max_hits, confidence=confidence)
    return list(match_entropy(full, ctx, rule)), ctx


def found(hits: list[Hit], text: str) -> list[str]:
    return [text[h.start : h.end] for h in hits]


def conf(hit: Hit, base: Confidence = Confidence.MEDIUM) -> Confidence:
    return Confidence(int(base) + hit.confidence_delta)


def test_registered_under_entropy() -> None:
    assert REGISTRY["entropy"] is match_entropy


# --------------------------------------------------------------------------- shannon & thresholds


@pytest.mark.parametrize(
    ("s", "h"),
    [("", 0.0), ("aaaa", 0.0), ("ab", 1.0), ("aabb", 1.0), ("abcd", 2.0), ("0123456789abcdef", 4.0)],
)
def test_shannon_known_values(s: str, h: float) -> None:
    assert shannon(s) == pytest.approx(h, abs=1e-12)


def _spec_shannon(s: str) -> float:
    size = len(s)
    return -sum((n / size) * math.log2(n / size) for n in Counter(s).values())


@settings(max_examples=500, deadline=None)
@given(s=st.text(min_size=1, max_size=300))
def test_shannon_matches_spec_formula_and_bounds(s: str) -> None:
    h = shannon(s)
    assert h == pytest.approx(_spec_shannon(s), abs=1e-9)
    assert 0.0 <= h <= math.log2(min(len(s), len(set(s)))) + 1e-9


@settings(max_examples=200, deadline=None)
@given(s=st.text(min_size=1, max_size=100), data=st.data())
def test_shannon_is_permutation_invariant(s: str, data: st.DataObject) -> None:
    perm = data.draw(st.permutations(list(s)))
    assert shannon("".join(perm)) == pytest.approx(shannon(s), abs=1e-9)


def test_shannon_handles_long_strings() -> None:
    assert shannon("a" * 5000 + "b" * 5000) == pytest.approx(1.0)


@pytest.mark.parametrize(
    ("charset", "length", "expected"),
    [
        ("hex", 16, 3.0), ("hex", 23, 3.0), ("hex", 24, 3.2), ("hex", 39, 3.2), ("hex", 40, 3.4),
        ("base64", 20, 3.8), ("base64", 30, 4.2), ("base64", 64, 4.5),
        ("base64url", 16, 3.8), ("base64url", 24, 4.2), ("base64url", 40, 4.5),
        ("alnum", 20, 3.6), ("alnum", 24, 4.0), ("alnum", 200, 4.3),
    ],
)
def test_threshold_buckets(charset: str, length: int, expected: float) -> None:
    assert threshold_for(charset, length) == pytest.approx(expected)


def test_threshold_override_and_delta() -> None:
    assert threshold_for("hex", 20, 2.5) == pytest.approx(2.5)
    assert threshold_for("hex", 20, 2.5, 0.5) == pytest.approx(3.0)
    assert threshold_for("alnum", 50, None, -0.3) == pytest.approx(4.0)


def test_charset_table_max_entropy() -> None:
    assert {k: v.max_entropy for k, v in CHARSETS.items()} == {
        "hex": 4.0, "base64": 6.0, "base64url": 6.0, "alnum": 5.95,
    }


# --------------------------------------------------------------------------- spec validation


@pytest.mark.parametrize(
    "spec",
    [
        None,
        {},
        {"charset": "base32"},
        {"charset": 3},
        {"charset": "hex", "scope": "everywhere"},
        {"charset": "hex", "threshold": True},
        {"charset": "hex", "threshold": "3"},
        {"charset": "hex", "min_classes": 4},
        {"charset": "hex", "min_len": "20"},
        {"charset": "hex", "context": "api"},
        {"charset": "hex", "context": {"keywords": "token"}},
        {"charset": "hex", "context": {"required": "yes"}},
        {"charset": "hex", "context": {"window_chars": -1}},
        {"charset": "hex", "exclude_regex": "abc"},
        {"charset": "hex", "exclude_regex": ["(unclosed"]},
    ],
)
def test_invalid_specs_raise_rule_error(spec: Any) -> None:
    with pytest.raises(RuleError):
        match_entropy(spec, FileCtx(path="f", text="x"), make_rule())


# --------------------------------------------------------------------------- true positives


def test_aws_secret_key_in_python() -> None:
    text = f'aws_secret_access_key = "{AWS_DOC_SECRET}"\n'
    (h,) = run(text)[0]
    assert found([h], text) == [AWS_DOC_SECRET]
    assert h.props == {"entropy": 4.66, "charset": "base64", "length": 40}
    assert h.secret_spans == [(h.start, h.end)]
    assert (h.line, h.col) == (1, 26)
    assert conf(h) is Confidence.MEDIUM  # keyword, but H < 4.5 + 0.3


def test_random_key_with_keyword_is_high_confidence() -> None:
    (h,) = run(f'API_TOKEN = "{R40}"\n')[0]
    assert conf(h) is Confidence.HIGH
    assert h.confidence_delta == 1


def test_aws_access_key_id_in_dotenv_alnum() -> None:
    text = f"AWS_ACCESS_KEY_ID={AKIA}\nREGION=eu-west-1\n"
    (h,) = run(text, "alnum")[0]
    assert found([h], text) == [AKIA]
    assert conf(h) is Confidence.MEDIUM


def test_hex_api_key() -> None:
    text = f"const hmacKey = '{HEX32}';\n"
    (h,) = run(text, "hex")[0]
    assert h.props["charset"] == "hex"
    assert conf(h) is Confidence.HIGH  # "hmac" in `hmacKey`, and H = 3.64 >= 3.2 + 0.3
    assert h.props["entropy"] == pytest.approx(3.64, abs=0.01)


@pytest.mark.parametrize(
    "line",
    [
        f'{{"client_secret": "{R32}"}}',                       # JSON
        f"  api-token: {R32}",                                  # YAML, unquoted value
        f'apiKey := "{R32}"',                                   # Go
        f":token => '{R32}'",                                   # Ruby
        f"'password' => '{R32}',",                              # PHP
        f'<add key="ApiSecret" value="{R32}"/>',                # XML: keyword in the window
        f"export DB_PASSWORD={R32}",                            # shell
        f"webhook_url: https://hooks.example.com/{R32}",        # keyword in key, token inside a URL
        f'"{{\\"api_key\\": \\"{R32}\\"}}"',                    # escaped JSON inside a string literal
        f"url = 'https://x.example/?access_key={R32}&v=1'",    # keyword inside the literal
        f"auth_header = `Bearer {R32}`",                        # template literal
    ],
)
def test_keyworded_values_in_many_syntaxes(line: str) -> None:
    hits, _ = run(line + "\n", "base64url")
    assert found(hits, line + "\n") == [R32]
    assert conf(hits[0]) is Confidence.HIGH


def test_no_keyword_means_low_confidence() -> None:
    text = f'value = "{R32}"\n'
    (h,) = run(text)[0]
    assert conf(h) is Confidence.LOW and h.confidence_delta == -1


def test_context_required_drops_unkeyed_tokens() -> None:
    text = f'value = "{R32}"\npassword = "{R40}"\n'
    hits, _ = run(text, context={"required": True})
    assert found(hits, text) == [R40]


@pytest.mark.parametrize(
    ("base", "expected_delta"),
    [(Confidence.HIGH, -2), (Confidence.MEDIUM, -1), (Confidence.LOW, 0)],
)
def test_confidence_delta_is_relative_to_the_rule(base: Confidence, expected_delta: int) -> None:
    (h,) = run(f'value = "{R32}"\n', confidence=base)[0]
    assert h.confidence_delta == expected_delta
    assert Confidence(int(base) + h.confidence_delta) is Confidence.LOW


def test_high_confidence_needs_margin_over_threshold() -> None:
    text = f'secret = "{R20}"\n'  # H = 4.32, threshold 3.8
    assert conf(run(text)[0][0]) is Confidence.HIGH
    assert conf(run(text, threshold=4.1)[0][0]) is Confidence.MEDIUM  # 4.32 < 4.1 + 0.3


# --------------------------------------------------------------------------- false positives


def test_uuid_is_exempt_without_keyword() -> None:
    text = f'request_id = "{UUID}"\n'
    assert run(text, "base64url", threshold=3.0)[0] == []  # entropy alone would pass


def test_uuid_is_kept_with_keyword() -> None:
    text = f'client_secret = "{UUID}"\n'
    assert found(run(text, "base64url", threshold=3.0)[0], text) == [UUID]


def test_uuids_fail_default_thresholds_anyway() -> None:
    assert run(f'client_secret = "{UUID}"\n', "base64url")[0] == []


@pytest.mark.parametrize(
    "line",
    [
        f"commit: {HEX40}",
        f"  rev = \"{HEX40}\"",
        f"GIT_COMMIT_SHA={HEX40}",
        f'"commitSha": "{HEX40}"',
        f"      uses: actions/checkout@{HEX40}",
        f"sha256 = \"{HEX64}\"",
        f"image: registry.example.com/app@sha256:{HEX64}",
        f'checksum: "{HEX64}"',
        f"digest = '{HEX64}'",
        f'"integrity": "{HEX64}"',
        f"  ref: {HEX40}",
    ],
)
def test_digests_with_digest_context_are_exempt(line: str) -> None:
    assert run(line + "\n", "hex")[0] == []


def test_digest_without_context_is_reported() -> None:
    text = f'value = "{HEX40}"\n'
    assert found(run(text, "hex")[0], text) == [HEX40]


def test_only_40_and_64_hex_count_as_digests() -> None:
    text = f'commit = "{HEX32}"\n'  # 32 hex is not a SHA-1/SHA-256 digest
    assert len(run(text, "hex")[0]) == 1


@pytest.mark.parametrize(
    "line",
    [
        f'api_key = "example_{R20}"',                  # token-level placeholder
        f'api_key = "YOUR_TOKEN_{R20}"',
        f'secret = "changeme{R20}"',
        f'token: "{{{{ .Values.{R20} }}}}"',            # Helm template value
        f'password = "${{{R20}}}"',                     # shell/compose variable
        f'password = "<{R20}>"',                        # angle placeholder
    ],
)
def test_placeholders_are_exempt(line: str) -> None:
    assert run(line + "\n", "base64url")[0] == []


def test_repeated_character_run_is_exempt() -> None:
    # A low threshold isolates the repetition condition from the entropy one.
    text = f'secret = "{R20[:10]}AAAAAA{R20[10:]}"\n'
    assert run(text, threshold=3.0)[0] == []
    assert len(run(f'secret = "{R20[:10]}AAAAA{R20[10:]}"\n', threshold=3.0)[0]) == 1  # five is fine


@pytest.mark.parametrize("seq", ["012345", "987654", "abcdef", "FEDCBA", "uvwxyz", "KLMNOP"])
def test_sequential_runs_are_exempt(seq: str) -> None:
    text = f'secret = "{R20[:8]}{seq}{R20[8:]}"\n'
    assert run(text)[0] == []


def test_near_sequential_is_not_exempt() -> None:
    text = f'secret = "{R20[:8]}01235{R20[8:]}"\n'
    assert len(run(text)[0]) == 1


def test_lockfiles_are_skipped() -> None:
    text = f'"integrity": "sha512-{R40}{R40}",\n"resolved": "{R32}"\n'
    assert run(text, tags=frozenset({"lockfile"}))[0] == []


def test_exclude_regex() -> None:
    text = f'secret = "sk_test_{R32}"\nsecret2 = "sk_live_{R32}"\n'
    hits, _ = run(text, "base64url", exclude_regex=["^sk_test_"])
    assert found(hits, text) == [f"sk_live_{R32}"]


def test_min_classes() -> None:
    text = f'secret = "{LOWER32}"\n'
    assert run(text, "alnum")[0] == []
    assert len(run(text, "alnum", min_classes=1)[0]) == 1
    assert run(f'secret = "{R32}"\n', "alnum", min_classes=3)[0] != []


def test_hex_class_rule_is_digit_and_letter() -> None:
    digits = j("31415926", "53589793", "2384")
    text = f'secret = "{digits}"\n'
    assert run(text, "hex")[0] == []
    assert len(run(text, "hex", min_classes=1)[0]) == 1


def test_low_entropy_values_are_ignored() -> None:
    text = 'password = "correcthorsebatterystaple"\nclass_name = "MyVeryLongClassNameHandler"\n'
    assert run(text)[0] == []
    assert run(text, "alnum")[0] == []


def test_min_and_max_len() -> None:
    text = f'secret = "{R20}"\n'
    assert run(text, min_len=21)[0] == []
    assert len(run(text, min_len=20)[0]) == 1
    assert run(f'secret = "{R40}"\n', max_len=39)[0] == []


def test_tokens_longer_than_the_charset_bound_are_not_candidates() -> None:
    text = f'blob = "{R40 * 6}"\n'  # 240 chars: longer than the 200-char token regex
    assert run(text)[0] == []


def test_base64_padding_is_part_of_the_token() -> None:
    text = f'secret = "{R32}=="\n'
    (h,) = run(text)[0]
    assert h.props["length"] == 34


# --------------------------------------------------------------------------- scope and context


def test_scope_values_ignores_bare_tokens_in_prose() -> None:
    text = f"The key {AKIA} leaked in the logs.\n"
    assert run(text, "alnum")[0] == []
    (h,) = run(text, "alnum", scope="anywhere")[0]
    assert conf(h) is Confidence.LOW


def test_scope_anywhere_placeholder_check_uses_the_surrounding_chunk() -> None:
    text = f"TOKEN ${{{R20}}} and <{R32}>\n"
    assert run(text, "base64url", scope="anywhere")[0] == []


def test_apostrophes_do_not_hide_double_quoted_literals() -> None:
    text = f"# don't forget: it's \"{R32}\" (password)\n"
    assert found(run(text)[0], text) == [R32]


def test_unterminated_literal_is_not_a_region() -> None:
    assert run(f'call("{R32}\n')[0] == []
    # ... while an assignment is still a key/value candidate: the `val` group needs no closing quote.
    assert len(run(f'x = "{R32}\n')[0]) == 1


def test_window_chars_bounds_the_keyword_search() -> None:
    text = "password" + " " * 100 + f'"{R32}"\n'
    assert conf(run(text)[0][0]) is Confidence.LOW
    assert conf(run(text, context={"window_chars": 120})[0][0]) is Confidence.HIGH


def test_keyword_on_previous_line_does_not_count() -> None:
    text = f'# password below\nvalue = "{R32}"\n'
    assert conf(run(text)[0][0]) is Confidence.LOW


def test_keyword_matching_ignores_case_and_separators() -> None:
    for key in ("ACCESS-KEY", "accessKey", "access_key", "Access_Key_Id", "x-api-key"):
        text = f'{key}: "{R32}"\n'
        assert conf(run(text)[0][0]) is Confidence.HIGH, key


def test_custom_keywords_replace_the_defaults() -> None:
    text = f'stripe_value = "{R32}"\npassword = "{R40}"\n'
    hits, _ = run(text, context={"keywords": ["stripe"], "required": True})
    assert found(hits, text) == [R32]


def test_empty_keyword_list_means_no_context() -> None:
    hits, _ = run(f'password = "{R32}"\n', context={"keywords": []})
    assert conf(hits[0]) is Confidence.LOW


def test_default_keywords_match_the_spec() -> None:
    assert DEFAULT_KEYWORDS == (
        "secret", "token", "passwd", "password", "pwd", "api_key", "apikey", "access_key", "private",
        "credential", "auth", "bearer", "signature", "client_secret", "dsn", "conn", "webhook", "hmac",
    )


# --------------------------------------------------------------------------- configuration hooks


def test_entropy_delta_from_ctx_cache() -> None:
    text = f'secret = "{AWS_DOC_SECRET}"\n'  # H = 4.66 vs 4.5
    assert len(run(text)[0]) == 1
    assert run(text, cache={ENTROPY_DELTA_KEY: 0.2})[0] == []
    (h,) = run(text, cache={ENTROPY_DELTA_KEY: -0.2})[0]
    assert conf(h) is Confidence.HIGH  # 4.66 >= 4.3 + 0.3


@pytest.mark.parametrize("bad", [True, "0.5", float("nan"), None])
def test_bad_entropy_delta_is_ignored(bad: Any) -> None:
    assert len(run(f'secret = "{AWS_DOC_SECRET}"\n', cache={ENTROPY_DELTA_KEY: bad})[0]) == 1


def test_rule_threshold_replaces_buckets() -> None:
    text = f'secret = "{R40}"\n'
    assert run(text, threshold=5.5)[0] == []
    assert len(run(text, threshold=5.0)[0]) == 1


def test_regions_and_tokens_are_shared_across_rules() -> None:
    text = f'secret = "{R32}"\nhex = "{HEX32}"\n'
    ctx = FileCtx(path="f.py", text=text)
    match_entropy({"charset": "base64"}, ctx, make_rule())
    regions = ctx.cache["entropy.regions"]
    match_entropy({"charset": "hex"}, ctx, make_rule())
    assert ctx.cache["entropy.regions"] is regions
    assert {"entropy.tokens.base64.values", "entropy.tokens.hex.values"} <= set(ctx.cache)


def test_cap_counts_overflow() -> None:
    lines = "".join(f'secret_{i} = "{R32[i % 7 :]}{R20[: i % 7]}{i:04d}"\n' for i in range(60))
    hits, ctx = run(lines, max_hits=10)
    assert len(hits) == 10
    assert ctx.cache[CAPPED_KEY]["WS-SEC-GEN-001"] >= 1


def test_through_evaluate_with_all() -> None:
    text = f'password = "{R32}"\n'
    ctx = FileCtx(path="app.py", text=text)
    expr = {"all": [{"entropy": {"charset": "base64"}}, {"not": {"regex": "nosecret"}}]}
    assert len(evaluate(expr, ctx, make_rule())) == 1


def test_empty_text() -> None:
    assert run("")[0] == []


# --------------------------------------------------------------------------- properties


_TOKEN = st.text(
    alphabet="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789+/_-", min_size=8, max_size=60
)


@settings(max_examples=300, deadline=None)
@given(
    rows=st.lists(st.tuples(st.sampled_from(["secret", "value", "id", "x"]), _TOKEN), max_size=8),
    charset=st.sampled_from(sorted(CHARSETS)),
)
def test_every_hit_satisfies_the_conditions(rows: list[tuple[str, str]], charset: str) -> None:
    text = "".join(f'{k} = "{v}"\n' for k, v in rows)
    hits, ctx = run(text, charset, max_hits=1000)
    prev_end = -1
    for h in hits:
        tok = text[h.start : h.end]
        assert h.start >= prev_end
        prev_end = h.end
        assert h.secret_spans == [(h.start, h.end)]
        assert 20 <= len(tok) <= 200 and h.props["length"] == len(tok)
        assert h.props["charset"] == charset
        assert shannon(tok) >= threshold_for(charset, len(tok)) - 1e-9
        assert h.props["entropy"] == round(shannon(tok), 2)
        assert h.line == ctx.pos(h.start)[0] and h.end_line == h.line  # tokens never cross lines
        assert -1 <= h.confidence_delta <= 1


# --------------------------------------------------------------------------- robustness


@pytest.mark.slow
def test_large_code_file_is_fast() -> None:
    block = (
        'def handler(event, context):\n'
        '    name = "some_identifier_name"\n'
        f"    url = 'https://api.example.com/v1/items?page=2'\n"
        '    msg = f"hello {name}, it\'s a \\"quoted\\" word"\n'
        f'    token = "{R32}"\n'
        '    return {"statusCode": 200, "body": msg}\n'
    )
    text = block * 5000  # ~1 MiB
    start = time.perf_counter()
    for charset in ("base64", "hex"):
        for scope in ("values", "anywhere"):
            run(text, charset, scope=scope, max_hits=50)
    assert time.perf_counter() - start < 4.0


@pytest.mark.slow
@pytest.mark.parametrize(
    "unit",
    ['"\\"', "'", '"a\\', "`", '"' + "\\x" * 300, "a=" + "b" * 300 + " "],
)
def test_hostile_literal_and_kv_input_is_linear(unit: str) -> None:
    text = unit * (200_000 // len(unit))
    start = time.perf_counter()
    run(text, "base64")
    assert time.perf_counter() - start < 2.0


@settings(max_examples=300, deadline=None)
@given(
    text=st.text(max_size=400),
    charset=st.sampled_from(sorted(CHARSETS)),
    scope=st.sampled_from(["values", "anywhere"]),
)
def test_arbitrary_text_never_crashes(text: str, charset: str, scope: str) -> None:
    hits, _ = run(text, charset, scope=scope, max_hits=1000, min_len=16)
    for h in hits:
        assert 0 <= h.start < h.end <= len(text)
        assert "\n" not in text[h.start : h.end]
