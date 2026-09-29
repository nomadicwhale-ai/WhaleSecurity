from whalescan.dedupe import Candidate, dedupe, fingerprints, normalized_snippet
from whalescan.model import Confidence, FileCtx, Hit


def ctx(text):
    return FileCtx(path="a.py", text=text)


def cand(rule, start, end, path="a.py", norm="n", **kw):
    return Candidate(rule, path, start, end, 1, start + 1, 1, end + 1, norm, **kw)


def test_normalized_snippet_collapses_whitespace_and_limits_lines():
    c = ctx("a  =   1\n\tb = 2\nc = 3\nd = 4\n")
    h = Hit.at(c, 0, 25)
    assert normalized_snippet(c, h) == "a = 1 b = 2 c = 3"


def test_normalized_snippet_masks_secrets():
    text = 'k = "AKIAIOSFODNN7EXAMPLE"\np = "short"\n'
    c = ctx(text)
    h = Hit.at(c, 0, 26)
    long_s = text.index("AKIA")
    n = normalized_snippet(c, h, [(long_s, long_s + 20)])
    assert "AKIA" not in n and n.startswith('k = "<SECRET:sha256hex' if False else 'k = "<SECRET:')
    short = text.index("short")
    h2 = Hit.at(c, 27, 38)
    assert "<SECRET:len=5>" in normalized_snippet(c, h2, [(short, short + 5)])


def test_normalized_snippet_does_not_normalize_unicode():
    c = ctx("a\u200bb\n")
    assert "\u200b" in normalized_snippet(c, Hit.at(c, 0, 3))


def test_exact_and_same_rule_overlap():
    a, b, c = cand("R", 0, 10), cand("R", 0, 10), cand("R", 5, 20)
    out = dedupe([a, b, c])
    assert out == [a]


def test_same_rule_longest_wins_at_same_start():
    short, long_ = cand("R", 0, 5), cand("R", 0, 30, norm="m")
    assert dedupe([short, long_]) == [long_]


def test_disjoint_same_rule_kept():
    assert len(dedupe([cand("R", 0, 5), cand("R", 10, 15)])) == 2


def test_cross_rule_specific_beats_generic():
    spec = cand("WS-SEC-AWS-001", 0, 20, secret_spans=((0, 20),), score=10, confidence=Confidence.HIGH)
    gen = cand("WS-SEC-GEN-001", 0, 20, secret_spans=((0, 20),), generic=True, score=10)
    out = dedupe([gen, spec])
    assert out == [spec] and spec.related == ["WS-SEC-GEN-001"]


def test_cross_rule_supersedes_then_score():
    a = cand("A", 0, 9, secret_spans=((0, 9),), score=5, supersedes=frozenset({"B"}))
    b = cand("B", 0, 9, secret_spans=((0, 9),), score=9)
    assert dedupe([a, b]) == [a]
    c = cand("C", 0, 9, secret_spans=((0, 9),), score=9)
    d = cand("D", 0, 9, secret_spans=((0, 9),), score=5)
    assert dedupe([c, d]) == [c]


def test_cross_rule_tie_is_deterministic():
    x, y = (
        cand("WS-X", 0, 9, secret_spans=((0, 9),), score=5),
        cand("WS-Y", 0, 9, secret_spans=((0, 9),), score=5),
    )
    assert dedupe([x, y]) == dedupe([y, x]) and dedupe([y, x])[0].rule_id == "WS-X"


def test_cross_rule_nonoverlapping_secrets_both_kept():
    a = cand("A", 0, 5, secret_spans=((0, 5),))
    b = cand("B", 10, 15, secret_spans=((10, 15),))
    assert len(dedupe([a, b])) == 2


def test_cross_rule_only_across_same_path():
    a = cand("A", 0, 9, path="x.py", secret_spans=((0, 9),))
    b = cand("B", 0, 9, path="y.py", secret_spans=((0, 9),))
    assert len(dedupe([a, b])) == 2


def test_fingerprints_ignore_line_numbers_and_disambiguate_duplicates():
    a1 = cand("R", 0, 5, norm="privileged: true")
    a2 = cand("R", 40, 45, norm="privileged: true")
    f = fingerprints([a1, a2])
    assert f[0] != f[1]
    moved = [cand("R", 100, 105, norm="privileged: true"), cand("R", 300, 305, norm="privileged: true")]
    assert fingerprints(moved) == f


def test_content_fingerprint_is_path_free():
    a = fingerprints([cand("R", 0, 5, path="old.py")])[0]
    b = fingerprints([cand("R", 0, 5, path="new.py")])[0]
    assert a[0] != b[0] and a[1] == b[1]
    assert a[0].startswith("sha256:") and len(a[0]) == 71
