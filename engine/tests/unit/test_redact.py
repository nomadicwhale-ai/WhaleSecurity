import hashlib

from whalescan.redact import Redactor, redact_spans, redact_value

AWS = "AKIAIOSFODNN7EXAMPLE"


def test_long_secret_prefix_and_hash():
    out = redact_value(AWS)
    digest = hashlib.sha256(AWS.encode()).hexdigest()[:8]
    assert out == f"AKIA…[sha256:{digest}]"
    assert AWS not in out


def test_short_secret_has_no_hash():
    assert redact_value("hunter2xyz") == "…[REDACTED len=10]"


def test_prefix_length_scales():
    s = "x" * 16
    assert redact_value(s).startswith("xxxx…")


def test_pem_keeps_header_only():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    out = redact_value(pem)
    assert out.startswith("-----BEGIN RSA PRIVATE KEY-----\n…[sha256:")
    assert "MIIEow" not in out


def test_redact_spans_multiple():
    t = 'a="SECRETVALUE1" b="SECRETVALUE2"'
    s1 = t.index("SECRETVALUE1")
    s2 = t.index("SECRETVALUE2")
    out = redact_spans(t, [(s1, s1 + 12), (s2, s2 + 12)])
    assert "SECRETVALUE" not in out and out.count("[REDACTED len=12]") == 2


def test_sweep_catches_echoes_longest_first():
    r = Redactor()
    r.add("supersecret-token-12345")
    r.add("supersecret-token")
    out = r.sweep("log: supersecret-token-12345 and supersecret-token")
    assert "supersecret" not in out


def test_sweep_ignores_tiny_values():
    r = Redactor()
    r.add("ab")
    assert r.sweep("abab") == "abab" and len(r) == 0


def test_pem_lines_swept_individually():
    r = Redactor()
    body = "MIIEowIBAAKCAQEAxxxxxxxxxxxxxxxxxxxx"
    r.add(f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----")
    assert body not in r.sweep(f"leaked line {body}")


def test_finalize_reveals_hidden_after_redaction():
    r = Redactor()
    r.add("topsecret-value-1")
    out = r.finalize("x\u200by topsecret-value-1")
    assert "\u200b" not in out and "[ZWSP]" in out and "topsecret" not in out


def test_redact_text_registers_and_sweeps():
    r = Redactor()
    t = 'pw="correcthorse1"'
    s = t.index("correcthorse1")
    assert "correcthorse1" not in r.redact_text(t, [(s, s + 13)])
    assert "correcthorse1" not in r.sweep("elsewhere correcthorse1")
