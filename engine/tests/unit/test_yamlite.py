"""Unit tests for whalescan.yamlite (spec §8.6 parser paragraph, limits §5.3).

Differential tests against PyYAML live in test_yamlite_differential.py.
"""

from __future__ import annotations

import math
import pickle
import time
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from whalescan import yamlite as Y
from whalescan.yamlite import (
    MAX_ALIASES,
    MAX_BYTES,
    MAX_DEPTH,
    MAX_NODES,
    Document,
    KeyNode,
    MapNode,
    ScalarNode,
    SeqNode,
    YamlError,
    load,
    load_all,
    resolve_scalar,
    to_python,
)

# --------------------------------------------------------------------------- helpers


def py(text: str, schema: str = "yaml12", helm: bool = False) -> list[Any]:
    """Values of all documents; fails the test on any document error."""
    docs = load_all(text, schema, helm)
    errors = [str(d.error) for d in docs if d.error is not None]
    assert not errors, errors
    return [to_python(d) for d in docs]


def one(text: str, schema: str = "yaml12", helm: bool = False) -> Any:
    (value,) = py(text, schema, helm)
    return value


def root(text: str, schema: str = "yaml12", helm: bool = False) -> Any:
    docs = load_all(text, schema, helm)
    assert len(docs) == 1 and docs[0].error is None, [str(d.error) for d in docs]
    return docs[0].root


def err(text: str, helm: bool = False) -> YamlError:
    """The error of the single document of ``text``."""
    docs = load_all(text, lenient_helm=helm)
    bad = [d.error for d in docs if d.error is not None]
    assert bad, f"expected a parse error for {text!r}"
    return bad[0]


# --------------------------------------------------------------------------- API basics


def test_empty_streams_have_no_documents() -> None:
    assert load_all("") == []
    assert load_all("# only a comment\n\n   \n") == []
    assert load_all("\n") == []
    assert load("") is None


def test_empty_explicit_document_is_a_null_scalar() -> None:
    (doc,) = load_all("---\n")
    assert isinstance(doc.root, ScalarNode)
    assert doc.root.raw == "" and doc.root.value is None
    assert doc.explicit_start and not doc.explicit_end
    assert py("---\n...\n---\n") == [None, None]
    assert py("a: 1\n---\n") == [{"a": 1}, None]


def test_document_flags_version_and_spans() -> None:
    text = "%YAML 1.2\n---\na: 1\n...\n---\nb: 2\n"
    d1, d2 = load_all(text)
    assert d1.version == "1.2" and d1.explicit_start and d1.explicit_end
    assert d2.version is None and d2.explicit_start and not d2.explicit_end
    assert d1.start == text.index("---") and d1.end == text.index("...")
    assert d2.start == text.index("---\nb") and d2.end == len(text)
    assert d1.line == 2 and d2.line == 5
    assert d1.index == 0 and d2.index == 1 and d1.schema == "yaml12"
    assert "Document #0" in repr(d1)


def test_bare_documents_after_document_end_marker() -> None:
    # YAML 1.2 allows a bare document after '...'
    assert py("a: 1\n...\nb: 2\n") == [{"a": 1}, {"b": 2}]


def test_load_single_document_and_rejects_streams() -> None:
    node = load("a: [1, 2]\n")
    assert isinstance(node, MapNode) and to_python(node) == {"a": [1, 2]}
    with pytest.raises(YamlError, match="single document"):
        load("a: 1\n---\nb: 2\n")
    with pytest.raises(YamlError):
        load("a: [1\n")


def test_argument_validation() -> None:
    with pytest.raises(TypeError):
        load_all(b"a: 1")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="schema"):
        load_all("a: 1", schema="yaml13")
    with pytest.raises(ValueError, match="schema"):
        to_python(load("a: 1"), schema="auto")
    with pytest.raises(ValueError, match="schema"):
        resolve_scalar("1", "json")


def test_document_to_python_raises_its_error() -> None:
    (doc,) = load_all("a: [1\n")
    assert doc.root is None and isinstance(doc.error, YamlError)
    with pytest.raises(YamlError):
        doc.to_python()
    with pytest.raises(YamlError):
        to_python(doc)
    assert to_python(None) is None


def test_strict_mode_raises_the_first_error() -> None:
    with pytest.raises(YamlError, match="unterminated"):
        load_all('a: 1\n---\nb: "x\n---\nc: 3\n', strict=True)


# --------------------------------------------------------------------------- raw keys (on: pitfall)


@pytest.mark.parametrize("schema", ["yaml11", "yaml12"])
@pytest.mark.parametrize(
    ("text", "key", "style"),
    [("on: push\n", "on", "plain"), ('"on": push\n', "on", "double"), ("'on': push\n", "on", "single")],
)
def test_on_key_is_never_resolved(schema: str, text: str, key: str, style: str) -> None:
    node = root(text, schema)
    (k, v), *_ = node.items
    assert isinstance(k, KeyNode)
    assert k.raw == key and k.value == key and k.style == style
    assert to_python(node) == {"on": "push"}
    assert v.value == "push"


@pytest.mark.parametrize("schema", ["yaml11", "yaml12"])
def test_true_key_stays_true_never_on(schema: str) -> None:
    assert one("true: pull_request_target\n", schema) == {"true": "pull_request_target"}
    assert one("on: 1\ntrue: 2\nyes: 3\n'no': 4\n", schema) == {"on": 1, "true": 2, "yes": 3, "no": 4}


def test_only_values_are_resolved() -> None:
    assert one("on: on\n", "yaml11") == {"on": True}
    assert one("on: on\n", "yaml12") == {"on": "on"}
    assert one("1: 1\nnull: null\n~: ~\n0x1F: 0x1F\n") == {"1": 1, "null": None, "~": None, "0x1F": 31}


GHA_ON_FORMS = {
    "scalar": "on: pull_request_target\njobs: {}\n",
    "flow-seq": "on: [push, pull_request_target]\njobs: {}\n",
    "block-seq": "on:\n  - push\n  - pull_request_target\njobs: {}\n",
    "mapping": "on:\n  pull_request_target:\n    types: [opened]\njobs: {}\n",
}


@pytest.mark.parametrize("form", sorted(GHA_ON_FORMS))
@pytest.mark.parametrize("quote", ["", '"', "'"])
def test_all_four_gha_on_forms_under_every_key_spelling(form: str, quote: str) -> None:
    text = GHA_ON_FORMS[form].replace("on:", f"{quote}on{quote}:", 1)
    for schema in ("yaml11", "yaml12"):
        node = root(text, schema)
        assert isinstance(node, MapNode)
        on = node.get("on")
        assert on is not None, (form, quote, schema)
        if form == "scalar":
            assert isinstance(on, ScalarNode) and on.raw == "pull_request_target"
        elif form == "mapping":
            assert isinstance(on, MapNode) and on.keys() == ["pull_request_target"]
        else:
            assert isinstance(on, SeqNode) and [n.raw for n in on.items if isinstance(n, ScalarNode)] == [
                "push",
                "pull_request_target",
            ]


# --------------------------------------------------------------------------- value tables (spec §8.6)

BOTH_BOOL = ["true", "True", "TRUE", "false", "False", "FALSE"]
Y11_ONLY_BOOL = [
    "yes",
    "Yes",
    "YES",
    "no",
    "No",
    "NO",
    "on",
    "On",
    "ON",
    "off",
    "Off",
    "OFF",
    "y",
    "Y",
    "n",
    "N",
]


@pytest.mark.parametrize("word", BOTH_BOOL)
def test_core_bools_in_both_schemas(word: str) -> None:
    expected = word.lower() == "true"
    assert resolve_scalar(word, "yaml12") is expected
    assert resolve_scalar(word, "yaml11") is expected


@pytest.mark.parametrize("word", Y11_ONLY_BOOL)
def test_yaml11_only_bools(word: str) -> None:
    assert resolve_scalar(word, "yaml12") == word
    assert resolve_scalar(word, "yaml11") is (word.lower() in ("yes", "on", "y"))


@pytest.mark.parametrize("word", ["null", "Null", "NULL", "~", ""])
def test_nulls(word: str) -> None:
    assert resolve_scalar(word, "yaml12") is None
    assert resolve_scalar(word, "yaml11") is None


@pytest.mark.parametrize(
    ("raw", "y12", "y11"),
    [
        ("0o17", 15, "0o17"),
        ("017", 17, 15),
        ("0x1F", 31, 31),
        ("1_000", "1_000", 1000),
        ("22:22", "22:22", 1342),
        ("-12", -12, -12),
        ("+7", 7, 7),
        ("0", 0, 0),
        ("0b101", "0b101", 5),
        ("1.5", 1.5, 1.5),
        ("1e3", 1000.0, "1e3"),
        ("1.0e+3", 1000.0, 1000.0),
        (".5", 0.5, 0.5),
        ("1.", 1.0, 1.0),
        ("190:20:30.15", "190:20:30.15", 685230.15),
        ("2001-12-14", "2001-12-14", "2001-12-14"),  # timestamps stay strings
        ("1.2.3", "1.2.3", "1.2.3"),
        ("0x", "0x", "0x"),
        ("-", "-", "-"),
        ("nULL", "nULL", "nULL"),
        ("0b_", "0b_", "0b_"),
    ],
)
def test_number_tables(raw: str, y12: Any, y11: Any) -> None:
    for schema, expected in (("yaml12", y12), ("yaml11", y11)):
        got = resolve_scalar(raw, schema)
        assert got == expected and type(got) is type(expected), (raw, schema, got)


def test_special_floats() -> None:
    for schema in ("yaml11", "yaml12"):
        assert resolve_scalar(".inf", schema) == math.inf
        assert resolve_scalar("-.Inf", schema) == -math.inf
        assert math.isnan(resolve_scalar(".NaN", schema))
        assert resolve_scalar("NaN", schema) == "NaN"


def test_quoted_and_block_scalars_are_strings() -> None:
    assert one("a: 'true'\nb: \"12\"\nc: |\n  null\n") == {"a": "true", "b": "12", "c": "null\n"}


@pytest.mark.parametrize(
    ("text", "y12", "y11"),
    [
        ("!!str 12", "12", "12"),
        ("!!int '12'", 12, 12),
        ("!!int 0x1F", 31, 31),
        ("!!int 1.5", "1.5", "1.5"),
        ("!!float 1", 1.0, 1.0),
        ("!!float '2.5'", 2.5, 2.5),
        ("!!bool yes", "yes", True),
        ("!!bool 'true'", True, True),
        ("!!null something", None, None),
        ("!Ref MyBucket", "MyBucket", "MyBucket"),
        ("! 12", "12", "12"),
        ("!!binary aGVsbG8=", "aGVsbG8=", "aGVsbG8="),
        ("!<tag:yaml.org,2002:str> 12", "12", "12"),
    ],
)
def test_tagged_scalars(text: str, y12: Any, y11: Any) -> None:
    assert one(f"v: {text}\n", "yaml12") == {"v": y12}
    assert one(f"v: {text}\n", "yaml11") == {"v": y11}


def test_huge_numbers_stay_strings() -> None:
    digits = "9" * 5000
    assert resolve_scalar(digits) == digits
    assert resolve_scalar(digits, "yaml11") == digits
    assert resolve_scalar("1" * 999) == int("1" * 999)


@given(
    st.text(max_size=40),
    st.sampled_from(["yaml11", "yaml12"]),
    st.sampled_from([None, "!!int", "!!float", "!!bool"]),
)
@settings(max_examples=300)
def test_resolve_scalar_never_raises(raw: str, schema: str, tag: str | None) -> None:
    v = resolve_scalar(raw, schema, "plain", tag)
    assert v is None or isinstance(v, (str, int, float, bool))


def test_values_are_resolved_lazily_and_cached() -> None:
    node = root("a: 017\n", "yaml11")
    (_, v), *_ = node.items
    assert isinstance(v, ScalarNode)
    assert v.value == 15 and v.value == 15
    assert v.resolve("yaml12") == 17 and v.resolve() == 15 and v.resolve("yaml11") == 15
    assert v.type_name() == "int" and v.type_name("yaml12") == "int"
    assert to_python(node, "yaml12") == {"a": 17}


def test_type_names() -> None:
    node = root("m: {}\ns: []\na: x\nb: 1\nc: 1.5\nd: true\ne: ~\nf: yes\n", "yaml11")
    assert isinstance(node, MapNode)
    names = {k.raw: v.type_name() for k, v in node.items}
    assert names == {
        "m": "map",
        "s": "seq",
        "a": "str",
        "b": "int",
        "c": "float",
        "d": "bool",
        "e": "null",
        "f": "bool",
    }
    assert node.type_name() == "map"
    f = node.get("f")
    assert f is not None and f.type_name("yaml12") == "str"


# --------------------------------------------------------------------------- plain and quoted scalars


def test_plain_scalar_rules() -> None:
    assert one("a: b#c\nd: e #comment\nf: http://x.y:8080/p?q=1#frag\ng: a:b:c\nh: C:\\dir\n") == {
        "a": "b#c",
        "d": "e",
        "f": "http://x.y:8080/p?q=1#frag",
        "g": "a:b:c",
        "h": "C:\\dir",
    }
    assert one("a: -b\nc: ?d\ne: :f\n-g: 1\n?h: 2\n:i: 3\n") == {
        "a": "-b",
        "c": "?d",
        "e": ":f",
        "-g": 1,
        "?h": 2,
        ":i": 3,
    }
    assert one("k: ${{ github.event.pull_request.head.sha }}\n") == {
        "k": "${{ github.event.pull_request.head.sha }}"
    }
    assert one("k:\u00a0x\n") == "k:\u00a0x"  # NBSP is not YAML whitespace


def test_multiline_plain_scalars_fold() -> None:
    assert one("a: b\n  c\n\n  d\n\n\n  e\n") == {"a": "b c\nd\n\ne"}
    assert one("- a\n  b\n- c\n") == ["a b", "c"]
    assert one("foo\nbar\n") == "foo bar"
    assert one("a: b\n  - c\n") == {"a": "b - c"}
    assert one("a: b\n  #c\n") == {"a": "b"}


def test_multiline_plain_key_is_an_error() -> None:
    assert "mapping values" in str(err("a: b\n  c: d\n"))
    assert "mapping values" in str(err("a: b: c\n"))


def test_single_quoted() -> None:
    assert one("a: 'it''s'\nb: 'x\n\n  y'\nc: '  lead  '\nd: ''\n") == {
        "a": "it's",
        "b": "x\ny",
        "c": "  lead  ",
        "d": "",
    }
    assert one("a: 'one\n  two'\n") == {"a": "one two"}


@pytest.mark.parametrize(
    ("escape", "char"),
    [
        ("\\0", "\0"),
        ("\\a", "\x07"),
        ("\\b", "\b"),
        ("\\t", "\t"),
        ("\\\t", "\t"),
        ("\\n", "\n"),
        ("\\v", "\x0b"),
        ("\\f", "\x0c"),
        ("\\r", "\r"),
        ("\\e", "\x1b"),
        ("\\ ", " "),
        ('\\"', '"'),
        ("\\/", "/"),
        ("\\\\", "\\"),
        ("\\N", "\x85"),
        ("\\_", "\xa0"),
        ("\\L", "\u2028"),
        ("\\P", "\u2029"),
        ("\\x41", "A"),
        ("\\u00e9", "é"),
        ("\\U0001F600", "\U0001f600"),
    ],
)
def test_double_quoted_escapes(escape: str, char: str) -> None:
    assert one(f'a: "<{escape}>"\n') == {"a": f"<{char}>"}
    assert one(f'"k{escape}": 1\n') == {f"k{char}": 1}
    assert one(f'{{"k": "<{escape}>"}}\n') == {"k": f"<{char}>"}


@pytest.mark.parametrize("bad", ["\\q", "\\x4", "\\u12", "\\UFFFFFFFF", "\\x"])
def test_invalid_escapes_are_errors_with_positions(bad: str) -> None:
    text = f'ok: 1\nbad: "ab{bad}"\n'
    e = err(text)
    assert "escape" in str(e)
    assert (e.line, e.col) == (2, 9)
    assert e.offset == text.index("\\")


def test_json_surrogate_pairs_are_combined_and_lone_surrogates_replaced() -> None:
    assert one('{"a": "\\ud83d\\ude00", "b": "\\ud800x"}') == {"a": "\U0001f600", "b": "\ufffdx"}


def test_multiline_double_quoted() -> None:
    assert one('a: "x\n  y"\n') == {"a": "x y"}
    assert one('a: "x\n\n  y"\n') == {"a": "x\ny"}
    assert one('a: "x\\\n    y"\n') == {"a": "xy"}  # escaped line break: no space, indent dropped
    assert one('a: "x\\ \n  y"\n') == {"a": "x  y"}  # escaped trailing space is kept
    assert one('a: "x \t\n  y"\n') == {"a": "x y"}  # unescaped trailing white space is not
    assert one('a: "x\\t\n  y"\n') == {"a": "x\t y"}
    assert one('"\\\n  x"\n') == "x"


def test_unterminated_quotes_are_errors_at_the_opening_quote() -> None:
    for text in ('a: "abc\nb: 1\n', "a: 'abc\nb: 1\n"):
        e = err(text)
        assert "unterminated" in e.message and (e.line, e.col) == (1, 4)


# --------------------------------------------------------------------------- block scalars


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("|", "a\n b\n\nc\n"),
        ("|-", "a\n b\n\nc"),
        ("|+", "a\n b\n\nc\n\n\n"),
        (">", "a\n b\n\nc\n"),
        (">-", "a\n b\n\nc"),
        (">+", "a\n b\n\nc\n\n\n"),
    ],
)
def test_block_scalar_chomping(header: str, expected: str) -> None:
    text = f"k: {header}\n  a\n   b\n\n  c\n\n\nnext: 1\n"
    assert one(text) == {"k": expected, "next": 1}


def test_folding_rules() -> None:
    assert one("a: >\n  one\n  two\n\n  three\n    indented\n  back\n") == {
        "a": "one two\nthree\n  indented\nback\n"
    }
    assert one("a: >\n\n  x\n\n") == {"a": "\nx\n"}
    assert one("a: >2\n   x\n  y\n") == {"a": " x\ny\n"}


def test_block_scalar_indentation() -> None:
    assert one("a: |2\n    x\n   y\n") == {"a": "  x\n y\n"}
    assert one("a: |1\n  x\n") == {"a": " x\n"}
    assert one("a: |-1\n  x\n") == {"a": " x"}
    assert one("- |\n  a\n  b\n- c\n") == ["a\nb\n", "c"]
    assert one("a:\n  - |\n    x\n  - y\n") == {"a": ["x\n", "y"]}
    assert one("--- |\n  root\n") == "root\n"
    assert one("a: |\n\n  x\n") == {"a": "\nx\n"}
    assert one("a: |\n  # not a comment\n  x\n") == {"a": "# not a comment\nx\n"}
    assert one("a: | # a real comment\n  x\n") == {"a": "x\n"}
    assert one("a: |\nb: 1\n") == {"a": "", "b": 1}
    assert one("a: |\n  x") == {"a": "x"}  # no final line break at EOF: nothing to clip
    assert one("a: |+\n  x\n  \n   \n") == {"a": "x\n\n \n"}


@pytest.mark.parametrize("header", ["|0", "|10", "|++", "|-+", "|x", ">!", "|2 3"])
def test_invalid_block_scalar_headers(header: str) -> None:
    assert isinstance(err(f"a: {header}\n  x\n"), YamlError)


def test_block_scalar_less_indented_content_is_an_error() -> None:
    err("a: |\n    x\n  y\n")
    err("a: |\n   \n  x\n")  # a leading blank line with more spaces than the text (as PyYAML)


# --------------------------------------------------------------------------- collections


def test_block_collections() -> None:
    text = "a:\n  b: 1\n  c:\n  - x\n  - y: 2\n    z: 3\n  -\n  - - n1\n    - n2\nd: []\n"
    assert one(text) == {"a": {"b": 1, "c": ["x", {"y": 2, "z": 3}, None, ["n1", "n2"]]}, "d": []}
    assert one("-   a: b\n    c: d\n- - - x\n    - y\n  - z\n") == [{"a": "b", "c": "d"}, [["x", "y"], "z"]]
    assert one("key:\n- a\n- b\nnext: 1\n") == {"key": ["a", "b"], "next": 1}
    assert one("a:\n  -\n    b: c\n") == {"a": [{"b": "c"}]}
    assert one("- &a\n- x\n") == [None, "x"]
    assert one("a: &x\n- b\n") == {"a": ["b"]}


def test_mapping_values_and_nulls() -> None:
    assert one("a:\nb: ~\nc: # comment\nd:\n  e:\n") == {"a": None, "b": None, "c": None, "d": {"e": None}}
    assert one("a   : b\n'q' : c\n") == {"a": "b", "q": "c"}


def test_duplicate_keys_are_kept_last_wins_in_python() -> None:
    node = root("a: 1\nb: 2\na: 3\n")
    assert isinstance(node, MapNode)
    assert node.keys() == ["a", "b", "a"]
    assert [v.value for v in node.get_all("a")] == [1, 3]
    last = node.get("a")
    assert last is not None and last.value == 3
    key = node.key_node("a")
    assert key is not None and key.line == 3
    assert node.get("missing") is None and node.key_node("missing") is None
    assert to_python(node) == {"a": 3, "b": 2}


def test_flow_collections() -> None:
    assert one("a: [b, c, ]\nd: {e: f, g: [h, {i: j}]}\n") == {
        "a": ["b", "c"],
        "d": {"e": "f", "g": ["h", {"i": "j"}]},
    }
    assert one("{a, b: , c}\n") == {"a": None, "b": None, "c": None}
    assert one("[a: b, c, d: ]\n") == [{"a": "b"}, "c", {"d": None}]
    assert one("[a\n  b, c #comment\n  , d]\n") == ["a b", "c", "d"]
    assert one("{a:b, c: d:e}\n") == {"a:b": None, "c": "d:e"}
    assert one('{"a":1, "b":"x", "c":[2]}\n') == {"a": 1, "b": "x", "c": [2]}
    assert one("[http://x, a#b, -, -x]\n") == ["http://x", "a#b", "-", "-x"]
    assert one("[a?b, 'q', \"d\"]\n") == ["a?b", "q", "d"]
    assert one("a: [\n]\nb: {\n}\n") == {"a": [], "b": {}}


@pytest.mark.parametrize(
    "text",
    [
        "[a,,b]\n",
        "[,]\n",
        "{: a}\n",
        "[a, b\n",
        "{a: 1\n",
        "[a]]\n",
        "a: [x] y\n",
        "[- a]\n",
        "[a, |\n  x]\n",
        "{? a: b}\n",
    ],
)
def test_flow_errors(text: str) -> None:
    assert isinstance(err(text), YamlError)


def test_complex_keys_are_rejected_for_that_document_only() -> None:
    for bad in ("? a\n: b\n", "[a, b]: c\n", "{a: 1}: 2\n", "- ? a\n", "{[a]: b}\n", "[[a]: b]\n"):
        docs = load_all(f"ok: 1\n---\n{bad}---\nalso: ok\n")
        assert [d.error is None for d in docs] == [True, False, True], bad
        assert "complex" in str(docs[1].error) or "not allowed" in str(docs[1].error)


def test_block_structure_errors() -> None:
    for text in (
        "a:\n  b: 1\n c: 2\n",  # bad dedent
        "a: 1\n b: 2\n",
        " a: 1\nb: 2\n",
        "a:\n  - b\n  c: d\n",
        "- a\n- b:\n  c\n",
        "key: - a\n",
        "--- a: b\n",
        "--- - a\n",
        "&a - x\n",
        "a: 'x' y\n",
        'a: "x"y\n',
        "a: *b\n",
        "a: %x\n",
        "a: @x\n",
        "a: `x\n",
        "a: ]\n",
        "a: }\n",
        "a: 1\n- b\n",
    ):
        assert isinstance(err(text), YamlError), text


# --------------------------------------------------------------------------- anchors, aliases, merges


def test_aliases_share_nodes() -> None:
    node = root("a: &x {k: [1, 2]}\nb: *x\nc: [*x, *x]\n")
    assert isinstance(node, MapNode)
    a, b, c = node.values()
    assert a is b and isinstance(c, SeqNode) and c.items[0] is a and c.items[1] is a
    assert a.anchor == "x" and b.anchor == "x"
    value = to_python(node)
    assert value == {"a": {"k": [1, 2]}, "b": {"k": [1, 2]}, "c": [{"k": [1, 2]}, {"k": [1, 2]}]}
    assert value["a"] is value["b"]  # shared, like PyYAML


def test_anchor_on_key_and_alias_keys() -> None:
    assert one("&k key: v\nother: *k\n") == {"key": "v", "other": "key"}
    assert one("a: &x b\n*x : 1\n*x: 2\n") == {"a": "b", "b": 2}
    e = err("a: &x [1]\n*x : 1\n")
    assert "complex" in e.message


def test_anchor_redefinition_uses_the_latest() -> None:
    assert one("a: &x 1\nb: &x 2\nc: *x\n") == {"a": 1, "b": 2, "c": 2}


def test_undefined_and_recursive_aliases_are_errors() -> None:
    assert "undefined alias" in err("a: *nope\n").message
    assert "undefined alias" in err("&a [*a]\n").message
    assert "undefined alias" in err("a: &a\n  b: *a\n").message
    # anchors do not cross documents
    docs = load_all("a: &x 1\n---\nb: *x\n")
    assert docs[0].error is None and docs[1].error is not None


def test_alias_cannot_carry_properties() -> None:
    assert "alias" in err("a: &b *c\n").message
    assert "alias" in err("a: [!t *c]\n").message


def test_merge_keys() -> None:
    text = (
        "base: &base {name: base, x: 1, y: 1}\n"
        "over: &over {x: 2, z: 2}\n"
        "one:\n  <<: *base\n  name: one\n"
        "before:\n  name: before\n  <<: *base\n"
        "list:\n  <<: [*over, *base]\n"
        "repeat:\n  <<: *base\n  <<: *over\n"
        "inline:\n  <<: {q: 1}\n  q: 2\n"
        "flow: {<<: *base, y: 9}\n"
        "quoted:\n  '<<': *base\n"
    )
    v = one(text)
    assert v["one"] == {"name": "one", "x": 1, "y": 1}
    assert v["before"] == {"name": "before", "x": 1, "y": 1}
    assert v["list"] == {"x": 2, "z": 2, "name": "base", "y": 1}  # earlier mapping wins
    assert v["repeat"] == {"name": "base", "x": 2, "y": 1, "z": 2}  # later << wins (PyYAML)
    assert v["inline"] == {"q": 2}
    assert v["flow"] == {"name": "base", "x": 1, "y": 9}
    assert v["quoted"] == {"<<": {"name": "base", "x": 1, "y": 1}}  # a quoted << is a plain key


def test_merged_pairs_keep_their_source_positions_and_explicit_keys_win() -> None:
    text = "base: &b\n  privileged: true\n  user: root\nsvc:\n  <<: *b\n  user: app\n"
    node = root(text)
    assert isinstance(node, MapNode)
    svc = node.get("svc")
    assert isinstance(svc, MapNode)
    assert svc.keys() == ["privileged", "user"]
    priv_key = svc.key_node("privileged")
    assert priv_key is not None and priv_key.line == 2  # points at the anchored definition
    user = svc.get("user")
    assert user is not None and user.value == "app" and user.line == 6


def test_invalid_merge_values_are_errors() -> None:
    assert "merge" in err("a: 1\n<<: a\n").message
    assert "merge" in err("x: &x [1]\ny:\n  <<: [*x]\n").message


# --------------------------------------------------------------------------- tags


def test_tags_are_kept_on_nodes() -> None:
    node = root(
        "a: !Ref Bucket\nb: !!str 1\nc: !<tag:yaml.org,2002:int> 3\nd: !<!local> x\ne: !<urn:x:y> z\n"
        "f: ! v\ng: !If [c, a, b]\nh: !!map\n  k: v\ni: !vault |\n  secret\n"
    )
    assert isinstance(node, MapNode)
    tags = {k.raw: v.tag for k, v in node.items}
    assert tags == {
        "a": "!Ref",
        "b": "!!str",
        "c": "!!int",
        "d": "!local",
        "e": "!<urn:x:y>",
        "f": "!",
        "g": "!If",
        "h": "!!map",
        "i": "!vault",
    }
    assert to_python(node)["c"] == 3


def test_tag_and_anchor_in_either_order_and_on_keys() -> None:
    node = root("a: &x !t 1\nb: !t &y 2\n!k key: 3\n&z k2: 4\n")
    assert isinstance(node, MapNode)
    (_, va), (_, vb), (kk, _), (kz, _) = node.items
    assert (va.anchor, va.tag, vb.anchor, vb.tag) == ("x", "!t", "y", "!t")
    assert kk.tag == "!k" and kk.raw == "key" and kz.anchor == "z"


@pytest.mark.parametrize(
    "text",
    ["a: !e!foo x\n", "a: !! x\n", "a: !<> x\n", "a: &x &y z\n", "a: !t !u z\n", "a: !If[x]\n", "a: &\n"],
)
def test_unsupported_or_malformed_properties(text: str) -> None:
    assert isinstance(err(text), YamlError)


def test_tag_directive_is_an_error_for_its_document_only() -> None:
    docs = load_all("a: 1\n...\n%TAG ! tag:example.com,2000:\n---\nb: !x 2\n---\nc: 3\n")
    assert [d.error is None for d in docs] == [True, False, True]
    assert "%TAG" in str(docs[1].error)


# --------------------------------------------------------------------------- streams and directives


def test_directives() -> None:
    (d,) = load_all("%YAML 1.1\n%FUTURE reserved\n---\na: 1\n")
    assert d.version == "1.1" and d.error is None
    assert "version" in str(err("%YAML 2.0\n---\na: 1\n"))
    assert "%YAML" in str(err("%YAML 1.1\n%YAML 1.2\n---\na: 1\n"))
    assert "---" in str(err("%YAML 1.2\na: 1\n"))
    assert "---" in str(err("a: 1\n...\n%YAML 1.2\n"))


def test_directive_line_ends_the_document_at_a_token_boundary() -> None:
    assert py("a: 1\n%YAML 1.1\n---\nb: 2\n") == [{"a": 1}, {"b": 2}]
    # ...but continues a multi-line root plain scalar, as PyYAML does
    assert py("--- x\n%YAML 1.2\n---\n") == ["x %YAML 1.2", None]
    assert py("---\n%YAML 1.1\n---\nx\n") == [None, "x"]


def test_content_after_document_end_marker_is_an_error() -> None:
    docs = load_all("a: 1\n... junk\nb: 2\n")
    assert [d.error is None for d in docs] == [True, False, True]


def test_parse_errors_affect_only_their_document() -> None:
    text = "ok1: 1\n---\nbad: [1, 2\n---\nok2: 2\n---\n  bad: 1\n bad2: 2\n---\nok3: 3\n"
    docs = load_all(text)
    assert [d.error is None for d in docs] == [True, False, True, False, True]
    assert [d.root is None for d in docs] == [False, True, False, True, False]
    assert to_python(docs[4]) == {"ok3": 3}
    e = docs[1].error
    assert e is not None and e.line == 3
    assert "line 3" in str(e)


def test_document_markers_split_quoted_and_flow_content() -> None:
    docs = load_all('a: "x\n---\nb: 1\n')
    assert docs[0].error is not None and to_python(docs[1]) == {"b": 1}
    assert load_all("---foo: 1\n")[0].root is not None  # not a marker without a space
    assert py("---\t# tab after marker\na: 1\n") == [{"a": 1}]


def test_bom_crlf_and_other_line_breaks() -> None:
    assert py("\ufeffa: 1\n") == [{"a": 1}]
    assert py("\ufeff---\na: 1\n") == [{"a": 1}]
    assert py("a: 1\r\nb:\r\n  - x\r\nc: |\r\n  l1\r\n  l2\r\n") == [{"a": 1, "b": ["x"], "c": "l1\nl2\n"}]
    assert py("a: b\rc: d\r") == [{"a": "b", "c": "d"}]  # lone CR (libyaml)
    assert py("a: b\x85c: d\n") == [{"a": "b", "c": "d"}]  # NEL
    assert py("a: b\u2028c: d\n") == [{"a": "b", "c": "d"}]  # LS
    assert py('a: "x\u2028y"\n') == [{"a": "x\u2028y"}]  # kept inside quotes (PyYAML)
    assert py("a: |\n  x\u2029  y\n") == [{"a": "x\u2029y\n"}]


def test_crlf_positions_are_code_point_offsets_into_the_original_text() -> None:
    text = "a: 1\r\nbb: xyz\r\n"
    node = root(text)
    assert isinstance(node, MapNode)
    k, v = node.items[1]
    assert (k.start, k.end) == (6, 8) and (v.start, v.end) == (10, 13)
    assert (v.line, v.col, v.end_line, v.end_col) == (2, 5, 2, 8)
    assert v.source == "xyz"


# --------------------------------------------------------------------------- positions


def test_positions_of_keys_and_scalars() -> None:
    text = "top:\n  key: value # c\n  q: 'it''s'\n  dq: \"a\\tb\"\n  empty:\n  é🙂k: v\n"
    node = root(text)
    assert isinstance(node, MapNode)
    inner = node.get("top")
    assert isinstance(inner, MapNode)
    k, v = inner.items[0]
    assert (k.start, k.end, k.line, k.col) == (text.index("key"), text.index("key") + 3, 2, 3)
    assert (v.start, v.end, v.line, v.col, v.end_col) == (
        text.index("value"),
        text.index("value") + 5,
        2,
        8,
        13,
    )
    _, q = inner.items[1]
    assert q.source == "'it''s'" and q.col == 6
    _, dq = inner.items[2]
    assert dq.source == '"a\\tb"'
    ek, ev = inner.items[3]
    colon = text.index("empty:") + 6
    assert ek.source == "empty" and (ev.start, ev.end) == (colon, colon)  # zero-width after ':'
    assert (ev.line, ev.col, ev.end_line, ev.end_col) == (5, 9, 5, 9)
    uk, uv = inner.items[4]
    assert uk.raw == "é🙂k" and uk.col == 3 and uk.end_col == 6 and uv.col == 8  # code points


def test_positions_of_collections_and_multiline_nodes() -> None:
    text = "a:\n  - x\n  - y\nb: {c: [1, 2]}\nd: |\n  l1\n  l2\n\ne: p1\n  p2\n"
    node = root(text)
    assert isinstance(node, MapNode)
    seq = node.get("a")
    assert isinstance(seq, SeqNode)
    assert (seq.start, seq.line, seq.col) == (text.index("- x"), 2, 3) and seq.end == text.index("y") + 1
    flow = node.get("b")
    assert isinstance(flow, MapNode) and flow.source == "{c: [1, 2]}"
    inner = flow.get("c")
    assert inner is not None and inner.source == "[1, 2]"
    block = node.get("d")
    assert isinstance(block, ScalarNode) and block.source == "|\n  l1\n  l2"
    assert (block.line, block.end_line, block.end_col) == (5, 7, 5)
    plain = node.get("e")
    assert isinstance(plain, ScalarNode) and plain.raw == "p1 p2" and plain.source == "p1\n  p2"
    assert (node.start, node.end) == (0, len(text) - 1)
    assert node.span == (node.start, node.end)


def test_empty_values_positions() -> None:
    text = "- \n- a:\n"
    node = root(text)
    assert isinstance(node, SeqNode)
    first = node.items[0]
    assert (first.start, first.end) == (1, 1)
    inner = node.items[1]
    assert isinstance(inner, MapNode)
    (_, v), *_ = inner.items
    assert v.start == v.end == text.index("a:") + 2


def test_tab_separated_values_and_tab_indented_json() -> None:
    assert one("a:\tb\nc:\t\t[1,\t2]\n") == {"a": "b", "c": [1, 2]}
    assert one('{\n\t"a": 1,\n\t"b": [\n\t\t2\n\t]\n}\n') == {"a": 1, "b": [2]}
    assert one("a: b\n\t# tab comment\n") == {"a": "b"}


def test_tabs_as_block_indentation_are_errors() -> None:
    for text in ("a:\n\tb: 1\n", "a:\n  \tb: 1\n", "- a\n\t- b\n", "a:\n\t- b\n"):
        assert isinstance(err(text), YamlError), text


# --------------------------------------------------------------------------- traversal helpers


def test_descendants_values_and_kinds() -> None:
    node = root("a: {b: [1, 2]}\nc: x\n")
    assert isinstance(node, MapNode)
    kinds = [n.kind for n in node.descendants()]
    assert kinds == ["map", "seq", "scalar", "scalar", "scalar"]
    assert [n.kind for n in node.values()] == ["map", "scalar"]
    assert node.is_map and not node.is_seq and not node.is_scalar
    seq = node.get("a")
    assert isinstance(seq, MapNode)
    inner = seq.get("b")
    assert isinstance(inner, SeqNode) and inner.is_seq and inner.values() == inner.items
    assert inner.values() is not inner.items
    assert list(inner.items[0].descendants()) == [] and inner.items[0].values() == []


def test_reprs_never_contain_document_text() -> None:
    secret = "AKIAIOSFODNN7EXAMPLE"
    node = root(f"{secret}: {secret}\nl: [{secret}]\n")
    assert isinstance(node, MapNode)
    for item in [node, *node.descendants(), *(k for k, _ in node.items)]:
        assert secret not in repr(item)
    (doc,) = load_all(f"k: {secret}\n")
    assert secret not in repr(doc)


def test_error_messages_never_contain_document_text() -> None:
    secret = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
    texts = [
        f'token: "{secret}\n',
        f"token: {secret}: x\n",
        f"*{secret}\n",
        f"a: !{secret}!x y\n",
        f'a: "{secret}\\q"\n',
        f"- {secret}\n {secret}: 1\n",
        f"[{secret}, \n",
        f"%YAML {secret}\n---\n",
    ]
    for text in texts:
        e = err(text)
        assert secret not in str(e) and secret not in repr(e) and secret not in e.message, text


def test_yaml_error_is_a_picklable_value_error() -> None:
    e = err("a: [1\n")
    assert isinstance(e, ValueError)
    e2 = pickle.loads(pickle.dumps(e))  # noqa: S301 - round-trips our own object
    assert (e2.message, e2.line, e2.col, e2.offset) == (e.message, e.line, e.col, e.offset)
    assert str(YamlError("plain")) == "plain"


# --------------------------------------------------------------------------- limits (§5.3)


def test_text_size_limit_counts_utf8_bytes() -> None:
    big = "x" * (MAX_BYTES + 1)
    (doc,) = load_all(big)
    assert doc.error is not None and "larger" in doc.error.message and doc.root is None
    with pytest.raises(YamlError):
        load_all(big, strict=True)
    euros = "€" * (MAX_BYTES // 3 + 1)  # fewer code points than MAX_BYTES, more bytes
    assert load_all(euros)[0].error is not None
    ok = "a: " + "x" * (MAX_BYTES - 10)
    (doc,) = load_all(ok)
    assert doc.error is None and len(to_python(doc)["a"]) == MAX_BYTES - 10


@pytest.mark.parametrize("kind", ["block-map", "block-seq", "flow-seq", "flow-map", "mixed"])
def test_depth_limit(kind: str) -> None:
    def build(depth: int) -> str:
        if kind == "block-map":
            return "".join("  " * d + f"k{d}:\n" for d in range(depth - 1)) + "  " * (depth - 1) + "k: v\n"
        if kind == "block-seq":
            return "".join("  " * d + "-\n" for d in range(depth - 1)) + "  " * (depth - 1) + "- v\n"
        if kind == "flow-seq":
            return "[" * depth + "]" * depth + "\n"
        if kind == "flow-map":
            return "{a: " * depth + "1" + "}" * depth + "\n"
        return "[{a: " * (depth // 2) + "1" + "}]" * (depth // 2) + "\n"

    ok = load_all(build(MAX_DEPTH))
    assert ok[0].error is None
    deep = load_all(build(MAX_DEPTH + 1) if kind != "mixed" else build(MAX_DEPTH + 2))
    assert deep[0].error is not None and "nesting" in deep[0].error.message


def test_extreme_nesting_never_overflows_the_stack() -> None:
    for text in (
        "[" * 100_000,
        "{a: " * 50_000,
        "- " * 50_000 + "x\n",
        "".join(" " * d + "a:\n" for d in range(3000)),
    ):
        (doc,) = load_all(text)
        assert doc.error is not None


def test_alias_expansion_counts_toward_depth() -> None:
    inner = "[" * 40 + "]" * 40
    text = f"a: &a {inner}\nb: " + "[" * 30 + "*a" + "]" * 30 + "\n"
    (doc,) = load_all(text)
    assert doc.error is not None and "alias" in doc.error.message
    text_ok = f"a: &a {inner}\nb: " + "[" * 20 + "*a" + "]" * 20 + "\n"
    assert load_all(text_ok)[0].error is None


def test_node_limit_is_per_stream_with_rollback() -> None:
    n = MAX_NODES // 2 + 10
    half = "[" + ",".join(["1"] * n) + "]\n"
    docs = load_all(half + "---\n" + half + "---\nsmall: 1\n")
    assert [d.error is None for d in docs] == [True, False, True]
    assert "nodes" in str(docs[1].error)
    too_many = "[" + ",".join(["1"] * MAX_NODES) + "]\n"
    assert load_all(too_many)[0].error is not None
    fits = "[" + ",".join(["1"] * (MAX_NODES - 2)) + "]\n"
    assert load_all(fits)[0].error is None


def test_billion_laughs_fails_fast() -> None:
    lines = ['a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]']
    for i, name in enumerate("bcdefghi"):
        prev = "abcdefghi"[i]
        lines.append(f"{name}: &{name} [" + ",".join([f"*{prev}"] * 9) + "]")
    text = "\n".join(lines) + "\n"
    t0 = time.perf_counter()
    (doc,) = load_all(text)
    assert time.perf_counter() - t0 < 1.0
    assert doc.error is not None and "alias" in doc.error.message


def test_alias_expansion_limit() -> None:
    text = "a: &a x\nb: [" + ",".join(["*a"] * (MAX_ALIASES + 1)) + "]\n"
    (doc,) = load_all(text)
    assert doc.error is not None and "alias expansions" in doc.error.message
    text_ok = "a: &a x\nb: [" + ",".join(["*a"] * (MAX_ALIASES - 1)) + "]\n"
    assert load_all(text_ok)[0].error is None


def test_merge_heavy_documents_are_bounded() -> None:
    body = ", ".join(f"k{i}: {i}" for i in range(500))
    text = f"base: &b {{{body}}}\n" + "".join(f"m{i}: {{<<: *b}}\n" for i in range(1000))
    (doc,) = load_all(text)
    assert doc.error is not None and "nodes" in doc.error.message


def test_traversal_of_shared_subtrees_is_bounded_by_the_node_limit() -> None:
    text = "a: &a [" + ",".join(["x"] * 1000) + "]\nb: [" + ",".join(["*a"] * 150) + "]\n"
    (doc,) = load_all(text)
    assert doc.error is None and doc.root is not None
    assert sum(1 for _ in doc.root.descendants()) < MAX_NODES


HUGE_INPUTS = {
    "long-plain": "a: " + "x" * 1_500_000 + "\n",
    "long-double-quoted": 'a: "' + "x" * 1_500_000 + '"\n',
    "long-literal": "a: |\n" + ("  " + "y" * 100 + "\n") * 10_000,
    "long-root-scalar": "k" * 1_000_000 + "\n",
    "space-run-no-colon": "a" + " " * 500_000 + "b\n",
    "many-words": "- " + "a " * 400_000 + "\n",
    "colon-runs": "x: " + "a:" * 400_000 + "\n",
    "hash-run": "a: " + "#" * 500_000 + "\n",
    "deep-indent": " " * 1_000_000 + "a: 1\n",
    "many-markers": "---\n" * 50_000,
    "wide-flow-seq": "[" + "a, " * 200_000 + "]\n",
    "wide-flow-map-duplicates": "{" + "'k': 'v', " * 100_000 + "}\n",
    "template-run": "- " + "{{ x }}" * 100_000 + "\n",
}


@pytest.mark.parametrize("name", sorted(HUGE_INPUTS))
def test_huge_inputs_parse_in_linear_time(name: str) -> None:
    text = HUGE_INPUTS[name]
    t0 = time.perf_counter()
    for helm in (False, True):
        load_all(text, lenient_helm=helm)
    assert time.perf_counter() - t0 < 10.0


# --------------------------------------------------------------------------- adversarial input


@given(st.binary(max_size=300))
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_arbitrary_input_only_ever_raises_yaml_error(data: bytes) -> None:
    text = data.decode("latin-1")
    for schema in ("yaml11", "yaml12"):
        for helm in (False, True):
            for doc in load_all(text, schema, helm):
                if doc.error is None:
                    assert doc.root is not None
                    to_python(doc)
                    for n in doc.root.descendants():
                        _ = (n.line, n.col, n.end_line, n.end_col)
                else:
                    assert isinstance(doc.error, YamlError) and doc.error.line >= 1


YAMLISH = st.text(alphabet=list("ab-:?#&*!|>'\"[]{},%@` \t\n\r\\0x.~\ufeff\u2028é"), max_size=80)


@given(YAMLISH)
@settings(max_examples=500)
def test_yamlish_noise_only_ever_raises_yaml_error(text: str) -> None:
    for helm in (False, True):
        for doc in load_all(text, lenient_helm=helm):
            if doc.error is None:
                assert doc.root is not None
                to_python(doc)
                assert 0 <= doc.root.start <= doc.root.end <= len(text)


def test_control_characters_and_nul_are_ordinary_content() -> None:
    assert one("a: b\x00c\nd: e\x1bf\x7f\n") == {"a": "b\x00c", "d": "e\x1bf\x7f"}


def test_many_documents() -> None:
    text = "".join(f"---\nk: {i}\n" for i in range(5000))
    docs = load_all(text)
    assert len(docs) == 5000 and to_python(docs[-1]) == {"k": 4999}


# --------------------------------------------------------------------------- Helm lenient mode

HELM_DEPLOYMENT = """\
{{- $fullName := include "chart.fullname" . -}}
{{/* Deployment for the chart */}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "chart.fullname" . }}
  labels:
    {{- include "chart.labels" . | nindent 4 }}
spec:
  {{- if not .Values.autoscaling.enabled }}
  replicas: {{ .Values.replicaCount }}
  {{- end }}
  template:
    metadata:
      {{- with .Values.podAnnotations }}
      annotations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      labels:
        app: {{ $fullName }}
        {{- toYaml .Values.extraLabels | nindent 8 }}
    spec:
      containers:
        - name: {{ .Chart.Name }}
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
          args: [{{ .Values.arg1 }}, --flag]
          securityContext:
            {{- toYaml .Values.securityContext | nindent 12 }}
          env:
            {{- toYaml .Values.env | nindent 12 }}
            - name: STATIC
              value: "1"
          command:
            - sh
            - -c
            - |
              echo start
              {{- if .Values.debug }}
              set -x
              {{- end }}
              exec app
"""


def test_helm_template_parses_in_lenient_mode() -> None:
    v = one(HELM_DEPLOYMENT, "yaml11", helm=True)
    assert v["metadata"]["name"] == '{{ include "chart.fullname" . }}'
    assert v["metadata"]["labels"] is None
    assert v["spec"]["replicas"] == "{{ .Values.replicaCount }}"
    tmpl = v["spec"]["template"]
    assert tmpl["metadata"]["annotations"] == "{{- toYaml . | nindent 8 }}"
    assert tmpl["metadata"]["labels"] == {"app": "{{ $fullName }}"}
    (container,) = tmpl["spec"]["containers"]
    assert container["name"] == "{{ .Chart.Name }}"
    assert container["image"].startswith("{{ .Values.image.repository }}:")
    assert container["args"] == ["{{ .Values.arg1 }}", "--flag"]
    assert container["securityContext"] == "{{- toYaml .Values.securityContext | nindent 12 }}"
    assert container["env"] == [{"name": "STATIC", "value": "1"}]
    assert container["command"][2] == "echo start\nset -x\nexec app\n"  # control lines are invisible


def test_helm_template_fails_without_lenient_mode() -> None:
    (doc,) = load_all(HELM_DEPLOYMENT)
    assert doc.error is not None


def test_helm_positions_refer_to_the_original_text() -> None:
    node = root(HELM_DEPLOYMENT, helm=True)
    assert isinstance(node, MapNode)
    meta = node.get("metadata")
    assert isinstance(meta, MapNode)
    name = meta.get("name")
    assert name is not None and name.source == '{{ include "chart.fullname" . }}'
    assert name.line == 6
    spec = node.get("spec")
    assert isinstance(spec, MapNode)
    # the blanked control line is not part of the mapping, but spans keep the original text
    assert spec.source.startswith("replicas:") and "{{- end }}" in spec.source


@pytest.mark.parametrize(
    "line",
    [
        "{{- if .Values.x }}",
        "{{ else }}",
        "{{- else if .x -}}",
        "  {{- end }}",
        "{{ range $k, $v := .Values.env }}",
        "{{- with .Values.x }}",
        '{{ define "x" }}',
        '{{ template "x" . }}',
        '{{- include "x" . | nindent 4 }}',
        "{{/* comment */}}",
        "{{- /* comment */ -}}",
        "{{- $x := 1 }}",
        '{{ $_ = set . "a" 1 }}',
    ],
)
def test_helm_control_lines_are_blanked(line: str) -> None:
    assert one(f"a: 1\n{line}\nb: 2\n", helm=True) == {"a": 1, "b": 2}


def test_helm_inline_templates_are_strings() -> None:
    text = (
        "a: {{ .Values.a }}\n"
        'b: {{ .Values.b | default "x: y" }}-suffix # comment\n'
        "{{ .Values.key }}: {{ .Values.value }}\n"
        "c: [{{ .Values.c }}, {{ x }} y]\n"
        "d: {{ unclosed\n"
        "e: plain {{ t }} text\n"
    )
    assert one(text, helm=True) == {
        "a": "{{ .Values.a }}",
        "b": '{{ .Values.b | default "x: y" }}-suffix',
        "{{ .Values.key }}": "{{ .Values.value }}",
        "c": ["{{ .Values.c }}", "{{ x }} y"],
        "d": "{{ unclosed",
        "e": "plain {{ t }} text",
    }


def test_helm_standalone_template_lines() -> None:
    assert one("a:\n  x: 1\n  {{ toYaml .Values.more | nindent 2 }}\n  y: 2\n", helm=True) == {
        "a": {"x": 1, "y": 2}
    }
    assert one("a:\n  {{ toYaml .Values.a }}\nb: 1\n", helm=True) == {"a": "{{ toYaml .Values.a }}", "b": 1}
    assert one("l:\n  - a\n  {{ toYaml .x }}\n  - b\n", helm=True) == {"l": ["a", "b"]}
    assert one("{{ toYaml .Values.extra }}\n", helm=True) == "{{ toYaml .Values.extra }}"
    assert one("{{ toYaml .x }}\nk: v\n", helm=True) == {"k": "v"}


def test_helm_mode_on_crlf_and_multi_document_templates() -> None:
    text = "{{- if .x }}\r\na: 1\r\n{{- end }}\r\n---\r\n{{- range .Values.items }}\r\nb: 2\r\n{{- end }}\r\n"
    assert py(text, helm=True) == [{"a": 1}, {"b": 2}]


# --------------------------------------------------------------------------- misc integration


def test_rule_pack_documents_convert_like_the_rules_loader_expects() -> None:
    text = """\
- id: WS-GHA-001
  title: pull_request_target checks out PR head code
  severity: critical
  cwe: [CWE-94]
  applies_to: { kind: ci, glob: [".github/workflows/*.y*ml"] }
  match:
    yaml_path:
      all:
        - path: "on.pull_request_target"          # handles the scalar and the mapping form
          exists: true
        - path: "jobs.*.steps[*].with.ref"
          regex: "github\\\\.event\\\\.pull_request\\\\.head\\\\.(sha|ref)"
        - { path: "args[*]", regex: '^(?:@[a-z0-9][\\w.-]*/)?[a-z0-9][\\w.-]*$' }
  message: >
    Workflow runs with a write token,
    but checks out fork code.
"""
    (doc,) = load_all(text)
    (rule,) = doc.to_python()
    assert rule["applies_to"] == {"kind": "ci", "glob": [".github/workflows/*.y*ml"]}
    conds = rule["match"]["yaml_path"]["all"]
    assert conds[0] == {"path": "on.pull_request_target", "exists": True}
    assert conds[1]["regex"] == "github\\.event\\.pull_request\\.head\\.(sha|ref)"
    assert conds[2]["regex"] == "^(?:@[a-z0-9][\\w.-]*/)?[a-z0-9][\\w.-]*$"
    assert rule["message"] == "Workflow runs with a write token, but checks out fork code.\n"


def test_documents_expose_to_python_for_the_rules_loader() -> None:
    from whalescan.rules import loader

    assert loader.default_yaml_loader("- a: 1\n- b: [x, y]\n---\n") == [[{"a": 1}, {"b": ["x", "y"]}], None]


def test_json_documents_parse_through_the_same_code() -> None:
    text = (
        '{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@scope/pkg@1.2.3"], "env": {}, "n": null}}}'
    )
    node = root(text)
    assert isinstance(node, MapNode)
    fs = node.get("mcpServers")
    assert isinstance(fs, MapNode)
    server = fs.get("fs")
    assert isinstance(server, MapNode)
    cmd = server.get("command")
    assert isinstance(cmd, ScalarNode) and cmd.style == "double" and cmd.source == '"npx"'
    assert to_python(node) == {
        "mcpServers": {"fs": {"command": "npx", "args": ["-y", "@scope/pkg@1.2.3"], "env": {}, "n": None}}
    }


def test_documents_are_independent_of_the_gc_pause() -> None:
    import gc

    was = gc.isenabled()
    big = "".join(f"k{i}: v{i}\n" for i in range(5000))
    assert len(big) > Y._GC_PAUSE_CHARS
    load_all(big)
    assert gc.isenabled() == was
    gc.disable()
    try:
        load_all(big)
        assert not gc.isenabled()
    finally:
        if was:
            gc.enable()


def test_document_class_is_exported() -> None:
    assert Document.__name__ == "Document" and "load_all" in Y.__all__
