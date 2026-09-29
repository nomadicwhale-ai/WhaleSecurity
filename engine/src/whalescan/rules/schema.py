# ruff: noqa: E501
"""Rule JSON Schema (spec §7.2) and a stdlib validator for exactly the keywords it uses.

`RULE_SCHEMA` is a verbatim copy of the §7.2 schema (draft 2020-12) as a Python dict; a unit test keeps it in
sync with the spec. `validate_rule` checks one rule object against it with a small validator that implements the
keywords the schema uses and nothing else: `type enum const pattern minLength maxLength minimum maximum items
minItems maxItems uniqueItems properties required additionalProperties minProperties maxProperties propertyNames
unevaluatedProperties allOf anyOf oneOf $ref` (plus the annotations `$schema $id title default`).

Deliberate differences from the reference `jsonschema` package, all of them stricter:

* `pattern` uses ECMA-262 semantics for a trailing `$` (end of input), so `"WS-INJ-001\n"` is rejected where
  Python's `re.search(..., "$")` would accept it.
* Instances must be JSON-shaped: dict keys are strings, values are dict/list/str/int/float/bool/None, floats are
  finite. Nesting deeper than `MAX_DEPTH` or larger than `MAX_NODES` is rejected before validation, which bounds
  recursion on attacker-supplied rule files (including self-referencing YAML aliases).
"""

from __future__ import annotations

import functools
import math
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Final

SCHEMA_VERSION: Final = 1
SCHEMA_ID: Final = "urn:whalescan:schema:rule:1"

# fmt: off
RULE_SCHEMA: Final[dict[str, Any]] = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:whalescan:schema:rule:1",
  "title": "whalescan rule (one item of a pack file's top-level sequence)",
  "type": "object", "additionalProperties": False,
  "required": ["id", "title", "pack", "severity", "confidence", "owner", "applies_to", "match", "message", "references"],
  "properties": {
    "id": {"type": "string", "pattern": "^WS-(INJ|ACC|CRY|SSRF|DES|WEB|SEC|AGT|GHA|K8S|TF|DKR|AIR|SPK|API|LLM|TRD)(-[A-Z0-9]{2,10})?-[0-9]{3}$"},
    "title": {"type": "string", "minLength": 8, "maxLength": 120},
    "pack": {"type": "string", "pattern": "^(appsec|secrets|agentsec|domain)/[a-z0-9][a-z0-9-]{0,40}$"},
    "severity": {"$ref": "#/$defs/severity"},
    "confidence": {"$ref": "#/$defs/confidence"},
    "cwe": {"type": "array", "uniqueItems": True, "items": {"type": "string", "pattern": "^CWE-[1-9][0-9]{0,4}$"}},
    "owasp": {"type": "array", "uniqueItems": True, "items": {"type": "string",
      "pattern": "^(A(0[1-9]|10)(:20(17|21|25))?|API([1-9]|10)(:2023)?|LLM(0[1-9]|10)(:2025)?|CICD-SEC-([1-9]|10)|K(0[1-9]|10))$"}},
    "atlas": {"type": "array", "uniqueItems": True, "items": {"type": "string", "pattern": "^AML\\.T[0-9]{4}(\\.[0-9]{3})?$"}},
    "tags": {"type": "array", "uniqueItems": True, "items": {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,31}$"}},
    "owner": {"type": "string", "pattern": "^@[A-Za-z0-9][A-Za-z0-9-]{0,38}(/[A-Za-z0-9._-]{1,64})?$"},
    "since": {"type": "string", "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$"},
    "deprecated": {"type": "boolean", "default": False},
    "replaced_by": {"$ref": "#/$defs/rule_ref"},
    "enabled_by_default": {"type": "boolean", "default": True},
    "applies_to": {"$ref": "#/$defs/applies_to"},
    "keywords": {"type": "array", "maxItems": 32, "items": {"type": "string", "minLength": 2, "maxLength": 64}},
    "keywords_case": {"enum": ["insensitive", "sensitive"], "default": "insensitive"},
    "match": {"$ref": "#/$defs/expr"},
    "filters": {"type": "object", "additionalProperties": False, "properties": {
      "file_regex": {"$ref": "#/$defs/pattern"}, "file_not_regex": {"$ref": "#/$defs/pattern"},
      "line_not_regex": {"$ref": "#/$defs/pattern"}, "path_not_glob": {"$ref": "#/$defs/strs"}}},
    "redact": {"type": "boolean", "default": False},
    "exposure_sensitive": {"type": "boolean", "default": True},
    "supersedes": {"type": "array", "uniqueItems": True, "items": {"$ref": "#/$defs/rule_ref"}},
    "max_hits_per_file": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 50},
    "message": {"type": "string", "minLength": 10, "maxLength": 600},
    "fix": {"type": "string", "maxLength": 1200},
    "references": {"type": "array", "minItems": 1, "items": {"type": "string", "pattern": "^https://\\S+$"}},
    "fixtures": {"default": "auto", "oneOf": [{"const": "auto"}, {"type": "object", "additionalProperties": False,
      "required": ["pos", "neg"], "properties": {"pos": {"$ref": "#/$defs/strs1"}, "neg": {"$ref": "#/$defs/strs1"}}}]}
  },
  "$defs": {
    "severity": {"enum": ["critical", "high", "medium", "low", "info"]},
    "confidence": {"enum": ["high", "medium", "low"]},
    "kind": {"enum": ["code", "iac", "ci", "agent-config", "doc", "data"]},
    "rule_ref": {"type": "string", "pattern": "^WS-[A-Z0-9-]+$"},
    "scalar": {"type": ["string", "number", "boolean", "null"]},
    "strs": {"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 256}},
    "strs1": {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1, "maxLength": 256}},
    "one_or_many": {"oneOf": [{"type": "string", "minLength": 1}, {"$ref": "#/$defs/strs1"}]},
    "pattern": {"type": "string", "minLength": 1, "maxLength": 4096},
    "group": {"type": "string", "pattern": "^[A-Za-z_][A-Za-z0-9_]*$"},
    "applies_to": {"type": "object", "additionalProperties": False, "minProperties": 1, "properties": {
      "kind": {"oneOf": [{"$ref": "#/$defs/kind"}, {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/kind"}}]},
      "lang": {"$ref": "#/$defs/one_or_many"}, "glob": {"$ref": "#/$defs/strs"}, "exclude_glob": {"$ref": "#/$defs/strs"},
      "tags_any": {"$ref": "#/$defs/strs"}, "tags_none": {"$ref": "#/$defs/strs"},
      "include_minified": {"type": "boolean", "default": False}, "max_bytes": {"type": "integer", "minimum": 1}}},
    "expr": {"oneOf": [
      {"type": "object", "additionalProperties": False, "required": ["all"], "properties": {
        "all": {"type": "array", "minItems": 2, "items": {"$ref": "#/$defs/expr"}},
        "near_lines": {"type": "integer", "minimum": 0, "maximum": 500}}},
      {"type": "object", "additionalProperties": False, "required": ["any"], "properties": {
        "any": {"type": "array", "minItems": 2, "items": {"$ref": "#/$defs/expr"}}}},
      {"type": "object", "additionalProperties": False, "required": ["not"], "properties": {"not": {"$ref": "#/$defs/expr"}}},
      {"type": "object", "additionalProperties": False, "minProperties": 1, "maxProperties": 1, "properties": {
        "regex": {"$ref": "#/$defs/regex"}, "multiline": {"$ref": "#/$defs/multiline"}, "unicode": {"$ref": "#/$defs/unicode"},
        "entropy": {"$ref": "#/$defs/entropy"}, "yaml_path": {"$ref": "#/$defs/yaml_path"}, "py_ast": {"$ref": "#/$defs/py_ast"},
        "hcl": {"$ref": "#/$defs/hcl"}, "builtin": {"enum": ["mcp_drift"]}}}]},
    "regex": {"oneOf": [{"$ref": "#/$defs/pattern"}, {"type": "object", "additionalProperties": False, "required": ["pattern"],
      "properties": {"pattern": {"$ref": "#/$defs/pattern"},
        "flags": {"type": "array", "uniqueItems": True, "items": {"enum": ["i", "x", "a"]}},
        "report_group": {"oneOf": [{"type": "integer", "minimum": 0}, {"$ref": "#/$defs/group"}], "default": 0},
        "secret_group": {"$ref": "#/$defs/group"}}}]},
    "multiline": {"oneOf": [
      {"type": "object", "additionalProperties": False, "required": ["pattern"], "properties": {
        "pattern": {"$ref": "#/$defs/pattern"},
        "flags": {"type": "array", "uniqueItems": True, "items": {"enum": ["i", "x", "a", "s"]}},
        "max_span_lines": {"type": "integer", "minimum": 1, "maximum": 200, "default": 30},
        "secret_group": {"$ref": "#/$defs/group"}}},
      {"type": "object", "additionalProperties": False, "required": ["sequence", "within_lines"], "properties": {
        "sequence": {"type": "array", "minItems": 2, "maxItems": 5, "items": {"$ref": "#/$defs/pattern"}},
        "within_lines": {"type": "integer", "minimum": 1, "maximum": 200},
        "flags": {"type": "array", "uniqueItems": True, "items": {"enum": ["i", "x", "a"]}}}}]},
    "unicode": {"type": "object", "additionalProperties": False, "required": ["classes"], "properties": {
      "classes": {"type": "array", "minItems": 1, "uniqueItems": True,
        "items": {"enum": ["ZW", "BIDI", "TAG", "VS", "PUA", "CTRL", "HOMOGLYPH"]}},
      "min_run": {"type": "integer", "minimum": 1, "maximum": 64, "default": 1},
      "bidi_unbalanced_only": {"type": "boolean", "default": False},
      "allow_emoji_sequences": {"type": "boolean", "default": True}}},
    "entropy": {"type": "object", "additionalProperties": False, "required": ["charset"], "properties": {
      "charset": {"enum": ["hex", "base64", "base64url", "alnum"]},
      "min_len": {"type": "integer", "minimum": 12, "maximum": 256, "default": 20},
      "max_len": {"type": "integer", "minimum": 16, "maximum": 1024, "default": 200},
      "threshold": {"type": "number", "minimum": 1.0, "maximum": 6.0},
      "scope": {"enum": ["values", "anywhere"], "default": "values"},
      "min_classes": {"type": "integer", "minimum": 1, "maximum": 3, "default": 2},
      "context": {"type": "object", "additionalProperties": False, "properties": {
        "keywords": {"$ref": "#/$defs/strs"}, "required": {"type": "boolean", "default": False},
        "window_chars": {"type": "integer", "minimum": 8, "maximum": 400, "default": 80}}},
      "exclude_regex": {"type": "array", "items": {"$ref": "#/$defs/pattern"}}}},
    "predicates": {"type": "object", "properties": {
      "exists": {"type": "boolean"}, "equals": {"$ref": "#/$defs/scalar"}, "not_equals": {"$ref": "#/$defs/scalar"},
      "in": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/scalar"}},
      "not_in": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/scalar"}},
      "regex": {"$ref": "#/$defs/pattern"}, "not_regex": {"$ref": "#/$defs/pattern"},
      "type": {"enum": ["str", "int", "float", "bool", "null", "map", "seq"]},
      "contains": {"type": ["string", "number", "boolean"]},
      "quantifier": {"enum": ["any", "all"], "default": "any"}}},
    "yaml_cond": {"allOf": [{"$ref": "#/$defs/predicates"}, {"type": "object", "required": ["path"], "minProperties": 2,
      "properties": {"path": {"type": "string", "minLength": 1, "maxLength": 512}, "promote": {"type": "boolean", "default": True}}}],
      "unevaluatedProperties": False},
    "yaml_conds": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/yaml_cond"}},
    "yaml_path": {"type": "object", "additionalProperties": False,
      "anyOf": [{"required": ["all"]}, {"required": ["any"]}, {"required": ["none"]}],
      "properties": {"each": {"type": "string", "minLength": 1, "maxLength": 512},
        "schema": {"enum": ["auto", "yaml11", "yaml12"], "default": "auto"},
        "all": {"$ref": "#/$defs/yaml_conds"}, "any": {"$ref": "#/$defs/yaml_conds"}, "none": {"$ref": "#/$defs/yaml_conds"}}},
    "arg_cond": {"type": "object", "additionalProperties": False, "minProperties": 1, "properties": {
      "tainted": {"type": "boolean"}, "dynamic_string": {"type": "boolean"}, "constant": {"type": "boolean"},
      "equals": {"$ref": "#/$defs/scalar"}, "not_equals": {"$ref": "#/$defs/scalar"}, "regex": {"$ref": "#/$defs/pattern"}}},
    "py_ast": {"oneOf": [
      {"type": "object", "additionalProperties": False, "required": ["call"], "properties": {"call": {
        "type": "object", "additionalProperties": False, "required": ["callee"], "properties": {
          "callee": {"$ref": "#/$defs/one_or_many"},
          "args": {"type": "object", "propertyNames": {"pattern": "^([0-9]{1,2}|\\*)$"}, "additionalProperties": {"$ref": "#/$defs/arg_cond"}},
          "kwargs": {"type": "object", "propertyNames": {"$ref": "#/$defs/group"}, "additionalProperties": {"$ref": "#/$defs/arg_cond"}},
          "kwarg_absent": {"$ref": "#/$defs/strs"}, "sources": {"$ref": "#/$defs/strs"},
          "sanitizers": {"$ref": "#/$defs/strs"}, "require_import": {"$ref": "#/$defs/one_or_many"}}}}},
      {"type": "object", "additionalProperties": False, "required": ["fastapi_route"], "properties": {"fastapi_route": {
        "type": "object", "additionalProperties": False, "properties": {
          "methods": {"type": "array", "items": {"enum": ["get", "post", "put", "patch", "delete", "api_route", "websocket"]}},
          "auth_regex": {"$ref": "#/$defs/pattern"}, "ignore_paths_regex": {"$ref": "#/$defs/pattern"}}}}}]},
    "hcl_cond": {"allOf": [{"$ref": "#/$defs/predicates"}, {"type": "object",
      "anyOf": [{"required": ["attr"]}, {"required": ["range_includes"]}],
      "properties": {"attr": {"type": "string", "minLength": 1, "maxLength": 256},
        "range_includes": {"type": "object", "additionalProperties": False, "required": ["lo", "hi", "any"], "properties": {
          "lo": {"type": "string"}, "hi": {"type": "string"},
          "any": {"type": "array", "minItems": 1, "items": {"type": "integer", "minimum": 0, "maximum": 65535}}}}}}],
      "unevaluatedProperties": False},
    "hcl_conds": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/hcl_cond"}},
    "hcl": {"type": "object", "additionalProperties": False, "required": ["block"], "properties": {
      "block": {"type": "string", "minLength": 1, "maxLength": 256}, "each": {"type": "string", "minLength": 1, "maxLength": 256},
      "all": {"$ref": "#/$defs/hcl_conds"}, "any": {"$ref": "#/$defs/hcl_conds"}, "none": {"$ref": "#/$defs/hcl_conds"},
      "on_unknown": {"enum": ["nomatch", "match"], "default": "nomatch"}}}
  }
}
# fmt: on

#: Keywords the validator implements (assertions and applicators) and annotation-only keywords it ignores.
IMPLEMENTED_KEYWORDS: Final = frozenset({
    "type", "enum", "const", "pattern", "minLength", "maxLength", "minimum", "maximum", "items", "minItems",
    "maxItems", "uniqueItems", "properties", "required", "additionalProperties", "minProperties",
    "maxProperties", "propertyNames", "unevaluatedProperties", "allOf", "anyOf", "oneOf", "$ref",
})
ANNOTATION_KEYWORDS: Final = frozenset({"$schema", "$id", "$defs", "title", "default", "description"})

MAX_DEPTH: Final = 32          # container nesting of one rule object
MAX_NODES: Final = 50_000      # values in one rule object

_Path = tuple[str | int, ...]


@dataclass(frozen=True, slots=True)
class SchemaIssue:
    """One schema violation. `path` is a dotted location inside the rule, e.g. `match.all[1].regex.pattern`."""

    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path or '(rule)'}: {self.message}"


def format_path(path: Iterable[str | int]) -> str:
    out: list[str] = []
    for seg in path:
        if isinstance(seg, int):
            out.append(f"[{seg}]")
        elif _IDENT.fullmatch(seg):
            out.append(f".{seg}" if out else seg)
        else:
            out.append(f"[{_show(seg)}]")
    return "".join(out)


_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$-]*")


def _show(value: Any, limit: int = 60) -> str:
    """Short JSON-ish rendering of a value for messages."""
    if isinstance(value, str):
        text = '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    elif value is None:
        text = "null"
    elif isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, (int, float)):
        text = repr(value)
    elif isinstance(value, dict):
        text = "{...}" if value else "{}"
    elif isinstance(value, list):
        text = "[...]" if value else "[]"
    else:
        text = f"<{type(value).__name__}>"
    text = text.encode("unicode_escape").decode("ascii") if not text.isprintable() else text
    return text if len(text) <= limit else text[: limit - 1] + "…"


def json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "integer" if value.is_integer() else "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_type(value: Any, name: str) -> bool:
    if name == "string":
        return isinstance(value, str)
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    if name == "number":
        return _is_number(value)
    if name == "integer":
        if isinstance(value, bool):
            return False
        return isinstance(value, int) or (isinstance(value, float) and value.is_integer())
    raise ValueError(f"unsupported schema type {name!r}")


def json_equal(a: Any, b: Any) -> bool:
    """Equality in the JSON data model: booleans never equal numbers, 1 == 1.0."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a is b
    if _is_number(a) and _is_number(b):
        return bool(a == b)
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(json_equal(x, y) for x, y in zip(a, b, strict=True))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(json_equal(a[k], b[k]) for k in a)
    return False


def _freeze(value: Any) -> Any:
    """Hashable key with `json_equal` semantics (depth is bounded by `precheck`)."""
    if isinstance(value, bool):
        return ("b", value)
    if _is_number(value):
        return ("n", value)            # hash(1) == hash(1.0) and 1 == 1.0
    if isinstance(value, str):
        return ("s", value)
    if value is None:
        return ("z",)
    if isinstance(value, list):
        return ("l", tuple(_freeze(v) for v in value))
    if isinstance(value, dict):
        return ("d", frozenset((k, _freeze(v)) for k, v in value.items()))
    return ("?", id(value))


_ECMA_CACHE: dict[str, re.Pattern[str]] = {}


def _schema_regex(pattern: str) -> re.Pattern[str]:
    """Compile a schema `pattern` with ECMA-262 end-of-input semantics for a trailing `$`."""
    rx = _ECMA_CACHE.get(pattern)
    if rx is None:
        src = pattern
        if src.endswith("$") and not src.endswith("\\$"):
            src = src[:-1] + r"\Z"
        rx = re.compile(src)
        _ECMA_CACHE[pattern] = rx
    return rx


def precheck(instance: Any, *, max_depth: int = MAX_DEPTH, max_nodes: int = MAX_NODES) -> SchemaIssue | None:
    """Reject non-JSON values and oversized/over-deep structures before any recursive processing.

    Iterative, so it is safe on arbitrarily deep or self-referencing input.
    """
    stack: list[tuple[Any, _Path]] = [(instance, ())]
    nodes = 0
    while stack:
        value, path = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            return SchemaIssue(format_path(path), f"rule is too large (more than {max_nodes} values)")
        if len(path) > max_depth:
            return SchemaIssue(format_path(path[:max_depth]), f"nesting deeper than {max_depth} levels")
        if isinstance(value, dict):
            for k, v in value.items():
                if not isinstance(k, str):
                    return SchemaIssue(format_path(path), f"mapping key {_show(k)} is not a string")
                stack.append((v, (*path, k)))
        elif isinstance(value, list):
            for i, v in enumerate(value):
                stack.append((v, (*path, i)))
        elif isinstance(value, float):
            if not math.isfinite(value):
                return SchemaIssue(format_path(path), "non-finite number")
        elif value is not None and not isinstance(value, (str, int, bool)):
            return SchemaIssue(format_path(path), f"unsupported value type {type(value).__name__}")
    return None


class Validator:
    """Validates JSON-shaped instances against a draft 2020-12 schema restricted to `IMPLEMENTED_KEYWORDS`."""

    def __init__(self, schema: Mapping[str, Any] | None = None) -> None:
        self._root: Mapping[str, Any] = RULE_SCHEMA if schema is None else schema
        unknown = sorted(set(iter_keywords(self._root)) - IMPLEMENTED_KEYWORDS - ANNOTATION_KEYWORDS)
        if unknown:
            raise ValueError(f"schema uses unsupported keywords: {', '.join(unknown)}")
        self._refs: dict[str, Any] = {}

    # -- public -------------------------------------------------------------------------------------------

    def iter_errors(self, instance: Any) -> list[SchemaIssue]:
        pre = precheck(instance)
        if pre is not None:
            return [pre]
        errors, _ = self._check(self._root, instance, ())
        return errors

    def is_valid(self, instance: Any) -> bool:
        return not self.iter_errors(instance)

    # -- core ---------------------------------------------------------------------------------------------

    def _resolve(self, ref: str) -> Any:
        hit = self._refs.get(ref)
        if hit is not None:
            return hit
        if not ref.startswith("#"):
            raise ValueError(f"only local $ref is supported: {ref!r}")
        node: Any = self._root
        for raw in ref[1:].split("/")[1:]:
            key = raw.replace("~1", "/").replace("~0", "~")
            node = node[int(key)] if isinstance(node, list) else node[key]
        self._refs[ref] = node
        return node

    def _check(self, schema: Any, x: Any, path: _Path) -> tuple[list[SchemaIssue], set[str]]:
        """Return (errors, evaluated property names). Validity is exactly `not errors`."""
        if schema is True:
            return [], set()
        if schema is False:
            return [SchemaIssue(format_path(path), "no value is allowed here")], set()
        errs: list[SchemaIssue] = []
        evaluated: set[str] = set()
        ref = schema.get("$ref")
        if ref is not None:
            e, ev = self._check(self._resolve(ref), x, path)
            errs += e
            evaluated |= ev

        t = schema.get("type")
        if t is not None:
            names = [t] if isinstance(t, str) else list(t)
            if not any(_is_type(x, n) for n in names):
                errs.append(SchemaIssue(format_path(path), f"expected {' or '.join(names)}, got {json_type(x)}"))
                return errs, evaluated

        if "enum" in schema and not any(json_equal(x, e) for e in schema["enum"]):
            choices = ", ".join(_show(e, 30) for e in schema["enum"])
            errs.append(SchemaIssue(format_path(path), f"{_show(x)} is not one of: {choices}"))
        if "const" in schema and not json_equal(x, schema["const"]):
            errs.append(SchemaIssue(format_path(path), f"expected {_show(schema['const'])}, got {_show(x)}"))

        if isinstance(x, str):
            self._check_string(schema, x, path, errs)
        elif _is_number(x):
            lo, hi = schema.get("minimum"), schema.get("maximum")
            if lo is not None and x < lo:
                errs.append(SchemaIssue(format_path(path), f"{_show(x)} is less than the minimum {lo}"))
            if hi is not None and x > hi:
                errs.append(SchemaIssue(format_path(path), f"{_show(x)} is greater than the maximum {hi}"))
        elif isinstance(x, list):
            self._check_array(schema, x, path, errs)
        elif isinstance(x, dict):
            evaluated |= self._check_object(schema, x, path, errs)

        if "allOf" in schema:
            for sub in schema["allOf"]:
                e, ev = self._check(sub, x, path)
                errs += e
                evaluated |= ev              # failing branches only affect messages: the result fails anyway
        if "anyOf" in schema:
            results = [self._check(sub, x, path) for sub in schema["anyOf"]]
            passed = [ev for e, ev in results if not e]
            if passed:
                for ev in passed:
                    evaluated |= ev
            else:
                errs += self._explain_alternatives(schema["anyOf"], results, x, path)
        if "oneOf" in schema:
            results = [self._check(sub, x, path) for sub in schema["oneOf"]]
            passed = [ev for e, ev in results if not e]
            if len(passed) == 1:
                evaluated |= passed[0]
            elif not passed:
                errs += self._explain_alternatives(schema["oneOf"], results, x, path)
            else:
                errs.append(SchemaIssue(format_path(path), f"matches {len(passed)} alternatives; exactly one is allowed"))

        if schema.get("unevaluatedProperties") is not None and isinstance(x, dict):
            uneval = schema["unevaluatedProperties"]
            for key in x:
                if key in evaluated:
                    continue
                if uneval is False:
                    errs.append(SchemaIssue(format_path(path), f"unexpected property {_show(key)}"))
                else:
                    e, _ = self._check(uneval, x[key], (*path, key))
                    errs += e
                evaluated.add(key)
        return errs, evaluated

    def _check_string(self, schema: Mapping[str, Any], x: str, path: _Path, errs: list[SchemaIssue]) -> None:
        lo, hi = schema.get("minLength"), schema.get("maxLength")
        if lo is not None and len(x) < lo:
            errs.append(SchemaIssue(format_path(path), f"must be at least {lo} characters long (got {len(x)})"))
        if hi is not None and len(x) > hi:
            errs.append(SchemaIssue(format_path(path), f"must be at most {hi} characters long (got {len(x)})"))
        pat = schema.get("pattern")
        if pat is not None and _schema_regex(pat).search(x) is None:
            errs.append(SchemaIssue(format_path(path), f"{_show(x)} does not match {_show(pat, 90)}"))

    def _check_array(self, schema: Mapping[str, Any], x: list[Any], path: _Path, errs: list[SchemaIssue]) -> None:
        lo, hi = schema.get("minItems"), schema.get("maxItems")
        if lo is not None and len(x) < lo:
            errs.append(SchemaIssue(format_path(path), f"must have at least {lo} item(s) (got {len(x)})"))
        if hi is not None and len(x) > hi:
            errs.append(SchemaIssue(format_path(path), f"must have at most {hi} item(s) (got {len(x)})"))
        if schema.get("uniqueItems") is True:
            seen: set[Any] = set()
            for item in x:
                key = _freeze(item)
                if key in seen:
                    errs.append(SchemaIssue(format_path(path), f"items must be unique ({_show(item)} repeats)"))
                    break
                seen.add(key)
        items = schema.get("items")
        if items is not None:
            for i, item in enumerate(x):
                e, _ = self._check(items, item, (*path, i))
                errs += e

    def _check_object(
        self, schema: Mapping[str, Any], x: dict[str, Any], path: _Path, errs: list[SchemaIssue]
    ) -> set[str]:
        evaluated: set[str] = set()
        for key in schema.get("required", ()):
            if key not in x:
                errs.append(SchemaIssue(format_path(path), f"missing required property {_show(key)}"))
        lo, hi = schema.get("minProperties"), schema.get("maxProperties")
        if lo is not None and len(x) < lo:
            errs.append(SchemaIssue(format_path(path), f"must have at least {lo} propert{'y' if lo == 1 else 'ies'}"))
        if hi is not None and len(x) > hi:
            names = ", ".join(_show(k, 24) for k in x)
            errs.append(SchemaIssue(format_path(path), f"must have at most {hi} propert{'y' if hi == 1 else 'ies'}, got {names}"))
        names_schema = schema.get("propertyNames")
        if names_schema is not None:
            for key in x:
                e, _ = self._check(names_schema, key, path)
                errs += [SchemaIssue(i.path, f"property name {i.message}") for i in e]
        props: Mapping[str, Any] = schema.get("properties", {})
        for key, sub in props.items():
            if key in x:
                e, _ = self._check(sub, x[key], (*path, key))
                errs += e
                evaluated.add(key)
        if "additionalProperties" in schema:
            extra = schema["additionalProperties"]
            for key, value in x.items():
                if key in props:
                    continue
                if extra is False:
                    errs.append(SchemaIssue(format_path(path), f"unexpected property {_show(key)}"))
                else:
                    e, _ = self._check(extra, value, (*path, key))
                    errs += e
                evaluated.add(key)
        return evaluated

    # -- diagnostics for failed alternatives ---------------------------------------------------------------

    def _branch_keys(self, schema: Any, depth: int = 0) -> tuple[set[str], set[str] | None]:
        """(property names a branch talks about, types it accepts or None for any)."""
        if not isinstance(schema, dict) or depth > 8:
            return set(), None
        keys = set(schema.get("properties", {})) | set(schema.get("required", ()))
        t = schema.get("type")
        types: set[str] | None = None if t is None else ({t} if isinstance(t, str) else set(t))
        if "$ref" in schema:
            k2, t2 = self._branch_keys(self._resolve(schema["$ref"]), depth + 1)
            keys |= k2
            types = t2 if types is None else types if t2 is None else types & t2
        if "enum" in schema or "const" in schema:
            values = schema.get("enum", [schema.get("const")])
            vtypes = {json_type(v) for v in values}
            types = vtypes if types is None else types & vtypes
        for sub in schema.get("allOf", ()):
            k2, _ = self._branch_keys(sub, depth + 1)
            keys |= k2
        return keys, types

    def _explain_alternatives(
        self,
        branches: list[Any],
        results: list[tuple[list[SchemaIssue], set[str]]],
        x: Any,
        path: _Path,
    ) -> list[SchemaIssue]:
        where = format_path(path)
        if all(isinstance(b, dict) and set(b) == {"required"} for b in branches):
            wanted = ", ".join(_show(k) for b in branches for k in b["required"])
            return [SchemaIssue(where, f"requires one of the properties {wanted}")]
        xtype = json_type(x)
        scored: list[tuple[int, int, int]] = []
        for i, branch in enumerate(branches):
            keys, types = self._branch_keys(branch)
            type_ok = types is None or xtype in types or (xtype == "integer" and "number" in types)
            affinity = len(keys & set(x)) if isinstance(x, dict) else 0
            scored.append((int(type_ok), affinity, -i))
        best = max(scored)
        winners = [s for s in scored if s[:2] == best[:2]]
        if best[0] and len(winners) == 1:
            return results[-best[2]][0]
        if not best[0]:
            accepted: list[str] = []
            for b in branches:
                _, types = self._branch_keys(b)
                accepted += sorted(types or {"any"})
            return [SchemaIssue(where, f"expected {' or '.join(dict.fromkeys(accepted))}, got {xtype}")]
        options: list[str] = []
        for b in branches:
            keys, _ = self._branch_keys(b)
            options += sorted(keys)
        if options:
            listed = ", ".join(dict.fromkeys(options))
            return [SchemaIssue(where, f"does not match any allowed form (expected one of the keys: {listed})")]
        return [SchemaIssue(where, "does not match any allowed form")]


def iter_keywords(schema: Any) -> Iterator[str]:
    """Every keyword used anywhere in `schema` (property names under `properties`/`$defs` are not keywords)."""
    stack: list[Any] = [schema]
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(node)
            continue
        if not isinstance(node, dict):
            continue
        for key, value in node.items():
            yield key
            if key in ("properties", "$defs"):
                stack.extend(value.values())
            elif key in ("enum", "const", "default", "required"):
                continue
            else:
                stack.append(value)


@functools.cache
def validator() -> Validator:
    """The shared validator for `RULE_SCHEMA` (built once per process)."""
    return Validator()


def validate_rule(rule: Any) -> list[SchemaIssue]:
    """Schema issues for one rule object (empty when valid)."""
    return validator().iter_errors(rule)


def is_valid_rule(rule: Any) -> bool:
    return not validate_rule(rule)
