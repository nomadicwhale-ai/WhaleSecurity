"""File classifier: path + content → ``(lang, kind, tags)`` (spec §6) plus file flags (§5.7).

Steps, in order: ``[classify].rules`` from config (first match) → path table A → extension
table B → content sniff C over the first 64 KiB → fallback ``text``/``data``. ``lang`` and
``kind`` are each fixed by the first step that provides them (table B deliberately leaves
``kind`` open for data formats so the sniff can decide); tags accumulate from every step, plus
the ``generated``/``minified``/``test`` flags. For multi-document YAML the highest kind wins:
``ci > iac > agent-config > code > doc > data``.

Hook-path module: regexes for the sniffs compile lazily on first use.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from functools import cache, lru_cache
from typing import Any, Protocol

from . import ignore

__all__ = [
    "KIND_RANK",
    "SNIFF_CHARS",
    "ClassifyRuleLike",
    "classify",
    "file_flags",
    "is_generated",
    "is_minified",
    "is_test_path",
]

SNIFF_CHARS = 64 * 1024
KIND_RANK: Mapping[str, int] = {"data": 0, "doc": 1, "code": 2, "agent-config": 3, "iac": 4, "ci": 5}
_MAX_YAML_DOCS = 256

Probe = Callable[[str], bool]


class ClassifyRuleLike(Protocol):
    @property
    def glob(self) -> str: ...
    @property
    def kind(self) -> str | None: ...
    @property
    def lang(self) -> str | None: ...
    @property
    def tags(self) -> Sequence[str]: ...


class _Result:
    __slots__ = ("kind", "lang", "tags")

    def __init__(self) -> None:
        self.lang: str | None = None
        self.kind: str | None = None
        self.tags: set[str] = set()

    def offer(self, lang: str | None, kind: str | None, tags: Iterable[str] = ()) -> None:
        if self.lang is None and lang is not None:
            self.lang = lang
        if self.kind is None and kind is not None:
            self.kind = kind
        self.tags.update(tags)


# =========================================================================== file flags (§5.7)

_GENERATED = re.compile(r"(?i)@generated\b|\bDO NOT EDIT\b|\bauto-?generated\b")
_TEST_PATH = re.compile(
    r"(?:^|/)(?:tests?|__tests__|spec|specs|fixtures?|testdata)/"
    r"|(?:^|/)(?:test_[^/]*\.py|[^/]*_test\.(?:py|go)|conftest\.py|[^/]*\.(?:spec|test)\.[jt]sx?)$"
)
_MIN_NAME = re.compile(r"\.min\.(?:js|css)$")


def _first_lines(text: str, n: int, cap: int = SNIFF_CHARS) -> str:
    end = -1
    for _ in range(n):
        end = text.find("\n", end + 1, cap)
        if end == -1:
            return text[:cap]
    return text[:end]


def is_generated(text: str) -> bool:
    """The first 5 lines carry a generated-code marker."""
    return _GENERATED.search(_first_lines(text, 5)) is not None


def is_minified(path: str, text: str, size: int | None = None) -> bool:
    """``size > 20 KiB`` and mean line length > 1000, or a ``.min.js``/``.min.css`` name.

    The mean is computed over the first 64 KiB of ``text`` (exact for smaller files).
    """
    if _MIN_NAME.search(path):
        return True
    nbytes = size if size is not None else len(text)
    if nbytes <= 20 * 1024:
        return False
    head = text[:SNIFF_CHARS]
    lines = head.count("\n") + (0 if head.endswith("\n") else 1)
    return len(head) / max(lines, 1) > 1000


def is_test_path(path: str) -> bool:
    return _TEST_PATH.search(path) is not None


def file_flags(path: str, text: str, size: int | None = None) -> frozenset[str]:
    flags: set[str] = set()
    if text and is_generated(text):
        flags.add("generated")
    if is_minified(path, text, size):
        flags.add("minified")
    if is_test_path(path):
        flags.add("test")
    return frozenset(flags)


# =========================================================================== table A (paths)

_Y = r"\.ya?ml"
_A_ROWS: tuple[tuple[str, str | None, str, tuple[str, ...]], ...] = (
    (rf"(?:^|/)\.github/workflows/[^/]+{_Y}$", "yaml", "ci", ("gha",)),
    (rf"(?:^|/)action{_Y}$", "yaml", "ci", ("gha-action",)),
    (rf"(?:^|/)\.tekton/(?:.+/)?[^/]+{_Y}$", "yaml", "ci", ("tekton",)),
    (r"(?:^|/)(?:\.gitlab-ci\.yml|\.circleci/config\.yml|azure-pipelines\.yml|bitbucket-pipelines\.yml)$",
     "yaml", "ci", ("ci-other",)),
    (r"(?:^|/)Jenkinsfile$", "groovy", "ci", ("ci-other",)),
    (r"(?:^|/)(?:CLAUDE\.md|CLAUDE\.local\.md|AGENTS\.md|SKILL\.md|\.cursorrules|\.windsurfrules|\.clinerules)$"
     r"|(?:^|/)\.claude/(?:commands|agents)/(?:.+/)?[^/]+\.md$|(?:^|/)\.cursor/rules/.+$"
     r"|(?:^|/)\.clinerules/.+$",
     "markdown", "agent-config", ("agent-instructions",)),
    (r"(?:^|/)\.?mcp\.json$", "json", "agent-config", ("mcp",)),
    (r"(?:^|/)\.claude/settings[^/]*\.json$|(?:^|/)\.claude-plugin/[^/]+\.json$|(?:^|/)hooks/hooks\.json$",
     "json", "agent-config", ("agent-settings",)),
    (r"(?i)(?:^|/)(?:dockerfile(?:\.[^/]+)?|[^/]+\.dockerfile|containerfile)$",
     "dockerfile", "iac", ("docker",)),
    (rf"(?:^|/)(?:docker-compose|compose)[^/]*{_Y}$", "yaml", "iac", ("compose",)),
    ("HELM", None, "iac", ()),  # handled in code: needs a sibling Chart.yaml
    (r"(?:^|/)terragrunt\.hcl$", "hcl", "iac", ("terragrunt",)),
    (rf"(?:^|/)kustomization{_Y}$", "yaml", "iac", ("k8s", "kustomize")),
    (rf"(?:^|/)(?:playbooks|roles|group_vars|host_vars)/(?:.+/)?[^/]+{_Y}$|(?:^|/)site\.yml$"
     r"|(?:^|/)playbook[^/]*\.yml$", "yaml", "iac", ("ansible",)),
    (r"(?:^|/)ansible\.cfg$", "ini", "iac", ("ansible",)),
    (r"(?:^|/)nginx\.conf$|(?:^|/)nginx/(?:.+/)?[^/]+\.conf$|(?:^|/)(?:sites-available|sites-enabled|conf\.d)/[^/]+$",
     "nginx", "iac", ("nginx",)),
    (rf"(?:^|/)traefik{_Y}$|(?:^|/)traefik/(?:.+/)?[^/]+{_Y}$", "yaml", "iac", ("traefik",)),
    (r"(?:^|/)traefik\.toml$|(?:^|/)traefik/(?:.+/)?[^/]+\.toml$", "toml", "iac", ("traefik",)),
    (r"(?:^|/)dags/(?:.+/)?[^/]+\.py$|(?:^|/)airflow/(?:.+/)?[^/]+\.py$", "python", "code", ("airflow-dag",)),
    (r"(?:^|/)(?:\.env|\.env\.[^/]+|[^/]+\.env)$", "dotenv", "data", ("env",)),
    (r"(?:^|/)requirements[^/]*\.txt$|(?:^|/)(?:yarn\.lock|go\.sum)$", "text", "data", ("lockfile",)),
    (r"(?:^|/)(?:poetry\.lock|uv\.lock|Cargo\.lock)$", "toml", "data", ("lockfile",)),
    (r"(?:^|/)(?:Pipfile\.lock|package-lock\.json)$", "json", "data", ("lockfile",)),
    (r"(?:^|/)pnpm-lock\.yaml$", "yaml", "data", ("lockfile",)),
)  # fmt: skip
_ENV_EXAMPLE = re.compile(r"\.(?:example|sample|template|dist)$")


@lru_cache(maxsize=1)
def _a_table() -> tuple[tuple[re.Pattern[str] | None, str | None, str, tuple[str, ...]], ...]:
    return tuple(
        (None if rx == "HELM" else re.compile(rx), lang, kind, tags) for rx, lang, kind, tags in _A_ROWS
    )


_HELM_VALUES = re.compile(rf"^values[^/]*{_Y}$")
_HELM_TEMPLATE_EXT = re.compile(r"\.(?:ya?ml|tpl)$")


def _helm(path: str, probe: Probe | None) -> tuple[str | None, str | None, tuple[str, ...]] | None:
    """Helm chart files: ``Chart.yaml``; ``values*.yaml``/``templates/**`` beside a Chart.yaml."""
    parts = path.split("/")
    name = parts[-1]
    if name == "Chart.yaml":
        return "yaml", "iac", ("helm",)
    if probe is None:
        return None
    if _HELM_VALUES.match(name):
        chart = "/".join([*parts[:-1], "Chart.yaml"])
        if probe(chart):
            return "yaml", "iac", ("helm",)
        return None
    # templates/** : the chart directory is the parent of the nearest "templates" component
    for i in range(len(parts) - 2, -1, -1):
        if parts[i] == "templates":
            chart = "/".join([*parts[:i], "Chart.yaml"])
            if probe(chart):
                if _HELM_TEMPLATE_EXT.search(name):
                    return "yaml", "iac", ("helm", "helm-template")
                return None, None, ("helm", "helm-template")
            break
    return None


def _table_a(path: str, probe: Probe | None) -> tuple[str | None, str | None, tuple[str, ...]] | None:
    for rx, lang, kind, tags in _a_table():
        if rx is None:
            hit = _helm(path, probe)
            if hit is not None:
                return hit
            continue
        if rx.search(path):
            if "env" in tags and _ENV_EXAMPLE.search(path):
                return lang, kind, (*tags, "example")
            return lang, kind, tags
    return None


# =========================================================================== table B (extensions)

_B: dict[str, tuple[str, str | None, tuple[str, ...]]] = {
    ".py": ("python", "code", ()), ".pyi": ("python", "code", ()), ".ipynb": ("json", "code", ("notebook",)),
    ".scala": ("scala", "code", ()), ".sc": ("scala", "code", ()), ".sbt": ("scala", "code", ()),
    ".java": ("java", "code", ()), ".kt": ("kotlin", "code", ()), ".go": ("go", "code", ()),
    ".rs": ("rust", "code", ()), ".rb": ("ruby", "code", ()), ".php": ("php", "code", ()),
    ".cs": ("csharp", "code", ()),
    ".js": ("javascript", "code", ()), ".mjs": ("javascript", "code", ()), ".cjs": ("javascript", "code", ()),
    ".jsx": ("javascript", "code", ()), ".ts": ("typescript", "code", ()), ".tsx": ("typescript", "code", ()),
    ".sql": ("sql", "code", ()), ".sh": ("shell", "code", ()), ".bash": ("shell", "code", ()),
    ".zsh": ("shell", "code", ()), ".ksh": ("shell", "code", ()), ".ps1": ("powershell", "code", ()),
    ".j2": ("jinja", "code", ("template",)), ".jinja": ("jinja", "code", ("template",)),
    ".jinja2": ("jinja", "code", ("template",)), ".tpl": ("jinja", "code", ("template",)),
    ".tf": ("hcl", "iac", ("terraform",)), ".tfvars": ("hcl", "iac", ("terraform",)),
    ".hcl": ("hcl", "iac", ("terraform",)),
    ".yml": ("yaml", None, ()), ".yaml": ("yaml", None, ()), ".json": ("json", None, ()),
    ".toml": ("toml", None, ()), ".ini": ("ini", None, ()), ".cfg": ("ini", None, ()),
    ".conf": ("ini", None, ()), ".properties": ("ini", None, ()), ".xml": ("xml", None, ()),
    ".csv": ("csv", None, ()), ".tsv": ("csv", None, ()),
    ".pem": ("text", "data", ("key-material",)), ".key": ("text", "data", ("key-material",)),
    ".crt": ("text", "data", ("key-material",)), ".asc": ("text", "data", ("key-material",)),
    ".md": ("markdown", "doc", ()), ".mdx": ("markdown", "doc", ()), ".markdown": ("markdown", "doc", ()),
    ".rst": ("rst", "doc", ()), ".adoc": ("text", "doc", ()), ".txt": ("text", "doc", ()),
    ".html": ("html", "doc", ()), ".htm": ("html", "doc", ()), ".xhtml": ("html", "doc", ()),
    ".svg": ("xml", "doc", ()),
}  # fmt: skip


def _ext(name: str) -> str:
    dot = name.rfind(".")
    return name[dot:].lower() if dot > 0 else ""


def _table_b(name: str) -> tuple[str, str | None, tuple[str, ...]] | None:
    low = name.lower()
    if low.endswith(".tf.json"):
        return "json", "iac", ("terraform",)
    return _B.get(_ext(name))


# =========================================================================== table C (content)


def _imports(mods: str) -> str:
    return (
        rf"(?m)^[ \t]*(?:from[ \t]+(?:{mods})\b"
        rf"|import[ \t]+(?:[\w.]+(?:[ \t]+as[ \t]+\w+)?[ \t]*,[ \t]*)*(?:{mods})\b)"
    )


# Sniff regexes, grouped by language so a single-file hook compiles only what it needs.
_RX_SRC: dict[str, dict[str, str]] = {
    "yaml": {
        "doc_sep": r"(?m)^---(?:[ \t].*)?$",
        "api": r"(?m)^apiVersion[ \t]*:[ \t]*[\"']?([^\s\"'#]*)",
        "kind": r"(?m)^kind[ \t]*:[ \t]*[\"']?([\w.-]*)",
        "rbac": r"(?:Cluster)?Role(?:Binding)?",
        "flux": r"(?:^|\.)toolkit\.fluxcd\.io/",
        "gha_on": r"(?m)^(?:on|\"on\"|'on')[ \t]*:",
        "gha_jobs": r"(?m)^jobs[ \t]*:",
        "services": r"(?m)^services[ \t]*:[ \t]*(?:#.*)?$",
        "top_key": r"(?m)^[^\s#-]",
        "svc_child": r"(?m)^[ \t]+(?:image|build)[ \t]*:",
        "ansible": r"(?m)^(?:-[ \t]+|[ \t]+)(?:hosts|tasks|import_playbook)[ \t]*:",
        "cfn": r"AWSTemplateFormatVersion|(?m:^[ \t]*[\"']?Type[\"']?[ \t]*:[ \t]*[\"']?AWS::)",
    },
    "json": {
        "cfn_json": r"\"AWSTemplateFormatVersion\"|\"Type\"\s*:\s*\"AWS::",
        "mcp": r"\"mcpServers\"\s*:",
        "tf_plan_a": r"\"format_version\"\s*:",
        "tf_plan_b": r"\"terraform_version\"\s*:",
    },
    "python": {
        "py_import_lines": r"(?m)^[ \t]*(?:from|import)[ \t][^\n]*",
        "py_fastapi": r"(?m)^[ \t]*(?:from|import)[ \t]+(?:fastapi|starlette)\b",
        "py_airflow": _imports(r"airflow"),
        "py_spark": _imports(r"pyspark"),
        "py_boto3": _imports(r"boto3"),
        "py_llm": _imports(r"vertexai|google\.cloud\.aiplatform|langchain\w*|llama_index")
        + r"|(?m:^[ \t]*from[ \t]+google\.cloud[ \t]+import[ \t]+[^\n]*\baiplatform\b)",
        "py_vectordb": _imports(r"pinecone|qdrant_client|weaviate|chromadb|pymilvus|pgvector"),
        "py_trading": _imports(r"ccxt|alpaca\w*|ib_insync|binance"),
        "py_kopf": _imports(r"kopf"),
    },
    "scala": {"scala_spark": r"(?m)^[ \t]*import[ \t]+org\.apache\.spark\b"},
}


@cache
def _rx(group: str) -> dict[str, re.Pattern[str]]:
    return {k: re.compile(v) for k, v in _RX_SRC[group].items()}


def _yaml_doc(doc: str, rx: Mapping[str, re.Pattern[str]]) -> tuple[str | None, set[str]]:
    tags: set[str] = set()
    kind: str | None = None

    def up(k: str) -> None:
        nonlocal kind
        if kind is None or KIND_RANK[k] > KIND_RANK[kind]:
            kind = k

    api = rx["api"].search(doc)
    k8s_kind = rx["kind"].search(doc)
    if api and k8s_kind:
        tags.add("k8s")
        version = api.group(1)
        if "tekton.dev/" in version:
            up("ci")
            tags.add("tekton")
        elif rx["flux"].search(version):
            up("ci")
            tags.add("flux")
        else:
            up("iac")
        kname = k8s_kind.group(1)
        if rx["rbac"].fullmatch(kname):
            tags.add("k8s-rbac")
        elif kname == "CustomResourceDefinition":
            tags.add("k8s-crd")
    if rx["gha_on"].search(doc) and rx["gha_jobs"].search(doc):
        up("ci")
        tags.add("gha")
    svc = rx["services"].search(doc)
    if svc:
        nxt = rx["top_key"].search(doc, svc.end())
        block = doc[svc.end() : nxt.start() if nxt else len(doc)]
        if rx["svc_child"].search(block):
            up("iac")
            tags.add("compose")
    first = _first_significant_line(doc)
    if first.startswith("-") and rx["ansible"].search(doc):
        up("iac")
        tags.add("ansible")
    if rx["cfn"].search(doc):
        up("iac")
        tags.add("cloudformation")
    return kind, tags


def _first_significant_line(doc: str) -> str:
    start = 0
    n = len(doc)
    for _ in range(10_000):
        if start >= n:
            return ""
        end = doc.find("\n", start)
        line = doc[start : end if end != -1 else n].strip()
        if line and not line.startswith("#") and not line.startswith("%") and line != "---":
            return line
        if end == -1:
            return ""
        start = end + 1
    return ""


def _sniff_yaml(head: str) -> tuple[str | None, set[str]]:
    rx = _rx("yaml")
    best: str | None = None
    tags: set[str] = set()
    pos = 0
    for _ in range(_MAX_YAML_DOCS):
        m = rx["doc_sep"].search(head, pos)
        doc = head[pos : m.start() if m else len(head)]
        kind, t = _yaml_doc(doc, rx)
        tags |= t
        if kind is not None and (best is None or KIND_RANK[kind] > KIND_RANK[best]):
            best = kind
        if m is None:
            break
        pos = m.end()
    return best, tags


def _sniff_json(head: str) -> tuple[str | None, set[str]]:
    rx = _rx("json")
    kind: str | None = None
    tags: set[str] = set()
    if rx["mcp"].search(head):
        kind = "agent-config"
        tags.add("mcp")
    if rx["cfn_json"].search(head):
        kind = kind or "iac"
        tags.add("cloudformation")
    if rx["tf_plan_a"].search(head) and rx["tf_plan_b"].search(head):
        kind = kind or "data"
        tags.add("terraform-plan")
    return kind, tags


def _sniff_python(text: str) -> set[str]:
    rx = _rx("python")
    tags: set[str] = set()
    # one pass over the file for import statements; the tag regexes then see only those lines
    head = "\n".join(rx["py_import_lines"].findall(text))
    if not head:
        return tags
    if rx["py_fastapi"].search(head):
        tags.add("fastapi")
    if rx["py_airflow"].search(head):
        tags.add("airflow-dag")
    if rx["py_spark"].search(head):
        tags.add("spark")
    if rx["py_llm"].search(head) or ("bedrock-runtime" in text and rx["py_boto3"].search(head)):
        tags.add("llm")
    if rx["py_vectordb"].search(head):
        tags.add("vectordb")
    if rx["py_trading"].search(head):
        tags.add("trading")
    if rx["py_kopf"].search(head):
        tags.add("k8s-operator")
    return tags


def _shebang(head: str) -> str | None:
    if not head.startswith("#!"):
        return None
    line = head[2 : head.find("\n") if "\n" in head else min(len(head), 512)].strip()
    tokens = line.split()
    if not tokens:
        return None
    interp = tokens[0].rsplit("/", 1)[-1]
    if interp == "env":
        rest = [t for t in tokens[1:] if not t.startswith("-") and "=" not in t]
        if not rest:
            return None
        interp = rest[0].rsplit("/", 1)[-1]
    if re.fullmatch(r"python[\d.]*", interp):
        return "python"
    if interp in ("sh", "bash", "zsh"):
        return "shell"
    return None


def _looks_json(head: str) -> bool:
    s = head.lstrip()[:1]
    return s in ("{", "[")


# =========================================================================== classify


def _norm(path: str) -> str:
    p = path.replace(os.sep, "/") if os.sep != "/" else path  # "\\" is a name char on POSIX
    while p.startswith("./"):
        p = p[2:]
    return p


RuleFields = tuple[str, str | None, str | None, Sequence[str]]


def _rule_fields(rule: ClassifyRuleLike | Mapping[str, Any]) -> RuleFields:
    if isinstance(rule, Mapping):
        return str(rule["glob"]), rule.get("kind"), rule.get("lang"), tuple(rule.get("tags", ()))
    return rule.glob, rule.kind, rule.lang, tuple(rule.tags)


def classify(
    path: str,
    head_text: str = "",
    cfg_rules: Sequence[ClassifyRuleLike | Mapping[str, Any]] = (),
    *,
    size: int | None = None,
    probe: Probe | None = None,
) -> tuple[str, str, frozenset[str]]:
    """Classify a file. Returns ``(lang, kind, tags)``.

    - ``path``: root-relative POSIX path (or absolute, or a virtual name). ``"<stdin>"`` and
      ``""`` skip the path tables: classification is by content only.
    - ``head_text``: decoded content; only the first 64 KiB are sniffed (passing the whole
      text is fine and makes the ``minified`` flag exact for small files).
    - ``cfg_rules``: ``[classify].rules`` entries (objects or mappings with glob/kind/lang/tags).
    - ``size``: file size in bytes, for the ``minified`` flag.
    - ``probe``: ``probe(path) -> bool`` tells whether a file exists at a path in the same path
      space as ``path``; used to find a sibling ``Chart.yaml`` for Helm values and templates.
    """
    p = _norm(path)
    virtual = p in ("", "<stdin>") or (p.startswith("<") and p.endswith(">"))
    head = head_text[:SNIFF_CHARS] if len(head_text) > SNIFF_CHARS else head_text
    res = _Result()

    if not virtual:
        # 1. config rules (first match)
        for rule in cfg_rules:
            r_glob, r_kind, r_lang, r_tags = _rule_fields(rule)
            if ignore.glob_match(r_glob, p):
                res.offer(r_lang, r_kind, r_tags)
                break
        # 2. path table A
        a = _table_a(p, probe)
        if a is not None:
            res.offer(*a)
        # 3. extension table B
        name = p.rsplit("/", 1)[-1]
        b = _table_b(name)
        if b is not None:
            res.offer(*b)
    else:
        name = ""

    # 4. content sniff C
    lang = res.lang
    if lang is None and not _ext(name):  # no extension (a leading dot alone is not one)
        sb = _shebang(head)
        if sb is not None:
            res.offer(sb, "code")
            lang = sb
    if lang is None and virtual and head:
        if _looks_json(head):
            kind, tags = _sniff_json(head)
            if kind is not None or tags:
                res.offer("json", kind, tags)
                lang = "json"
        else:
            kind, tags = _sniff_yaml(head)
            if kind is not None:
                res.offer("yaml", kind, tags)
                lang = "yaml"
    elif lang == "yaml":
        kind, tags = _sniff_yaml(head)
        res.offer(None, kind, tags)
    elif lang == "json":
        kind, tags = _sniff_json(head)
        res.offer(None, kind, tags)
    elif lang == "python":
        res.offer(None, None, _sniff_python(head))
    elif lang == "scala" and _rx("scala")["scala_spark"].search(head):
        res.tags.add("spark")

    # 5. fallback
    res.offer("text", "data")
    if virtual:
        res.tags |= file_flags("", head_text, size) - {"test"}
    else:
        res.tags |= file_flags(p, head_text, size)
    return res.lang or "text", res.kind or "data", frozenset(res.tags)
