"""Tests for whalescan.classify (spec §6 tables A/B/C, §5.7 file flags)."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from whalescan.classify import (
    KIND_RANK,
    SNIFF_CHARS,
    classify,
    file_flags,
    is_generated,
    is_minified,
    is_test_path,
)
from whalescan.config import ClassifyRule
from whalescan.model import KINDS

# --------------------------------------------------------------------------- table A (paths)


@pytest.mark.parametrize(
    ("path", "lang", "kind", "tags"),
    [
        (".github/workflows/ci.yml", "yaml", "ci", {"gha"}),
        (".github/workflows/release.yaml", "yaml", "ci", {"gha"}),
        ("tools/checkout/action.yml", "yaml", "ci", {"gha-action"}),
        (".tekton/pipelines/build.yaml", "yaml", "ci", {"tekton"}),
        (".gitlab-ci.yml", "yaml", "ci", {"ci-other"}),
        (".circleci/config.yml", "yaml", "ci", {"ci-other"}),
        ("azure-pipelines.yml", "yaml", "ci", {"ci-other"}),
        ("bitbucket-pipelines.yml", "yaml", "ci", {"ci-other"}),
        ("Jenkinsfile", "groovy", "ci", {"ci-other"}),
        ("CLAUDE.md", "markdown", "agent-config", {"agent-instructions"}),
        ("CLAUDE.local.md", "markdown", "agent-config", {"agent-instructions"}),
        ("services/api/AGENTS.md", "markdown", "agent-config", {"agent-instructions"}),
        ("skills/audit/SKILL.md", "markdown", "agent-config", {"agent-instructions"}),
        (".claude/commands/whale/audit.md", "markdown", "agent-config", {"agent-instructions"}),
        (".claude/agents/reviewer.md", "markdown", "agent-config", {"agent-instructions"}),
        (".cursorrules", "markdown", "agent-config", {"agent-instructions"}),
        (".cursor/rules/python.mdc", "markdown", "agent-config", {"agent-instructions"}),
        (".windsurfrules", "markdown", "agent-config", {"agent-instructions"}),
        (".clinerules", "markdown", "agent-config", {"agent-instructions"}),
        (".mcp.json", "json", "agent-config", {"mcp"}),
        ("config/mcp.json", "json", "agent-config", {"mcp"}),
        (".vscode/mcp.json", "json", "agent-config", {"mcp"}),
        (".claude/settings.json", "json", "agent-config", {"agent-settings"}),
        (".claude/settings.local.json", "json", "agent-config", {"agent-settings"}),
        (".claude-plugin/plugin.json", "json", "agent-config", {"agent-settings"}),
        ("plugin/hooks/hooks.json", "json", "agent-config", {"agent-settings"}),
        ("Dockerfile", "dockerfile", "iac", {"docker"}),
        ("svc/Dockerfile.prod", "dockerfile", "iac", {"docker"}),
        ("svc/api.Dockerfile", "dockerfile", "iac", {"docker"}),
        ("Containerfile", "dockerfile", "iac", {"docker"}),
        ("docker-compose.yml", "yaml", "iac", {"compose"}),
        ("deploy/compose.prod.yaml", "yaml", "iac", {"compose"}),
        ("charts/api/Chart.yaml", "yaml", "iac", {"helm"}),
        ("live/prod/terragrunt.hcl", "hcl", "iac", {"terragrunt", "terraform"}),
        ("overlays/prod/kustomization.yaml", "yaml", "iac", {"k8s", "kustomize"}),
        ("ansible/roles/web/tasks/main.yml", "yaml", "iac", {"ansible"}),
        ("playbooks/site.yaml", "yaml", "iac", {"ansible"}),
        ("group_vars/all.yml", "yaml", "iac", {"ansible"}),
        ("site.yml", "yaml", "iac", {"ansible"}),
        ("playbook-db.yml", "yaml", "iac", {"ansible"}),
        ("ansible.cfg", "ini", "iac", {"ansible"}),
        ("nginx.conf", "nginx", "iac", {"nginx"}),
        ("deploy/nginx/sites/app.conf", "nginx", "iac", {"nginx"}),
        ("etc/sites-enabled/default", "nginx", "iac", {"nginx"}),
        ("etc/conf.d/app.conf", "nginx", "iac", {"nginx"}),
        ("traefik.yml", "yaml", "iac", {"traefik"}),
        ("traefik.toml", "toml", "iac", {"traefik"}),
        ("deploy/traefik/dynamic/routes.yaml", "yaml", "iac", {"traefik"}),
        ("dags/etl/orders.py", "python", "code", {"airflow-dag"}),
        ("platform/airflow/plugins/x.py", "python", "code", {"airflow-dag"}),
        (".env", "dotenv", "data", {"env"}),
        (".env.production", "dotenv", "data", {"env"}),
        ("config/prod.env", "dotenv", "data", {"env"}),
        (".env.example", "dotenv", "data", {"env", "example"}),
        (".env.sample", "dotenv", "data", {"env", "example"}),
        ("x/.env.template", "dotenv", "data", {"env", "example"}),
        (".env.dist", "dotenv", "data", {"env", "example"}),
        ("requirements-dev.txt", "text", "data", {"lockfile"}),
        ("poetry.lock", "toml", "data", {"lockfile"}),
        ("uv.lock", "toml", "data", {"lockfile"}),
        ("Pipfile.lock", "json", "data", {"lockfile"}),
        ("web/package-lock.json", "json", "data", {"lockfile"}),
        ("pnpm-lock.yaml", "yaml", "data", {"lockfile"}),
        ("yarn.lock", "text", "data", {"lockfile"}),
        ("go.sum", "text", "data", {"lockfile"}),
        ("Cargo.lock", "toml", "data", {"lockfile"}),
    ],
)
def test_table_a(path: str, lang: str, kind: str, tags: set[str]) -> None:
    got = classify(path, "")
    assert got[0] == lang and got[1] == kind
    assert tags <= got[2], got


def test_table_a_order_first_row_wins() -> None:
    # a workflow named action.yml is still a workflow (row 1 before row 2)
    assert classify(".github/workflows/action.yml", "")[2] >= {"gha"}
    assert "gha-action" not in classify(".github/workflows/action.yml", "")[2]


def test_envrc_is_not_dotenv() -> None:
    assert classify(".envrc", "")[0] != "dotenv"


# --------------------------------------------------------------------------- helm


def _probe(*files: str):  # type: ignore[no-untyped-def]
    s = set(files)
    return lambda p: p in s


def test_helm_values_and_templates_need_chart() -> None:
    probe = _probe("charts/api/Chart.yaml")
    assert classify("charts/api/values.yaml", "a: 1", probe=probe) == ("yaml", "iac", frozenset({"helm"}))
    assert classify("charts/api/values-prod.yaml", "a: 1", probe=probe)[1] == "iac"
    t = classify("charts/api/templates/deployment.yaml", "{{ .Values.x }}", probe=probe)
    assert t == ("yaml", "iac", frozenset({"helm", "helm-template"}))
    assert classify("charts/api/templates/_helpers.tpl", "{{- define }}", probe=probe)[:2] == ("yaml", "iac")
    notes = classify("charts/api/templates/NOTES.txt", "hi", probe=probe)
    assert notes[:2] == ("text", "doc") and {"helm", "helm-template"} <= notes[2]
    # no Chart.yaml beside: ordinary data yaml
    assert classify("other/values.yaml", "a: 1", probe=probe) == ("yaml", "data", frozenset())
    assert classify("charts/api/values.yaml", "a: 1") == ("yaml", "data", frozenset())
    assert classify("x/templates/a.yaml", "a: 1", probe=probe)[1] == "data"


# --------------------------------------------------------------------------- table B (extensions)


@pytest.mark.parametrize(
    ("path", "lang", "kind", "tags"),
    [
        ("a.py", "python", "code", set()),
        ("a.pyi", "python", "code", set()),
        ("nb.ipynb", "json", "code", {"notebook"}),
        ("A.scala", "scala", "code", set()),
        ("build.sbt", "scala", "code", set()),
        ("x.sc", "scala", "code", set()),
        ("A.java", "java", "code", set()),
        ("a.kt", "kotlin", "code", set()),
        ("a.go", "go", "code", set()),
        ("a.rs", "rust", "code", set()),
        ("a.rb", "ruby", "code", set()),
        ("a.php", "php", "code", set()),
        ("a.cs", "csharp", "code", set()),
        ("a.mjs", "javascript", "code", set()),
        ("a.cjs", "javascript", "code", set()),
        ("a.jsx", "javascript", "code", set()),
        ("a.tsx", "typescript", "code", set()),
        ("q.sql", "sql", "code", set()),
        ("run.sh", "shell", "code", set()),
        ("run.zsh", "shell", "code", set()),
        ("run.ps1", "powershell", "code", set()),
        ("t.j2", "jinja", "code", {"template"}),
        ("t.jinja2", "jinja", "code", {"template"}),
        ("main.tf", "hcl", "iac", {"terraform"}),
        ("x.tf.json", "json", "iac", {"terraform"}),
        ("prod.tfvars", "hcl", "iac", {"terraform"}),
        ("pack.hcl", "hcl", "iac", {"terraform"}),
        ("a.yml", "yaml", "data", set()),
        ("a.json", "json", "data", set()),
        ("a.toml", "toml", "data", set()),
        ("a.cfg", "ini", "data", set()),
        ("a.properties", "ini", "data", set()),
        ("a.xml", "xml", "data", set()),
        ("a.tsv", "csv", "data", set()),
        ("server.pem", "text", "data", {"key-material"}),
        ("id.key", "text", "data", {"key-material"}),
        ("README.md", "markdown", "doc", set()),
        ("a.mdx", "markdown", "doc", set()),
        ("a.rst", "rst", "doc", set()),
        ("a.adoc", "text", "doc", set()),
        ("notes.txt", "text", "doc", set()),
        ("a.html", "html", "doc", set()),
        ("icon.svg", "xml", "doc", set()),
        ("UPPER.PY", "python", "code", set()),
    ],
)
def test_table_b(path: str, lang: str, kind: str, tags: set[str]) -> None:
    got = classify(path, "")
    assert (got[0], got[1]) == (lang, kind)
    assert tags <= got[2]


def test_fallback_text_data() -> None:
    assert classify("LICENSE", "MIT License") == ("text", "data", frozenset())
    assert classify("weird.zzz", "") == ("text", "data", frozenset())


# --------------------------------------------------------------------------- table C (content)


def test_k8s_sniff_and_rbac_crd() -> None:
    assert classify("deploy/app.yaml", "apiVersion: apps/v1\nkind: Deployment\n") == (
        "yaml",
        "iac",
        frozenset({"k8s"}),
    )
    rbac = classify("r.yaml", "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n")
    assert rbac[1] == "iac" and {"k8s", "k8s-rbac"} <= rbac[2]
    role = classify("r.yaml", "kind: Role\napiVersion: rbac.authorization.k8s.io/v1\n")
    assert "k8s-rbac" in role[2]
    crd = classify("c.yaml", 'apiVersion: apiextensions.k8s.io/v1\nkind: "CustomResourceDefinition"\n')
    assert "k8s-crd" in crd[2]
    assert "k8s-rbac" not in classify("x.yaml", "apiVersion: v1\nkind: RoleBindingThing\n")[2]


def test_tekton_and_flux_are_ci() -> None:
    t = classify("p.yaml", "apiVersion: tekton.dev/v1beta1\nkind: Pipeline\n")
    assert t[1] == "ci" and {"tekton", "k8s"} <= t[2]
    f = classify("f.yaml", "apiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\n")
    assert f[1] == "ci" and "flux" in f[2]


def test_indented_api_version_is_not_top_level() -> None:
    assert classify("v.yaml", "spec:\n  apiVersion: v1\n  kind: Pod\n")[1] == "data"


def test_multidoc_yaml_highest_kind_wins() -> None:
    text = "apiVersion: v1\nkind: ConfigMap\n---\napiVersion: tekton.dev/v1\nkind: Task\n---\nfoo: 1\n"
    lang, kind, tags = classify("all.yaml", text)
    assert (lang, kind) == ("yaml", "ci")
    assert {"k8s", "tekton"} <= tags
    assert KIND_RANK["ci"] > KIND_RANK["iac"] > KIND_RANK["agent-config"] > KIND_RANK["code"]
    assert KIND_RANK["code"] > KIND_RANK["doc"] > KIND_RANK["data"]
    assert set(KIND_RANK) == set(KINDS)


def test_gha_outside_workflows_dir() -> None:
    wf = 'name: x\n"on":\n  push: {}\njobs:\n  build: {}\n'
    assert classify("ci/workflow.yml", wf) == ("yaml", "ci", frozenset({"gha"}))
    assert classify("ci/w.yml", "on: push\njobs: {}\n")[1] == "ci"
    assert classify("ci/w.yml", "jobs: {}\n")[1] == "data"


def test_compose_sniff() -> None:
    compose = "version: '3'\nservices:\n  web:\n    build: .\nvolumes:\n  image: fake\n"
    assert classify("stack.yml", compose) == ("yaml", "iac", frozenset({"compose"}))
    not_compose = "services:\n  - name: a\nother:\n  image: x\n"
    assert classify("svc.yml", not_compose)[1] == "data"


def test_ansible_sniff() -> None:
    play = "---\n# comment\n- name: deploy\n  hosts: web\n  tasks:\n    - ping:\n"
    assert classify("deploy.yml", play) == ("yaml", "iac", frozenset({"ansible"}))
    assert classify("list.yml", "- a\n- b\n")[1] == "data"


def test_cloudformation_sniff() -> None:
    assert classify("t.yaml", "AWSTemplateFormatVersion: '2010-09-09'\n")[2] == {"cloudformation"}
    cfn = "Resources:\n  B:\n    Type: AWS::S3::Bucket\n"
    assert classify("t.yaml", cfn) == ("yaml", "iac", frozenset({"cloudformation"}))
    js = '{"Resources": {"B": {"Type": "AWS::S3::Bucket"}}}'
    assert classify("t.json", js) == ("json", "iac", frozenset({"cloudformation"}))


def test_json_sniffs() -> None:
    assert classify("claude.json", '{"projects": {}, "mcpServers": {"x": {}}}') == (
        "json",
        "agent-config",
        frozenset({"mcp"}),
    )
    plan = '{"format_version": "1.2", "terraform_version": "1.7.0", "planned_values": {}}'
    assert classify("plan.json", plan) == ("json", "data", frozenset({"terraform-plan"}))
    assert classify("x.json", '{"format_version": "1"}')[2] == frozenset()


def test_python_sniffs() -> None:
    src = (
        "import os\n"
        "from fastapi import FastAPI\n"
        "import numpy as np, boto3\n"
        "client = boto3.client('bedrock-runtime')\n"
        "from qdrant_client import QdrantClient\n"
        "import ccxt\n"
        "from pyspark.sql import SparkSession\n"
    )
    lang, kind, tags = classify("app/main.py", src)
    assert (lang, kind) == ("python", "code")
    assert {"fastapi", "llm", "vectordb", "trading", "spark"} <= tags


@pytest.mark.parametrize(
    ("src", "tag"),
    [
        ("from starlette.applications import Starlette\n", "fastapi"),
        ("from airflow import DAG\n", "airflow-dag"),
        ("import airflow.models\n", "airflow-dag"),
        ("import vertexai\n", "llm"),
        ("from google.cloud import aiplatform\n", "llm"),
        ("import google.cloud.aiplatform as aip\n", "llm"),
        ("from langchain_openai import ChatOpenAI\n", "llm"),
        ("from llama_index.core import VectorStoreIndex\n", "llm"),
        ("import pinecone\n", "vectordb"),
        ("import chromadb\n", "vectordb"),
        ("from pymilvus import MilvusClient\n", "vectordb"),
        ("from pgvector.sqlalchemy import Vector\n", "vectordb"),
        ("import weaviate\n", "vectordb"),
        ("import alpaca_trade_api as tradeapi\n", "trading"),
        ("from ib_insync import IB\n", "trading"),
        ("from binance.client import Client\n", "trading"),
        ("import kopf\n", "k8s-operator"),
    ],
)
def test_python_sniff_rows(src: str, tag: str) -> None:
    assert tag in classify("m.py", src)[2]


def test_python_sniff_negatives() -> None:
    assert "llm" not in classify("m.py", "import boto3\ns3 = boto3.client('s3')\n")[2]
    assert "llm" not in classify("m.py", "x = 'bedrock-runtime'\n")[2]
    assert "fastapi" not in classify("m.py", "# from fastapi import X\nprint('import fastapi')\n")[2]
    assert "trading" not in classify("m.py", "import binancex\n")[2]
    # sniffs only apply to Python
    assert "fastapi" not in classify("m.txt", "from fastapi import FastAPI\n")[2]


def test_scala_spark() -> None:
    assert "spark" in classify("Job.scala", "import org.apache.spark.sql.SparkSession\n")[2]


@pytest.mark.parametrize(
    ("head", "lang"),
    [
        ("#!/usr/bin/env python3\nprint(1)\n", "python"),
        ("#!/usr/bin/python3.11\n", "python"),
        ("#!/bin/bash\necho\n", "shell"),
        ("#!/bin/sh\n", "shell"),
        ("#!/usr/bin/env -S bash -e\n", "shell"),
        ("#! /usr/bin/env zsh\n", "shell"),
        ("#!/usr/bin/env FOO=1 python\n", "python"),
    ],
)
def test_shebang_without_extension(head: str, lang: str) -> None:
    assert classify("scripts/deploy", head)[:2] == (lang, "code")


def test_shebang_ignored_with_extension_or_unknown_interpreter() -> None:
    assert classify("notes.txt", "#!/bin/bash\n")[0] == "text"
    assert classify("bin/tool", "#!/usr/bin/perl\n") == ("text", "data", frozenset())
    assert classify("bin/tool", "#!/usr/bin/env\n")[0] == "text"
    assert classify("bin/tool", "#!\n")[0] == "text"


def test_stdin_is_content_only() -> None:
    assert classify("<stdin>", "apiVersion: v1\nkind: Secret\n")[:2] == ("yaml", "iac")
    assert classify("<stdin>", '  {"mcpServers": {}}')[:2] == ("json", "agent-config")
    assert classify("<stdin>", "#!/bin/sh\necho hi\n")[:2] == ("shell", "code")
    assert classify("<stdin>", "just words\n") == ("text", "data", frozenset())
    assert classify("", "") == ("text", "data", frozenset())
    # the path tables never apply to the virtual name
    assert classify("<stdin>", "tests/x")[2] == frozenset()


def test_sniff_limited_to_first_64k() -> None:
    padding = "# pad\n" * (SNIFF_CHARS // 6 + 10)
    assert classify("late.yaml", padding + "apiVersion: v1\nkind: Pod\n")[1] == "data"
    assert classify("early.yaml", "apiVersion: v1\nkind: Pod\n" + padding)[1] == "iac"


# --------------------------------------------------------------------------- config rules


def test_config_rules_first_and_accumulate() -> None:
    rules = [
        ClassifyRule("platform/manifests/**/*.yaml", kind="iac", lang="yaml", tags=("k8s",)),
        ClassifyRule("platform/**", kind="doc"),
    ]
    got = classify("platform/manifests/a/b.yaml", "", rules)
    assert got == ("yaml", "iac", frozenset({"k8s"}))
    assert classify("platform/readme.yaml", "", rules)[1] == "doc"


def test_config_rules_mapping_and_partial() -> None:
    rules = [{"glob": "*.tpl", "lang": "gotemplate", "tags": ["tmpl"]}]
    lang, kind, tags = classify("x/y.tpl", "", rules)
    assert lang == "gotemplate"
    assert kind == "code"  # kind still comes from table B
    assert {"tmpl", "template"} <= tags  # tags from every step


def test_config_rule_overrides_table_a() -> None:
    rules = [ClassifyRule("CLAUDE.md", kind="doc", lang="markdown")]
    lang, kind, tags = classify("CLAUDE.md", "", rules)
    assert (lang, kind) == ("markdown", "doc")
    assert "agent-instructions" in tags


# --------------------------------------------------------------------------- flags


def test_generated_flag() -> None:
    assert is_generated("// Code generated by protoc. DO NOT EDIT.\n")
    assert is_generated("# @generated\n")
    assert is_generated("a\nb\nc\nd\n/* Auto-generated file */\n")
    assert not is_generated("a\nb\nc\nd\ne\n# @generated\n")  # only the first 5 lines
    assert is_generated("do not edit\n")  # the (?i) flag applies to every alternative
    assert not is_generated("generated_at = now()\n")
    assert "generated" in classify("gen/api_pb2.py", "# autogenerated\nx = 1\n")[2]


def test_minified_flag() -> None:
    long_line = "var a=1;" * 5000  # 40 KB, one line
    assert is_minified("static/app.js", long_line)
    assert not is_minified("static/app.js", "x\n" * 20000)  # big but short lines
    assert not is_minified("small.js", "x" * 20000)  # <= 20 KiB
    assert is_minified("static/app.min.js", "")
    assert is_minified("static/app.min.css", "a{}")
    assert not is_minified("static/app.min.jsx", "")
    assert is_minified("app.js", "x" * 100, size=30_000) is False  # mean line length 100
    assert "minified" in classify("static/vendor.js", long_line)[2]


@pytest.mark.parametrize(
    ("path", "ok"),
    [
        ("tests/test_a.py", True),
        ("pkg/test/x.go", True),
        ("src/__tests__/a.js", True),
        ("spec/a.rb", True),
        ("specs/x", True),
        ("fixtures/a.json", True),
        ("x/fixture/a.json", True),
        ("testdata/in.txt", True),
        ("test_models.py", True),
        ("pkg/models_test.py", True),
        ("cmd/main_test.go", True),
        ("conftest.py", True),
        ("ui/Button.test.tsx", True),
        ("ui/Button.spec.js", True),
        ("src/latest/app.py", False),
        ("contest.py", False),
        ("attestation/x.py", False),
        ("tests.py", False),
    ],
)
def test_test_flag(path: str, ok: bool) -> None:
    assert is_test_path(path) is ok
    assert ("test" in file_flags(path, "")) is ok


# --------------------------------------------------------------------------- properties


@given(st.text(max_size=300), st.text(alphabet="abc/._-", max_size=40))
def test_classify_total(text: str, path: str) -> None:
    lang, kind, tags = classify(path, text)
    assert kind in KINDS
    assert isinstance(lang, str) and lang
    assert all(isinstance(t, str) for t in tags)


@given(
    st.sampled_from(["a.py", "CLAUDE.md", "x.yaml", ".mcp.json", "Dockerfile", "a.txt"]),
    st.text(max_size=200),
)
def test_path_decisions_do_not_depend_on_content_for_decisive_rows(path: str, text: str) -> None:
    lang, kind, _ = classify(path, text)
    if path != "x.yaml":
        assert (lang, kind) == classify(path, "")[:2]
