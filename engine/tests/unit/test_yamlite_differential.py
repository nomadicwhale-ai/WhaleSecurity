# ruff: noqa: E501 - the embedded corpus reproduces real-world files, long lines included
"""Differential tests: whalescan.yamlite against PyYAML (a dev-only dependency).

PyYAML is the reference for structure, scalar text, styles and positions. Reference loaders keep
keys raw (like yamlite) and use yamlite's value tables: YAML 1.1 as PyYAML resolves it plus y/n
bools and no timestamps ("yaml11"), and the YAML 1.2 core schema ("yaml12").

Documented deviations that inputs here avoid (each has a unit test in test_yamlite.py):
complex ``?`` keys and collection keys (rejected), recursive aliases (rejected), duplicate anchors
(PyYAML rejects, yamlite lets the later one win), ``\\u`` surrogate pairs (combined, JSON style),
the non-specific ``!`` tag (a string, per YAML 1.2), tags directly followed by ``[`` or ``,``, and
tab characters (PyYAML rejects most tabs; yamlite accepts them as separators as YAML 1.2 does).
"""

from __future__ import annotations

import json
import math
import random
import re
import sys
import time
from typing import Any, ClassVar

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from whalescan import yamlite as Y

yaml = pytest.importorskip("yaml")

from yaml.nodes import MappingNode as PMap  # noqa: E402
from yaml.nodes import ScalarNode as PScalar  # noqa: E402
from yaml.nodes import SequenceNode as PSeq  # noqa: E402

# --------------------------------------------------------------------------- reference loaders

_STYLE = {None: "plain", "'": "single", '"': "double", "|": "literal", ">": "folded"}


class _RawKeys:
    """Mixin: mapping keys are the scalar's text, never resolved (yamlite's contract)."""

    def construct_mapping(self, node: Any, deep: bool = False) -> Any:
        if isinstance(node, PMap):
            self.flatten_mapping(node)  # type: ignore[attr-defined]
        out: dict[str, Any] = {}
        for key_node, value_node in node.value:
            if not isinstance(key_node, PScalar):
                raise yaml.constructor.ConstructorError(None, None, "complex key", key_node.start_mark)
            out[key_node.value] = self.construct_object(value_node, deep=deep)  # type: ignore[attr-defined]
        return out


def _custom_tag(loader: Any, suffix: str, node: Any) -> Any:
    if isinstance(node, PScalar):
        return node.value
    if isinstance(node, PSeq):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


class Y11Loader(_RawKeys, yaml.SafeLoader):  # type: ignore[misc]
    bool_values: ClassVar[dict[str, bool]] = {**yaml.SafeLoader.bool_values, "y": True, "n": False}


Y11Loader.yaml_implicit_resolvers = {}
for _ch, _resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items():
    _kept = [
        (t, r) for t, r in _resolvers if t not in ("tag:yaml.org,2002:timestamp", "tag:yaml.org,2002:value")
    ]
    if _kept:
        Y11Loader.yaml_implicit_resolvers[_ch] = _kept
for _ch in "yYnN":
    Y11Loader.yaml_implicit_resolvers.setdefault(_ch, []).insert(
        0, ("tag:yaml.org,2002:bool", re.compile(r"^(?:y|Y|n|N)$"))
    )


class Y12Loader(_RawKeys, yaml.SafeLoader):  # type: ignore[misc]
    pass


Y12Loader.yaml_implicit_resolvers = {}
for _tag, _rx, _first in [
    ("tag:yaml.org,2002:null", r"^(?:~|null|Null|NULL|)$", ["~", "n", "N", ""]),
    ("tag:yaml.org,2002:bool", r"^(?:true|True|TRUE|false|False|FALSE)$", list("tTfF")),
    ("tag:yaml.org,2002:int", r"^(?:[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+)$", list("-+0123456789")),
    (
        "tag:yaml.org,2002:float",
        r"^(?:[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$",
        list("-+0123456789."),
    ),
    ("tag:yaml.org,2002:merge", r"^(?:<<)$", ["<"]),
]:
    for _ch in _first:
        Y12Loader.yaml_implicit_resolvers.setdefault(_ch, []).append((_tag, re.compile(_rx)))


def _y12_int(loader: Any, node: Any) -> int:
    v = loader.construct_scalar(node)
    if v.startswith("0o"):
        return int(v[2:], 8)
    if v.startswith("0x"):
        return int(v[2:], 16)
    return int(v, 10)


def _y12_float(loader: Any, node: Any) -> float:
    v = loader.construct_scalar(node).lower()
    if v.endswith(".inf"):
        return -math.inf if v.startswith("-") else math.inf
    if v.endswith(".nan"):
        return math.nan
    return float(v)


Y12Loader.add_constructor("tag:yaml.org,2002:int", _y12_int)
Y12Loader.add_constructor("tag:yaml.org,2002:float", _y12_float)
Y11Loader.add_multi_constructor("!", _custom_tag)
Y12Loader.add_multi_constructor("!", _custom_tag)


def _norm(v: Any) -> Any:
    """Comparable form: NaN-safe, and bool/int/float kept apart."""
    if isinstance(v, float) and math.isnan(v):
        return ("nan",)
    if isinstance(v, dict):
        return {k: _norm(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_norm(x) for x in v]
    if isinstance(v, (bool, int, float)):
        return (type(v).__name__, v)
    return v


def assert_values_match(text: str, schema: str) -> bool:
    """Where PyYAML loads ``text``, yamlite must load the same values. Returns PyYAML's verdict."""
    try:
        expected = list(yaml.load_all(text, Loader=Y11Loader if schema == "yaml11" else Y12Loader))
    except yaml.YAMLError:
        return False
    docs = Y.load_all(text, schema)
    errors = [str(d.error) for d in docs if d.error is not None]
    assert not errors, f"yamlite rejects what PyYAML accepts: {errors}\n{text!r}"
    got = [Y.to_python(d) for d in docs]
    assert _norm(got) == _norm(expected), (
        f"values differ ({schema})\n{text!r}\n got: {got!r}\nwant: {expected!r}"
    )
    return True


def assert_nodes_match(text: str) -> bool:
    """Structure, scalar text, styles, keys and start/end offsets agree with PyYAML's node graph."""
    try:
        expected = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    except yaml.YAMLError:
        return False
    docs = Y.load_all(text)
    assert [str(d.error) for d in docs if d.error is not None] == [], text
    assert len(docs) == len(expected), text
    seen: set[tuple[int, int]] = set()
    for doc, pnode in zip(docs, expected, strict=True):
        _cmp(doc.root, pnode, text, seen)
    return True


def _cmp(n: Any, p: Any, text: str, seen: set[tuple[int, int]]) -> None:
    if (id(n), id(p)) in seen:
        return
    seen.add((id(n), id(p)))
    where = f"at line {p.start_mark.line + 1} col {p.start_mark.column + 1} of {text!r}"
    if isinstance(p, PScalar):
        assert isinstance(n, Y.ScalarNode), where
        assert (n.raw, n.style) == (p.value, _STYLE[p.style]), where
        if n.raw and n.tag is None and n.anchor is None and n.style not in ("literal", "folded"):
            assert (n.start, n.end) == (p.start_mark.index, p.end_mark.index), where
        return
    if isinstance(p, PSeq):
        assert isinstance(n, Y.SeqNode) and len(n.items) == len(p.value), where
        if p.flow_style and n.tag is None and n.anchor is None:
            assert (n.start, n.end) == (p.start_mark.index, p.end_mark.index), where
        for a, b in zip(n.items, p.value, strict=True):
            _cmp(a, b, text, seen)
        return
    assert isinstance(p, PMap) and isinstance(n, Y.MapNode), where
    if any(isinstance(k, PScalar) and k.tag == "tag:yaml.org,2002:merge" for k, _ in p.value):
        return  # merges are compared at the value level
    assert len(n.items) == len(p.value), where
    if p.flow_style and n.tag is None and n.anchor is None and text[n.start] == "{":
        assert (n.start, n.end) == (p.start_mark.index, p.end_mark.index), where
    for (k, v), (pk, pv) in zip(n.items, p.value, strict=True):
        assert isinstance(pk, PScalar), where
        assert (k.raw, k.style) == (pk.value, _STYLE[pk.style]), where
        if k.tag is None and k.anchor is None and text[k.start] != "*":
            assert (k.start, k.end) == (pk.start_mark.index, pk.end_mark.index), where
        _cmp(v, pv, text, seen)


def _dump(n: Any) -> Any:
    if isinstance(n, Y.ScalarNode):
        return ("S", n.raw, n.style, n.tag, n.anchor, n.start, n.end)
    if isinstance(n, Y.SeqNode):
        return ("Q", n.tag, n.anchor, n.start, n.end, [_dump(x) for x in n.items])
    items = [(k.raw, k.style, k.tag, k.anchor, k.start, k.end, _dump(v)) for k, v in n.items]
    return ("M", n.tag, n.anchor, n.start, n.end, items)


def _trees(text: str, helm: bool) -> list[Any]:
    return [
        (d.start, d.end, d.error.message if d.error else None, _dump(d.root) if d.root is not None else None)
        for d in Y.load_all(text, lenient_helm=helm)
    ]


def assert_fast_paths_match(text: str) -> None:
    """The single-regex fast paths must build exactly what the general parser builds."""
    for helm in (False, True):
        fast = _trees(text, helm)
        Y._FAST_PATHS = False
        try:
            slow = _trees(text, helm)
        finally:
            Y._FAST_PATHS = True
        assert fast == slow, f"fast paths differ (helm={helm}) on {text!r}"


# --------------------------------------------------------------------------- realistic corpus

CORPUS: dict[str, str] = {}

CORPUS["k8s-deployment.yaml"] = r"""# Source: pricing-api/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pricing-api
  namespace: trading
  labels:
    app.kubernetes.io/name: pricing-api
    app.kubernetes.io/version: "1.4.2"
  annotations:
    kubernetes.io/change-cause: "bump to 1.4.2"
    prometheus.io/scrape: 'true'
    prometheus.io/port: "9102"
spec:
  replicas: 3
  revisionHistoryLimit: 5
  strategy:
    type: RollingUpdate
    rollingUpdate: {maxSurge: 25%, maxUnavailable: 0}
  selector:
    matchLabels:
      app.kubernetes.io/name: pricing-api
  template:
    metadata:
      labels:
        app.kubernetes.io/name: pricing-api
    spec:
      serviceAccountName: pricing-api
      automountServiceAccountToken: false
      hostNetwork: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        fsGroup: 2000
        seccompProfile:
          type: RuntimeDefault
      initContainers:
        - name: migrate
          image: registry.example.com/pricing-api:1.4.2@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
          command: ["/app/migrate", "--to", "latest"]
          envFrom:
            - secretRef:
                name: pricing-db
      containers:
        - name: api
          image: "registry.example.com/pricing-api:1.4.2"
          imagePullPolicy: IfNotPresent
          args:
            - --port=8080
            - --log-level=info
            - "--feature-flags=a,b,c"
          ports:
            - name: http
              containerPort: 8080
              protocol: TCP
            - {name: metrics, containerPort: 9102}
          env:
            - name: DB_HOST
              value: postgres.trading.svc.cluster.local
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef: {name: pricing-db, key: password}
            - name: JAVA_OPTS
              value: >-
                -XX:MaxRAMPercentage=75
                -XX:+UseG1GC
            - name: EMPTY
              value: ""
          resources:
            requests: {cpu: 250m, memory: 512Mi}
            limits:
              cpu: "1"
              memory: 1Gi
          livenessProbe:
            httpGet: {path: /healthz, port: http}
            initialDelaySeconds: 10
            periodSeconds: 15
          readinessProbe:
            exec:
              command:
                - sh
                - -c
                - 'curl -fsS http://localhost:8080/ready || exit 1'
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
              add: []
          volumeMounts:
            - name: config
              mountPath: /etc/pricing
              readOnly: true
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: config
          configMap:
            name: pricing-api
            defaultMode: 0440
        - name: tmp
          emptyDir: {}
      tolerations:
        - key: "dedicated"
          operator: "Equal"
          value: "trading"
          effect: "NoSchedule"
---
apiVersion: v1
kind: Service
metadata:
  name: pricing-api
  namespace: trading
spec:
  type: ClusterIP
  selector:
    app.kubernetes.io/name: pricing-api
  ports:
  - name: http
    port: 80
    targetPort: http
  - name: metrics
    port: 9102
    targetPort: 9102
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: pricing-api
data:
  app.properties: |
    server.port=8080
    feed.url=wss://feed.example.com/v2
    # comment kept inside the literal
    retries=3

  entrypoint.sh: |-
    #!/bin/sh
    set -eu
    exec /app/server "$@"
  empty: ""
  multi: "line one
    line two"
"""

CORPUS["k8s-privileged.yaml"] = r"""apiVersion: v1
kind: Pod
metadata:
  name: node-exporter
  namespace: monitoring
spec:
  hostPID: true
  hostIPC: yes
  hostNetwork: on
  containers:
  - name: exporter
    image: quay.io/prometheus/node-exporter:v1.8.1
    securityContext:
      privileged: true
      capabilities:
        add: ["SYS_ADMIN", "NET_ADMIN"]
    volumeMounts:
    - {name: root, mountPath: /host, readOnly: true}
  volumes:
  - name: root
    hostPath:
      path: /
      type: Directory
...
"""

CORPUS["k8s-rbac.yaml"] = r"""apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ci-deployer
rules:
- apiGroups: ["", "apps", "batch"]
  resources: ["deployments", "jobs", "pods", "pods/log"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ['*']
  resources: ['*']
  verbs: ['*']
- nonResourceURLs: ["/metrics"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ci-deployer
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ci-deployer
subjects:
  - kind: ServiceAccount
    name: ci
    namespace: ci
  - kind: Group
    name: system:authenticated
    apiGroup: rbac.authorization.k8s.io
"""

CORPUS["k8s-cronjob.yaml"] = r"""apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly-report
spec:
  schedule: "*/5 * * * *"
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 3
  jobTemplate:
    spec:
      backoffLimit: 2
      template:
        spec:
          restartPolicy: OnFailure
          containers:
            - name: report
              image: alpine:3.20
              command:
                - /bin/sh
                - -c
                - |
                  apk add --no-cache curl
                  curl -sSL https://reports.example.com/run \
                    -H "Authorization: Bearer ${TOKEN}" \
                    --data-binary @/data/report.json
              env:
                - name: TOKEN
                  valueFrom:
                    secretKeyRef:
                      name: report-token
                      key: token
"""

CORPUS["kustomization.yaml"] = r"""apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: trading
resources:
  - ../../base
  - ingress.yaml
images:
  - name: registry.example.com/pricing-api
    newTag: 1.4.2
patches:
  - path: replicas.yaml
    target:
      kind: Deployment
      name: pricing-api
configMapGenerator:
  - name: pricing-env
    literals:
      - LOG_LEVEL=debug
      - FEATURE_X=on
commonLabels:
  team: quant
"""

CORPUS["gha-pr-target.yml"] = r"""name: PR build
on:
  pull_request_target:
    types: [opened, synchronize, reopened]
    branches:
      - main
      - 'release/**'
  workflow_dispatch:
    inputs:
      debug:
        description: "Enable debug"
        required: false
        default: false
        type: boolean

permissions:
  contents: read
  pull-requests: write

concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true

env:
  NODE_VERSION: 20
  FORCE_COLOR: "1"

jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest]
        node: [ 18, 20, 22 ]
        include:
          - os: ubuntu-latest
            experimental: true
    steps:
      - uses: actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab # v3.5.2
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false
      - name: Setup node
        uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node }}
          cache: npm
      - run: npm ci
      - name: Test
        if: ${{ !cancelled() && matrix.os == 'ubuntu-latest' }}
        run: |
          npm test -- --coverage
          echo "title=${{ github.event.pull_request.title }}" >> "$GITHUB_OUTPUT"
        env:
          CI: true
          TOKEN: ${{ secrets.NPM_TOKEN }}
      - name: Comment
        if: github.event_name == 'pull_request_target' && success()
        uses: actions/github-script@v7
        with:
          script: |
            const body = `Build ok for ${context.payload.pull_request.head.ref}`;
            await github.rest.issues.createComment({ ...context.repo, issue_number: context.issue.number, body });
  deploy:
    needs: [build]
    if: >-
      github.ref == 'refs/heads/main' &&
      github.event_name != 'pull_request_target'
    runs-on: [self-hosted, linux, x64]
    environment:
      name: production
      url: https://pricing.example.com
    steps:
      - uses: ./.github/actions/deploy
        with: {env: production, dry-run: "false"}
"""

CORPUS["gha-on-scalar.yml"] = (
    "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
)
CORPUS["gha-on-flow-seq.yml"] = (
    "on: [push, pull_request_target]\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
    "    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.ref }}\n"
)
CORPUS["gha-on-block-seq.yml"] = "on:\n  - push\n  - pull_request_target\njobs: {}\n"
CORPUS["gha-on-double-quoted.yml"] = '"on":\n  pull_request_target:\njobs: {}\n'
CORPUS["gha-on-single-quoted.yml"] = "'on':\n  push:\n    branches: [main]\njobs: {}\n"
CORPUS["gha-true-key.yml"] = "true: pull_request_target\njobs: {}\n"

CORPUS["gha-composite-action.yml"] = r"""name: 'Deploy'
description: 'Deploys the service'
inputs:
  env:
    description: 'Target environment'
    required: true
  dry-run:
    description: 'Only print'
    default: 'false'
outputs:
  url:
    description: "Deployed URL"
    value: ${{ steps.deploy.outputs.url }}
runs:
  using: "composite"
  steps:
    - id: deploy
      shell: bash
      run: |
        set -euo pipefail
        if [ "${{ inputs.dry-run }}" = "true" ]; then
          echo "would deploy ${{ inputs.env }}"
        else
          ./deploy.sh "${{ inputs.env }}"
        fi
        echo "url=https://${{ inputs.env }}.example.com" >> "$GITHUB_OUTPUT"
"""

CORPUS["docker-compose.yml"] = r"""version: "3.9"

x-common: &common
  restart: unless-stopped
  logging:
    driver: json-file
    options: {max-size: "10m", max-file: "3"}
  environment: &common-env
    TZ: UTC
    LOG_LEVEL: info

x-healthcheck: &hc
  interval: 30s
  timeout: 5s
  retries: 3

services:
  db:
    <<: *common
    image: postgres:16.3
    environment:
      <<: *common-env
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
      POSTGRES_DB: pricing
    volumes:
      - db-data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    healthcheck:
      <<: *hc
      test: ["CMD-SHELL", "pg_isready -U postgres"]
    secrets: [db_password]
  api:
    <<: *common
    build:
      context: .
      dockerfile: Dockerfile
      args:
        - GIT_SHA=${GIT_SHA:-dev}
    ports:
      - "8080:8080"
      - 9102:9102
      - "127.0.0.1:5005:5005"
    depends_on:
      db:
        condition: service_healthy
    command: >
      /app/server
      --port 8080
      --db postgres://db:5432/pricing
    privileged: false
    cap_add: [NET_BIND_SERVICE]
    network_mode: bridge
    restart: always
  worker:
    <<: [*common]
    image: registry.example.com/worker:latest
    deploy:
      replicas: 2
      resources:
        limits: {cpus: '0.50', memory: 256M}
    environment:
      - QUEUE=prices
      - "CONCURRENCY=4"

volumes:
  db-data: {}

secrets:
  db_password:
    file: ./secrets/db_password.txt
"""

CORPUS["helm-values.yaml"] = r"""# Default values for pricing-api.
replicaCount: 1

image:
  repository: registry.example.com/pricing-api
  pullPolicy: IfNotPresent
  # Overrides the image tag whose default is the chart appVersion.
  tag: ""

imagePullSecrets: []
nameOverride: ""
fullnameOverride: ""

serviceAccount:
  create: true
  annotations: {}
  name: ""

podAnnotations: {}

podSecurityContext: {}
  # fsGroup: 2000

securityContext: {}
  # capabilities:
  #   drop:
  #   - ALL
  # readOnlyRootFilesystem: true

service:
  type: ClusterIP
  port: 80

ingress:
  enabled: false
  className: ""
  annotations: {}
    # kubernetes.io/ingress.class: nginx
  hosts:
    - host: chart-example.local
      paths:
        - path: /
          pathType: ImplementationSpecific
  tls: []

resources: {}
autoscaling:
  enabled: false
  minReplicas: 1
  maxReplicas: 100
  targetCPUUtilizationPercentage: 80
nodeSelector: {}
tolerations: []
affinity: {}
extraEnv:
  FEATURE_FLAG: off
  RETRIES: 017
  RATIO: 0.75
  PORT_MAP: 22:22
"""

CORPUS["ansible-site.yml"] = r"""---
- name: Configure web servers
  hosts: webservers
  become: yes
  gather_facts: true
  vars:
    http_port: 80
    max_clients: 200
    packages:
      - nginx
      - python3-pip
    db_password: !vault |
      $ANSIBLE_VAULT;1.1;AES256
      62313365396662343061393464336163383764373764613633653634306231386433626436623361
      6134333665353966363534333632666535333761666131620a663537646436643839616531643561
  pre_tasks:
    - name: Update apt cache
      apt: update_cache=yes cache_valid_time=3600
      when: ansible_os_family == "Debian"
  tasks:
    - name: Install packages
      ansible.builtin.package:
        name: "{{ item }}"
        state: present
      loop: "{{ packages }}"
    - name: Template config
      template:
        src: templates/nginx.conf.j2
        dest: /etc/nginx/nginx.conf
        mode: '0644'
      notify:
        - restart nginx
    - name: Run a shell command
      shell: |
        curl -fsSL https://get.example.com | sh
      args:
        creates: /usr/local/bin/example
      no_log: True
    - block:
        - name: Try something
          command: /bin/false
      rescue:
        - debug: msg="it failed"
      always:
        - debug:
            msg: "always runs"
  handlers:
    - name: restart nginx
      service: name=nginx state=restarted

- hosts: dbservers
  remote_user: root
  tasks:
    - name: Ensure postgres
      yum: name=postgresql state=latest
      tags: [db, packages]
"""

CORPUS["gitlab-ci.yml"] = r""".defaults: &defaults
  image: python:3.12-slim
  before_script:
    - pip install -r requirements.txt
  tags: [docker]

stages: [lint, test, deploy]

variables:
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"
  GIT_DEPTH: 10

lint:
  <<: *defaults
  stage: lint
  script:
    - ruff check .
    - mypy src

test:
  <<: *defaults
  stage: test
  script:
    - pytest -q
  coverage: '/TOTAL.*\s+(\d+%)$/'
  artifacts:
    reports:
      junit: report.xml
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

deploy:
  stage: deploy
  image: alpine:3.20
  script:
    - 'curl -X POST -H "Authorization: Bearer $DEPLOY_TOKEN" https://deploy.example.com/hooks/pricing'
  only:
    - main
  when: manual
"""

CORPUS["cloudformation.yaml"] = r"""AWSTemplateFormatVersion: "2010-09-09"
Description: >
  Bucket and role for the pricing service.
Parameters:
  Env:
    Type: String
    AllowedValues: [dev, prod]
Conditions:
  IsProd: !Equals [!Ref Env, prod]
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub "pricing-${Env}-${AWS::AccountId}"
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: !If [IsProd, true, false]
      Tags:
        - Key: team
          Value: quant
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: {Service: [lambda.amazonaws.com]}
            Action: sts:AssumeRole
      Policies:
        - PolicyName: all
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action: "*"
                Resource: !GetAtt Bucket.Arn
Outputs:
  BucketArn:
    Value: !GetAtt [Bucket, Arn]
    Export:
      Name: !Join ["-", [!Ref Env, bucket]]
"""

CORPUS["tekton-pipeline.yaml"] = r"""apiVersion: tekton.dev/v1
kind: Pipeline
metadata:
  name: build-and-push
spec:
  params:
    - name: image
      type: string
    - name: revision
      default: main
  workspaces:
    - name: source
  tasks:
    - name: clone
      taskRef:
        name: git-clone
        kind: ClusterTask
      params:
        - name: url
          value: $(params.repo-url)
        - name: revision
          value: $(params.revision)
      workspaces:
        - {name: output, workspace: source}
    - name: build
      runAfter: [clone]
      taskSpec:
        steps:
          - name: kaniko
            image: gcr.io/kaniko-project/executor:v1.23.0
            script: |
              #!/busybox/sh
              /kaniko/executor --context=$(workspaces.source.path) \
                --destination=$(params.image)
            securityContext:
              runAsUser: 0
"""

CORPUS["prometheus-rules.yaml"] = r"""groups:
  - name: pricing.rules
    interval: 30s
    rules:
      - alert: PricingApiDown
        expr: up{job="pricing-api"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Pricing API {{ $labels.instance }} down"
          description: >-
            The pricing API on {{ $labels.instance }} has been down
            for more than 5 minutes.


      - record: job:http_requests:rate5m
        expr: |
          sum by (job) (
            rate(http_requests_total[5m])
          )
"""

CORPUS["rule-pack.yaml"] = r"""# rules/domain/gha.yaml
- id: WS-GHA-001
  title: pull_request_target checks out PR head code
  pack: domain/gha
  severity: critical
  confidence: high
  owner: appsec
  cwe: [CWE-94]
  owasp: [CICD-SEC-4]
  applies_to: { kind: ci, glob: [".github/workflows/*.y*ml"] }
  match:
    yaml_path:
      all:
        - path: "on.pull_request_target"          # handles both `on: pull_request_target` and the mapping form
          exists: true
        - path: "jobs.*.steps[*].with.ref"
          regex: "github\\.event\\.pull_request\\.head\\.(sha|ref)"
  message: >
    Workflow runs with a write token and secrets, but checks out untrusted fork code.
  fix: >
    Use `pull_request` for untrusted code, or split into a privileged workflow_run job
    that never executes PR code.
  references: ["https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"]
  fixtures: auto
- id: WS-AGT-MCP-010
  title: MCP server launched from an unpinned package
  pack: agentsec/mcp
  severity: high
  confidence: medium
  owner: agentsec
  references: []
  message: "Pin the package version."
  match:
    yaml_path:
      each: "mcpServers.*"
      all:
        - { path: "command", in: [npx, bunx, pnpx, uvx] }
        - { path: "args[*]", regex: '^(?:@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$' }   # package spec with no @version
"""

CORPUS["openapi.yaml"] = r"""openapi: 3.0.3
info:
  title: Pricing API
  version: 1.4.2
  description: |
    Real-time pricing.

    ## Auth
    Use a bearer token.
paths:
  /prices/{symbol}:
    get:
      summary: Get a price
      parameters:
        - in: path
          name: symbol
          required: true
          schema: {type: string, pattern: '^[A-Z]{1,6}$'}
      responses:
        '200':
          description: OK
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Price'
        "404": {description: Not found}
      security:
        - bearerAuth: []
components:
  securitySchemes:
    bearerAuth: {type: http, scheme: bearer, bearerFormat: JWT}
  schemas:
    Price:
      type: object
      required: [symbol, bid, ask]
      properties:
        symbol: {type: string}
        bid: {type: number, format: double, example: 101.25}
        ask: {type: number, example: 1.0e+2}
        ts: {type: string, format: date-time, example: "2024-05-01T12:00:00Z"}
"""

CORPUS["mcp.json"] = r"""{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/projects"],
      "env": {}
    },
    "github": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server"],
      "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${input:github_token}"}
    },
    "remote": {"type": "http", "url": "https://mcp.example.com/mcp", "headers": {"X-Api": "k\u00e9y \"quoted\" \\ slash\/ok"}},
    "weird": {"disabled": false, "timeout": 30.5, "retries": -1, "ratio": 1e-3, "big": 12345678901234567890, "nothing": null}
  },
  "inputs": [{"type": "promptString", "id": "github_token", "password": true}]
}
"""

CORPUS["package.json"] = (
    r"""{"name":"pricing-ui","version":"1.4.2","private":true,"scripts":{"build":"vite build","postinstall":"node scripts/fetch.js || true"},"dependencies":{"react":"^18.3.1","left-pad":"1.3.0"},"devDependencies":{},"engines":{"node":">=18"},"files":[],"keywords":["a","b"],"nested":[[1,2],[3,[4,[5]]]],"unicode":"\u2603 snow"}"""
)

CORPUS["cfn.json"] = r"""{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Bucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "AccessControl": "PublicRead",
        "Tags": [ { "Key": "a", "Value": "b" } ]
      }
    },
    "Policy": {
      "Type": "AWS::IAM::Policy",
      "Properties": {
        "PolicyDocument": {
          "Statement": [
            {"Effect": "Allow", "Action": ["s3:*"], "Resource": {"Fn::Join": ["", ["arn:aws:s3:::", {"Ref": "Bucket"}, "/*"]]}}
          ]
        }
      }
    }
  }
}
"""

CORPUS["main.tf.json"] = r"""{
  "terraform": {"required_version": ">= 1.5.0"},
  "provider": {"aws": [{"region": "eu-west-1"}]},
  "resource": {
    "aws_security_group": {
      "open": {
        "name": "open",
        "ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"], "description": "", "ipv6_cidr_blocks": [], "prefix_list_ids": [], "security_groups": [], "self": false}]
      }
    }
  }
}
"""

CORPUS["misc-scalars.yaml"] = r"""plain: some text here
url: http://example.com:8080/path?q=1#frag
colon_in_value: a:b:c
hash_in_value: C# is fine
windows: C:\Users\me
quoted_hash: "# not a comment"
single: 'it''s ok'
double_escapes: "tab\tnewline\nquote\"backslash\\ unicode\u00e9 \x41"
emptyval:
tilde: ~
nulls: [null, Null, NULL, ~, ]
bools11: [yes, No, ON, off, y, N, true, FALSE]
ints: [0, -12, +7, 017, 0o17, 0x1F, 1_000, 0b101, 22:22]
floats: [1.5, -0.25, .5, 1., 1e3, 1.0e+3, .inf, -.Inf, .NaN, 1_000.5, 190:20:30.15]
not_numbers: [1.2.3, 0x, 0o, "12", 1e, e3, 12abc, "0x1F", -, --1]
dates: [2001-12-14, 2001-12-14t21:59:43.10-05:00]
version: 1.20
multi_plain: this is
  a multi line
  plain scalar

  with a blank line
folded: >
  folded text
  continues here

  new paragraph
    more indented
  back
literal_keep: |+
  keep trailing

literal_strip: |-
  strip trailing
indent_indicator: |2
    two extra spaces
   one extra
long_key_with_spaces   : value
"quoted key": 1
'single key': 2

"""

CORPUS["anchors.yaml"] = r"""base: &base
  name: base
  tags: &tags [a, b]
  nested: &nested {x: 1, y: [1, 2]}
derived:
  <<: *base
  name: derived
  extra: *tags
list:
  - *nested
  - &item7 seven
  - *item7
multi:
  <<: [*nested, {z: 3, x: 99}]
  y: override
flowmerge: {<<: *nested, x: 5}
empty_anchor: &e
ref_empty: *e
"""

CORPUS["argo-workflow.yaml"] = r"""apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: nightly-
spec:
  entrypoint: main
  arguments:
    parameters: [{name: date, value: "{{workflow.creationTimestamp}}"}]
  templates:
  - name: main
    steps:
    - - name: extract
        template: run
        arguments: {parameters: [{name: cmd, value: extract}]}
    - - name: load
        template: run
  - name: run
    inputs:
      parameters:
      - name: cmd
    container:
      image: python:3.12
      command: [python, -c]
      args: ["import sys; print(sys.argv)", "{{inputs.parameters.cmd}}"]
"""

CORPUS["pre-commit-config.yaml"] = r"""repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.5.0
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format
  - repo: local
    hooks:
      - id: whalescan
        name: whalescan
        entry: whalescan scan --fail-on high
        language: system
        pass_filenames: false
        always_run: true
"""

CORPUS["dependabot.yml"] = r"""version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
    open-pull-requests-limit: 5
    labels: [dependencies, ci]
    ignore:
      - dependency-name: "actions/*"
        update-types: ["version-update:semver-major"]
"""

CORPUS["networkpolicy.yaml"] = r"""kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: default-deny
  namespace: trading
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.169.254/32
    ports:
    - {protocol: TCP, port: 443}
    - protocol: UDP
      port: 53
"""


@pytest.mark.parametrize("name", sorted(CORPUS))
def test_corpus_nodes_match_pyyaml(name: str) -> None:
    assert assert_nodes_match(CORPUS[name]), "the corpus must be valid for PyYAML"


@pytest.mark.parametrize("schema", ["yaml11", "yaml12"])
@pytest.mark.parametrize("name", sorted(CORPUS))
def test_corpus_values_match_pyyaml(name: str, schema: str) -> None:
    assert assert_values_match(CORPUS[name], schema)


@pytest.mark.parametrize("name", sorted(CORPUS))
def test_corpus_fast_paths_match_general_parser(name: str) -> None:
    assert_fast_paths_match(CORPUS[name])


@pytest.mark.parametrize("name", sorted(n for n in CORPUS if n.endswith(".json")))
def test_json_corpus_matches_the_json_module(name: str) -> None:
    text = CORPUS[name]
    assert Y.to_python(Y.load(text)) == json.loads(text)
    indented = json.dumps(json.loads(text), indent="\t")  # tab-indented JSON is valid YAML 1.2 flow
    assert Y.to_python(Y.load(indented)) == json.loads(text)


@pytest.mark.parametrize("name", sorted(CORPUS))
def test_corpus_positions_agree_with_the_engine_line_index(name: str) -> None:
    from whalescan.model import FileCtx

    text = CORPUS[name]
    ctx = FileCtx(path=name, text=text)
    for doc in Y.load_all(text):
        assert doc.root is not None
        nodes: list[Any] = [doc.root, *doc.root.descendants()]
        nodes += [k for n in nodes if isinstance(n, Y.MapNode) for k, _ in n.items]
        for n in nodes:
            assert 0 <= n.start <= n.end <= len(text)
            assert (n.line, n.col) == ctx.pos(n.start)
            if n.end > n.start:
                assert (n.end_line, n.end_col) == ctx.end_pos(n.end)
            assert n.source == text[n.start : n.end]
            if isinstance(n, Y.ScalarNode) and n.style == "plain" and "\n" not in n.source:
                assert n.source == n.raw


# --------------------------------------------------------------------------- generated documents

_TRICKY = [
    "yes", "no", "on", "off", "y", "n", "true", "null", "~", "", "0x1F", "017", "0o17", "1_000", "22:22",
    "1e3", ".5", "- a", "a: b", "#x", "'", '"', "{", "[", "&a", "*a", "!t", "|", ">", "%", "@", "`",
    " lead", "trail ", "a #b", "a#b", "a:b", "http://x:1/y", "multi\nline", "tab\there", "\\", "<<", "---",
    "...", "é", " nbsp", "{{ tpl }}", "${{ expr }}", "a, b", "[x]",
]  # fmt: skip
_TEXT = st.text(
    st.characters(blacklist_categories=("Cs", "Cc"), blacklist_characters="  \x85﻿"), max_size=12
) | st.sampled_from(_TRICKY)
_SCALARS = st.none() | st.booleans() | st.integers(-(10**12), 10**12) | st.floats(allow_nan=False) | _TEXT
_KEYS = _TEXT.filter(lambda k: k != "" and "\n" not in k and len(k) < 100)  # PyYAML emits `? ` otherwise
_VALUES = st.recursive(
    _SCALARS,
    lambda inner: st.lists(inner, max_size=4) | st.dictionaries(_KEYS, inner, max_size=4),
    max_leaves=25,
)


_DUMP_OPTIONS = st.fixed_dictionaries(
    {
        "default_flow_style": st.sampled_from([False, True, None]),
        "indent": st.sampled_from([2, 3, 4]),
        "width": st.sampled_from([12, 40, 1000]),
        "allow_unicode": st.booleans(),
        "explicit_end": st.booleans(),
        "default_style": st.sampled_from([None, None, '"', "'"]),
    }
)


@given(st.lists(_VALUES, min_size=1, max_size=3), _DUMP_OPTIONS)
@settings(max_examples=250, deadline=None, suppress_health_check=list(HealthCheck))
def test_pyyaml_dumps_round_trip_identically(docs: list[Any], options: dict[str, Any]) -> None:
    text = yaml.dump_all(docs, explicit_start=len(docs) > 1, sort_keys=False, **options)
    assert assert_nodes_match(text)
    assert assert_values_match(text, "yaml12")
    assert assert_values_match(text, "yaml11")
    assert_fast_paths_match(text)


# NEL/LS/PS are line breaks for libyaml-family parsers (and yamlite), but plain characters in JSON
_JSON_TEXT = st.text(
    st.characters(blacklist_categories=("Cs",), blacklist_characters="\x85\u2028\u2029"), max_size=10
)
_JSON = st.recursive(
    st.none() | st.booleans() | st.integers(-(10**20), 10**20) | st.floats(allow_nan=False, allow_infinity=False)
    | _JSON_TEXT,
    lambda inner: st.lists(inner, max_size=4) | st.dictionaries(_JSON_TEXT, inner, max_size=4),
    max_leaves=25,
)  # fmt: skip


@given(_JSON, st.sampled_from([None, 0, 2, "\t"]), st.booleans(), st.booleans())
@settings(max_examples=250, deadline=None)
def test_json_parses_like_the_json_module(value: Any, indent: Any, ascii_only: bool, compact: bool) -> None:
    text = json.dumps(
        value, indent=indent, ensure_ascii=ascii_only, separators=(",", ":") if compact else None
    )
    assert _norm(Y.to_python(Y.load(text))) == _norm(json.loads(text))
    assert Y.load(text, "yaml11") is not None


_WORDS = st.sampled_from(
    ["a", "b", "key", "on", "yes", "1", "0x1F", "1.5", "~", "null", "x y", "a:b", "a#b", "http://h:1", "-x", "?x",
     ":x", "<<", "$v", "${{ e }}", "é", "a,b", "a]", "a}", "{{ t }}"]
)  # fmt: skip
_TOKENS = st.one_of(
    _WORDS,
    st.sampled_from(
        ['""', '"a b"', '"a\\tb"', '"q\\"q"', '"a: b"', '"#"', '"\\u00e9"', "'it''s'", "'a: b'", "''"]
    ),
    st.sampled_from(
        ["[a, b]", "[]", "{}", "{a: 1, b: [2, 3]}", "[a: b, c]", "{a, b}", "[a,", "{a: 1", "[\n", "{\n"]
    ),
    st.sampled_from(["*a1", "*a2", "&a1 x", "&a2 [1, 2]", "!t v", "!!str 1", "&a1", "!!int '3'"]),
    st.sampled_from(["|", "|-", "|+", ">", ">-", "|2", ">1+", "|  # c"]),
    st.just(""),
)
_LINE = st.builds(
    lambda ind, dashes, key, sep, val, com: (
        " " * ind + "- " * dashes + (key + sep if key else "") + val + com
    ),
    st.integers(0, 6),
    st.integers(0, 2),
    st.none() | _WORDS | st.sampled_from(['"q k"', "'s k'", "&a1 k", "<<"]),
    st.sampled_from([": ", ":", " : "]),
    _TOKENS,
    st.sampled_from(["", "", " # c", "#c", "  "]),
)
_SPECIAL = st.sampled_from(
    ["---", "...", "--- x", "# comment", "", "  ", "%YAML 1.2", "--- |", "  text", "    more"]
)
_YAMLISH = st.lists(_LINE | _SPECIAL, min_size=1, max_size=12).map(lambda ls: "\n".join(ls) + "\n")


def _pyyaml_accepts_without_known_deviations(text: str) -> bool:
    try:
        trees = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    except yaml.YAMLError:
        return False

    def bad(node: Any, stack: frozenset[int]) -> bool:
        if id(node) in stack:
            return True  # recursive alias
        if isinstance(node, PMap):
            s = stack | {id(node)}
            return any(not isinstance(k, PScalar) or bad(k, s) or bad(v, s) for k, v in node.value)
        if isinstance(node, PSeq):
            return any(bad(x, stack | {id(node)}) for x in node.value)
        return False

    if any(t is not None and bad(t, frozenset()) for t in trees):
        return False
    if "? " in text or text.startswith("?") or "\n?" in text or "! " in text:
        return False
    try:
        list(yaml.load_all(text, Loader=Y12Loader))  # merge keys are validated at load time
    except (yaml.YAMLError, ValueError, TypeError):
        return False  # e.g. `!!int x`, which PyYAML cannot construct and yamlite keeps as a string
    return True


def _check_any_text(text: str) -> bool:
    """No crash (only YamlError), fast paths == general parser, and PyYAML agreement."""
    for schema in ("yaml11", "yaml12"):
        for helm in (False, True):
            for doc in Y.load_all(text, schema, helm):
                if doc.error is None:
                    assert doc.root is not None
                    Y.to_python(doc)
                    for _ in doc.root.descendants():
                        pass
                else:
                    assert isinstance(doc.error, Y.YamlError)
    assert_fast_paths_match(text)
    if not _pyyaml_accepts_without_known_deviations(text):
        return False
    assert assert_nodes_match(text)
    assert_values_match(text, "yaml12")
    assert_values_match(text, "yaml11")
    return True


@given(_YAMLISH)
@settings(max_examples=400, deadline=None, suppress_health_check=list(HealthCheck))
def test_random_yamlish_text_matches_pyyaml(text: str) -> None:
    _check_any_text(text)


_PIECES = [
    " ", "  ", "\n", "- ", ": ", ":", "#", "'", '"', "[", "]", "{", "}", ",", "&a ", "*a", "!t ", "|", ">",
    "\t", "---\n", "...\n", "? ", "%YAML 1.2\n", "\\", "x",
]  # fmt: skip


def _mutate(rng: random.Random, text: str) -> str:
    for _ in range(rng.randint(1, 4)):
        op = rng.random()
        p = rng.randrange(len(text) + 1)
        if op < 0.35:
            text = text[:p] + rng.choice(_PIECES) + text[p:]
        elif op < 0.65:
            text = text[:p] + text[min(len(text), p + rng.randint(1, 6)) :]
        else:
            lines = text.split("\n")
            k = rng.randrange(len(lines))
            if op < 0.85:
                lines[k] = (
                    " " * rng.randint(0, 3) + lines[k].lstrip(" ") if rng.random() < 0.5 else lines[k][1:]
                )
            else:
                lines.insert(k, lines[k])
            text = "\n".join(lines)
    return text


@pytest.mark.parametrize("seed", range(4))
def test_mutated_corpus_documents_match_pyyaml(seed: int) -> None:
    rng = random.Random(seed)  # noqa: S311 - deterministic test input, not cryptography
    names = sorted(CORPUS)
    accepted = 0
    for _ in range(150):
        text = _mutate(rng, CORPUS[rng.choice(names)])
        accepted += _check_any_text(text)
    assert accepted > 20  # the comparison is exercised, not vacuous


# --------------------------------------------------------------------------- performance


def _best_mb_per_s(text: str, rounds: int = 5) -> float:
    Y.load_all(text)
    best = math.inf
    for _ in range(rounds):
        t0 = time.perf_counter()
        docs = Y.load_all(text)
        best = min(best, time.perf_counter() - t0)
    assert all(d.error is None for d in docs)
    return len(text.encode()) / best / 1e6


def _traced() -> bool:
    return sys.gettrace() is not None or "coverage" in sys.modules


def test_parse_time_is_linear() -> None:
    small = "---\n".join([CORPUS["k8s-deployment.yaml"]] * 8)
    large = "---\n".join([CORPUS["k8s-deployment.yaml"]] * 64)
    ratio = _best_mb_per_s(small) / _best_mb_per_s(large)
    assert ratio < 2.0, ratio  # throughput must not collapse on 8x the input


@pytest.mark.skipif(_traced(), reason="throughput is meaningless under a tracer or coverage")
def test_throughput_sanity() -> None:
    manifests = "---\n".join([CORPUS["k8s-deployment.yaml"]] * 60)
    assert _best_mb_per_s(manifests) >= 2.0


@pytest.mark.slow
@pytest.mark.skipif(_traced(), reason="throughput is meaningless under a tracer or coverage")
@pytest.mark.parametrize("name", ["k8s-deployment.yaml", "gha-pr-target.yml", "ansible-site.yml"])
def test_throughput_target_on_typical_manifests(name: str) -> None:
    text = "---\n".join([CORPUS[name].removeprefix("---\n")] * 60)
    assert _best_mb_per_s(text) >= 5.0
