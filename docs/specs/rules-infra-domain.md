# WhaleSecurity — Infra and Domain Rule Catalog (v1)

This spec is the v1 rule catalog for the `whalescan` infrastructure and domain packs. It covers Kubernetes, Helm and
operators; Dockerfile and Compose; Terraform and Terragrunt on AWS and GCP; CI/CD (GitHub Actions, Tekton, Flux, a
little GitLab CI); reverse proxies (NGINX, Traefik, Coolify); FastAPI; Airflow; Spark; LLM, RAG and agents on
Bedrock and Vertex AI; and trading systems. Each rule gets an ID, a title, severity and confidence, CWE and
benchmark references, target files, a matcher, the exact detection expression, false-positive guards and a fix.
With that, pack files and fixtures can be written without making further design decisions. The catalog builds on
DESIGN.md §4–§5 and on the engine spec (`docs/specs/engine.md` §6–§8). Anything here that changes either document
is listed in §14.

**Contents:** 1 Packs, notation and shared rules · 2 Kubernetes, Helm, operators (`WS-K8S`) · 3 Dockerfile and
Compose (`WS-DKR`) · 4 Terraform, Terragrunt, AWS, GCP (`WS-TF`) · 5 CI/CD (`WS-GHA`, `-TKN`, `-FLX`, `-GLC`) ·
6 Reverse proxies (`WS-WEB-PRX`) · 7 FastAPI (`WS-API`) · 8 Airflow (`WS-AIR`) · 9 Spark (`WS-SPK`) · 10 LLM, RAG,
agents (`WS-LLM`) · 11 Trading (`WS-TRD`) · 12 Four complete rules with fixtures · 13 Test plan · 14 Refinements to
DESIGN.md

---

## 1. Packs, notation and shared rules

### 1.1 Packs

| Namespace | Pack | File | Owner | Rules | † ext |
|---|---|---|---|---|---|
| `WS-K8S` | `domain/k8s` | `rules/domain/k8s.yaml` | `@whalesecurity/platform` | 26 | 009, 013, 026 |
| `WS-DKR` | `domain/docker` | `rules/domain/docker.yaml` (Dockerfile 001–011, Compose 020–026) | `@whalesecurity/platform` | 18 | 004 |
| `WS-TF` | `domain/terraform` | `rules/domain/terraform.yaml` (AWS 001–023, GCP 030–040) | `@whalesecurity/cloud` | 34 | 018, 020 |
| `WS-GHA` | `domain/gha` | `rules/domain/gha.yaml` | `@whalesecurity/cicd` | 16 | 004, 006 |
| `WS-GHA-TKN`, `WS-GHA-FLX` | `domain/tekton-flux` | `rules/domain/tekton-flux.yaml` | `@whalesecurity/cicd` | 6 + 6 | TKN-004 |
| `WS-GHA-GLC` | `domain/gitlab` | `rules/domain/gitlab.yaml` | `@whalesecurity/cicd` | 3 | — |
| `WS-WEB-PRX` | `domain/proxy` | `rules/domain/proxy.yaml` (NGINX 001–010, Traefik 020–025, Coolify 030) | `@whalesecurity/platform` | 17 | 009, 010 |
| `WS-API` | `domain/fastapi` | `rules/domain/fastapi.yaml` | `@whalesecurity/appsec` | 10 | — |
| `WS-AIR` | `domain/airflow` | `rules/domain/airflow.yaml` | `@whalesecurity/data` | 9 | — |
| `WS-SPK` | `domain/spark` | `rules/domain/spark.yaml` | `@whalesecurity/data` | 7 | 007 |
| `WS-LLM` | `domain/llm-rag` | `rules/domain/llm-rag.yaml` | `@whalesecurity/ai` | 15 | 010 |
| `WS-TRD` | `domain/trading` | `rules/domain/trading.yaml` | `@whalesecurity/trading` | 13 | 010 |

That is 180 rules in total, 166 of them core. Rules marked **†** carry `tags: [ext]`. They can slip to v1.1 without
changing their IDs, and they are not part of the P3 exit criterion. IDs are never reused. A retired rule gets
`deprecated: true` and `replaced_by`.

### 1.2 Notation

**Columns.** *Sev* is the base severity: C, H, M, L or I for critical, high, medium, low and info. Engine §10 then
adjusts it for reachability and exposure. *Conf* is the confidence: H, M or L. *Refs* lists CWE IDs plus OWASP IDs as
the rule schema spells them (`A01`–`A10`, `API1`–`API10`, `LLM01`–`LLM10`, `CICD-SEC-n`, Kubernetes Top 10 `K01`–`K10`),
MITRE ATLAS `AML.T…` IDs, and these benchmarks:
`CIS-K8s` (CIS Kubernetes Benchmark v1.9), `CIS-Docker` (v1.6), `CIS-AWS` / `CIS-GCP` (Foundations v3.0),
`FSBP` (AWS Foundational Security Best Practices control IDs), `PSS` (Pod Security Standards level) and `NSA-K8s`
(NSA/CISA Kubernetes Hardening Guide v1.2). Benchmark numbers are re-checked at the quarterly rule review
(DESIGN §11). Each rule's `references` URLs are the authoritative source.

**Files column: `applies_to` shorthand.**

| Code | `applies_to` |
|---|---|
| K8S | `{kind: iac, lang: yaml, tags_any: [k8s, helm, kustomize]}`. Helm templates are parsed in lenient mode (engine §8.6) |
| CHART | `{kind: iac, lang: yaml, glob: ["**/Chart.yaml"]}` |
| OP-PY | `{kind: code, lang: python, tags_any: [k8s-operator]}` (files that import `kopf`) |
| DKF · CMP | `{kind: iac, lang: dockerfile}` · `{kind: iac, lang: yaml, tags_any: [compose]}` |
| SH | `{kind: code, lang: shell}` |
| TF | `{kind: iac, lang: [hcl, json], tags_any: [terraform, terragrunt]}` (`*.tf`, `*.tf.json`, `terragrunt.hcl`) |
| TFVARS | `{kind: iac, glob: ["**/*.tfvars", "**/*.auto.tfvars", "**/terragrunt.hcl", "**/*.hcl"]}` |
| POLICY | `{kind: [iac, data], lang: [hcl, json], exclude_glob: ["**/package*.json", "**/tsconfig*.json", "**/*.lock*"]}` |
| GHA · TKN · FLX · GLC | `{kind: ci, lang: yaml, tags_any: [gha, gha-action]}` · `[tekton]` · `[flux]` · `[gitlab]` (tag added in §14) |
| NGX · TRF | `{kind: iac, lang: nginx}` · `{kind: iac, lang: [yaml, toml], tags_any: [traefik]}` |
| PRX-ANY | `{kind: iac, lang: [yaml, toml], tags_any: [traefik, compose, k8s, helm]}`: Traefik CLI flags and labels wherever they live |
| PY-API · PY-AIR · PY-SPK · PY-LLM · PY-TRD | `{kind: code, lang: python, tags_any: [...]}` with `[fastapi]` · `[airflow-dag]` · `[spark]` · `[llm, vectordb]` · `[trading]` |
| PY · SCALA · JS · SQL | `{kind: code, lang: python}` · `{kind: code, lang: scala}` · `{kind: code, lang: [javascript, typescript]}` · `{kind: code, lang: sql}` |
| AIR-CFG | `{kind: [iac, data, code], glob: ["**/airflow.cfg", "**/*.env", "**/{docker-compose,compose}*.y*ml", "**/values*.y*ml", "**/webserver_config.py", "**/Dockerfile*"]}`, `keywords: [airflow]` |
| CFG-ANY | `{kind: [code, iac, ci, data]}`, which is cheap because the rule's keywords gate it |

**Matcher column.** `yp` yaml_path · `rx` regex · `ml` multiline pattern · `seq` multiline sequence · `ast` py_ast
`call` · `route` py_ast `fastapi_route` · `hcl` hcl-lite.

**Detection column.** This is a compact form of the rule's `match`:

- `each P ·` becomes `each: "P"`. Conditions separated by `;` form `all:`. `any(…)` and `none(…)` are those lists.
- `p == v` is `equals` · `p != v` is `not_equals` · `p in […]` / `p not_in […]` · `p ~ R` is `regex` · `p !~ R` is
  `not_regex` · `p ∋ v` is `contains` · `p exists` / `p absent` is `exists: true/false` · `p type str` is `type`.
- `R` is a quoted regex, or `@NAME` for a pattern in the section's pattern block. `@LIST` names a list constant.
- `POD` stands for `**.{containers,initContainers,ephemeralContainers}[*]`. `CTR` stands for `**.{containers,initContainers}[*]`.
- For matchers: `A ∨ B` is `any: [A, B]`. `A ∧ B` is `all: [A, B]`. `¬B` is `{not: B}` inside that `all`. `±N` is
  `near_lines: N`. `seq[a, b] ≤N` is `sequence: [a, b], within_lines: N`.
- For py_ast: `call C · args.N cond · kwargs.K cond · kwarg_absent […] · sources […] · require_import […]`. The
  callee syntax is engine §8.7's.
- For hcl: `block B · each E · conds`. Inside `each`, `$.attr` refers to the matched `block` (§14 #7).
- Pattern blocks are YAML maps. Pack files inline each pattern, or define it once as a YAML anchor. Keys that
  start with `CALLEE_` hold py_ast callee patterns, not regexes.

### 1.3 Shared detection rules

1. **Structured before text.** Triggers, keys and nesting are tested only with `yp`, `hcl` or `ast`. A regex
   never decides whether a GHA trigger or a k8s field is present (§5.1 explains why). The regex tier is for
   line-oriented formats: Dockerfile, NGINX, shell, CLI flags and code idioms.
2. **YAML value schema.** The engine picks it automatically: `yaml11` for k8s, helm, kustomize, tekton and flux, and
   `yaml12` for gha, compose and traefik. Where a boolean can arrive as either type, rules list both forms
   (`in: [true, "true"]`). Under yaml11, `privileged: yes` is `true`, and a regression fixture pins this.
3. **Helm.** Scalar values that contain `{{` are skipped by every rule that checks a literal (`!~ '\{\{'`),
   because `values.yaml` decides the value. Values files are covered by explicit conditions such as K8S-011.
4. **Location.** The first relative condition of `all` (then `any`) locates the hit. Conditions prefixed with `$.` are
   filters and never locate (§14 #8). Authors order conditions with this in mind.
5. **Regex safety.** Every pattern passes lints R1–R7 (engine §8.2): repeats are bounded (`{0,N}`, N ≤ 4096), no
   pattern starts with an unbounded class, and cross-line constructs appear only in `ml` and `seq`.
   `tests/test_redos.py` loads every pattern block in this document's pack files.
6. **Secrets.** Rules that capture a secret value set `secret_group: secret` and `redact: true`, and snippets never
   carry the value (engine §13). A domain rule `supersedes` a generic `WS-SEC-*` hit on the same span only when its
   message is more actionable.
7. **Exposure.** Rules that exist to scan test paths set `exposure_sensitive: false` (TRD-009). All other rules use
   engine exposure, so fixtures under `tests/` are demoted as expected.
8. **Keywords.** Every rule lists literal `keywords` taken from its patterns (`pull_request_target`, `hostPath`,
   `alias`, `create_order`). The prefilter therefore works the same whichever YAML form a file uses.

---

## 2. Kubernetes, Helm and operators (`WS-K8S`)

| ID | Title | Sev | Conf | Refs | Files | M | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|
| WS-K8S-001 | Privileged container | H | H | CWE-250 · CIS-K8s 5.2.2 · PSS baseline · K01 | K8S | yp | `each POD · securityContext.privileged == true` (engine §8.6 example) | Node agents (CNI, CSI, node-exporter) take an inline suppression with a reason | Remove `privileged`, add only the capability that is needed, and label the namespace `pod-security.kubernetes.io/enforce: restricted` |
| WS-K8S-002 | allowPrivilegeEscalation not disabled | M | M | CWE-250 · CIS-K8s 5.2.6 · PSS restricted | K8S | yp | `each POD · none(securityContext.allowPrivilegeEscalation == false, $.**.spec.os.name == windows)` | Windows pods are excluded | `allowPrivilegeEscalation: false` |
| WS-K8S-003 | Container explicitly runs as root | H | H | CWE-250 · CIS-K8s 5.2.7 | K8S | yp | `yp each POD · any(securityContext.runAsUser == 0, securityContext.runAsNonRoot == false)` ∨ `yp any(**.spec.securityContext.runAsUser == 0, **.spec.securityContext.runAsNonRoot == false)` | Init containers that chown volumes should use `fsGroup`; otherwise suppress with a reason | `runAsNonRoot: true`, `runAsUser: 10001` |
| WS-K8S-004 | No non-root enforcement at pod or container level | L | M | CWE-250 · CIS-K8s 5.2.7 · PSS restricted | K8S | yp | `each POD · none(securityContext.runAsNonRoot == true, securityContext.runAsUser ~ @NONZERO_UID, $.**.spec.securityContext.runAsNonRoot == true, $.**.spec.securityContext.runAsUser ~ @NONZERO_UID)` | The image may declare a non-root `USER`. `finding-verifier` reads the Dockerfile | Pod-level `securityContext.runAsNonRoot: true` |
| WS-K8S-005 | Container-runtime socket mounted through hostPath | C | H | CWE-250, CWE-668 · CIS-K8s 5.2.12 · K01 | K8S | yp | `each **.volumes[*] · hostPath.path ~ @K8S_SOCK` · `supersedes: [WS-K8S-006]` | — | Use a socket proxy that allow-lists read-only endpoints, or rootless BuildKit/Kaniko for builds |
| WS-K8S-006 | Sensitive host path mounted | H | M | CWE-668 · CIS-K8s 5.2.12 · PSS baseline | K8S | yp | `each **.volumes[*] · hostPath.path ~ @K8S_HOST_DIR` | Log and metric DaemonSets (`/sys`, `/proc`) take an inline suppression with a reason | Use `emptyDir`, a CSI volume or a projected volume; if unavoidable, `readOnly: true` on a specific subpath |
| WS-K8S-007 | Host network, PID or IPC namespace shared | H | H | CWE-250, CWE-653 · CIS-K8s 5.2.3–5.2.5 | K8S | yp | `any(**.spec.hostNetwork == true, **.spec.hostPID == true, **.spec.hostIPC == true)` | CNI and ingress DaemonSets in `kube-system` are suppressed | Remove the setting and expose the workload through a Service |
| WS-K8S-008 | Dangerous Linux capability added | H | H | CWE-250 · CIS-K8s 5.2.8–5.2.9 | K8S | yp | `each POD · securityContext.capabilities.add[*] ~ @K8S_CAPS` | `NET_ADMIN` for CNI and VPN sidecars is suppressed | `drop: [ALL]`, and add back only `NET_BIND_SERVICE` if it is needed |
| WS-K8S-009 † | Capabilities not dropped | L | M | CWE-250 · PSS restricted | K8S | yp | `each POD · none(securityContext.capabilities.drop ∋ ALL)` | — | `capabilities: {drop: [ALL]}` |
| WS-K8S-010 | Seccomp or AppArmor explicitly unconfined | M | H | CWE-693 · CIS-K8s 5.7.2 · PSS baseline | K8S | yp | `any(**.seccompProfile.type == Unconfined, **.appArmorProfile.type == Unconfined, **.annotations.* == unconfined)` | Debug pods are suppressed | `seccompProfile: {type: RuntimeDefault}` |
| WS-K8S-011 | Mutable image reference (`:latest` or no tag) | M | H | CWE-829, CWE-1357 · K02 | K8S | yp | `yp each POD · image ~ @IMG_UNPINNED ; image !~ '\{\{'` ∨ `yp **.image.tag == latest` (Helm `values*.yaml`) | Templated images are skipped | Pin a version tag, and a `@sha256:` digest for prod, with Renovate or Dependabot bumping them |
| WS-K8S-012 | No memory limit | L | M | CWE-770 · K01 · NSA-K8s | K8S | yp | `each CTR · resources.limits.memory absent` | A namespace `LimitRange` may set defaults (the verifier checks) | Set `resources.limits.memory` together with requests |
| WS-K8S-013 † | Service-account token auto-mounted | L | L | CWE-1188 · CIS-K8s 5.1.6 | K8S | yp | `$.kind in @WL ; **.spec.automountServiceAccountToken absent` | Writing `true` explicitly records the choice and silences the rule | `automountServiceAccountToken: false` on the pod and on the default SA |
| WS-K8S-014 | Secret literal in container env | H | M | CWE-798, CWE-312 · CIS-K8s 5.4.1 · K08 | K8S | yp | `each CTR.env[*]`, i.e. `**.{containers,initContainers}[*].env[*]` · `value ~ @ENV_LITERAL ; value !~ @ENV_PLACEHOLDER ; name ~ @K8S_SECRET_NAME ; name !~ @K8S_NONSECRET_SUFFIX` | Placeholders are skipped, as are names ending `_FILE`, `_PATH`, `_URL`, `_NAME` or `_TTL` | `valueFrom.secretKeyRef` backed by External Secrets or Vault |
| WS-K8S-015 | RBAC wildcard verb or resource | H | H | CWE-269 · CIS-K8s 5.1.3 · K03 | K8S | yp | `each rules[*] · any(verbs ∋ "*", resources ∋ "*") ; $.kind in [Role, ClusterRole]` | Upstream aggregated admin roles are baselined | List the verbs and resources explicitly |
| WS-K8S-016 | Cluster-wide read of Secrets | H | M | CWE-269, CWE-200 · CIS-K8s 5.1.2 · K03 | K8S | yp | `each rules[*] · resources ∋ secrets ; verbs[*] in [get, list, watch, "*"] ; resourceNames absent ; $.kind == ClusterRole` | Secret operators (external-secrets, cert-manager, sealed-secrets) are suppressed with a reason | A namespaced Role with `resourceNames` |
| WS-K8S-017 | RBAC privilege-escalation verbs or subresources | H | H | CWE-269 · CIS-K8s 5.1.4, 5.1.8 · K03 | K8S | yp | `yp each rules[*] · verbs[*] in [escalate, bind, impersonate]` ∨ `yp each rules[*] · resources[*] in [pods/exec, pods/attach, serviceaccounts/token, nodes/proxy] ; verbs[*] in [create, get, "*"]` | — | A break-glass role bound just in time |
| WS-K8S-018 | Binding grants cluster-admin | H | H | CWE-269 · CIS-K8s 5.1.1 · K03 | K8S | yp | `roleRef.name == cluster-admin ; $.kind in [ClusterRoleBinding, RoleBinding]` | GitOps bootstrap bindings are suppressed with a reason | A dedicated least-privilege ClusterRole |
| WS-K8S-019 | Binding to anonymous or all-authenticated subjects | C | H | CWE-306, CWE-269 · K03 | K8S | yp | `subjects[*].name in ["system:anonymous", "system:unauthenticated", "system:authenticated"] ; $.kind in [ClusterRoleBinding, RoleBinding] ; none(roleRef.name in [system:public-info-viewer, system:discovery, system:basic-user])` | Built-in discovery roles are excluded | Remove the binding |
| WS-K8S-020 | Operator ClusterRole can rewrite cluster control objects | H | M | CWE-269 · K03 | K8S | yp | `each rules[*] · resources[*] in @CONTROL_OBJECTS ; verbs[*] in [create, update, patch, delete, deletecollection, "*"] ; resourceNames absent ; $.kind == ClusterRole` | CRD installers and OLM are suppressed | Install CRDs and webhooks out of band, and scope the operator with `resourceNames` |
| WS-K8S-021 | Admission webhook fails open | M | L | CWE-636 · K04 | K8S | yp | `each webhooks[*] · failurePolicy == Ignore ; $.kind in [ValidatingWebhookConfiguration, MutatingWebhookConfiguration]` | Non-policy webhooks (defaulting, sidecar injection) | Policy engines use `failurePolicy: Fail` with HA replicas and a `timeoutSeconds` |
| WS-K8S-022 | Datastore or admin port exposed through LoadBalancer or NodePort | H | M | CWE-668 · K07 | K8S | yp | `spec.ports[*].port in @DB_PORTS ; spec.type in [LoadBalancer, NodePort] ; $.kind == Service ; none(spec.loadBalancerSourceRanges exists, @INTERNAL_LB)` | Internal load balancers (`@INTERNAL_LB` annotations) are excluded | ClusterIP plus a private endpoint, or `loadBalancerSourceRanges` |
| WS-K8S-023 | ingress-nginx snippet annotations enabled | H | H | CWE-15, CWE-94 · CVE-2021-25742, CVE-2025-1974 · K09 | K8S | yp | `yp any(metadata.annotations."nginx.ingress.kubernetes.io/configuration-snippet" exists, metadata.annotations."nginx.ingress.kubernetes.io/server-snippet" exists, metadata.annotations."nginx.ingress.kubernetes.io/auth-snippet" exists)` ∨ `yp data."allow-snippet-annotations" in ["true", true] ; $.kind == ConfigMap` | Snippets are inert when the controller sets `allow-snippet-annotations: "false"` (the default since v1.9; the verifier checks) | Use first-class annotations or Gateway API policies; keep snippets disabled; patch the controller |
| WS-K8S-024 | Helm dependency over HTTP or with a floating version | M | H | CWE-829, CWE-319 · K02 | CHART | yp | `each dependencies[*] · any(repository ~ '^http://', version ~ @UNBOUNDED_VER)` | `file://` dependencies never match | An HTTPS or OCI registry, an exact version or `~x.y.z`, and a committed `Chart.lock` |
| WS-K8S-025 | Operator handler passes custom-resource fields to a shell or eval | H | M | CWE-78, CWE-94 · K01 | OP-PY | ast | `call [subprocess.{run,call,check_call,check_output,Popen}, os.{system,popen}, {eval,exec}] · args.0 tainted · sources [k8s_cr] · require_import kopf` (source set in §14 #5) | Allow-list validators listed in `sanitizers: ["**.validate_*"]` | Add `enum`, `pattern` and `maxLength` to the CRD schema; pass argv lists; never `shell=True` |
| WS-K8S-026 † | CRD accepts arbitrary fields | L | L | CWE-20 | K8S | yp | `each spec.versions[*] · any(schema.openAPIV3Schema.x-kubernetes-preserve-unknown-fields == true, schema.openAPIV3Schema.properties.spec.x-kubernetes-preserve-unknown-fields == true) ; $.kind == CustomResourceDefinition` | Pass-through CRDs are baselined | A structural schema with bounds |

```yaml
# patterns: k8s
K8S_SOCK: '^/(?:var/)?run/(?:docker\.sock|containerd/containerd\.sock|crio/crio\.sock|podman/podman\.sock|cri-dockerd\.sock|k3s/containerd/containerd\.sock)/?$'
K8S_HOST_DIR: '^/(?:(?:etc|root|proc|sys|boot|dev|home|var/lib/(?:kubelet|docker|containerd|etcd))(?:/[^\n]{0,256})?|(?:var/)?run)?/?$'
IMG_UNPINNED: ':latest$|^[^:@\s]{1,256}$|^[^@/\s]{1,253}:[0-9]{1,5}/[^:@\s]{1,256}$'
NONZERO_UID: '^[1-9][0-9]{0,9}$'
K8S_CAPS: '(?i)^(?:CAP_)?(?:ALL|SYS_ADMIN|SYS_MODULE|SYS_PTRACE|SYS_RAWIO|DAC_READ_SEARCH|BPF|NET_ADMIN)$'
ENV_LITERAL: '^[^\n]{6,512}$'
ENV_PLACEHOLDER: '(?i)^(?:\$\(|\{\{|<|changeme$|change-me$|dummy|example|placeholder|x{4,}|\*{3,})'
K8S_SECRET_NAME: '(?i)(?:passw(?:or)?d|secret|token|api_?key|access_?key|private_?key|credential|dsn)'
K8S_NONSECRET_SUFFIX: '(?i)_(?:file|path|ttl|name|ref|id|url|uri|endpoint|length|expiry|header|dir)$'
UNBOUNDED_VER: '^(?:\*|[xX]|latest|>=?[ \t]{0,2}v?[0-9][^,<|\n]{0,40})$'
WL: [Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, ReplicationController, Job, CronJob, PodTemplate]
DB_PORTS: [5432, 3306, 1433, 6379, 27017, 9200, 9300, 2379, 2380, 10250, 9092, 2181, 8983, 5601, 15672, 11211, 9042, 8086, 5984, 8123]
CONTROL_OBJECTS: [customresourcedefinitions, mutatingwebhookconfigurations, validatingwebhookconfigurations, clusterroles, clusterrolebindings, roles, rolebindings]
INTERNAL_LB:   # each entry is one `none` condition
  - { path: 'metadata.annotations."service.beta.kubernetes.io/aws-load-balancer-internal"', in: ["true", true] }
  - { path: 'metadata.annotations."service.beta.kubernetes.io/aws-load-balancer-scheme"', equals: internal }
  - { path: 'metadata.annotations."networking.gke.io/load-balancer-type"', equals: Internal }
```

---

## 3. Containers: Dockerfile and Compose (`WS-DKR`)

| ID | Title | Sev | Conf | Refs | Files | M | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|
| WS-DKR-001 | Final stage has no USER, so it runs as root | M | M | CWE-250 · CIS-Docker 4.1 | DKF | ml | `@DKR_LAST_FROM_NO_USER`, which matches the last `FROM` when no `USER` follows it | `line_not_regex: @DKR_NONROOT_BASE` covers distroless `:nonroot`, Chainguard and `scratch` | `USER 10001:10001` after package installation |
| WS-DKR-002 | Final USER is root | H | H | CWE-250 · CIS-Docker 4.1 | DKF | ml | `@DKR_USER_ROOT_LAST`, which matches `USER root` or `USER 0` when no later `USER` or `FROM` follows | — | Drop privileges in the final stage |
| WS-DKR-003 | Mutable base image (`:latest` or no tag) | M | H | CWE-829, CWE-1357 · K02 | DKF | rx | `@DKR_FROM_LATEST ∨ @DKR_FROM_NOTAG_NS ∨ @DKR_FROM_NOTAG_OFFICIAL` | Stage aliases (`FROM builder`) never match, because a match needs a `/` or an official image name; `ARG`-templated images are skipped | `python:3.12-slim-bookworm@sha256:…` |
| WS-DKR-004 † | Base image not pinned by digest (opt-in) | L | H | CWE-829 | DKF | rx | `@DKR_FROM_NO_DIGEST`, `enabled_by_default: false` | Untagged images are left to 003 | Pin a digest and let Renovate bump it |
| WS-DKR-005 | Secret literal in ENV or ARG | H | M | CWE-798, CWE-538 · CIS-Docker 4.10 | DKF | rx | `@DKR_ENV_SECRET` (`secret_group: secret`) · `supersedes: [WS-SEC-GEN-001]` | `line_not_regex: @DKR_SECRET_FP` | `RUN --mount=type=secret,id=…`; inject at runtime |
| WS-DKR-006 | Secret-named build ARG | M | M | CWE-538 · CIS-Docker 4.10 | DKF | rx | `@DKR_ARG_SECRET` | Same as 005 | `docker build --secret id=npm,src=…` (build args persist in image history) |
| WS-DKR-007 | ADD from a remote URL without a checksum | M | H | CWE-494 · CIS-Docker 4.9 | DKF | rx | `@DKR_ADD_URL` | `ADD --checksum=` never matches | `ADD --checksum=sha256:…`, or `curl` followed by `sha256sum -c` |
| WS-DKR-008 | Download piped into an interpreter | H | H | CWE-494 · CICD-SEC-3 | DKF, SH, GHA, GLC | rx | `@PIPE_TO_SHELL` | Vendored installers pinned by hash don't use a pipe | Download, verify the checksum or signature, then execute |
| WS-DKR-009 | Package index trust weakened | M | M | CWE-427, CWE-295 · CICD-SEC-3 | DKF, SH, GHA, `requirements*.txt`, `pip.conf` | rx | `@PIP_EXTRA_INDEX ∨ @PIP_HTTP_INDEX` | A single HTTPS `--index-url` that replaces PyPI does not match | One proxy index (Artifactory or CodeArtifact) plus `--require-hashes` |
| WS-DKR-010 | Secret material copied into the image | H | M | CWE-538 | DKF | rx | `@DKR_COPY_SECRET` | `.env.example` and similar are excluded, as are CA bundles (`line_not_regex: @DKR_CA_BUNDLE`) | `.dockerignore` plus build secrets |
| WS-DKR-011 | World-writable permissions | L | H | CWE-732 | DKF, SH | rx | `@CHMOD_WORLD` | `1777` (sticky `/tmp`) does not match | `chown` to the app user with mode `0750` |
| WS-DKR-020 | Privileged Compose service | H | H | CWE-250 | CMP | yp | `each services.* · privileged == true` | — | Minimal `cap_add` |
| WS-DKR-021 | Runtime socket mounted into a service | C | H | CWE-250, CWE-668 | CMP | yp | `each services.* · any(volumes[*] ~ @COMPOSE_SOCK, volumes[*].source ~ @K8S_SOCK) ; none(image ~ '(?i)socket-proxy')` | Traefik and Coolify proxies are still flagged: route them through a socket proxy | A Docker socket proxy that allows only `containers` reads |
| WS-DKR-022 | Host namespaces in Compose | H | H | CWE-250, CWE-653 | CMP | yp | `each services.* · any(network_mode == host, pid == host, ipc == host, userns_mode == host)` | Monitoring agents are suppressed | User-defined Docker networks with published ports only where needed |
| WS-DKR-023 | Datastore or admin port published on all interfaces | H | M | CWE-668 | CMP | yp | `yp each services.* · ports[*] ~ @COMPOSE_DB_PORT` ∨ `yp each services.*.ports[*] · target in @DB_PORTS ; none(host_ip ~ @LOOPBACK)` | Docker-published ports bypass ufw and firewalld, so a host firewall does not count as a guard | `127.0.0.1:5432:5432`, or drop `ports:` and use an internal network |
| WS-DKR-024 | Secret literal in service environment | H | M | CWE-798 | CMP | rx | `@COMPOSE_ENV_SECRET` (`secret_group: secret`) | `${VAR}` interpolation never matches; `line_not_regex: @COMPOSE_ENV_FP` | `env_file` kept out of VCS, or Compose `secrets:` |
| WS-DKR-025 | Dangerous capability or confinement disabled | H | H | CWE-250, CWE-693 | CMP | yp | `each services.* · any(cap_add[*] ~ @K8S_CAPS, security_opt[*] ~ @COMPOSE_UNCONFINED)` | — | Drop the capability and keep the default seccomp and AppArmor profiles |
| WS-DKR-026 | Mutable service image | M | H | CWE-829 | CMP | yp | `each services.* · image ~ @IMG_UNPINNED ; image !~ '\$\{' ; build absent` | Services built locally (`build:`) are skipped | Pin a tag or digest |

```yaml
# patterns: docker
DKR_LAST_FROM_NO_USER: '(?i)^[ \t]*FROM[ \t][^\n]{1,512}$(?=(?:\n(?![ \t]*(?:USER|FROM)[ \t])[^\n]{0,4096}){0,4000}\Z)'
DKR_USER_ROOT_LAST: '(?i)^[ \t]*USER[ \t]+(?:root|0)(?::[^\s]{1,64})?[ \t]*$(?=(?:\n(?![ \t]*(?:USER|FROM)[ \t])[^\n]{0,4096}){0,4000}\Z)'
DKR_NONROOT_BASE: '(?i)[:-]nonroot\b|cgr\.dev/chainguard/|^[ \t]*FROM[ \t]+(?:--platform=[^\s]{1,64}[ \t]+)?scratch\b'
DKR_FROM_LATEST: '(?i)^[ \t]*FROM[ \t]+(?:--platform=[^\s]{1,64}[ \t]+)?(?P<img>[^\s]{1,256}:latest)(?:[ \t]+AS[ \t]+[^\s]{1,64})?[ \t]*$'
DKR_FROM_NOTAG_NS: '(?i)^[ \t]*FROM[ \t]+(?:--platform=[^\s]{1,64}[ \t]+)?(?P<img>[a-z0-9][a-z0-9._-]{0,127}(?::[0-9]{1,5})?/[a-z0-9._/-]{1,200})(?:[ \t]+AS[ \t]+[^\s]{1,64})?[ \t]*$'
DKR_FROM_NOTAG_OFFICIAL: '(?i)^[ \t]*FROM[ \t]+(?:--platform=[^\s]{1,64}[ \t]+)?(?P<img>python|node|alpine|ubuntu|debian|golang|eclipse-temurin|openjdk|amazoncorretto|postgres|mysql|redis|nginx|traefik|busybox|rockylinux|ruby|rust)(?:[ \t]+AS[ \t]+[^\s]{1,64})?[ \t]*$'
DKR_FROM_NO_DIGEST: '(?i)^[ \t]*FROM[ \t]+(?:--platform=[^\s]{1,64}[ \t]+)?(?P<img>[a-z0-9][^\s@:]{0,200}:[^\s@]{1,128})(?:[ \t]+AS[ \t]+[^\s]{1,64})?[ \t]*$'
DKR_ENV_SECRET: '(?i)^[ \t]*(?:ENV|ARG)[ \t]+(?P<key>[A-Za-z0-9_]{0,63}?(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|DSN)[A-Za-z0-9_]{0,32})(?:[ \t]*=[ \t]*|[ \t]+)["'']?(?P<secret>[^\s"''$][^\s"'']{5,255})'
DKR_SECRET_FP: '(?i)^[ \t]*(?:ENV|ARG)[ \t]+[A-Za-z0-9_]{0,96}_(?:URL|URI|FILE|PATH|NAME|TTL|HEADER|ENDPOINT|DIR|ID)\b|=[ \t]*["'']?(?:changeme|dummy|example|placeholder|x{4,}|<[^>\n]{1,64}>)'
DKR_ARG_SECRET: '(?i)^[ \t]*ARG[ \t]+(?P<key>[A-Za-z0-9_]{0,63}?(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|INDEX_URL)[A-Za-z0-9_]{0,32})[ \t]*$'
DKR_ADD_URL: '(?i)^[ \t]*ADD[ \t]+(?:--(?!checksum)[a-z-]{1,32}(?:=[^\s]{1,128})?[ \t]+){0,4}(?P<url>https?://[^\s]{1,512})'
PIPE_TO_SHELL: '(?i)\b(?:curl|wget)\b[^\n|;&]{0,256}\|[ \t]*(?:sudo[ \t]+(?:-[A-Za-z]{1,8}[ \t]+){0,3})?(?:(?:ba|z|da|k)?sh|python[0-9.]{0,4}|perl|ruby|node)\b'
PIP_EXTRA_INDEX: '(?i)(?:--extra-index-url|--trusted-host|\bPIP_EXTRA_INDEX_URL\b|\bPIP_TRUSTED_HOST\b|^[ \t]*extra-index-url[ \t]*=|^[ \t]*trusted-host[ \t]*=)'
PIP_HTTP_INDEX: '(?i)(?:--index-url|--extra-index-url|\bPIP_(?:EXTRA_)?INDEX_URL|^[ \t]*(?:extra-)?index-url)[ \t]*[= ][ \t]*["'']?http://(?!(?:localhost|127\.0\.0\.1)[:/])'
DKR_COPY_SECRET: '(?i)^[ \t]*(?:COPY|ADD)[ \t][^\n]{0,512}?(?<![\w.-])(?P<file>\.env(?!\.(?:example|sample|template|dist)\b)(?:\.[A-Za-z0-9_-]{1,32})?|id_(?:rsa|dsa|ecdsa|ed25519)|[\w.-]{1,128}\.(?:pem|p12|pfx|jks)|private[\w.-]{0,64}\.key|\.aws/|\.ssh/|\.kube/|kubeconfig|\.git-credentials|\.npmrc|\.pypirc|\.netrc|credentials\.json|service[-_]?account[\w.-]{0,64}\.json)(?=[\s/"'',\]]|$)'
DKR_CA_BUNDLE: '(?i)(?:^|[/\s])(?:ca|cacert|ca-bundle|ca-certificates|chain|fullchain|root-?ca)[\w.-]{0,32}\.pem\b'
CHMOD_WORLD: '\bchmod[ \t]+(?:-[A-Za-z]{1,4}[ \t]{1,4}){0,3}(?:0?777|a\+rwx|[ao]\+w)\b'
COMPOSE_SOCK: '(?:^|:)/(?:var/)?run/(?:docker\.sock|containerd/containerd\.sock|podman/podman\.sock)(?::|$)'
COMPOSE_DB_PORT: '^(?:(?:0\.0\.0\.0|\[::\]):)?(?:[0-9]{1,5}(?:-[0-9]{1,5})?:)?(?:5432|3306|3307|1433|6379|27017|9200|9300|5601|2375|2376|11211|5984|8086|9042|15672|5672|9092|2181|8983|6443|10250|8123|9000)(?:/(?:tcp|udp))?$'
LOOPBACK: '^(?:127\.[0-9.]{1,11}|::1|localhost)$'
COMPOSE_ENV_SECRET: '(?i)^[ \t]{2,}(?:-[ \t]{1,4})?["'']?(?P<key>[A-Z0-9_]{0,40}?(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY)[A-Z0-9_]{0,24})["'']?[ \t]*[:=][ \t]*["'']?(?P<secret>[^\s"''$#{][^\s"'']{5,255})'
COMPOSE_ENV_FP: '(?i)_(?:FILE|PATH|URL|NAME)["'']?[ \t]*[:=]|[:=][ \t]*["'']?(?:changeme|dummy|example|placeholder)\b'
COMPOSE_UNCONFINED: '(?i)^(?:(?:seccomp|apparmor)[:=]unconfined|label[:=]disable|no-new-privileges[:=]false)$'
```

---

## 4. Terraform, Terragrunt, AWS and GCP (`WS-TF`)

hcl paths follow engine §8.8 plus the §14 #7 additions: `{a,b}` alternation in `block`, dotted `each`, and `$.`
meaning the matched block. Values that stay unresolved (`var.x` with no literal default, `random_password.*.result`,
`data.*`) are *unknown* and never match (`on_unknown: nomatch`).

| ID | Title | Sev | Conf | Refs | Files | M | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|
| WS-TF-001 | Security group opens an admin or datastore port to the internet | H | H | CWE-284, CWE-668 · FSBP EC2.19 · CIS-AWS 5.2 | TF | hcl | Four hcl matchers joined by ∨. (1) `block resource.aws_security_group.* · each ingress · cidr_blocks ∋ "0.0.0.0/0" ; any(range_includes{from_port, to_port, @ADMIN_PORTS}, protocol in ["-1", "all"])`. (2) The same with `ipv6_cidr_blocks ∋ "::/0"`. (3) `block resource.aws_security_group_rule.* · type == ingress ; cidr_blocks ∋ "0.0.0.0/0" ; any(range…, protocol…)`. (4) `block resource.aws_vpc_security_group_ingress_rule.* · any(cidr_ipv4 == "0.0.0.0/0", cidr_ipv6 == "::/0") ; any(range…, ip_protocol == "-1")` | Ports 80 and 443 are not in `@ADMIN_PORTS` | Use SSM Session Manager or a bastion; allow only VPC or VPN CIDRs |
| WS-TF-002 | S3 ACL grants public access | C | H | CWE-284, CWE-732 · FSBP S3.2, S3.3 | TF | hcl | `block resource.{aws_s3_bucket_acl,aws_s3_bucket,aws_s3_object}.* · acl in [public-read, public-read-write, authenticated-read]` | — | Block public access, and serve content through CloudFront with OAC |
| WS-TF-003 | S3 public access block disabled | H | H | CWE-284 · FSBP S3.1, S3.8 | TF | hcl | `block resource.{aws_s3_bucket_public_access_block,aws_s3_account_public_access_block}.* · any(block_public_acls == false, block_public_policy == false, ignore_public_acls == false, restrict_public_buckets == false)` | — | Set all four to `true` |
| WS-TF-004 | Resource policy allows any principal with no condition | H | M | CWE-284 | POLICY | hcl ∨ rx | `hcl block data.aws_iam_policy_document.* · each statement · principals.identifiers ∋ "*" ; none(effect == Deny, condition.variable exists)` ∨ `rx @TF_PRINCIPAL_STAR ∧ ¬@TF_CONDITION ∧ ¬@TF_EFFECT_DENY ±12` | Statements with `aws:PrincipalOrgID` or `aws:SourceArn` conditions carry a condition, so they don't match | Name the principals, or add a `PrincipalOrgID` or `SourceArn` condition |
| WS-TF-005 | IAM statement allows `*` on `*` | C | H | CWE-269, CWE-732 · FSBP IAM.1 · CIS-AWS 1.16 | POLICY | hcl ∨ rx | `hcl block data.aws_iam_policy_document.* · each statement · actions ∋ "*" ; resources ∋ "*" ; none(effect == Deny)` ∨ `rx @TF_IAM_ACTION_STAR ∧ @TF_IAM_RESOURCE_STAR ∧ ¬@TF_EFFECT_DENY ±6` | A break-glass admin module is suppressed with a reason | Scope the actions and resources, or use AWS job-function policies |
| WS-TF-006 | GitHub OIDC trust not bound to a repository | C | H | CWE-863, CWE-284 · CICD-SEC-2 | POLICY | seq ∨ rx | `seq[@TF_GH_OIDC_SUB, @TF_GH_SUB_WILDCARD] ≤4` ∨ `rx @TF_GH_OIDC_AUD ∧ ¬@TF_GH_OIDC_SUB` (whole file) | An explicit list such as `repo:org/app:*` does not match (it is repo-scoped) | `StringEquals` on `…:sub` = `repo:org/app:ref:refs/heads/main` or `repo:org/app:environment:prod` |
| WS-TF-007 | EC2 instance or launch template allows IMDSv1 | H | H | CWE-918, CWE-1188 · FSBP EC2.8 | TF | hcl | §12.2 | An `aws_ec2_instance_metadata_defaults` with `http_tokens = "required"` in the same file suppresses it | `metadata_options { http_tokens = "required" }` with hop limit 1 (2 on EKS nodes whose pods need IMDS) |
| WS-TF-008 | RDS or Aurora storage not encrypted | H | H | CWE-311 · FSBP RDS.3 | TF | hcl | `block resource.{aws_db_instance,aws_rds_cluster}.* · any(storage_encrypted absent, storage_encrypted == false) ; none(replicate_source_db exists, snapshot_identifier exists)` | Replicas and snapshot restores inherit encryption | `storage_encrypted = true` with `kms_key_id` |
| WS-TF-009 | RDS instance publicly accessible | H | H | CWE-668 · FSBP RDS.2 | TF | hcl | `block resource.{aws_db_instance,aws_rds_cluster_instance}.* · publicly_accessible == true` | — | Private subnets, and SSM port forwarding for access |
| WS-TF-010 | EBS volume not encrypted | M | M | CWE-311 · FSBP EC2.3 | TF | hcl | `hcl block resource.aws_ebs_volume.* · any(encrypted absent, encrypted == false)` ∨ `hcl block resource.aws_instance.* · root_block_device.encrypted == false` ∧ `¬hcl block resource.aws_ebs_encryption_by_default.* · enabled == true` | An account-level default in another stack is checked by the verifier | `aws_ebs_encryption_by_default { enabled = true }` |
| WS-TF-011 | S3 state backend without encryption | H | H | CWE-311 · CICD-SEC-6 | TF, TFVARS | hcl | `hcl block terraform · any(backend.encrypt absent, backend.encrypt == false) ∧ rx @TF_BACKEND_S3` ∨ `hcl block remote_state · backend == s3 ; any(config.encrypt absent, config.encrypt == false)` | — | `encrypt = true`, `kms_key_id`, and a bucket policy that denies unencrypted puts |
| WS-TF-012 | State backend without locking | M | H | CWE-362, CWE-667 | TF, TFVARS | hcl | `hcl block terraform · none(backend.dynamodb_table exists, backend.use_lockfile == true) ∧ rx @TF_BACKEND_S3` ∨ `hcl block remote_state · backend == s3 ; none(config.dynamodb_table exists, config.use_lockfile == true)` | GCS and azurerm backends lock natively and never match | `use_lockfile = true` (Terraform 1.10+) or `dynamodb_table` |
| WS-TF-013 | EKS API endpoint open to the internet | H | M | CWE-668 · FSBP EKS.1 | TF | hcl | `block resource.aws_eks_cluster.* · none(vpc_config.endpoint_public_access == false) ; any(vpc_config.public_access_cidrs absent, vpc_config.public_access_cidrs ∋ "0.0.0.0/0")` | — | A private endpoint plus VPN or SSM, or a CIDR allow-list |
| WS-TF-014 | Long-lived cloud credential managed in Terraform | M | H | CWE-312, CWE-522 · CIS-GCP 1.4 | TF | hcl | `block resource.{aws_iam_access_key,google_service_account_key,aws_iam_user_login_profile}.*` (block only; the secret lands in state) | Break-glass users are suppressed | OIDC, IRSA or Workload Identity; otherwise `pgp_key` plus short rotation |
| WS-TF-015 | Hardcoded secret in a resource argument | H | M | CWE-798 · CICD-SEC-6 | TF | hcl | `hcl block resource.{aws_db_instance,aws_rds_cluster,aws_docdb_cluster,aws_elasticache_replication_group,google_sql_user}.* · any(password type str, master_password type str, auth_token type str)` ∨ `hcl block resource.aws_secretsmanager_secret_version.* · secret_string type str` ∨ `hcl block resource.aws_ssm_parameter.* · type == SecureString ; value type str` | Unknown values never match. `var.x` matches only when its default is a literal | `manage_master_user_password = true`; `random_password` plus Secrets Manager; `ephemeral` resources (Terraform 1.10+) |
| WS-TF-016 | Lambda function URL without authentication | H | M | CWE-306 · API2 | TF | hcl | `block resource.aws_lambda_function_url.* · authorization_type == NONE` | A public webhook must verify signatures in the handler (see TRD-006), so confidence is M | `AWS_IAM` with SigV4, or API Gateway with an authorizer |
| WS-TF-017 | Module source not pinned | M | H | CWE-829 · CICD-SEC-3 | TF, TFVARS | hcl | `hcl block {module.*,terraform} · source ~ @TF_MODULE_REMOTE ; source !~ @TF_MODULE_PINNED` ∨ `hcl block module.* · source ~ @TF_MODULE_REGISTRY ; source !~ @TF_MODULE_REMOTE ; version absent` | Local paths (`./`, `../`) never match | `?ref=<40-hex>` or an exact tag, with `.terraform.lock.hcl` committed |
| WS-TF-018 † | CloudTrail without log validation or not multi-region | L | H | CWE-778, CWE-354 · FSBP CloudTrail.4 · CIS-AWS 3.2 | TF | hcl | `block resource.aws_cloudtrail.* · any(enable_log_file_validation absent, enable_log_file_validation == false, is_multi_region_trail absent, is_multi_region_trail == false)` | Org trails managed elsewhere | Enable both |
| WS-TF-019 | KMS key rotation disabled | L | H | CWE-324 · FSBP KMS.4 | TF | hcl | `block resource.aws_kms_key.* · any(enable_key_rotation absent, enable_key_rotation == false) ; none(customer_master_key_spec != SYMMETRIC_DEFAULT)` | Asymmetric and HMAC keys are excluded | `enable_key_rotation = true` |
| WS-TF-020 † | ECR tags mutable or not scanned | L | H | CWE-494 · FSBP ECR.1, ECR.2 | TF | hcl | `block resource.aws_ecr_repository.* · any(image_tag_mutability absent, image_tag_mutability == MUTABLE, image_scanning_configuration.scan_on_push == false)` | Registry-level scanning configuration | `IMMUTABLE` plus scan on push |
| WS-TF-021 | Load balancer listener serves plain HTTP without a redirect | M | M | CWE-319 | TF | hcl | `block resource.{aws_lb_listener,aws_alb_listener}.* · protocol == HTTP ; none(default_action.type == redirect)` | Internal ALBs (the verifier checks `aws_lb.internal`) | Redirect to HTTPS (`HTTP_301`) |
| WS-TF-022 | Legacy TLS policy on a listener | M | H | CWE-326, CWE-327 | TF | hcl | `block resource.{aws_lb_listener,aws_alb_listener}.* · ssl_policy ~ @TF_OLD_TLS_POLICY` | — | `ELBSecurityPolicy-TLS13-1-2-2021-06` |
| WS-TF-023 | Secret literal in tfvars or Terragrunt inputs | H | M | CWE-798 | TFVARS | rx | `@TF_VARS_SECRET` (`secret_group: secret`) | `line_not_regex: @TF_SECRET_FP` | SOPS (`sops_decrypt_file()` in Terragrunt), `get_env()`, or a secrets manager data source |
| WS-TF-030 | GCS bucket readable by allUsers or allAuthenticatedUsers | C | H | CWE-284 · CIS-GCP 5.1 | TF | hcl | `hcl block resource.{google_storage_bucket_iam_member,google_storage_bucket_access_control,google_storage_default_object_access_control,google_storage_object_access_control}.* · any(member in @GCP_PUBLIC, entity in @GCP_PUBLIC)` ∨ `hcl block resource.google_storage_bucket_iam_binding.* · any(members ∋ allUsers, members ∋ allAuthenticatedUsers)` | A public-asset bucket behind a CDN is suppressed with a reason | IAM on named principals, or signed URLs |
| WS-TF-031 | GCS bucket without uniform bucket-level access | M | H | CWE-284 · CIS-GCP 5.2 | TF | hcl | `block resource.google_storage_bucket.* · any(uniform_bucket_level_access absent, uniform_bucket_level_access == false)` | — | `uniform_bucket_level_access = true` and `public_access_prevention = "enforced"` |
| WS-TF-032 | Firewall opens an admin or datastore port to the internet | H | H | CWE-284 · CIS-GCP 3.6, 3.7 | TF | hcl | `block resource.google_compute_firewall.* · each allow · any(ports ~ @GCP_ADMIN_PORT, ports absent) ; $.source_ranges ∋ "0.0.0.0/0" ; none($.direction == EGRESS, $.disabled == true, protocol == icmp)` | The IAP range `35.235.240.0/20` never matches | IAP TCP forwarding and narrow source ranges |
| WS-TF-033 | Cloud SQL authorized network 0.0.0.0/0 | C | H | CWE-668 · CIS-GCP 6.5 | TF | hcl | `block resource.google_sql_database_instance.* · each settings.ip_configuration.authorized_networks · value == "0.0.0.0/0"` | — | Private IP plus the Cloud SQL Auth Proxy |
| WS-TF-034 | Cloud SQL does not require TLS | M | H | CWE-319 · CIS-GCP 6.4 | TF | hcl | `block resource.google_sql_database_instance.* · none(settings.ip_configuration.ssl_mode in [ENCRYPTED_ONLY, TRUSTED_CLIENT_CERTIFICATE_REQUIRED], settings.ip_configuration.require_ssl == true, settings.ip_configuration.ipv4_enabled == false)` | Private-IP-only instances are excluded | `ssl_mode = "ENCRYPTED_ONLY"` |
| WS-TF-035 | Basic role (owner or editor) granted | H | M | CWE-269 | TF | hcl | `block resource.{google_project_iam_member,google_project_iam_binding,google_folder_iam_member,google_folder_iam_binding,google_organization_iam_member,google_organization_iam_binding}.* · role in [roles/owner, roles/editor]` | Break-glass group bindings are suppressed with a reason | Predefined or custom roles |
| WS-TF-036 | GKE legacy authorization or client certificates | H | H | CWE-285 | TF | hcl | `block resource.google_container_cluster.* · any(enable_legacy_abac == true, master_auth.client_certificate_config.issue_client_certificate == true)` | — | RBAC only, plus Workload Identity |
| WS-TF-037 | GKE control plane reachable from anywhere | M | M | CWE-668 · K07 | TF | hcl | `block resource.google_container_cluster.* · none(master_authorized_networks_config.cidr_blocks.cidr_block exists, private_cluster_config.enable_private_endpoint == true)` | DNS-endpoint clusters with IAM-only access (the verifier checks) | Authorized networks or a private endpoint |
| WS-TF-038 | GKE nodes expose instance metadata (Workload Identity off) | M | M | CWE-918, CWE-200 | TF | hcl | `block resource.{google_container_node_pool,google_container_cluster}.* · any(node_config.workload_metadata_config.mode absent, node_config.workload_metadata_config.mode != GKE_METADATA) ; none(enable_autopilot == true, remove_default_node_pool == true)` | Autopilot clusters and clusters that remove the default pool | `workload_metadata_config { mode = "GKE_METADATA" }` |
| WS-TF-039 | Instance uses the default service account with full API scope | M | M | CWE-250 · CIS-GCP 4.2 | TF | hcl | `block resource.{google_compute_instance,google_compute_instance_template}.* · each service_account · scopes ∋ cloud-platform ; any(email absent, email ~ @GCP_DEFAULT_SA)` | — | A dedicated least-privilege service account |
| WS-TF-040 | GitHub workload identity provider without an attribute condition | H | H | CWE-863 · CICD-SEC-2 | TF | hcl | `block resource.google_iam_workload_identity_pool_provider.* · oidc.issuer_uri ~ 'token\.actions\.githubusercontent\.com' ; attribute_condition absent` | — | `attribute_condition = "assertion.repository_owner_id == '…' && assertion.ref == 'refs/heads/main'"` |

```yaml
# patterns: terraform
ADMIN_PORTS: [22, 3389, 5432, 3306, 1433, 6379, 9200, 27017, 2375, 2376, 6443, 10250, 11211, 9092, 5601, 8080, 15672]
GCP_PUBLIC: [allUsers, allAuthenticatedUsers]
TF_IAM_ACTION_STAR: '(?:"Action"|\bAction)[ \t]{0,4}[:=][ \t]{0,4}(?:\[[ \t]{0,4})?"\*(?::\*)?"'
TF_IAM_RESOURCE_STAR: '(?:"Resource"|\bResource)[ \t]{0,4}[:=][ \t]{0,4}(?:\[[ \t]{0,4})?"\*"'
TF_EFFECT_DENY: '(?:"Effect"|\bEffect)[ \t]{0,4}[:=][ \t]{0,4}"Deny"'
TF_PRINCIPAL_STAR: '(?:"Principal"|\bPrincipal)[ \t]{0,4}[:=][ \t]{0,4}(?:"\*"|\{[ \t]{0,4}(?:"AWS"|AWS)[ \t]{0,4}[:=][ \t]{0,4}(?:\[[ \t]{0,4})?"\*")'
TF_CONDITION: '(?:"Condition"|\bCondition)[ \t]{0,4}[:=]'
TF_GH_OIDC_AUD: 'token\.actions\.githubusercontent\.com:aud'
TF_GH_OIDC_SUB: 'token\.actions\.githubusercontent\.com:sub'
TF_GH_SUB_WILDCARD: '"repo:(?:\*|[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{0,100}\*)'
TF_BACKEND_S3: '^[ \t]*backend[ \t]+"s3"'
TF_MODULE_REMOTE: '^(?:git::|git@|github\.com/|bitbucket\.org/|https?://|s3::|gcs::)'
TF_MODULE_PINNED: '[?&]ref=(?:[0-9a-f]{40}|v?[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6})(?:&|$)'
TF_MODULE_REGISTRY: '^(?:[a-z0-9.-]{1,253}/)?[a-z0-9_-]{1,64}/[a-z0-9_-]{1,64}/[a-z0-9_-]{1,64}$'
TF_OLD_TLS_POLICY: '^ELBSecurityPolicy-(?:2011-08|2014-01|2014-10|2015-02|2015-03|2015-05|2016-08|TLS-1-0-2015-04|TLS-1-1-2017-01)$'
TF_VARS_SECRET: '(?i)^[ \t]*(?P<key>[a-z0-9_]{0,40}?(?:password|passwd|secret|token|api_key|private_key|access_key)[a-z0-9_]{0,24})[ \t]*=[ \t]*"(?P<secret>[^"$%\n]{6,256})"'
TF_SECRET_FP: '(?i)_(?:name|arn|id|path|file|version|length|ttl|rotation_days|kms_key_id)[ \t]*=|=[ \t]*"(?:changeme|dummy|example|placeholder|x{4,})"'
GCP_ADMIN_PORT: '^(?:22|3389|5432|3306|1433|6379|9200|27017|2375|2376|6443|10250|11211|9092|8080|0-65535|1-65535)$'
GCP_DEFAULT_SA: '-compute@developer\.gserviceaccount\.com$'
```

---

## 5. CI/CD (`WS-GHA`, `WS-GHA-TKN`, `WS-GHA-FLX`, `WS-GHA-GLC`)

**Namespacing.** All CI/CD rules share the `WS-GHA` namespace. Non-GitHub engines use a sub-namespace that the
engine ID pattern already allows (`WS-GHA(-[A-Z0-9]{2,10})?-nnn`): `WS-GHA-TKN-nnn` for Tekton, `WS-GHA-FLX-nnn` for
Flux and `WS-GHA-GLC-nnn` for GitLab CI. Each engine numbers from 001 on its own. See §14 #1.

### 5.1 GitHub Actions `on:` handling

The trap is PyYAML (YAML 1.1). `yaml.safe_load("on: push")` returns `{True: "push"}`. Any tool that looks up `"on"`
finds nothing, and every trigger-gated rule silently misses. Tools that dump the data back write `true:`. The engine
avoids this in three layers:

1. **Keys are raw text.** `yamlite` never resolves keys (engine §8.6), so `on`, `"on"` and `'on'` are all the key
   `on`, and `true:` stays the key `true`.
2. **Promotion.** A trigger condition is always written `$.on.<event>` (or `on.<event>` when there is no `each`), and
   a key step against a scalar or a sequence promotes a matching item. One path therefore covers all the shapes below.
3. **No regex decides a trigger.** The keyword prefilter uses the bare event name (`pull_request_target`), which
   appears in every form. Regex rules never test `^on:`.

| # | Form in the workflow | yamlite view of `$.on` | `$.on.pull_request_target exists` |
|---|---|---|---|
| 1 | `on: pull_request_target` | scalar `pull_request_target` | true (promoted scalar) |
| 2 | `on: [push, pull_request_target]` | flow seq | true (promoted item) |
| 3 | `on:` then `  - push` / `  - pull_request_target` | block seq | true (promoted item) |
| 4 | `on:` then `  pull_request_target:` with no value | map with a null value | true (the node exists even though its value is null) |
| 5 | `on:` then `  pull_request_target:` / `    types: [opened, synchronize]` | nested map | true; `…pull_request_target.types ∋ opened` also works |
| 6 | `on: {pull_request_target: {types: [opened]}}` | flow map | true |
| 7 | `"on":` or `'on':` followed by any shape above | quoted key, same raw text | true |
| 8 | `on: # triggers` with comment or blank lines before the children | comments dropped | true |
| 9 | `on: &t {…}` with a later `*t`, or `<<:` merges | expanded at parse time | true |
| 10 | `true:` (a YAML 1.1 round-trip) | the key is `true`; there is no `on` | false. WS-GHA-016 reports the file instead of silently skipping it |
| 11 | `on:` nested under `jobs.x.with` or similar | not at `$.` | false (absolute path) |

`workflow_call` workflows inherit their caller's trigger, which is not visible in the file. Rules gated on untrusted
triggers therefore also accept `$.on.workflow_call exists` with `confidence: low`. Each form above is a regression
fixture at `tests/fixtures/_regress/gha-on/<nn>-<form>.yml`, and `test_regressions.py` asserts the WS-GHA-001 hit
count for each (1 for forms 1–9, 0 for 10 and 11, plus 1 WS-GHA-016 hit for form 10). The classifier sniff for
workflows outside `.github/workflows/` must accept the quoted and `true:` keys (§14 #9).

### 5.2 GitHub Actions

| ID | Title | Sev | Conf | Refs | Files | M | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|
| WS-GHA-001 | `pull_request_target` checks out PR head code | C | H | CWE-94 · CICD-SEC-4 | GHA | yp | DESIGN §4: `on.pull_request_target exists ; jobs.*.steps[*].with.ref ~ @GHA_PR_HEAD` (no `each`, so one hit per offending `with.ref`) | A checkout that is never built or executed (the verifier checks for later steps) | Use `pull_request` for untrusted code, and do privileged follow-up in `workflow_run` without running PR code |
| WS-GHA-002 | Untrusted event field expanded inside a step script | H | H | CWE-78, CWE-94 · CICD-SEC-4 | GHA | yp | §12.1: `each **.steps[*] · run ~ @GHA_UNTRUSTED`, plus the `actions/github-script` `with.script` variant | Numbers, SHAs and labels set by maintainers are not in the list | Pass the value through `env:` and quote it as `"$VAR"` |
| WS-GHA-003 | Third-party action not pinned to a commit SHA | M | H | CWE-829 · CICD-SEC-3, CICD-SEC-8 | GHA | yp | `yp each **.steps[*] · uses !~ @GHA_PINNED_OR_LOCAL ; uses !~ @GHA_FIRST_PARTY` ∨ `yp each jobs.* · uses !~ @GHA_PINNED_OR_LOCAL ; uses !~ @GHA_FIRST_PARTY` | Local `./` actions and digest-pinned `docker://` images | `owner/action@<40-hex>  # vX.Y.Z` plus Dependabot for `github-actions` |
| WS-GHA-004 † | First-party action not pinned (opt-in) | L | H | CWE-829 | GHA | yp | The same paths with `uses ~ @GHA_FIRST_PARTY ; uses !~ @GHA_PINNED_OR_LOCAL`, `enabled_by_default: false` | — | Same as 003 |
| WS-GHA-005 | Workflow token granted `write-all` | M | H | CWE-250, CWE-272 · CICD-SEC-5 | GHA | yp | `any(permissions == write-all, jobs.*.permissions == write-all)` | — | Top-level `permissions: {contents: read}` and per-job grants |
| WS-GHA-006 † | No explicit token permissions | L | L | CWE-272 · CICD-SEC-5 | GHA | yp | `jobs exists ; permissions absent ; none(jobs.*.permissions exists)` | An org default of read-only is not visible in the repo | Declare `permissions:` |
| WS-GHA-007 | All secrets passed to an external reusable workflow | H | H | CWE-200, CWE-668 · CICD-SEC-6 | GHA | yp | `each jobs.* · secrets == inherit ; uses !~ '^\./'` | — | Pass named secrets explicitly |
| WS-GHA-008 | `workflow_run` consumes artifacts of the triggering run | H | M | CWE-494, CWE-829 · CICD-SEC-4 | GHA | yp | `each **.steps[*] · uses ~ @GHA_DOWNLOAD_ARTIFACT ; any(with.run-id ~ @GHA_WORKFLOW_RUN_ID, with.run_id ~ @GHA_WORKFLOW_RUN_ID) ; $.on.workflow_run exists` | Artifacts handled only as inert data (the verifier checks: no execution and no `$GITHUB_ENV` writes) | Extract to a temp dir and validate. Never execute or source the content. Keep secrets out of that job |
| WS-GHA-009 | Deprecated unsafe workflow commands re-enabled | H | H | CWE-77 | GHA | yp | `**.env.ACTIONS_ALLOW_UNSECURE_COMMANDS in [true, "true"]` | — | Remove it; use `$GITHUB_ENV` and `$GITHUB_PATH` |
| WS-GHA-010 | Self-hosted runner reachable from fork PRs | H | M | CWE-250, CWE-668 · CICD-SEC-7 | GHA | yp | `jobs.*.runs-on ~ 'self-hosted' ; any($.on.pull_request exists, $.on.pull_request_target exists, $.on.issue_comment exists)` | Private repos, and ephemeral JIT runners (the verifier checks) | GitHub-hosted runners for PR events, or ephemeral runners plus required approval for fork PRs |
| WS-GHA-011 | All secrets serialized | H | H | CWE-200, CWE-532 · CICD-SEC-6 | GHA | rx | `@GHA_TOJSON_SECRETS` | — | Reference each secret by name |
| WS-GHA-012 | Long-lived cloud keys used instead of OIDC | L | H | CWE-522 · CICD-SEC-6 | GHA | yp | `each **.steps[*] · any(with.aws-secret-access-key exists, with.credentials_json exists)` | Runners without OIDC reachability | `permissions: {id-token: write}` plus `role-to-assume` or `workload_identity_provider` |
| WS-GHA-013 | Checkout token persisted into an uploaded workspace | M | M | CWE-538, CWE-200 · CICD-SEC-6 | GHA | yp ∧ yp | `yp each **.steps[*] · uses ~ '^actions/checkout@' ; none(with.persist-credentials in [false, "false"])` ∧ `yp each **.steps[*] · uses ~ '^actions/upload-artifact@' ; with.path ~ @GHA_WS_PATH` | — | `persist-credentials: false`, and upload only explicit build outputs |
| WS-GHA-014 | Comment-triggered workflow checks out PR code without an authorization check | H | M | CWE-94, CWE-862 · CICD-SEC-4 | GHA | yp ∧ ¬rx | `yp each **.steps[*] · with.ref ~ @GHA_PR_REF ; $.on.issue_comment exists` ∧ `¬rx @GHA_AUTHZ_CHECK` (whole file) | — | Gate on `author_association` ∈ {OWNER, MEMBER, COLLABORATOR} plus environment approval |
| WS-GHA-015 | Privileged workflow writes data into `$GITHUB_ENV` or `$GITHUB_PATH` | H | M | CWE-94, CWE-15 · CICD-SEC-4 | GHA | yp | `each **.steps[*] · run ~ @GHA_ENV_FILE_WRITE ; $.on.{workflow_run,pull_request_target} exists` | Constant writes, via `line_not_regex: @GHA_CONST_ENV_WRITE` (the hit line is the matched line, §14 #8) | Use `$GITHUB_OUTPUT` with validated values; never write artifact or PR content into env files |
| WS-GHA-016 | Trigger key rewritten to `true` by a YAML 1.1 tool | I | H | — | GHA | yp | `true exists` (with `promote: false`) `; jobs exists ; on absent` | — | Restore `on:`, and stop round-tripping workflows through PyYAML |

```yaml
# patterns: gha
GHA_UNTRUSTED: '\$\{\{[ \t]{0,8}(?:github\.head_ref|github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.(?:ref|label|repo\.default_branch))|(?:comment|review|review_comment)\.body|discussion\.(?:title|body)|pages(?:\[[^\]\n]{0,16}\]|\.\*)\.page_name|(?:commits(?:\[[^\]\n]{0,16}\]|\.\*)|head_commit|workflow_run\.head_commit)\.(?:message|author\.(?:email|name))|workflow_run\.(?:head_branch|display_title)))\b'
GHA_PR_HEAD: 'github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs/pull/'
GHA_PINNED_OR_LOCAL: '^(?:\./|docker://[^@\s]{1,256}@sha256:[0-9a-f]{64}$)|@[0-9a-f]{40}$'
GHA_FIRST_PARTY: '^(?:actions|github)/'
GHA_TOJSON_SECRETS: '\$\{\{[ \t]{0,8}toJSON\([ \t]{0,8}secrets[ \t]{0,8}\)'
GHA_DOWNLOAD_ARTIFACT: '^(?:actions/download-artifact|dawidd6/action-download-artifact)@'
GHA_WORKFLOW_RUN_ID: 'github\.event\.workflow_run\.id'
GHA_WS_PATH: '^(?:\.|\./|\$\{\{[ \t]{0,8}github\.workspace[ \t]{0,8}\}\}/?)$'
GHA_PR_REF: 'refs/pull/|github\.event\.issue\.number|pull_request\.head\.(?:sha|ref)|steps\.[A-Za-z0-9_-]{1,64}\.outputs\.(?:head_)?(?:sha|ref)\b'
GHA_AUTHZ_CHECK: 'author_association|github\.event\.comment\.user\.login|github\.actor[ \t]{0,4}==|permission-level|getCollaboratorPermissionLevel|contains\([ \t]{0,4}fromJSON\('
GHA_ENV_FILE_WRITE: '>>[ \t]{0,4}"?\$\{?GITHUB_(?:ENV|PATH)\b'
GHA_CONST_ENV_WRITE: '^[ \t]*echo[ \t]+["'']?[A-Z_][A-Z0-9_]{0,64}=[A-Za-z0-9_./:-]{0,200}["'']?[ \t]*>>'
```

### 5.3 Tekton (`WS-GHA-TKN`)

| ID | Title | Sev | Conf | Refs | Files | M | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|
| WS-GHA-TKN-001 | Parameter or result interpolated into a step script | H | M | CWE-78 · CICD-SEC-4 | TKN | yp | `each **.{steps,sidecars}[*] · script ~ @TKN_PARAM_INTERP` | Params that come only from maintainers' PipelineRuns (the verifier traces TriggerBinding `$(body.*)`) | `env: [{name: REF, value: $(params.ref)}]` in the step, and `"$REF"` in the script |
| WS-GHA-TKN-002 | Privileged or root step | H | H | CWE-250 · K01 | TKN | yp | `yp each **.{steps,sidecars}[*] · any(securityContext.privileged == true, securityContext.runAsUser == 0)` ∨ `yp **.stepTemplate.securityContext.privileged == true` | Image builders are suppressed with a reason | Rootless Buildah or Kaniko |
| WS-GHA-TKN-003 | EventListener trigger without a signature-verifying interceptor | H | M | CWE-345, CWE-306 · CICD-SEC-4 | TKN | yp | `each spec.triggers[*] · none(interceptors[*].params[*].value.secretName exists, interceptors[*].{github,gitlab,bitbucket}.secretRef.secretName exists, triggerRef exists) ; $.kind == EventListener` | A CEL interceptor that verifies an HMAC header itself (the verifier checks) | The `github` or `gitlab` ClusterInterceptor with `secretRef` |
| WS-GHA-TKN-004 † | Step image not pinned by digest | L | H | CWE-829 · K02 | TKN | yp | `each **.{steps,sidecars}[*] · image !~ @TKN_DIGEST_OR_PARAM` | Parameterised images are skipped | `image: …@sha256:…` |
| WS-GHA-TKN-005 | Remote Task or Pipeline resolved from a mutable reference | M | H | CWE-829 · CICD-SEC-3 | TKN | yp | `each **.{taskRef,pipelineRef} · resolver in [git, bundles, http] ; none(params[*].value ~ @TKN_PINNED)` | Hub resolver versions don't match | `revision: <40-hex>`, or a bundle `@sha256:` |
| WS-GHA-TKN-006 | EventListener exposed through LoadBalancer or NodePort | M | M | CWE-668 · K07 | TKN | yp | `spec.resources.kubernetesResource.serviceType in [LoadBalancer, NodePort] ; $.kind == EventListener` | — | ClusterIP plus an Ingress with TLS and a source allow-list for the Git host |

### 5.4 Flux (`WS-GHA-FLX`)

Every rule also has the filter `$.apiVersion ~ '\.toolkit\.fluxcd\.io/'`, which keeps kustomize's own
`Kustomization` out.

| ID | Title | Sev | Conf | Refs | Files | M | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|
| WS-GHA-FLX-001 | GitRepository without commit signature verification | M | M | CWE-345, CWE-494 · CICD-SEC-9 | FLX | yp | `spec.url exists ; spec.verify absent ; $.kind == GitRepository` | Repos that don't sign commits yet are baselined | `spec.verify: {mode: HEAD, secretRef: …}` with signed commits or tags |
| WS-GHA-FLX-002 | OCIRepository without signature verification | M | M | CWE-345 · CICD-SEC-9 | FLX | yp | `spec.url exists ; spec.verify absent ; $.kind == OCIRepository` | — | `spec.verify.provider: cosign` (keyless, `matchOIDCIdentity`) or notation |
| WS-GHA-FLX-003 | Source fetched over plaintext or with TLS disabled | H | H | CWE-319 · CICD-SEC-9 | FLX | yp | `any(spec.url ~ '^http://', spec.endpoint ~ '^http://', spec.insecure == true) ; $.kind in [GitRepository, HelmRepository, OCIRepository, Bucket]` | — | HTTPS or SSH, and remove `insecure` |
| WS-GHA-FLX-004 | Kustomization or HelmRelease runs as the controller's cluster-admin identity | M | L | CWE-250 · K03 | FLX | yp | `spec.serviceAccountName absent ; metadata.namespace not_in [flux-system] ; $.kind in [Kustomization, HelmRelease]` | Single-tenant clusters (hence confidence L) | Multi-tenancy lockdown: `--default-service-account` plus a per-tenant SA |
| WS-GHA-FLX-005 | HelmRelease chart version floats | M | H | CWE-829 · K02 | FLX | yp | `spec.chart exists ; any(spec.chart.spec.version absent, spec.chart.spec.version ~ @UNBOUNDED_VER) ; spec.chartRef absent ; $.kind == HelmRelease` (a missing version means `*`) | — | An exact version or a bounded range, or `chartRef` to a digest-pinned OCIRepository |
| WS-GHA-FLX-006 | Receiver authenticates by URL token only | M | M | CWE-345 · CICD-SEC-4 | FLX | yp | `spec.type == generic ; $.kind == Receiver` | Receivers reachable only internally | A provider type (`github`, `gitlab`) or `generic-hmac` |

### 5.5 GitLab CI (`WS-GHA-GLC`)

| ID | Title | Sev | Conf | Refs | Files | M | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|
| WS-GHA-GLC-001 | Remote CI include not pinned | M | H | CWE-829 · CICD-SEC-3 | GLC | yp | `yp any(include ~ '^https?://', include[*] ~ '^https?://', include[*].remote exists)` ∨ `yp each include[*] · project exists ; none(ref ~ @GLC_PINNED_REF)` ∨ `yp each include[*] · component ~ @GLC_COMPONENT_FLOAT` | `local:` and `template:` includes never match | `project:` plus `ref: <sha or tag>`; components pinned to `@<sha>` or an exact version |
| WS-GHA-GLC-002 | Commit or MR text evaluated by a shell | H | M | CWE-78 · CICD-SEC-4 | GLC | rx | `@GLC_EVAL_VAR` | — | Never `eval`; quote variables; validate branch names |
| WS-GHA-GLC-003 | Docker-in-Docker over unauthenticated TCP | M | H | CWE-319, CWE-306 | GLC | yp | `any(**.DOCKER_TLS_CERTDIR == "", **.DOCKER_HOST ~ @GLC_DIND_TCP)` | — | `DOCKER_TLS_CERTDIR: "/certs"` with `tcp://docker:2376`, or rootless BuildKit or Kaniko |

```yaml
# patterns: tekton-flux-gitlab
TKN_PARAM_INTERP: '\$\((?:params|inputs\.params)\.[A-Za-z0-9_.-]{1,64}\)|\$\(params\[[ \t]{0,2}["''][^"''\]\n]{1,64}["''][ \t]{0,2}\]\)|\$\(tasks\.[A-Za-z0-9_-]{1,64}\.results\.[A-Za-z0-9_.-]{1,64}\)'
TKN_DIGEST_OR_PARAM: '@sha256:[0-9a-f]{64}$|\$\('
TKN_PINNED: '^[0-9a-f]{40}$|@sha256:[0-9a-f]{64}$'
GLC_PINNED_REF: '^(?:[0-9a-f]{40}|v?[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6})$'
GLC_COMPONENT_FLOAT: '@(?:main|master|HEAD|~latest)$'
GLC_EVAL_VAR: '\b(?:eval|(?:ba|z)?sh[ \t]+-c)\b[^\n]{0,200}\$\{?CI_(?:COMMIT_(?:MESSAGE|TITLE|DESCRIPTION|BRANCH|REF_NAME|TAG_MESSAGE|AUTHOR)|MERGE_REQUEST_(?:TITLE|DESCRIPTION|SOURCE_BRANCH_NAME))\b'
GLC_DIND_TCP: '^tcp://[^\s:]{1,253}:2375/?$'
```

---

## 6. Reverse proxies: NGINX, Traefik, Coolify (`WS-WEB-PRX`)

Proxy configuration is web-tier configuration, so these rules live in the `WS-WEB` namespace under the sub-namespace
`PRX` and in the pack `domain/proxy`. See §14 #2. NGINX has no structured matcher and uses `rx`/`ml`. Traefik static
and dynamic YAML uses `yp`. Traefik CLI flags and Docker labels are found with `rx` wherever they appear (compose
`command:`, k8s `args:`, labels). Coolify deploys Compose files behind its own Traefik (or Caddy) proxy. The Traefik
rules apply to any Coolify proxy configuration committed to the repo, and PRX-030 covers the Coolify-specific trap.

| ID | Title | Sev | Conf | Refs | Files | M | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|
| WS-WEB-PRX-001 | Directory listing enabled | M | H | CWE-548 · A05 | NGX | rx | `'^[ \t]*autoindex[ \t]+on[ \t]*;'` | Download mirrors are suppressed | `autoindex off;` |
| WS-WEB-PRX-002 | Legacy TLS protocol enabled | M | H | CWE-326, CWE-327 · A02 | NGX | rx | `@NGX_OLD_TLS` | — | `ssl_protocols TLSv1.2 TLSv1.3;` |
| WS-WEB-PRX-003 | Weak cipher allowed | M | H | CWE-327 · A02 | NGX | rx | `@NGX_WEAK_CIPHER` | Entries negated with `!` are ignored | The Mozilla "intermediate" cipher list |
| WS-WEB-PRX-004 | `proxy_pass` target taken from the request | H | M | CWE-918 · A10 | NGX | rx | `@NGX_PROXY_PASS_VAR` | Variables produced by an allow-listing `map` don't match | A `map` from host to upstream allow-list, or fixed `upstream {}` blocks |
| WS-WEB-PRX-005 | `alias` off-by-slash path traversal | H | H | CWE-22 · A01 | NGX | ml | `@NGX_ALIAS` (full rule in §12.3) | Regex locations and slash-balanced pairs never match | End both the location and the alias with `/`, or use `root` |
| WS-WEB-PRX-006 | Reflected CORS origin with credentials | H | H | CWE-942 · A05 | NGX | rx | `@NGX_CORS_REFLECT ∧ @NGX_CORS_CREDS ∧ ¬@NGX_ORIGIN_CHECK ±12` | Allow-lists written with `map $http_origin` or `if ($http_origin ~ …)` | `map $http_origin $cors_ok { default ""; "~^https://app\.example\.com$" $http_origin; }` |
| WS-WEB-PRX-007 | `$uri` in a redirect or header enables CRLF injection | M | H | CWE-113, CWE-93 · A03 | NGX | rx | `@NGX_CRLF_URI` | — | Use `$request_uri`, which stays percent-encoded |
| WS-WEB-PRX-008 | Status endpoint without access control | M | M | CWE-200 · A05 | NGX | rx | `@NGX_STATUS ∧ ¬@NGX_ACCESS_CTRL ±6` | Listeners bound to 127.0.0.1 (the verifier checks) | `allow 10.0.0.0/8; deny all;` |
| WS-WEB-PRX-009 † | Upstream TLS certificate not verified | L | L | CWE-295 · A02 | NGX | rx | `@NGX_PROXY_HTTPS ∧ ¬@NGX_SSL_VERIFY_ON` (whole file) | Loopback upstreams are excluded by the pattern | `proxy_ssl_verify on; proxy_ssl_trusted_certificate …; proxy_ssl_name …;` |
| WS-WEB-PRX-010 † | Request body size unlimited | L | H | CWE-770 · API4 | NGX | rx | `'^[ \t]*client_max_body_size[ \t]+0[ \t]*;'` | Upload endpoints that enforce a limit in the app | An explicit limit per location |
| WS-WEB-PRX-020 | Traefik API or dashboard in insecure mode | H | H | CWE-306 · A05 | TRF, PRX-ANY | yp ∨ rx ∨ seq | `yp api.insecure == true` ∨ `rx @TRF_API_INSECURE_CLI` ∨ `seq[@TOML_API_SECTION, @TOML_INSECURE_TRUE] ≤8` | — | `api.dashboard: true` behind a router with auth middleware on an internal entrypoint |
| WS-WEB-PRX-021 | Dashboard router without auth middleware | H | M | CWE-306 | PRX-ANY | rx ∨ yp | `rx @TRF_DASH_ROUTER ∧ ¬@TRF_ROUTER_MW ±20` ∨ `yp each spec.routes[*] · services[*].name == api@internal ; middlewares absent ; $.kind == IngressRoute` | A router bound to an internal-only entrypoint (the verifier checks) | A `basicAuth` or `forwardAuth` (OIDC) middleware plus an IP allow-list |
| WS-WEB-PRX-022 | Backend TLS verification disabled | M | H | CWE-295 | TRF, PRX-ANY | yp ∨ rx | `yp **.insecureSkipVerify == true` ∨ `rx @TRF_SKIPVERIFY_CLI` | — | A `serversTransport` with `rootCAs` |
| WS-WEB-PRX-023 | Forwarded headers trusted from any client | H | M | CWE-348, CWE-290 | TRF, PRX-ANY | yp ∨ rx | `yp any(**.forwardedHeaders.insecure == true, **.proxyProtocol.insecure == true, **.forwardedHeaders.trustedIPs[*] in ["0.0.0.0/0", "::/0"])` ∨ `rx @TRF_FWD_INSECURE_CLI` | — | `trustedIPs` limited to the cloud load balancer's CIDRs. Otherwise `ipAllowList` and app rate limits can be bypassed with a spoofed `X-Forwarded-For` |
| WS-WEB-PRX-024 | Docker provider exposes every container | M | M | CWE-1188 · A05 | TRF, PRX-ANY | yp ∨ rx | `yp providers.docker exists ; none(providers.docker.exposedByDefault == false)` ∨ `rx @TRF_DOCKER_PROVIDER_CLI ∧ ¬@TRF_EXPOSED_FALSE_CLI` | — | `exposedByDefault: false` plus a `traefik.enable=true` label per service |
| WS-WEB-PRX-025 | Basic-auth hashes committed in labels or dynamic config | M | H | CWE-522, CWE-916 | PRX-ANY | rx ∨ yp | `rx @TRF_BASICAUTH_INLINE` ∨ `yp **.basicAuth.users[*] ~ @HTPASSWD_ENTRY` | bcrypt `$2y$` is still flagged, because the hash is in VCS | `usersFile` mounted from a Secret, or forwardAuth with OIDC |
| WS-WEB-PRX-030 | Coolify-managed service publishes host ports | H | H | CWE-668 | CMP | yp ∧ rx | `yp each services.* · ports[*] ~ @COMPOSE_PUBLISHED_PORT` ∧ `rx @COOLIFY_MARKER` · `supersedes: [WS-DKR-023]` | Ports bound to loopback never match the pattern | Remove `ports:` and route through Coolify's proxy (domains), or bind `127.0.0.1:`. Published ports bypass both the proxy and the host firewall |

```yaml
# patterns: proxy
NGX_OLD_TLS: '^[ \t]*(?:ssl_protocols|proxy_ssl_protocols)[ \t][^;\n]{0,200}?\b(?P<proto>SSLv2|SSLv3|TLSv1(?:\.1)?)(?![.0-9])'
NGX_WEAK_CIPHER: '^[ \t]*(?:ssl_ciphers|proxy_ssl_ciphers)[ \t][^;\n]{0,1000}?(?<![!A-Za-z0-9])(?P<cipher>RC4|3DES|DES|MD5|NULL|EXPORT|EXP)(?![A-Za-z0-9])'
NGX_PROXY_PASS_VAR: '^[ \t]*proxy_pass[ \t]+(?:https?://)?\$(?:arg_[A-Za-z0-9_]{1,64}|http_[A-Za-z0-9_]{1,64}|cookie_[A-Za-z0-9_]{1,64}|host|request_uri|uri|args|query_string)\b'
NGX_ALIAS: '^[ \t]*location[ \t]+(?:\^~[ \t]+|=[ \t]+)?(?P<loc>/[^\s{;]{0,200})(?<!/)[ \t]*\{[^{}]{0,2000}?\balias[ \t]+["'']?(?P<target>[^\s;"'']{1,300}/)["'']?[ \t]*;'
NGX_CORS_REFLECT: '(?i)^[ \t]*add_header[ \t]+["'']?Access-Control-Allow-Origin["'']?[ \t]+["'']?\$http_origin\b'
NGX_CORS_CREDS: '(?i)^[ \t]*add_header[ \t]+["'']?Access-Control-Allow-Credentials["'']?[ \t]+["'']?true\b'
NGX_ORIGIN_CHECK: '(?i)\bif[ \t]*\([ \t]*\$http_origin[ \t]*!?~|\bmap[ \t]+\$http_origin\b'
NGX_CRLF_URI: '^[ \t]*(?:return[ \t]+30[1278][ \t]+|rewrite[ \t]+[^\s]{1,300}[ \t]+|add_header[ \t]+[^\s]{1,100}[ \t]+|proxy_set_header[ \t]+[^\s]{1,100}[ \t]+)[^;\n]{0,300}?\$(?:uri|document_uri)\b'
NGX_STATUS: '^[ \t]*(?:stub_status|vhost_traffic_status_display)\b[^;\n]{0,20};'
NGX_ACCESS_CTRL: '^[ \t]*(?:allow|deny|auth_basic|auth_request|satisfy)[ \t]'
NGX_PROXY_HTTPS: '^[ \t]*proxy_pass[ \t]+https://(?!(?:127\.0\.0\.1|localhost|\[::1\])[:/;])'
NGX_SSL_VERIFY_ON: '^[ \t]*proxy_ssl_verify[ \t]+on[ \t]*;'
TRF_API_INSECURE_CLI: '(?i)--api\.insecure(?:=true)?(?=["''\s,\]]|$)'
TOML_API_SECTION: '^[ \t]*\[api\][ \t]*$'
TOML_INSECURE_TRUE: '^[ \t]*insecure[ \t]*=[ \t]*true\b'
TRF_DASH_ROUTER: '(?i)traefik\.http\.routers\.[A-Za-z0-9_-]{1,64}\.service[ \t]*[=:][ \t]*["'']?api@internal'
TRF_ROUTER_MW: '(?i)traefik\.http\.routers\.[A-Za-z0-9_-]{1,64}\.middlewares[ \t]*[=:]'
TRF_SKIPVERIFY_CLI: '(?i)--serverstransport\.insecureskipverify(?:=true)?(?=["''\s,\]]|$)'
TRF_FWD_INSECURE_CLI: '(?i)--entrypoints\.[A-Za-z0-9_-]{1,64}\.(?:forwardedheaders|proxyprotocol)\.insecure(?:=true)?(?=["''\s,\]]|$)'
TRF_DOCKER_PROVIDER_CLI: '(?i)--providers\.docker(?:=true)?(?=["''\s,\]]|$)'
TRF_EXPOSED_FALSE_CLI: '(?i)--providers\.docker\.exposedbydefault=false\b'
TRF_BASICAUTH_INLINE: '(?i)basicauth\.users[ \t]*[=:][ \t]*["'']?[^\s:"'',]{1,64}:\$\$?(?:apr1|2[aby]|5|6)\$'
HTPASSWD_ENTRY: '^[^:\s]{1,64}:\$(?:apr1|2[aby]|5|6)\$'
COMPOSE_PUBLISHED_PORT: '^(?:(?:0\.0\.0\.0|\[::\]):)?[0-9]{1,5}(?:-[0-9]{1,5})?:[0-9]{1,5}(?:-[0-9]{1,5})?(?:/(?:tcp|udp))?$'
COOLIFY_MARKER: '\bSERVICE_(?:FQDN|URL)_[A-Z0-9_]{1,64}\b|\bcoolify\.(?:managed|applicationId|serviceId|name)\b'
```

---

## 7. FastAPI and Python web (`WS-API`)

Generic sinks that DESIGN §5 lists for this pack are owned by the appsec pack and are not duplicated here: `yaml.load`
(`WS-DES`), `eval` on request data and SQL built from route parameters (`WS-INJ`), and SSRF (`WS-SSRF`). The rules
below are FastAPI- and ASGI-specific.

| ID | Title | Sev | Conf | Refs | Files | M | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|
| WS-API-001 | State-changing route without an auth dependency | H | M | CWE-306, CWE-862 · API2, API5 | PY-API | route | `fastapi_route {methods: [post, put, patch, delete]}` with the engine §8.7 defaults for `auth_regex` and health paths | Auth attached in another module gives `confidence_delta = -1`, and the verifier checks | `APIRouter(dependencies=[Depends(require_user)])` |
| WS-API-002 | Wildcard CORS with credentials | H | H | CWE-942 · API8 | PY-API | ast | `call **.add_middleware · args.0 regex 'CORSMiddleware$' ; kwargs.allow_credentials == true ; any(kwargs.allow_origins regex '\*', kwargs.allow_origin_regex regex @API_ANY_ORIGIN_RX)`. Starlette reflects the request origin in this setup | — | An explicit list of origins |
| WS-API-003 | Debug mode enabled | M | H | CWE-489, CWE-215 · API8 | PY-API | ast | `call **.{FastAPI,Starlette} · kwargs.debug == true` | — | `debug=settings.debug`, defaulting to False |
| WS-API-004 | Secret compared with `==` | M | M | CWE-208 · API2 | PY | rx | `@API_SECRET_EQ ∨ @API_SECRET_EQ_REV` | Comparisons with `None`, `""`, `0`, `True` and `False` are excluded by the pattern | `hmac.compare_digest(a, b)` |
| WS-API-005 | Proxy headers trusted from any source | H | M | CWE-348 · API8 | CFG-ANY | rx | `@API_PROXY_TRUST_ALL` | An app reachable only from the proxy on a private network (the verifier checks) | Set `--forwarded-allow-ips` to the proxy CIDRs |
| WS-API-006 | Request body spread into a model constructor | M | L | CWE-915 · API3 | PY-API | rx ∨ seq | `rx @API_MASS_ASSIGN` ∨ `seq[@API_SETATTR_FOR, 'setattr\('] ≤3` | Pydantic-to-Pydantic copies, where the target is not an ORM model (the verifier checks) | Map fields explicitly, or `model_dump(include=ALLOWED)` |
| WS-API-007 | StaticFiles serves the project root | H | H | CWE-552, CWE-538 · API8 | PY-API | ast | `call **.StaticFiles · kwargs.directory regex @API_ROOT_DIR` | — | A dedicated `static/` directory |
| WS-API-008 | Exception text returned to the client | M | M | CWE-209 · API8 | PY-API | rx | `@API_EXC_DETAIL` | — | Log server-side with a correlation ID and return a generic `detail` |
| WS-API-009 | WebSocket endpoint without auth | M | M | CWE-306, CWE-1385 · API2 | PY-API | route | `fastapi_route {methods: [websocket]}` | A token check inside the handler before `accept()` (the verifier checks) | Authenticate and check `Origin` before `websocket.accept()` |
| WS-API-010 | Auth or session cookie without Secure or HttpOnly | M | M | CWE-614, CWE-1004 · API2 | PY-API | ast | `call **.set_cookie · args.0 regex @API_SESSION_COOKIE · kwarg_absent [httponly]` ∨ the same with `[secure]` ∨ `call **.set_cookie · any kwarg of {httponly, secure} == false` | A non-constant `secure=settings.cookie_secure` counts as present | `secure=True, httponly=True, samesite="lax"` |

```yaml
# patterns: fastapi
API_ANY_ORIGIN_RX: '^\^?\.[*+]\$?$'
API_SECRET_EQ: '(?i)^[ \t]*(?:if|elif|assert|return|while)\b[^\n#]{0,160}?\b(?P<name>[A-Za-z0-9_.]{0,60}?(?:api_?key|token|secret|signature|passw(?:or)?d|hmac|digest))\b[ \t]*(?:==|!=)(?![ \t]*(?:None\b|["'']{2}|0\b|True\b|False\b))'
API_SECRET_EQ_REV: '(?i)^[ \t]*(?:if|elif|assert|return|while)\b[^\n#]{0,160}?(?:==|!=)[ \t]*[A-Za-z0-9_.]{0,60}?(?:api_?key|token|secret|signature|passw(?:or)?d|hmac|digest)\b'
API_PROXY_TRUST_ALL: '(?i)(?:--forwarded-allow-ips(?:=|[ \t]+)["'']?\*|\bforwarded_allow_ips[ \t]*=[ \t]*["'']\*["'']|\bFORWARDED_ALLOW_IPS["'']?[ \t]*[=:][ \t]*["'']?\*|\btrusted_hosts[ \t]*=[ \t]*["'']\*["''])'
API_MASS_ASSIGN: '\b[A-Z][A-Za-z0-9_]{0,63}\([ \t]*\*\*[ \t]*(?:await[ \t]+)?(?:request\.json\(\)|[a-z_][a-z0-9_]{0,40}\.(?:dict|model_dump)\([ \t]*\))'
API_SETATTR_FOR: '\bfor[ \t]+[a-z_][a-z0-9_]{0,20}[ \t]*,[ \t]*[a-z_][a-z0-9_]{0,20}[ \t]+in[ \t]+[^\n]{0,120}?\.(?:dict|model_dump)\([^\n)]{0,80}\)\.items\(\)'
API_ROOT_DIR: '^(?:\.{1,2}|/|/app|/srv|/code|/workspace)/?$'
API_EXC_DETAIL: '\bdetail[ \t]*=[ \t]*(?:(?:str|repr)\([ \t]*(?:e|ex|exc|err|error|exception)[ \t]*\)|f["''][^"''\n]{0,200}\{(?:e|ex|exc|err|error|exception)(?:![rs])?\})|(?:return|JSONResponse\(|PlainTextResponse\()[^\n]{0,200}?traceback\.format_exc\(\)'
API_SESSION_COOKIE: '(?i)session|sess_?id|\bsid\b|token|auth|jwt|refresh|remember'
```

---

## 8. Airflow (`WS-AIR`)

`dag_run.conf` is set by whoever can trigger a DAG: the UI, the REST API, or a `TriggerDagRunOperator` fed by
upstream data. `params` can be overridden from the trigger's `conf`, because `dag_run_conf_overrides_params` defaults
to true. Both are treated as untrusted.

| ID | Title | Sev | Conf | Refs | Files | M | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|
| WS-AIR-001 | Trigger conf or params rendered into a shell command | H | H | CWE-78, CWE-1336 · A03 | PY-AIR | seq | `seq[@AIR_OP_SHELL, @AIR_CMD_KW, @AIR_JINJA_UNTRUSTED] ≤12` (engine §8.3 example, extended to SSH, KPO and Docker) | — | `env={"X": "{{ dag_run.conf['x'] }}"}` and `"$X"` in the command, with validation by a `Param(type="string", pattern=…)` schema |
| WS-AIR-002 | Trigger conf or params rendered into SQL | H | H | CWE-89 · A03 | PY-AIR, SQL under `dags/**` | ml ∨ rx | `ml @AIR_SQL_JINJA` ∨ `rx @AIR_JINJA_UNTRUSTED` in `**/dags/**/*.sql` | Values passed through `parameters=` never match | `sql="… WHERE id = %(id)s"` with `parameters={"id": "{{ dag_run.conf['id'] }}"}` |
| WS-AIR-003 | Trigger conf reaches a hook query or a subprocess | H | M | CWE-89, CWE-78 · A03 | PY-AIR | ast | `call [**.{run,get_records,get_first,get_pandas_df,execute}, subprocess.{run,call,check_output,Popen}, os.system] · args.0 tainted · sources [airflow] · require_import airflow` | `int()` and `UUID()` casts (default sanitizers) | Bind parameters and argv lists |
| WS-AIR-004 | Connection or Variable secret written to logs | M | M | CWE-532 · A09 | PY-AIR | rx | `@AIR_LOG_SECRET` | — | Never log it. Transformations such as slicing or `.upper()` defeat the secrets masker |
| WS-AIR-005 | Connection defined with a literal password | H | H | CWE-798 · A07 | PY-AIR, AIR-CFG | ast ∨ rx | `ast call **.Connection · kwargs.password constant · require_import airflow` ∨ `rx @AIR_CONN_ENV` (`secret_group: secret`) | `${VAR}` and `{{ }}` values never match | A secrets backend (AWS Secrets Manager, GCP Secret Manager, Vault) |
| WS-AIR-006 | REST API without authentication | C | H | CWE-306 · API2 | AIR-CFG | rx | `@AIR_AUTH_DEFAULT` | — | `airflow.api.auth.backend.session` or `basic_auth` (the Airflow 3 auth manager), plus a network policy |
| WS-AIR-007 | Configuration exposed in the web UI | M | H | CWE-200 · A05 | AIR-CFG | rx | `@AIR_EXPOSE_CONFIG` | `non-sensitive-only` does not match | `expose_config = False` |
| WS-AIR-008 | Static webserver secret key or Fernet key committed | H | M | CWE-798, CWE-321 | AIR-CFG | rx | `@AIR_STATIC_KEY` (`secret_group: secret`), keywords `[airflow, fernet]` | — | Generate the key per environment and reference a Secret (`webserverSecretKeySecretName` and `fernetKeySecretName` in the official chart) |
| WS-AIR-009 | Operator runs a privileged container | H | H | CWE-250 | PY-AIR | ast ∨ seq | `ast call **.DockerOperator · kwargs.privileged == true` ∨ `seq[@AIR_KPO, @AIR_PRIV_DICT] ≤15` | — | Drop `privileged`, and use `pod_template_file` with a restricted `securityContext` |

```yaml
# patterns: airflow
AIR_OP_SHELL: '\b(?:BashOperator|SSHOperator|KubernetesPodOperator|DockerOperator)\('
AIR_CMD_KW: '\b(?:bash_command|command|cmds|arguments)[ \t]*='
AIR_JINJA_UNTRUSTED: '\{\{[ \t]{0,4}(?:dag_run\.conf|params)\b'
AIR_SQL_JINJA: '\bsql[ \t]*=[ \t]*[rbfRBF]{0,2}(?P<q>"""|''''''|"|'')(?:(?!(?P=q))[^\\]|\\.){0,4000}?\{\{[ \t]{0,4}(?:dag_run\.conf|params)\b'
AIR_LOG_SECRET: '\b(?:print|(?:log|logger|logging|self\.log)\.(?:info|debug|warning|warn|error|exception|critical))\([^\n]{0,200}?(?:Variable\.get\(|\.password\b|\.get_password\(\)|\.extra_dejson\b|\.get_uri\(\)|BaseHook\.get_connection\()'
AIR_CONN_ENV: '\bAIRFLOW_CONN_[A-Z0-9_]{1,64}["'']?[ \t]*[=:][ \t]*["'']?[a-z][a-z0-9+.-]{1,30}://[^:\s/@"'']{1,128}:(?P<secret>[^@\s$"''{]{1,256})@'
AIR_AUTH_DEFAULT: '(?i)auth_backends?\b["'']?[ \t]*[=:][ \t]*["'']?[^\n]{0,200}?\bairflow\.api\.auth\.backend\.default\b'
AIR_EXPOSE_CONFIG: '(?i)expose_config\b["'']?[ \t]*[=:][ \t]*["'']?true\b'
AIR_STATIC_KEY: '(?i)(?:AIRFLOW__WEBSERVER__SECRET_KEY|AIRFLOW__CORE__FERNET_KEY|webserverSecretKey|fernetKey|^[ \t]*(?:secret_key|fernet_key))["'']?[ \t]*[=:][ \t]*["'']?(?P<secret>[A-Za-z0-9+/_=-]{16,128})'
AIR_KPO: '\bKubernetesPodOperator\('
AIR_PRIV_DICT: '["'']privileged["''][ \t]*:[ \t]*True\b'
```

---

## 9. Spark and PySpark (`WS-SPK`)

| ID | Title | Sev | Conf | Refs | Files | M | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|
| WS-SPK-001 | `spark.sql` with a dynamically built string | H | M | CWE-89 · A03 | PY-SPK | ast | `call **.sql · args.0 dynamic_string · require_import pyspark`. Reachability becomes `tainted` when a source reaches the argument | Module constants get `constant` reachability (×0.6, engine §10) | `spark.sql("… WHERE d = :d", args={"d": v})` (Spark 3.4+) or the DataFrame API |
| WS-SPK-002 | Scala interpolated SQL string | H | M | CWE-89 · A03 | SCALA (`spark` tag) | ml | `@SPK_SCALA_SQL` | Constants (the verifier checks) | `spark.sql(q, Map("d" -> v))` (Spark 3.4+) |
| WS-SPK-003 | JDBC credentials inline | H | H | CWE-798 | PY-SPK, SCALA | rx | `@SPK_JDBC_PWD_OPT ∨ @SPK_JDBC_URL_PWD` (`secret_group: secret`) | `${…}` and `dbutils.secrets.get(...)` values never match | Read credentials from a secrets manager at runtime, or use IAM database auth |
| WS-SPK-004 | JDBC `query` or `dbtable` option built dynamically | H | M | CWE-89 | PY-SPK | ast | `call **.option · args.0 regex @SPK_JDBC_SQL_OPT ; args.1 dynamic_string · require_import pyspark` | — | Push predicates down with DataFrame filters, and allow-list table names |
| WS-SPK-005 | Object-store keys in Spark configuration | H | H | CWE-798 | PY-SPK, SCALA, `**/spark-defaults.conf`, K8S (`SparkApplication`) | rx | `@SPK_CLOUD_KEY_CONF` (`secret_group: secret`) | — | IRSA or Workload Identity with `fs.s3a.aws.credentials.provider=…WebIdentityTokenCredentialsProvider` |
| WS-SPK-006 | `rdd.pipe` with a dynamic command | H | M | CWE-78 | PY-SPK, SCALA | ast ∨ rx | `ast call **.pipe · args.0 dynamic_string · require_import pyspark` ∨ `rx @SPK_SCALA_PIPE` | — | A fixed command, with data passed only on stdin |
| WS-SPK-007 † | `pickleFile` on an externally supplied path | M | L | CWE-502 | PY-SPK | ast | `call **.pickleFile · require_import pyspark` | Internal checkpoint directories (the verifier checks) | Parquet or Delta. Never unpickle external data |

```yaml
# patterns: spark
SPK_SCALA_SQL: '\.sql\([ \t\n]{0,8}s"(?:"")?(?:[^"$\\]|\\.){0,4000}\$\{?[A-Za-z_]'
SPK_JDBC_PWD_OPT: '\.option\([ \t]*["'']password["''][ \t]*,[ \t]*["''](?P<secret>[^"''\n$]{1,256})["'']'
SPK_JDBC_URL_PWD: '(?i)jdbc:(?:postgresql|mysql|mariadb|singlestore|sqlserver|oracle:thin|redshift|snowflake)[^\s"'']{0,300}?[?&;](?:password|pwd)=(?P<secret>[^&\s"'';$]{1,128})'
SPK_JDBC_SQL_OPT: '^(?:query|dbtable|predicates|sessionInitStatement|prepareQuery)$'
SPK_CLOUD_KEY_CONF: '(?:spark\.hadoop\.)?fs\.(?:s3a\.(?:secret\.key|access\.key|session\.token)|azure\.account\.key\.[A-Za-z0-9.-]{1,200}|gs\.auth\.service\.account\.private\.key)["'']?[ \t]*[,=:][ \t]*["'']?(?P<secret>[A-Za-z0-9/+=_-]{16,4096})'
SPK_SCALA_PIPE: '\.pipe\([ \t]*s"[^"\n]{0,300}\$'
```

---

## 10. LLM, RAG and agents (`WS-LLM`)

The source set `llm` is defined in engine §8.7. It covers the results of `invoke`, `converse`, `invoke_model`,
`generate_content` and similar calls in files tagged `llm`, which includes Bedrock (`bedrock-runtime`) and Vertex AI
(`vertexai`, `google.cloud.aiplatform`). The new set `tool_args` is defined in §14 #5.

| ID | Title | Sev | Conf | Refs | Files | M | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|
| WS-LLM-001 | Model output reaches eval or exec | C | H | CWE-94, CWE-95 · LLM05 · AML.T0051 | PY-LLM | ast | `call {eval,exec,compile} · args.0 tainted · sources [llm]` | `ast.literal_eval` and `json.loads` are not sinks | Parse structured output with a schema and dispatch to allow-listed functions |
| WS-LLM-002 | Model output reaches a shell | C | H | CWE-78 · LLM05, LLM06 | PY-LLM | ast | `call [subprocess.{run,call,check_call,check_output,Popen}, os.{system,popen}, asyncio.{create_subprocess_shell,create_subprocess_exec}] · args.0 tainted · sources [llm]` | `shlex.quote` (a default sanitizer) | An argv list from an allow-list, and a sandbox without credentials for code-running agents |
| WS-LLM-003 | Model output executed as SQL | H | H | CWE-89 · LLM05 | PY-LLM | ast | `call [**.execute, **.executemany, **.sql, sqlalchemy.text, pandas.read_sql, **.read_sql_query] · args.0 tainted · sources [llm]` | Text-to-SQL on a read-only role with a statement allow-list is suppressed with a reason | A read-only DB role, `SET TRANSACTION READ ONLY`, and parsing with an allow-list of tables |
| WS-LLM-004 | Model output chooses an outbound URL | H | M | CWE-918 · LLM06 · AML.T0057 | PY-LLM | ast | `call [{requests,httpx}.{get,post,put,patch,request,stream}, urllib.request.urlopen] · args.0 tainted · sources [llm]` | Allow-list validators listed in the rule's `sanitizers` | Resolve URLs from IDs in an allow-list, and send egress through a proxy |
| WS-LLM-005 | Agent toolkit with unrestricted code, shell or HTTP | H | H | CWE-749, CWE-250 · LLM06 | PY-LLM | ast | `ast call **.{ShellTool,PythonREPLTool,PythonAstREPLTool,BashProcess}` ∨ `ast call ** · kwargs.allow_dangerous_code == true` ∨ `ast call ** · kwargs.allow_dangerous_requests == true` | `path_not_glob: ["**/notebooks/**"]` | Narrow, typed tools; code tools run in a sandbox with no secrets |
| WS-LLM-006 | Tool function forwards model-chosen arguments to a dangerous sink | H | M | CWE-78, CWE-22, CWE-94 · LLM06 · AML.T0053 | PY-LLM, PY (MCP servers) | ast | `call [subprocess.*, os.{system,popen,remove}, {eval,exec,open}, shutil.{rmtree,copy,move}] · args.0 tainted · sources [tool_args]` | Path jails (`os.path.basename`, a default sanitizer) and validators in `sanitizers` | Validate arguments (`Literal`, bounded types) and jail paths with `resolve().is_relative_to(root)` |
| WS-LLM-007 | Secret interpolated into a prompt | H | M | CWE-200, CWE-1427 · LLM02, LLM07 · AML.T0056 | PY-LLM | rx | `@LLM_SECRET_IN_PROMPT` | — | Keep credentials out of prompts. Tools fetch them server-side |
| WS-LLM-008 | Model output rendered as HTML | H | M | CWE-79 · LLM05 | PY-LLM, JS | ast ∨ rx | `ast call streamlit.markdown · kwargs.unsafe_allow_html == true ; args.0 constant: false` ∨ `ast call [markupsafe.Markup, **.HTMLResponse] · args.0 tainted · sources [llm]` ∨ `rx @LLM_JSX_HTML` | Constant HTML | Render as text, or sanitize with an allow-list sanitizer and block remote images (markdown image exfiltration) |
| WS-LLM-009 | Untrusted input placed in the system prompt | M | M | CWE-1427 · LLM01 · AML.T0051.001 | PY-LLM | ast | `ast call **.{converse,converse_stream} · kwargs.system tainted · sources [web, net, msg]` ∨ `ast call **.GenerativeModel · kwargs.system_instruction tainted · sources [web, net, msg]` | — | Keep the system prompt constant, and put retrieved or user content in user turns with provenance labels |
| WS-LLM-010 † | RAG ingestion without provenance metadata | L | L | CWE-345 · LLM04, LLM08 · AML.T0070 | PY-LLM | ast | `call **.{add_texts,aadd_texts,from_texts,afrom_texts} · kwarg_absent [metadatas] · require_import [langchain, langchain_community, langchain_core, llama_index]` | `add_documents` (metadata lives in the Document) is not matched | `metadatas=[{"source": uri, "sha256": h, "trust": "untrusted"}]`, filtered by trust at retrieval |
| WS-LLM-011 | Bedrock call without a guardrail | L | L | CWE-1427 · LLM01 | PY-LLM | ast | `ast call **.{converse,converse_stream} · kwarg_absent [guardrailConfig] · require_import boto3` ∨ `ast call **.{invoke_model,invoke_model_with_response_stream} · kwarg_absent [guardrailIdentifier] · require_import boto3` | Batch and offline jobs are demoted by `internal` exposure | `guardrailConfig={"guardrailIdentifier": …, "guardrailVersion": …}` |
| WS-LLM-012 | Vertex AI safety filters disabled | L | H | CWE-693 · LLM01 | PY-LLM | rx | `@LLM_SAFETY_OFF` | `path_not_glob: ["**/evals/**", "**/redteam/**"]` | Default thresholds, with documented exceptions |
| WS-LLM-013 | Remote code or pickle executed while loading a model | H | H | CWE-94, CWE-502 · LLM03 · AML.T0010 | PY | ast | `ast call **.{from_pretrained,pipeline} · kwargs.trust_remote_code == true` ∨ `ast call torch.load · kwargs.weights_only == false` | A missing `weights_only` is safe on torch 2.6+ and not flagged | `trust_remote_code=False`, or a `revision=<sha>` of a reviewed commit; safetensors; `weights_only=True` |
| WS-LLM-014 | Vector database reached over plaintext on a remote host | M | M | CWE-319 · LLM08 | PY-LLM | rx | `@LLM_VECTOR_HTTP` | `line_not_regex: @LLM_SVC_DNS` covers in-cluster service DNS on a meshed network | HTTPS plus an API key, or mesh mTLS |
| WS-LLM-015 | Agent loop without an iteration bound | M | M | CWE-770, CWE-834 · LLM10 | PY-LLM | ast | `call **.AgentExecutor · kwargs.max_iterations == null` | — | `max_iterations`, `max_execution_time` and a token budget |

```yaml
# patterns: llm-rag
LLM_SECRET_IN_PROMPT: '(?i)\b(?:system_?prompt|system_?message|system_?instruction|instructions|SystemMessage\(|"role"[ \t]*:[ \t]*"system")[^\n]{0,200}?\{[ \t]{0,4}(?:os\.environ|os\.getenv|settings\.[A-Za-z0-9_]{0,40}(?:key|token|secret|password))'
LLM_JSX_HTML: 'dangerouslySetInnerHTML=\{\{[ \t]*__html:[ \t]*[^}\n]{0,120}?\b(?:completion|response|answer|output|message|content|generated|llm)\w{0,20}'
LLM_SAFETY_OFF: '(?:HarmBlockThreshold\.|\bthreshold["'']?[ \t]*[=:][ \t]*["'']?(?:HarmBlockThreshold\.)?)(?:BLOCK_NONE|OFF)\b'
LLM_VECTOR_HTTP: '\b(?:QdrantClient|HttpClient|MilvusClient|Elasticsearch|OpenSearch|connect_to_custom|WeaviateClient)\([^\n]{0,300}?\b(?:url|host|uri|hosts|http_host)[ \t]*=[ \t]*\[?[ \t]*["'']http://(?!(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)[:/"''])'
LLM_SVC_DNS: 'http://[^/"''\s]{1,200}\.svc(?:\.cluster\.local)?[:/"'']'
```

---

## 11. Trading systems (`WS-TRD`)

The threat model is money leaving the account and orders the strategy did not intend: duplicated, oversized, sent to
live instead of the sandbox, or triggered by a forged signal. The references are SEC Rule 15c3-5 (pre-trade risk
controls for market access) and MiFID II RTS 6, Art. 12 (kill functionality) and Art. 15 (pre-trade controls). Exchange
keys in code are handled by `WS-SEC-TRD-*` (secrets pack). The rules below catch what that pack cannot see.

| ID | Title | Sev | Conf | Refs | Files | M | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|
| WS-TRD-001 | Exchange credential scoped for withdrawals or transfers | H | H | CWE-250, CWE-272 | PY-TRD, CFG-ANY | rx | `@TRD_WITHDRAW_SCOPE` | `path_not_glob: ["**/treasury/**"]` | Trade-only, IP-restricted keys. Withdrawals go through a separate, human-approved treasury path with an address allow-list |
| WS-TRD-002 | Trading process calls a withdrawal or transfer API | H | M | CWE-250, CWE-269 | PY-TRD | ast | `call **.{withdraw,transfer,create_withdrawal,withdraw_crypto} · require_import [ccxt, binance, coinbase, pybit, okx]` | Internal sub-account transfers (the verifier checks), and treasury paths | Same as 001 |
| WS-TRD-003 | Order placed without a client order ID | H | M | CWE-837 | PY-TRD | ast ∧ ¬rx | §12.4: `call @CALLEE_ORDER ∧ ¬@TRD_CLIENT_ID ±12` | Wrapper calls (`self.*_order(`) are removed by `line_not_regex` | A deterministic `clientOrderId` derived from (strategy, signal ID, leg), reused on every retry |
| WS-TRD-004 | Order path without a pre-trade notional or size guard | H | L | CWE-770, CWE-20 · SEC 15c3-5 · RTS 6 Art. 15 | PY-TRD | ast ∧ ¬rx | `call @CALLEE_ORDER ∧ ¬@TRD_RISK_GUARD ±40` | A guard enforced in a gateway module (the verifier checks) | A central `risk.check(order)` before every submit: max notional, max quantity, price collar, position limit |
| WS-TRD-005 | Order loop without a kill-switch check | H | L | CWE-754 · RTS 6 Art. 12 | PY-TRD | seq ∧ ¬rx | `seq[@TRD_LOOP_HEAD, @TRD_ORDER_METHOD] ≤30 ∧ ¬@TRD_KILL_SWITCH ±40` | — | Check a shared halt flag (Redis, DB or feature flag) on every iteration, plus the venue's cancel-on-disconnect or dead-man switch where it exists |
| WS-TRD-006 | Trading webhook accepts unsigned signals | C | M | CWE-345, CWE-306 · API2 | PY (keywords `[webhook, signal, alert, tradingview]`) | route ∧ ¬rx ∨ rx ∧ ¬rx | `route {methods: [post], auth_regex: @TRD_WEBHOOK_AUTH, ignore_paths_regex: @TRD_WEBHOOK_PATH_IGNORE} ∧ ¬@TRD_SIG_VERIFY` ∨ `rx @FLASK_WEBHOOK_ROUTE ∧ ¬@TRD_SIG_VERIFY` (whole file) | A `Depends(verify_signature)` counts as auth through `auth_regex` | HMAC-SHA256 over the raw body plus a timestamp, checked with `hmac.compare_digest` inside a replay window. For senders that cannot sign: a secret in the body compared in constant time, plus a source IP allow-list |
| WS-TRD-007 | Binary floating point for prices, quantities or balances | M | M | CWE-1339, CWE-681 | PY, SCALA, SQL (keywords `[price, qty, quantity, amount, notional, balance, pnl]`) | rx | `@TRD_FLOAT_CAST ∨ @TRD_DECIMAL_FROM_FLOAT ∨ @TRD_FLOAT_ANNOT ∨ @TRD_SQL_FLOAT` | `path_not_glob: ["**/research/**", "**/notebooks/**", "**/backtest*/**"]` | `Decimal` quantized to the venue's tick and lot size; `NUMERIC(38,18)` columns (Postgres, MySQL, SingleStore); `BigDecimal` in Scala |
| WS-TRD-008 | Trading client defaults to live mode | M | M | CWE-1188 | PY-TRD, CFG-ANY | rx | `@TRD_LIVE_DEFAULT` | `path_not_glob: ["**/prod/**", "**/live/**"]` | Default to paper or testnet. Live needs an explicit `TRADING_MODE=live` plus an account-ID allow-list |
| WS-TRD-009 | Live venue endpoint in test or staging code | H | H | CWE-1188 | `glob: ["**/tests/**", "**/test_*.py", "**/*_test.py", "**/conftest.py", "**/*staging*/**"]` | rx | `@TRD_LIVE_URL` with `exposure_sensitive: false` | `path_not_glob: ["**/cassettes/**"]` (recorded responses) | Testnet or paper URLs from config, plus a fail-closed guard that rejects live URLs when `ENV != prod` |
| WS-TRD-010 † | Live endpoint next to sandbox or testnet identifiers | M | L | CWE-1188 | PY-TRD, CFG-ANY | rx | `@TRD_LIVE_URL ∧ @TRD_SANDBOX_WORD ±5` | Explicit mode→URL tables (the verifier checks) | One validated mapping from mode to (base URL, key set) at startup |
| WS-TRD-011 | Unbounded retry around order submission | H | M | CWE-834, CWE-837 | PY-TRD | seq | `seq[@TRD_RETRY_NO_STOP, @TRD_DEF, @TRD_ORDER_METHOD] ≤30` ∨ `seq[@TRD_BACKOFF_NO_MAX, @TRD_DEF, @TRD_ORDER_METHOD] ≤30` ∨ `seq[@TRD_WHILE_TRUE, @TRD_ORDER_METHOD, @TRD_EXCEPT, @TRD_SWALLOW] ≤15` | Loops that look up the order by client ID before resubmitting (the verifier checks) | `stop_after_attempt(3)`; retry only with the same client order ID; on timeout, reconcile with `fetch_order` instead of resending |
| WS-TRD-012 | HTTP retry policy retries order POSTs | H | M | CWE-837 | PY-TRD | rx | `@TRD_HTTP_RETRY_POST` | — | Keep urllib3's default `allowed_methods` (idempotent verbs only) for order sessions |
| WS-TRD-013 | Message payload drives order parameters without validation | H | M | CWE-20 | PY-TRD | ast | `call @CALLEE_ORDER · args.* tainted · sources [msg, web] · sanitizers ["**.validate_order", "**.check_limits", "risk.*"]` | — | Validate against a schema with bounds (Pydantic), run the risk check, then submit |

```yaml
# patterns: trading
CALLEE_ORDER: '**.{create_order,create_limit_order,create_market_order,create_limit_buy_order,create_limit_sell_order,create_market_buy_order,create_market_sell_order,submit_order,place_order,new_order}'
TRD_WITHDRAW_SCOPE: '(?i)\bwallet:(?:withdrawals:create|transactions:send)\b|\benable_?withdrawals?["'']?[ \t]*[=:][ \t]*["'']?(?:true|1)\b|\b(?:permissions?|scopes?)["'']?[ \t]*[=:][ \t]*[\[(]?[^\n\])]{0,200}?["''](?:withdraw(?:als?)?|transfer)["'']'
TRD_CLIENT_ID: '(?i)\b(?:client_?order_?id|newClientOrderId|clOrdId|orderLinkId|client_oid|cl_ord_id|userref)\b'
TRD_RISK_GUARD: '(?i)\b(?:max_?notional|notional_?limit|max_?order_?(?:size|qty|value)|position_?limit|risk_?(?:check|limit|guard|manager|engine)|pre_?trade|check_?limits?|exposure_?limit|fat_?finger|price_?collar)'
TRD_KILL_SWITCH: '(?i)\b(?:kill_?switch|trading_?(?:enabled|halted|paused|allowed)|halt(?:ed)?_?trading|circuit_?breaker|emergency_?stop|is_?halted|stop_?event|should_?stop)\b'
TRD_LOOP_HEAD: '^[ \t]*(?:async[ \t]+)?(?:while[ \t]+(?:True|1)|for[ \t]+[^\n:]{1,120}?[ \t]in[ \t][^\n]{1,200}):'
TRD_ORDER_METHOD: '\.(?:(?:create|submit|place|new|send)_(?:\w{0,24}_)?order|placeOrder|submitOrder|newOrder)\('
TRD_FLOAT_CAST: '(?i)\bfloat\([^\n)]{0,80}?\b(?:price|px|qty|quantity|amount|notional|size|balance|pnl|fee|cost|equity)'
TRD_DECIMAL_FROM_FLOAT: '\bDecimal\([ \t]*-?[0-9]{1,30}\.[0-9]{1,30}[ \t]*\)'
TRD_FLOAT_ANNOT: '(?i)\b(?:\w{0,24}_)?(?:price|px|qty|quantity|amount|notional|balance|pnl|fee)\w{0,20}[ \t]*:[ \t]*(?:Double|Float)\b'
TRD_SQL_FLOAT: '(?i)^[ \t]*[`"]?(?:\w{0,24}_)?(?:price|amount|notional|balance|qty|quantity|pnl|fee|cost)(?:_\w{0,24})?[`"]?[ \t]+(?:FLOAT[48]?|DOUBLE(?:[ \t]+PRECISION)?|REAL)\b'
TRD_LIVE_URL: 'https://(?:api[1-4]?|fapi|dapi)\.binance\.com\b|https://api\.(?:exchange\.)?coinbase\.com\b|https://api\.kraken\.com\b|https://api\.alpaca\.markets\b|https://api\.bybit\.com\b|https://www\.okx\.com\b|https://api\.bitfinex\.com\b'
TRD_SANDBOX_WORD: '(?i)testnet|sandbox|paper|demo'
TRD_LIVE_DEFAULT: '(?i)\b(?:sandbox|testnet|paper|dry_?run|simulat(?:e|ion|ed))\w{0,20}[ \t]*(?::[ \t]*bool[ \t]*)?=[ \t]*(?:False|0)\b|\bset_sandbox_mode\([ \t]*False[ \t]*\)|getenv\([ \t]*["'']\w{0,20}(?:PAPER|SANDBOX|TESTNET|DRY_RUN)["''][ \t]*,[ \t]*["''](?:false|0|no)["'']'
TRD_RETRY_NO_STOP: '^[ \t]*@(?:tenacity\.)?retry\b(?!(?:[^\n]{0,300}\n){0,6}?[^\n]{0,300}?\b(?:stop|stop_max_attempt_number|stop_max_delay|tries|attempts)[ \t]*=)'
TRD_BACKOFF_NO_MAX: '^[ \t]*@backoff\.on_(?:exception|predicate)\((?!(?:[^\n]{0,300}\n){0,6}?[^\n]{0,300}?\bmax_(?:tries|time)[ \t]*=[ \t]*(?!None\b))'
TRD_DEF: '^[ \t]*(?:async[ \t]+)?def[ \t]'
TRD_WHILE_TRUE: '^[ \t]*while[ \t]+(?:True|1)[ \t]*:'
TRD_EXCEPT: '^[ \t]*except\b'
TRD_SWALLOW: '^[ \t]*(?:continue|pass)\b|\b(?:time|asyncio)\.sleep\('
TRD_HTTP_RETRY_POST: '\bRetry\([^\n)]{0,300}?\b(?:allowed_methods|method_whitelist)[ \t]*=[ \t]*(?:None|False|[^\n)]{0,120}?["'']POST["''])'
TRD_WEBHOOK_AUTH: '(?i)(?:signature|hmac|webhook_?auth|verify)'
TRD_WEBHOOK_PATH_IGNORE: '^(?![^\n]{0,200}(?:webhook|signal|alert|hook|tradingview|callback))[^\n]'
TRD_SIG_VERIFY: '(?i)\bhmac\.(?:compare_digest|new)\b|\bverify_?(?:signature|hmac|webhook)\b|X-(?:Hub-)?Signature|\bsecrets\.compare_digest\b'
FLASK_WEBHOOK_ROUTE: '(?i)@\w{1,40}\.(?:route|post)\([ \t]*["''][^"''\n]{0,200}?(?:webhook|signal|alert|hook|tradingview)'
```

---

## 12. Four complete rules with fixtures

Each rule below is a complete pack entry. It passes the rule JSON Schema and the loader's semantic checks (engine
§7.2–§7.3), and each regex passes R1–R7. Fixtures live at `tests/fixtures/<ID>/`, and `expect:` annotations mark the
exact lines where hits must land (§14 #10).

### 12.1 WS-GHA-002: untrusted event field in a step script (`yaml_path`, yaml12, quoted `on`)

```yaml
- id: WS-GHA-002
  title: Untrusted event field expanded inside a step script
  pack: domain/gha
  severity: high
  confidence: high
  owner: "@whalesecurity/cicd"
  since: "1.0.0"
  cwe: [CWE-78, CWE-94]
  owasp: [CICD-SEC-4]
  tags: [gha, script-injection]
  applies_to: { kind: ci, lang: yaml, tags_any: [gha, gha-action] }
  keywords: ["github.event.", "github.head_ref"]
  match:
    any:
      - yaml_path:
          each: "**.steps[*]"
          all:
            - path: run
              regex: &untrusted '\$\{\{[ \t]{0,8}(?:github\.head_ref|github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.(?:ref|label|repo\.default_branch))|(?:comment|review|review_comment)\.body|discussion\.(?:title|body)|pages(?:\[[^\]\n]{0,16}\]|\.\*)\.page_name|(?:commits(?:\[[^\]\n]{0,16}\]|\.\*)|head_commit|workflow_run\.head_commit)\.(?:message|author\.(?:email|name))|workflow_run\.(?:head_branch|display_title)))\b'
      - yaml_path:
          each: "**.steps[*]"
          all:
            - path: with.script
              regex: *untrusted
            - path: uses
              regex: '^actions/github-script@'
  message: >
    A step splices an attacker-controlled github.event field into a shell or JavaScript body with an
    expression. The runner substitutes the text before the interpreter parses it, so a crafted issue
    title, PR title, branch name or commit message runs as code with the job's token and secrets.
  fix: >
    Move the value into env (TITLE set from the expression) and reference it as "$TITLE" in the shell,
    or process.env.TITLE in github-script. Never splice event fields into script text.
  references:
    - "https://securitylab.github.com/research/github-actions-untrusted-input/"
    - "https://cwe.mitre.org/data/definitions/78.html"
```

`tests/fixtures/WS-GHA-002/pos.yml`: the trigger key is quoted, one `run` is a plain scalar, one is a block scalar,
and there is one github-script step.

```yaml
name: issue-triage
"on":
  issues:
    types: [opened, edited]
permissions:
  contents: read
  issues: write
jobs:
  triage:
    runs-on: ubuntu-24.04
    steps:
      - name: Echo the title
        run: echo "Title ${{ github.event.issue.title }}"   # expect: WS-GHA-002
      - name: Parse the body
        run: |
          set -euo pipefail
          BODY="${{ github.event.issue.body }}"   # expect: WS-GHA-002
          ./scripts/triage.sh "$BODY"
      - name: Label from script
        uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea
        with:
          script: |
            const title = "${{ github.event.issue.title }}"; // expect: WS-GHA-002
            core.info(title);
```

`tests/fixtures/WS-GHA-002/neg.yml`: env indirection, fields an attacker cannot control, a commented-out line, and a
safe github-script step. The mapping-form `on:` also carries `pull_request_target`, which WS-GHA-001 would evaluate.

```yaml
name: issue-triage
on:
  issues:
    types: [opened]
  pull_request_target:
    types: [opened]
permissions: read-all
jobs:
  triage:
    runs-on: ubuntu-24.04
    steps:
      - name: Title through env
        env:
          TITLE: ${{ github.event.issue.title }}
        run: printf 'Title %s\n' "$TITLE"
      - name: Fields an attacker cannot set
        run: echo "PR ${{ github.event.pull_request.number }} at ${{ github.event.pull_request.head.sha }}"
      # run: echo "${{ github.event.issue.body }}"
      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea
        env:
          TITLE: ${{ github.event.issue.title }}
        with:
          script: core.info(process.env.TITLE)
```

Expected: three hits in `pos.yml`, at lines 13, 17 and 23. The block-scalar hits land on the matched inner line
(§14 #8). `neg.yml` has zero hits.

### 12.2 WS-TF-007: IMDSv1 allowed (`hcl`, variable resolution, same-file guard)

```yaml
- id: WS-TF-007
  title: EC2 instance or launch template allows IMDSv1
  pack: domain/terraform
  severity: high
  confidence: high
  owner: "@whalesecurity/cloud"
  since: "1.0.0"
  cwe: [CWE-918, CWE-1188]
  owasp: [A05, A10]
  tags: [aws, imds]
  applies_to: { kind: iac, lang: [hcl, json], tags_any: [terraform] }
  keywords: [aws_instance, aws_launch_template]
  match:
    all:
      - any:
          - hcl:
              block: "resource.aws_instance.*"
              any:
                - { attr: "metadata_options.http_tokens", exists: false }
                - { attr: "metadata_options.http_tokens", not_equals: "required" }
          - hcl:
              block: "resource.aws_launch_template.*"
              any:
                - { attr: "metadata_options.http_tokens", exists: false }
                - { attr: "metadata_options.http_tokens", not_equals: "required" }
      - not:
          hcl:
            block: "resource.aws_ec2_instance_metadata_defaults.*"
            all:
              - { attr: http_tokens, equals: "required" }
  message: >
    Instance metadata accepts IMDSv1 (unauthenticated GET). Any SSRF in software on the host, such as
    an Airflow worker, a Spark executor or a webhook receiver, can read the instance role's credentials.
  fix: >
    Add metadata_options { http_tokens = "required", http_put_response_hop_limit = 1 } (use a hop limit
    of 2 only on EKS nodes whose pods must reach IMDS), or set the account default with
    aws_ec2_instance_metadata_defaults.
  references:
    - "https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html"
    - "https://cwe.mitre.org/data/definitions/918.html"
```

`tests/fixtures/WS-TF-007/pos.tf`

```hcl
resource "aws_instance" "airflow_worker" {   # expect: WS-TF-007
  ami           = "ami-0123456789abcdef0"
  instance_type = "m6i.large"
}

resource "aws_launch_template" "spark_exec" {
  name_prefix = "spark-exec-"
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"   # expect: WS-TF-007
  }
}
```

`tests/fixtures/WS-TF-007/neg.tf`

```hcl
variable "imds_tokens" {
  type    = string
  default = "required"
}

variable "tokens_from_caller" {
  type = string
}

resource "aws_instance" "airflow_worker" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "m6i.large"
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}

resource "aws_launch_template" "spark_exec" {
  name_prefix = "spark-exec-"
  metadata_options {
    http_tokens = var.imds_tokens          # resolves to the literal default "required"
  }
}

resource "aws_launch_template" "unknown" {
  name_prefix = "unknown-"
  metadata_options {
    http_tokens = var.tokens_from_caller   # no default: unknown, never matches (on_unknown: nomatch)
  }
}
```

Expected: two hits in `pos.tf`. The first is at the `aws_instance` block header (line 1), because no attribute satisfied the
value condition and the hit falls back to the anchor. The second is at the `http_tokens` line (line 10). `neg.tf` has zero
hits. A second negative fixture, `neg_defaults.tf`, contains `pos.tf` plus
`resource "aws_ec2_instance_metadata_defaults" "acct" { http_tokens = "required" }`, and proves the `not` guard.

### 12.3 WS-WEB-PRX-005: NGINX `alias` off-by-slash (`multiline`)

```yaml
- id: WS-WEB-PRX-005
  title: NGINX alias off-by-slash path traversal
  pack: domain/proxy
  severity: high
  confidence: high
  owner: "@whalesecurity/platform"
  since: "1.0.0"
  cwe: [CWE-22]
  owasp: [A01]
  tags: [nginx, traversal]
  applies_to: { kind: iac, lang: nginx }
  keywords: [alias]
  match:
    multiline:
      pattern: '^[ \t]*location[ \t]+(?:\^~[ \t]+|=[ \t]+)?(?P<loc>/[^\s{;]{0,200})(?<!/)[ \t]*\{[^{}]{0,2000}?\balias[ \t]+["'']?(?P<target>[^\s;"'']{1,300}/)["'']?[ \t]*;'
      max_span_lines: 40
  message: >
    location {{loc}} has no trailing slash but its alias {{target}} does. A request for
    {{loc}}../ resolves one directory above the alias target, which exposes sibling files
    such as app source, .env files and keys.
  fix: >
    Make both end with "/" (location /static/ { alias /srv/app/static/; }), or use root instead of
    alias when the path suffix matches the directory name.
  references:
    - "https://cwe.mitre.org/data/definitions/22.html"
    - "https://nginx.org/en/docs/http/ngx_http_core_module.html#alias"
```

`tests/fixtures/WS-WEB-PRX-005/pos.conf`

```nginx
server {
    listen 443 ssl;
    server_name api.example.internal;

    location /static {                      # expect: WS-WEB-PRX-005
        alias /srv/app/static/;
    }

    location ^~ /media {                    # expect: WS-WEB-PRX-005
        add_header Cache-Control "public, max-age=3600";
        alias "/srv/app/media/";
    }
}
```

`tests/fixtures/WS-WEB-PRX-005/neg.conf`

```nginx
server {
    listen 443 ssl;
    server_name api.example.internal;

    location /static/ {
        alias /srv/app/static/;
    }

    location /downloads {
        alias /srv/app/downloads;
    }

    location / {
        root /srv/app/public;
    }

    location ~ ^/img/(.+\.png)$ {
        alias /srv/app/img/$1;
    }
}
```

Expected: two hits in `pos.conf`, at lines 5 and 9. Each hit starts on the `location` line and ends on the `alias`
line. `neg.conf` has zero hits: the slashes are balanced, or there is no alias slash, or `root` is used, or it is a
regex location. Both fixtures need the nginx content sniff from §14 #9, because `*.conf` outside an `nginx/` directory
is otherwise classified as `data`.

### 12.4 WS-TRD-003: order without a client order ID (`py_ast` ∧ ¬`regex`, `near_lines`)

```yaml
- id: WS-TRD-003
  title: Order placed without a client order ID
  pack: domain/trading
  severity: high
  confidence: medium
  owner: "@whalesecurity/trading"
  since: "1.0.0"
  cwe: [CWE-837]
  tags: [trading, idempotency]
  applies_to: { kind: code, lang: python, tags_any: [trading] }
  keywords: [create_order, create_limit, create_market, submit_order, place_order, new_order]
  match:
    all:
      - py_ast:
          call:
            callee: "**.{create_order,create_limit_order,create_market_order,create_limit_buy_order,create_limit_sell_order,create_market_buy_order,create_market_sell_order,submit_order,place_order,new_order}"
            require_import: [ccxt, alpaca, alpaca_trade_api, binance, coinbase, pybit, okx]
      - not:
          regex: '(?i)\b(?:client_?order_?id|newClientOrderId|clOrdId|orderLinkId|client_oid|cl_ord_id|userref)\b'
    near_lines: 12
  filters:
    line_not_regex: '^[ \t]*(?:return[ \t]+)?(?:await[ \t]+)?(?:self|cls|super\(\))\.(?:create|submit|place|new)_\w{0,40}order\('
  message: >
    This order is submitted without a client order ID. After a timeout or a 5xx the strategy cannot
    tell whether the venue accepted it, so a retry can double the position. With a client ID the
    venue rejects the duplicate.
  fix: >
    Derive a deterministic client order ID from (strategy, signal id, leg) and pass it on every attempt
    (ccxt params={"newClientOrderId": ...} or {"clientOrderId": ...}; Alpaca client_order_id=...). On
    timeout, look the order up by that ID before resubmitting. A fresh uuid4() on each attempt defeats
    the purpose.
  references:
    - "https://cwe.mitre.org/data/definitions/837.html"
    - "https://docs.ccxt.com/"
```

`tests/fixtures/WS-TRD-003/pos.py`

```python
"""Order router: two call styles that omit a client order ID."""
import os
from decimal import Decimal

import ccxt
from alpaca.trading.client import TradingClient
from alpaca.trading.enums import OrderSide, TimeInForce
from alpaca.trading.requests import MarketOrderRequest

exchange = ccxt.binance({"enableRateLimit": True})
broker = TradingClient(os.environ["ALPACA_KEY"], os.environ["ALPACA_SECRET"], paper=True)


def buy_limit(symbol: str, qty: Decimal, px: Decimal) -> dict:
    return exchange.create_order(symbol, "limit", "buy", str(qty), str(px))  # expect: WS-TRD-003


def buy_market(symbol: str, qty: Decimal):
    req = MarketOrderRequest(symbol=symbol, qty=str(qty), side=OrderSide.BUY,
                             time_in_force=TimeInForce.DAY)
    return broker.submit_order(order_data=req)  # expect: WS-TRD-003
```

`tests/fixtures/WS-TRD-003/neg.py`

```python
"""The same router with idempotent client order IDs, plus a wrapper call the filter removes."""
import os
from decimal import Decimal

import ccxt
from alpaca.trading.client import TradingClient
from alpaca.trading.enums import OrderSide, TimeInForce
from alpaca.trading.requests import MarketOrderRequest

exchange = ccxt.binance({"enableRateLimit": True})
broker = TradingClient(os.environ["ALPACA_KEY"], os.environ["ALPACA_SECRET"], paper=True)


def coid(strategy: str, signal_id: str, leg: int = 0) -> str:
    # Deterministic, so a retry of the same signal reuses the ID and the venue rejects the duplicate.
    return f"{strategy}-{signal_id}-{leg}"[:36]


def buy_limit(symbol: str, qty: Decimal, px: Decimal, signal_id: str) -> dict:
    return exchange.create_order(
        symbol, "limit", "buy", str(qty), str(px),
        params={"newClientOrderId": coid("mm", signal_id)},
    )


def buy_market(symbol: str, qty: Decimal, signal_id: str):
    req = MarketOrderRequest(symbol=symbol, qty=str(qty), side=OrderSide.BUY,
                             time_in_force=TimeInForce.DAY,
                             client_order_id=coid("mom", signal_id))
    return broker.submit_order(order_data=req)


class Router:
    def submit(self, order):
        return self.submit_order(order)
```

Expected: two hits in `pos.py`, at lines 15 and 21. `neg.py` has zero hits. There, a client-ID token sits within
12 lines of each venue call, and the `self.submit_order(` line is removed by `line_not_regex`.

---

## 13. Test plan

| Layer | What | Where |
|---|---|---|
| Rule contract | Every rule has ≥1 `pos*` and ≥1 `neg*` fixture. Every `pos` has an `expect:` annotation on each hit line. `neg` files have zero hits | `tests/fixtures/<ID>/`, `tests/test_rules.py` |
| Patterns | Every `# patterns:` block is loaded, and each regex is linted (R1–R7) and timed against 100 KB inputs: repeated `a`, spaces, `{`, `/`, `$`, `\n`, 100 KB lines of `FROM x`, `location /a {`, `- name: x`, and random printable text. Each run must stay under 50 ms | `tests/test_redos.py` |
| Scanner pitfalls | The 11 `on:` forms (§5.1); yaml11 `privileged: yes` and `hostNetwork: on`; compose `22:22` ports (a yaml12 string); Helm `{{- if }}` lines; hcl heredoc and `jsonencode` policies; `.tf.json`; a Dockerfile with `USER` in a builder stage only; CRLF line endings | `tests/fixtures/_regress/`, `tests/test_regressions.py` |
| Precision corpus | Pinned-SHA clones of public Helm charts, `terraform-aws-modules`, Airflow example DAGs, FastAPI templates and ccxt examples. The false-positive rate per domain pack must stay below 5% (DESIGN §9) | `evals/corpus/`, `evals/run_eval.py` |
| Verifier hand-off | Rules with `Conf L`, and FP guards that say "the verifier checks", emit `props.verify_hint` naming the cross-file fact to confirm (for example `LimitRange`, `allow-snippet-annotations`, a gateway risk module) | `agents/finding-verifier.md` |

---

## 14. Refinements to DESIGN.md

1. **CI/CD sub-namespaces.** Tekton, Flux and GitLab CI rules use `WS-GHA-TKN-nnn`, `WS-GHA-FLX-nnn` and
   `WS-GHA-GLC-nnn`, and each engine numbers independently. The engine's ID pattern already allows this, so the schema
   does not change. The new pack `domain/gitlab` (`rules/domain/gitlab.yaml`) joins `gha.yaml` and `tekton-flux.yaml`.
2. **Reverse-proxy namespace.** NGINX, Traefik and Coolify rules are `WS-WEB-PRX-nnn` in the new pack `domain/proxy`
   (`rules/domain/proxy.yaml`). NGINX uses 001–019, Traefik 020–029 and Coolify 030–039. `WS-WEB` already covers web-tier
   misconfiguration, and the loader already allows `WS-WEB` in `domain/*`, so no 18th namespace is needed.
3. **Compose rules** live in `WS-DKR` (`docker.yaml`, 020–039), and the `docker` pack covers both Dockerfile and
   Compose. The pack file names `fastapi.yaml`, `airflow.yaml`, `spark.yaml`, `llm-rag.yaml` and `trading.yaml` are as
   DESIGN §3 lists them.
4. **Budget.** DESIGN §5 estimates about 65 rules for these packs. This catalog has 180: 166 core and 14 marked †
   (`tags: [ext]`). The v1 total becomes about 265. The P3 exit criterion counts core rules only, and † rules may slip
   to v1.1 with the same IDs.
5. **New py_ast source sets.** `k8s_cr` covers the parameters `spec`, `body`, `meta`, `status`, `old`, `new`, `diff`
   and `patch` of functions decorated with `@kopf.on.*`, `@kopf.timer` or `@kopf.daemon`. `tool_args` covers the
   parameters of functions decorated with `@*.tool` / `@tool` (MCP SDK FastMCP, LangChain), and of `_run` / `_arun` in
   `BaseTool` subclasses. Both use the same annotation exemptions as `web` (`int`, `bool`, `Literal[...]`, …).
6. **py_ast argument conditions.** `regex` on a non-scalar argument (a list, dict or call) tests `ast.unparse(arg)`,
   which is needed for `allow_origins=["*"]`. `constant: false` is the negation of `constant: true`.
7. **hcl paths.** `block` accepts `{a,b}` alternation in any segment
   (`resource.{aws_lb_listener,aws_alb_listener}.*`). `each` accepts a dotted path of nested block types
   (`settings.ip_configuration.authorized_networks`), with labels ignored. Inside `each`, an `attr` starting with `$.`
   resolves against the matched `block`. A value predicate on a list-valued attribute applies to each item under
   `quantifier` (default `any`), as for yaml sequences; `contains` is unchanged. Hits are located as in yaml_path.
8. **Location refinements (yaml_path and hcl).** (a) Conditions written with `$.` are filters and never locate. (b)
   The hit is placed on the first satisfied relative value condition, scanning `all` and then `any`. Failing that,
   it goes on the first `exists: true` condition, then on the anchor. (c) When the locating predicate is `regex` on a
   scalar, the hit narrows to the regex match span. For `|` block scalars this maps to the source line. For `>` folded
   scalars it stays on the node start. `filters.line_not_regex` then applies to that line.
9. **Classifier additions (engine §6).**
   - The GHA sniff accepts `^(?:on|"on"|'on'|true):` together with `^jobs:`.
   - nginx: a `.conf`, `.conf.template` or `.nginx` file whose first 64 KiB contains
     `^[ \t]*(?:server|http|upstream|location)\b[^\n{;]{0,200}\{` and one of `listen`, `server_name`, `proxy_pass` or
     `root` becomes lang `nginx`, kind `iac`, tag `nginx`.
   - Traefik: YAML or TOML with top-level `http:` holding `routers`, `middlewares` or `services`, or with top-level
     `entryPoints` or `providers`, gets tag `traefik`.
   - GitLab: `.gitlab/ci/**/*.{yml,yaml}` and `*.gitlab-ci.yml` become kind `ci`, and `.gitlab-ci.yml` gets tag
     `gitlab` in addition to `ci-other`.
   - Coolify: compose files containing `SERVICE_FQDN_` or `SERVICE_URL_` get tag `coolify`.
   - `spark-defaults.conf` gets tag `spark`, and `airflow.cfg` gets tag `airflow-cfg`.
10. **Fixture annotations.** The contract test accepts `expect: <ID>` after any of the comment leaders `#`, `//` or
    `--`, which covers JS inside YAML block scalars, Scala and SQL fixtures.
11. **GHA trigger pattern.** WS-GHA-001 keeps DESIGN §4's structure. `@GHA_PR_HEAD` extends DESIGN's
    `github\.event\.pull_request\.head\.(sha|ref)` with `github.head_ref` and `refs/pull/`.
12. **`true:` workflows** produce WS-GHA-016 (info) instead of being skipped silently. WhaleSecurity's own hooks and
    tools never parse workflows with PyYAML.
13. **Named patterns** (`@NAME`) and list constants are a convention of this document only. Pack files inline them or
    use YAML anchors, and the rule schema does not change.
