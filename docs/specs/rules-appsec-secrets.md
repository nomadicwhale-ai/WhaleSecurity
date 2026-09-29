# Rule Catalog v1: `appsec` and `secrets` packs

This spec lists every v1 rule in the `appsec` pack (44 rules: injection, SSRF, access control,
deserialization, cryptography and web-platform flaws across Python, JS/TS, Go, Java and SQL) and
the `secrets` pack (37 rules: cloud, VCS, AI, payments, SaaS, exchange/broker and generic
credentials). It is the source of truth for `rules/appsec/*.yaml`, `rules/secrets/*.yaml` and
`tests/fixtures/<RULE-ID>/`. Each rule has an ID, severity, confidence, CWE/OWASP mapping, target
languages, matcher tier, the exact detection logic, its false-positive guards and a fix. Every
regex in the tables below compiles under Python `re` (3.10+). Each one has been run against its
listed samples and against 100 KB adversarial inputs, and none took more than 50 ms (the worst was
about 36 ms, on CPython 3.11). The examples are tailored to the stack this project defends:
FastAPI services, Airflow/Spark jobs, Postgres/MySQL/SingleStore, Kubernetes, CI pipelines, LLM
agents and trading/transaction engines.

**Contents**

1. [Conventions](#1-conventions)
2. [appsec pack (44 rules)](#2-appsec-pack)
3. [secrets pack (37 rules)](#3-secrets-pack)
4. [Example rules with fixtures](#4-example-rules-with-fixtures)
5. [Secrets redaction and verification](#5-secrets-redaction-and-verification)
6. [Quality gates specific to these packs](#6-quality-gates-specific-to-these-packs)
7. [Refinements to DESIGN.md](#7-refinements-to-designmd)

---

## 1. Conventions

### 1.1 Files and IDs

| Pack | File | ID prefix | Rules |
|---|---|---|---|
| appsec/injection | `rules/appsec/injection.yaml` | `WS-INJ-NNN` | 11 |
| appsec/ssrf | `rules/appsec/ssrf.yaml` | `WS-SSRF-NNN` | 3 |
| appsec/access | `rules/appsec/access.yaml` | `WS-ACC-NNN` (path traversal, zip slip, mass assignment, SQL privileges) | 6 |
| appsec/deser | `rules/appsec/deser.yaml` | `WS-DES-NNN` (incl. XXE) | 5 |
| appsec/crypto | `rules/appsec/crypto.yaml` | `WS-CRY-NNN` (hashing, ciphers, RNG, TLS, JWT) | 7 |
| appsec/web | `rules/appsec/web.yaml` | `WS-WEB-NNN` (XSS, redirects, ReDoS, prototype pollution, CORS, cookies, debug, data exposure) | 12 |
| secrets/cloud | `rules/secrets/cloud.yaml` | `WS-SEC-{AWS,GCP,AZ}-NNN` | 8 |
| secrets/vcs | `rules/secrets/vcs.yaml` | `WS-SEC-{GH,GL}-NNN` | 3 |
| secrets/ai | `rules/secrets/ai.yaml` | `WS-SEC-{OAI,ANT,HF,VDB}-NNN` | 4 |
| secrets/payments | `rules/secrets/payments.yaml` | `WS-SEC-STR-NNN` | 1 |
| secrets/saas | `rules/secrets/saas.yaml` (new) | `WS-SEC-{SLK,TWL,SG,TG}-NNN` | 4 |
| secrets/trading | `rules/secrets/trading.yaml` | `WS-SEC-TRD-NNN` (Binance 001, Coinbase 002, Kraken 003, Alpaca 004, IBKR 005, Polygon 006, ccxt 007) | 7 |
| secrets/generic | `rules/secrets/generic.yaml` | `WS-SEC-{PK,DB,JWT,GEN,K8S,PKG,AGE}-NNN` | 10 |

IDs are never reused. A retired rule keeps its ID with `deprecated: true` so baselines stay valid.

### 1.2 Column meanings

- **Sev**: `critical | high | medium | low | info`. This is the base severity. `severity.py` may
  raise or lower it through reachability and exposure (DESIGN.md §2), and so can the
  `severity_overrides` listed under FP guards.
- **Conf**: `high | medium | low`. It is how likely a hit is a true positive before the
  `finding-verifier` agent looks at it. For appsec rules, hits under `tests/`, `**/test_*.py`,
  `*_test.go`, `*.spec.ts` and `__fixtures__/` drop one confidence step but are still reported.
  Secrets are **not** downgraded in tests, because a live key in a test is still a live key.
- **CWE**: the primary CWE first. **OWASP**: Top 10:2021 IDs (`A01`–`A10`), the same style as
  DESIGN.md's `A07`.
- **Lang / kind**: `py` = python, `js`/`ts` (includes jsx/tsx/vue/svelte), `go`, `java`, `sql`,
  `tmpl` (engine langs `jinja`/`html`, plus `.hbs`/`.ejs`/`.njk`), `cfg` (dotenv/ini/properties/tfvars/compose/Helm values; engine kinds `data`/`iac`),
  `sh/ci` (shell, Dockerfile, CI YAML), `any text` (every non-binary file the walker yields).
- **Matcher**: the tier from DESIGN.md §4. `regex + py_ast` means the regex ships in P0 and the AST
  matcher replaces it for Python in P3. When both hit the same span they merge, and the AST result
  sets the confidence.
- **Detection**: the label before each pattern (`py`, `js`, `go`, ...) names the language it targets.
  `require` and `exclude` map to schema constructs as shown in §1.3.

> **Escaping.** Inside table cells, `|` is written `\|` (GitHub-Flavored Markdown). The canonical
> string is the one in the YAML file. When copying from this page, turn every `\|` back into `|`.
> No catalog regex needs a literal pipe; `[|]` is used for that (see WS-INJ-004).

### 1.3 How the table notation maps onto the rule schema

The tables use a compact notation. Every entry maps onto the rule schema and matcher behavior in
[engine.md](engine.md) §7–§8, with no new schema needed, except the three items marked
*proposed*, which are listed in §7.

| Table notation | Rule schema (engine.md) |
|---|---|
| **lang** `pattern` | A `regex` child. `regex` runs `finditer` over the whole file with `re.M` and reports every hit (§8.2). The label is the language the pattern targets; the rule's `applies_to.lang` lists all of them. *Proposed:* a per-child `lang`. |
| *require* `R` | `all: [<pattern>, {regex: R}]` with `near_lines: 0` (same line) or the stated N. |
| *exclude* `E` (same line) | `filters.line_not_regex` (several patterns are joined with `\|`). |
| *exclude* within N lines / in the file | A `not: {regex: E}` child in the `all` with `near_lines: N` / `filters.file_not_regex`. |
| *exclude when all match* | `any` of one `all: [<pattern>, not: E_i]` branch per `E_i`. A hit survives while any one of them is absent. |
| "file-level require X" | `filters.file_regex: X` (plus `keywords` for the prefilter). |
| value (secret) | The last capturing group. In YAML it is written `(?P<secret>…)` with `secret_group: secret`, and it drives redaction (engine.md §13). |
| entropy rows | The engine `entropy` matcher (§8.5) with `context.required: true`. The table's regex is the effective keyword-context candidate, and its threshold replaces the length buckets. |
| "window is the call / the SQL statement" (in FP guards) | *Proposed:* `near_scope: call \| sql_statement` (§7). Until then, use `near_lines: 6` / `near_lines: 12`. |
| Severity/confidence adjustments in "FP guards" | Where the engine already has the signal (reachability, test paths, exposure; §10) they come for free. Value-based ones (`sk_test_`, `PK…` paper keys, `ENCRYPTED` PEM) are *proposed* `severity_overrides`. |

**Regex hygiene.** Every pattern passes lint R1–R7 (engine.md §8.2): no nested unbounded repeats,
no leading unbounded `.`/`\s`/negated class, no zero-width patterns, no DOTALL in `regex`, and
bounded repeats on `.`/negated classes. Under whole-text matching, a secret value must never
cross a line. So context rules write `[ \t]{0,8}` around `:`/`=` instead of `\s*`, and line-start
anchors are `^[ \t]{0,16}`. Inside the pack YAML, patterns are single-quoted or `|-` literal
blocks, never plain scalars. This avoids the dash-leading and `#` pitfalls.

---

## 2. appsec pack

Boundaries with other packs:
- `spark.sql(f"...")` belongs to WS-SPK.
- FastAPI `CORSMiddleware`, `FastAPI(debug=True)` and routes without auth belong to WS-API.
- Airflow `BashOperator` template injection belongs to WS-AIR.
- LLM output flowing into `eval`/shell/SQL is reported by the appsec rule here *and* tagged
  `llm_output: true` for WS-LLM correlation. It is never double-counted.

### 2.1 Injection (`WS-INJ`)

| ID | Title | Sev | Conf | CWE | OWASP | Lang / kind | Matcher | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|---|
| `WS-INJ-001` | SQL built by string formatting (Python DB-API, pandas, SQLAlchemy `text()`, Django `raw()`) | high | medium | CWE-89 | A03 | py | regex + py_ast | **py** `\b(?:execute\|executemany\|executescript\|mogrify\|read_sql(?:_query)?\|text\|raw\|exec_driver_sql)\(\s*(?:(?:[rR][fF]\|[fF][rR]?)["']\|["'][^"'\n]{0,300}["']\s*(?:%\s*[\w(]\|\+\s*\w\|\.format\())`<br>*require* `(?i)\b(?:select\|insert\|update\|delete\|merge\|upsert\|replace\|truncate\|drop\|alter\|with\|call)\b`<br>py_ast: `Call(func.attr in SINKS, args[0] in {JoinedStr, BinOp(Mod/Add), Call(.format)})` with a non-constant part; critical when that part is tainted by a route param, `request.*`, `dag_run.conf` or LLM output | Drop when every interpolated name is an UPPER_CASE module constant or `sql.Identifier(...)`; `spark.sql` belongs to WS-SPK<br>*exclude* `\bsql\.(?:SQL\|Identifier\|Literal)\(` | Use driver placeholders (`%s`, `:name`, `?`) and pass values separately; build identifiers with `psycopg.sql.Identifier` or an allowlist |
| `WS-INJ-002` | SQL built by string interpolation (JS/TS: pg, mysql2, knex, Sequelize, Prisma `*Unsafe`) | high | medium | CWE-89 | A03 | js, ts | regex | **js** `` \.(?:query\|execute\|raw\|unsafe\|whereRaw\|orderByRaw\|havingRaw\|joinRaw\|\$queryRawUnsafe\|\$executeRawUnsafe)\(\s*(?:`[^`]{0,500}\$\{\|["'][^"'\n]{0,300}["']\s*\+\s*\w) ``<br>**js** `\.\$(?:query\|execute)RawUnsafe\(\s*[A-Za-z_$]`<br>*require* `(?i)\b(?:select\|insert\|update\|delete\|merge\|upsert\|truncate\|drop\|alter\|with\|call)\b\|RawUnsafe` | Prisma tagged templates (`` $queryRaw`...` ``) are parameterized and never match; the require window is 3 lines for multi-line template literals | Use `$1`/`?` placeholders with a values array, knex bindings, or Prisma tagged `$queryRaw` |
| `WS-INJ-003` | OS command injection (Python `os.system`, `subprocess(..., shell=True)`, `create_subprocess_shell`) | high | high | CWE-78 | A03 | py | regex + py_ast | **py** `\b(?:os\.(?:system\|popen)\|subprocess\.(?:getoutput\|getstatusoutput)\|asyncio\.create_subprocess_shell)\(\s*(?!["'][^"'\n]{0,500}["']\s*[,)])`<br>**py** `\bsubprocess\.(?:run\|call\|check_call\|check_output\|Popen)\((?=[^\n]{0,400}\bshell\s*=\s*True\b)\s*(?![rR]?["'][^"'\n]{0,500}["']\s*,)`<br>py_ast: `subprocess.*` with `shell=True` and non-constant `args[0]`; critical when tainted by request/route param, `dag_run.conf`, or LLM tool output | Constant command strings never match; `shlex.quote()` around every interpolation lowers to low | Pass an argv list without `shell=True` (`subprocess.run(["pg_dump", db], check=True)`); validate against an allowlist |
| `WS-INJ-004` | Dynamic SQL concatenated inside SQL (PL/pgSQL `EXECUTE ... \|\|`, MySQL/SingleStore `PREPARE ... CONCAT`, T-SQL `EXEC(+)`) | high | medium | CWE-89 | A03 | sql | regex | **sql** `(?i)\bexecute\s+(?:immediate\s+)?(?:'[^'\n]{0,300}'\|\w+)\s*[\|]{2}\|\bprepare\s+\w+\s+from\s+concat\s*\(\|\bset\s+@\w+\s*=\s*concat\s*\(\s*'\s*(?:select\|insert\|update\|delete\|call)\b\|\bexec(?:ute)?\s*\(\s*(?:N?'[^'\n]{0,300}'\|@\w+)\s*\+` | Drop when every concatenated piece is wrapped in `quote_ident`/`quote_literal` or built with `format('%I','%L')`<br>*exclude* `(?i)\bquote_(?:ident\|literal\|nullable)\(\|\bformat\(\s*'[^'\n]{0,300}%[IL]` | PL/pgSQL: `EXECUTE format('... %I ...', tbl) USING val`; MySQL/SingleStore: `PREPARE s FROM '... ?'` + `EXECUTE s USING @v` |
| `WS-INJ-005` | NoSQL operator injection (MongoDB query built from raw request objects, `$where`) | high | medium | CWE-943 | A03 | js, ts, py | regex | **js** `\.(?:find\|findOne\|findOneAndUpdate\|findOneAndDelete\|updateOne\|updateMany\|deleteOne\|deleteMany\|countDocuments\|replaceOne)\(\s*(?:req\.(?:body\|query\|params)\b(?!\.)\|\{[^}\n]{0,200}:\s*req\.(?:body\|query)\.\w+\s*[,}])`<br>**py** `\.(?:find\|find_one\|find_one_and_update\|update_one\|update_many\|delete_one\|delete_many\|count_documents)\(\s*(?:request\.(?:json\|args\|form)\b\|await\s+request\.json\(\s*\)\|\{[^}\n]{0,200}:\s*request\.(?:json\|args)\b)`<br>**any** `["']?\$(?:where\|function\|accumulator)["']?\s*:` | Drop when the value is coerced (`String(x)`, `str(x)`, Pydantic model field) or `express-mongo-sanitize` is mounted (then confidence low)<br>*exclude* `\bString\(\|\bstr\(\|\bsanitize\w*\(\|\$eq\s*:` | Coerce scalars, validate with a schema (zod/Pydantic), wrap values in `{$eq: v}`; never use `$where`/`$function` |
| `WS-INJ-006` | SQL built by string formatting (Go `database/sql`/sqlx/GORM, Java JDBC/JPA/JdbcTemplate) | high | medium | CWE-89 | A03 | go, java | regex | **go** `\.(?:Query\|QueryRow\|QueryContext\|QueryRowContext\|Exec\|ExecContext\|Prepare\|PrepareContext\|Raw\|Select\|Get\|NamedExec)\(\s*(?:[\w&.()]{1,60}\s{0,4},\s{0,4}){0,2}(?:fmt\.Sprintf\(\|"[^"\n]{0,300}"\s*\+\s*\w)`<br>**go** `\b\w{1,64}\s*:?=\s*fmt\.Sprintf\(\s*"(?i:\s*(?:select\|insert\|update\|delete\|with)\b)`<br>**java** `\.(?:executeQuery\|executeUpdate\|executeLargeUpdate\|execute\|addBatch\|prepareStatement\|prepareCall\|createQuery\|createNativeQuery\|queryForObject\|queryForList\|queryForMap\|query\|update)\(\s*(?:"[^"\n]{0,300}"\s*\+\s*\w\|String\.format\()`<br>*require* `(?i)\b(?:select\|insert\|update\|delete\|merge\|upsert\|truncate\|drop\|alter\|with\|call)\b` | Drop when the only concatenated value is a `final static` constant or an identifier checked against an allowlist `switch`/`map` in the previous 10 lines | Go: `db.QueryContext(ctx, "... WHERE id = $1", id)`; Java: `PreparedStatement` with `?` or named parameters in JPA |
| `WS-INJ-007` | OS command injection (Node `child_process.exec*`, `spawn(..., {shell:true})`) | high | high | CWE-78 | A03 | js, ts | regex | **js** `` (?:\b(?:child_process\|childProcess\|cp)\.\|(?<![\w$.]))(?:exec\|execSync)\(\s*(?:`[^`]{0,300}\$\{\|["'][^"'\n]{0,300}["']\s*\+\|[A-Za-z_$][\w$.]*\s*[,)]) ``<br>**js** `\bspawn(?:Sync)?\([^)\n]{0,300}\bshell\s*:\s*true\b` | File must import `child_process`, `execa` or `shelljs` (file-level require); `RegExp#exec` is excluded by the look-behind | `execFile`/`spawn` with an argv array and no shell; validate inputs against an allowlist |
| `WS-INJ-008` | Command run through a shell (`sh -c`) with dynamic input (Go `exec.Command`, Java `Runtime.exec`/`ProcessBuilder`) | high | high | CWE-78 | A03 | go, java | regex | **go** `\bexec\.Command(?:Context)?\(\s*(?:\w+\s*,\s*)?"(?:/bin/\|/usr/bin/)?(?:ba\|z\|da\|k)?sh"\s*,\s*"-c"\s*,\s*(?!"[^"\n]{0,500}"\s*\))`<br>**java** `\bRuntime\.getRuntime\(\)\.exec\(\s*(?:"[^"\n]{0,300}"\s*\+\|String\.format\(\|new\s+String\[\]\s*\{\s*"(?:/bin/)?(?:ba)?sh"\s*,\s*"-c")`<br>**java** `\bnew\s+ProcessBuilder\(\s*(?:List\.of\(\|Arrays\.asList\()?\s*"(?:/bin/)?(?:ba\|z)?sh"\s*,\s*"-c"\s*,\s*(?!"[^"\n]{0,500}"\s*\))` | A constant `-c` script never matches | Call the binary directly with separate args (`exec.CommandContext(ctx, "helm", "upgrade", rel)`) |
| `WS-INJ-009` | Dynamic code evaluation of non-constant input (`eval`/`exec`, `new Function`, `vm.run*`) | critical | medium | CWE-95 | A03 | py, js, ts | regex + py_ast | **py** `(?<![\w.])(?:eval\|exec)\(\s*(?!["'][^"'\n]{0,500}["']\s*\)\|\))`<br>**js** `` (?<![\w$.])eval\(\s*(?!["'][^"'\n]{0,500}["']\s*\))\|\bnew\s+Function\(\|\bset(?:Timeout\|Interval)\(\s*(?:`[^`]{0,300}\$\{\|["'][^"'\n]{0,300}["']\s*\+)\|\bvm\.(?:runInNewContext\|runInThisContext\|runInContext\|compileFunction)\(\|\bnew\s+vm\.Script\( `` | `ast.literal_eval`, `model.eval()`, `df.eval` never match (look-behind); downgrade to medium under `tests/` | `ast.literal_eval`/`json.loads` for data; a parser or allowlisted operator table for formulas; never eval LLM output |
| `WS-INJ-010` | Server-side template injection (Jinja2/Mako, EJS/Pug/Handlebars/Nunjucks/lodash, SpEL/Velocity/FreeMarker) | critical | medium | CWE-1336 | A03 | py, js, ts, java | regex | **py** `\b(?:render_template_string\|from_string\|(?:jinja2\|mako\.template)\.Template)\(\s*(?:[rR]?[fF]["']\|["'][^"'\n]{0,300}["']\s*(?:%\|\+\|\.format\()\|request\.)`<br>**js** `` \b(?:ejs\.render\|ejs\.compile\|pug\.render\|pug\.compile\|[Hh]andlebars\.compile\|nunjucks\.renderString\|_\.template\|lodash\.template\|doT\.template)\(\s*(?:req\.(?:body\|query\|params)\|`[^`]{0,300}\$\{\|["'][^"'\n]{0,300}["']\s*\+) ``<br>**java** `\bVelocity\.evaluate\(\|\bnew\s+Template\(\s*[^,\n]{1,100},\s*new\s+StringReader\(\|\bparseExpression\(\s*(?!"[^"\n]{0,300}"\s*\))` | Rendering a file template with data (`render_template("x.html", v=...)`) never matches; prompt templates built from user text are reported with the same ID | Keep templates static and pass user data as context variables; use `SandboxedEnvironment` if templates must be user-authored |
| `WS-INJ-011` | LDAP filter built from unescaped input | high | medium | CWE-90 | A03 | py, js, go, java | regex | **any** `\(\s*&?\s*\(?\s*(?:uid\|cn\|sAMAccountName\|userPrincipalName\|mail\|member\|memberOf\|ou\|objectClass)\s*=\s*(?:["']\s*\+\|\{[A-Za-z_]\|%s\|\$\{)` | File-level require `ldap\|DirContext\|go-ldap\|LdapTemplate`; JNDI `{0}` filter arguments are the safe form and never match<br>*exclude* `\bescape_filter_chars\(\|\bescape_rdn\(\|\bLdapEncoder\.filterEncode\(\|\bldap\.EscapeFilter\(\|\bFilter\.encodeValue\(` | Escape with `ldap3.utils.conv.escape_filter_chars` / `ldap.EscapeFilter` / `LdapEncoder.filterEncode`, or use JNDI filter args |

### 2.2 Server-side request forgery (`WS-SSRF`)

The SSRF rules fire when the **host** is dynamic. When only the path or query is interpolated
into a fixed host (`https://api.binance.com/...{sym}`), the rules do not fire. Cloud metadata
endpoints (169.254.169.254, `metadata.google.internal`, `fd00:ec2::254`) are listed in every fix
because they are the usual first target.

| ID | Title | Sev | Conf | CWE | OWASP | Lang / kind | Matcher | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|---|
| `WS-SSRF-001` | Outbound HTTP request to a request-controlled host (Python requests/httpx/aiohttp/urllib) | high | medium | CWE-918 | A10 | py | regex + py_ast | **py** `\b(?:requests\|httpx\|aiohttp\|urllib3\|session\|client\|http_client\|async_client)\.(?:get\|post\|put\|patch\|delete\|head\|options\|request\|stream)\(\s*(?:["'](?:GET\|POST\|PUT\|PATCH\|DELETE\|HEAD)["']\s*,\s*)?(?:[rR]?[fF]["'](?:https?://)?\{\|request\.(?:args\|query_params\|json\|form\|values\|GET\|POST)\b\|url\s*=\s*request\.)`<br>**py** `\burllib\.request\.urlopen\(\s*(?!["']https?://[^"'{\n]{0,500}["'])`<br>py_ast: URL arg tainted by route param / `request.*` / webhook body; sanitizer = `urlparse(u).hostname in ALLOWED` before the call | A fixed scheme+host with only path/query interpolated (`f"https://api.binance.com/...{sym}"`) never matches; drop when an allowlist check precedes the call (10 lines) | Allowlist hosts, resolve and reject private/link-local IPs (169.254.169.254, fd00:ec2::254), disable redirects, go through an egress proxy |
| `WS-SSRF-002` | Outbound HTTP request to a request-controlled URL (fetch/axios/got/undici) | high | medium | CWE-918 | A10 | js, ts | regex | **js** `` \b(?:fetch\|axios(?:\.(?:get\|post\|put\|patch\|delete\|head\|request))?\|got(?:\.(?:get\|post))?\|needle\|superagent\.(?:get\|post)\|https?\.(?:get\|request)\|undici\.request\|ky(?:\.(?:get\|post))?)\(\s*(?:req\.(?:query\|body\|params\|headers)\b\|`(?:https?://)?\$\{) `` | A literal scheme+host before the first `${` never matches | Parse with `new URL()`, compare `.hostname` to an allowlist, block private ranges, set `redirect: "manual"` |
| `WS-SSRF-003` | Outbound HTTP request to a request-controlled URL (Go net/http, Java URL/RestTemplate/WebClient) | high | medium | CWE-918 | A10 | go, java | regex | **go** `\bhttp\.(?:Get\|Head\|Post\|PostForm)\(\s*(?:r\.(?:URL\.Query\(\)\.Get\|FormValue\|PostFormValue)\(\|c\.(?:Query\|PostForm\|Param)\(\|fmt\.Sprintf\(\s*"(?:https?://)?%s\|"https?://"\s*\+)`<br>**go** `\bhttp\.NewRequest(?:WithContext)?\([^)\n]{0,120}?(?:r\.URL\.Query\(\)\.Get\(\|r\.FormValue\(\|c\.(?:Query\|PostForm\|Param)\(\|fmt\.Sprintf\(\s*"(?:https?://)?%s)`<br>**java** `\bnew\s+URL\(\s*(?:request\.getParameter\(\|"https?://"\s*\+)\|\b(?:getForObject\|getForEntity\|postForObject\|postForEntity\|exchange)\(\s*(?:request\.getParameter\(\|"https?://"\s*\+)\|\.uri\(\s*(?:request\.getParameter\(\|"https?://"\s*\+)` | Literal URLs never match; drop when `net.ParseIP(...).IsPrivate()`/allowlist check is in the same function | Allowlist hosts, use a dialer `Control` hook that rejects private/link-local addresses, disable redirects |

### 2.3 Access control (`WS-ACC`)

| ID | Title | Sev | Conf | CWE | OWASP | Lang / kind | Matcher | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|---|
| `WS-ACC-001` | Path traversal: request-derived path reaches a file API (Python/FastAPI/Flask) | high | medium | CWE-22 | A01 | py | regex + py_ast | **py** `\b(?:open\|FileResponse\|send_file\|send_from_directory\|os\.remove\|os\.unlink\|shutil\.(?:rmtree\|copy\|copyfile\|move)\|Path)\(\s*(?:[rR]?[fF]["'][^"'\n]{0,200}\{[^}\n]{0,80}\}\|os\.path\.join\([^)\n]{0,200}\b(?:request\.\|filename\|file_name)\|request\.)`<br>py_ast: sink arg tainted by a route path param, `UploadFile.filename` or `request.*`; sanitizer = `resolve()` + `is_relative_to(BASE)` | Regex tier additionally requires a route decorator, `UploadFile` or `request.` within 20 lines above<br>*exclude* `\bsecure_filename\(\|\bsafe_join\(\|\.is_relative_to\(\|\bos\.path\.realpath\(` | `p = (BASE / name).resolve(); if not p.is_relative_to(BASE): raise HTTPException(404)`; store uploads under generated IDs |
| `WS-ACC-002` | Path traversal: request-derived path reaches a file API (Node fs/Express, Go os/http, Java File/Paths) | high | medium | CWE-22 | A01 | js, ts, go, java | regex | **js** `\b(?:fs\.(?:promises\.)?(?:readFile\|readFileSync\|createReadStream\|writeFile\|writeFileSync\|createWriteStream\|unlink\|unlinkSync\|rm\|rmSync\|readdir)\|res\.(?:sendFile\|download)\|path\.(?:join\|resolve))\([^)\n]{0,200}\breq\.(?:params\|query\|body\|headers)\b`<br>**go** `\b(?:os\.(?:Open\|OpenFile\|ReadFile\|WriteFile\|Create\|Remove\|RemoveAll)\|ioutil\.ReadFile\|http\.ServeFile\|filepath\.Join\|path\.Join)\([^)\n]{0,200}(?:r\.URL\.Query\(\)\.Get\(\|r\.FormValue\(\|mux\.Vars\(r\)\|chi\.URLParam\(\|c\.(?:Param\|Query)\()`<br>**java** `\bnew\s+File(?:InputStream\|OutputStream\|Reader\|Writer)?\([^)\n]{0,200}request\.getParameter\(\|\bPaths?\.(?:get\|of)\([^)\n]{0,200}request\.getParameter\(` | Express `sendFile(x, {root})`, Go `os.Root`/`filepath.IsLocal`, and `path.basename(...)` are treated as sanitizers<br>*exclude* `\bpath\.basename\(\s*req\.\|\broot\s*:\|\bfilepath\.IsLocal\(\|\bOpenInRoot\(\|\bsecurejoin\.` | Resolve against a base dir and verify containment (`path.relative`, `filepath.IsLocal`, `os.Root`, `toRealPath().startsWith(base)`) |
| `WS-ACC-003` | Archive extraction without member-path validation (tar/zip slip) | high | medium | CWE-22 | A01 | py, java, go | regex | **py** `\.(?:extractall\|extract)\(\s*(?![^)\n]{0,200}\bfilter\s*=)\|\bshutil\.unpack_archive\((?![^)\n]{0,200}\bfilter\s*=)`<br>**java** `\bnew\s+File\(\s*[^,\n]{1,120},\s*\w+\.getName\(\)\s*\)`<br>**go** `\bfilepath\.Join\([^)\n]{0,120}\b\w+\.Name\s*\)` | File-level require: py `tarfile`/`unpack_archive` (stdlib `zipfile` strips `..`), java `ZipEntry\|TarArchiveEntry\|ZipInputStream`, go `"archive/(zip\|tar)"`; drop when a `startsWith(dest)`/`IsLocal` check follows within 10 lines; py downgraded to low when `requires-python >= 3.14` (default filter is `data`) | Python: `tar.extractall(dest, filter="data")`; Java/Go: canonicalize and check the target stays under `dest` |
| `WS-ACC-004` | Mass assignment: request body bound straight onto a model/ORM entity | medium | medium | CWE-915 | A01 | py, js, ts | regex | **py** `\b[A-Z]\w*\(\s*\*\*\s*(?:request\.(?:json\|form\|args\|get_json\(\s*\))\|await\s+request\.json\(\s*\)\|\w+\.(?:dict\|model_dump)\(\s*\))`<br>**js** `\bObject\.assign\(\s*\w+\s*,\s*req\.body\b\|\.(?:create\|insertOne\|build\|upsert)\(\s*(?:\{\s*\.\.\.req\.body\s*\}\|req\.body\s*[,)])\|\.(?:findByIdAndUpdate\|findOneAndUpdate\|updateOne\|updateMany)\(\s*[^,\n]{1,80},\s*(?:req\.body\b\|\{\s*\.\.\.req\.body\s*\})\|\bnew\s+[A-Z]\w*\(\s*req\.body\s*\)` | `model_dump(include=...)`/`exclude=...` never match; raised to high when the target model has `role`, `is_admin`, `balance`, `owner_id` or `tenant_id` columns<br>*exclude* `\bcreateHmac\(\|\bcreateHash\(` | Separate input schemas (Pydantic/zod) that exclude privileged fields; copy fields explicitly |
| `WS-ACC-005` | Over-broad SQL grant (`GRANT ALL`, `TO PUBLIC`, `'user'@'%'`, `SUPERUSER`) | high | medium | CWE-269 | A01 | sql | regex | **sql** `` (?i)\bgrant\s+all(?:\s+privileges)?\s+on\s+[^;\n]{1,200}?\bto\s+(?:public\b\|['"`][^'"`\n]{1,64}['"`]\s*@\s*['"`]%['"`])\|\bgrant\s+[^;\n]{1,200}?\bto\s+public\b\|\b(?:alter\|create)\s+(?:user\|role)\s+\S{1,64}\s+(?:with\s+)?[^;\n]{0,100}?\bsuperuser\b `` | Downgraded to low under `docker-entrypoint-initdb.d/`, `dev/`, `local/` | Grant least privilege per schema/table to named roles; restrict MySQL/SingleStore hosts to the app CIDR |
| `WS-ACC-006` | Postgres `SECURITY DEFINER` function without a pinned `search_path` | high | high | CWE-426 | A01 | sql | multiline | **sql** `(?i)\bsecurity\s+definer\b` | Window is the enclosing SQL statement (split on `;` outside `$$`/`$tag$` bodies)<br>*exclude* `(?i)\bset\s+search_path\s*(?:=\|to)` | Add `SET search_path = pg_catalog, pg_temp` to the function and schema-qualify every object |

### 2.4 Deserialization and XML (`WS-DES`)

| ID | Title | Sev | Conf | CWE | OWASP | Lang / kind | Matcher | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|---|
| `WS-DES-001` | Unsafe Python deserialization (pickle family, `joblib`, `torch.load` without `weights_only`) | high | medium | CWE-502 | A08 | py | regex + py_ast | **py** `\b(?:pickle\|cPickle\|_pickle\|dill\|cloudpickle\|jsonpickle)\.(?:loads?\|Unpickler\|decode)\(\|\b(?:pd\|pandas)\.read_pickle\(\|\bjoblib\.load\(\|\bshelve\.open\(\|\btorch\.load\((?![^)\n]{0,200}\bweights_only\s*=\s*True)\|\bnp\.load\([^)\n]{0,200}\ballow_pickle\s*=\s*True`<br>py_ast: critical when the bytes come from a socket, HTTP body, Redis/Kafka message or an object store path built from input | `torch.load` dropped when torch>=2.6 is pinned and `weights_only` is not set to False; downgrade to low under `tests/` and for paths under the repo | JSON/Arrow/Parquet/`safetensors` for data and models; if pickle is unavoidable, sign blobs with HMAC and verify first |
| `WS-DES-002` | PyYAML/ruamel unsafe load | high | high | CWE-502 | A08 | py | regex | **py** `\byaml\.(?:unsafe_load(?:_all)?\|full_load(?:_all)?)\(\|\byaml\.load(?:_all)?\((?![^)\n]{0,200}\b(?:Loader\s*=\s*)?(?:yaml\.)?C?(?:Safe\|Base)Loader\b)\|\bYAML\(\s*typ\s*=\s*["']unsafe["']` | `SafeLoader`/`CSafeLoader`/`BaseLoader` (keyword or positional) never match | `yaml.safe_load(...)`; for ruamel `YAML(typ="safe")` |
| `WS-DES-003` | Java native / polymorphic deserialization (`ObjectInputStream`, Jackson default typing, XStream, SnakeYAML 1.x) | critical | medium | CWE-502 | A08 | java | regex | **java** `\bnew\s+ObjectInputStream\(\|\.enableDefaultTyping\(\|\.activateDefaultTyping\(\|@JsonTypeInfo\(\s*use\s*=\s*JsonTypeInfo\.Id\.(?:CLASS\|MINIMAL_CLASS)\b\|\bnew\s+XStream\(\|\bnew\s+Yaml\(\s*\)\|\bnew\s+XMLDecoder\(\|\bSerializationUtils\.deserialize\(` | `new XStream(` dropped when the file calls `allowTypes`/`addPermission`; `new Yaml()` dropped when the build pins SnakeYAML >= 2.0 | Bind to concrete DTO classes; use an `ObjectInputFilter` allowlist; `PolymorphicTypeValidator` with explicit subtypes |
| `WS-DES-004` | JS/TS unsafe deserialization (`node-serialize`, `serialize-to-js`, js-yaml full schema) | critical | medium | CWE-502 | A08 | js, ts | regex | **js** `\brequire\(\s*["'](?:node-serialize\|serialize-to-js\|funcster\|cryo)["']\s*\)\|\bfrom\s+["'](?:node-serialize\|serialize-to-js\|funcster\|cryo)["']\|\bunserialize\(\|\byaml\.load\([^)\n]{0,200}\b(?:DEFAULT_FULL_SCHEMA\|JS_SCHEMA)\b` | js-yaml 3.x `load()` without a schema is also unsafe: raised when the lockfile pins `js-yaml@3` | `JSON.parse` plus schema validation; js-yaml >= 4 `load` with the default schema |
| `WS-DES-005` | XML parser with external entities / DTDs enabled (XXE) | high | medium | CWE-611 | A05 | py, java | regex | **py** `\bresolve_entities\s*=\s*True\b\|\bno_network\s*=\s*False\b\|\bfeature_external_(?:ges\|pes)\s*,\s*True\b`<br>**java** `\b(?:DocumentBuilderFactory\|SAXParserFactory\|XMLInputFactory\|TransformerFactory\|SchemaFactory)\.newInstance\(\|\bnew\s+(?:SAXReader\|SAXBuilder)\(\s*\)` | Java: the exclude patterns are checked against the whole file, so a factory hardened anywhere in the file is not reported<br>*exclude* `disallow-doctype-decl\|FEATURE_SECURE_PROCESSING\|IS_SUPPORTING_EXTERNAL_ENTITIES\|SUPPORT_DTD\|ACCESS_EXTERNAL_DTD` | Python: `defusedxml`; Java: `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` |

### 2.5 Cryptography, TLS and JWT (`WS-CRY`)

| ID | Title | Sev | Conf | CWE | OWASP | Lang / kind | Matcher | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|---|
| `WS-CRY-001` | MD5/SHA-1 used where a security property is needed | medium | medium | CWE-328 | A02 | py, js, ts, go, java | regex | **py** `\bhashlib\.(?:md5\|sha1)\((?![^)\n]{0,200}\busedforsecurity\s*=\s*False)\|\bhashlib\.new\(\s*["'](?:md5\|sha1\|md4)["']`<br>**js** `\bcrypto\.createHash\(\s*["'](?:md5\|sha1\|md4)["']`<br>**go** `\b(?:md5\|sha1)\.(?:New\|Sum)\(`<br>**java** `\bMessageDigest\.getInstance\(\s*"(?:MD2\|MD4\|MD5\|SHA-?1\|SHA)"\|\bDigestUtils\.(?:md5\|sha1\|sha)(?:Hex)?\(` | `usedforsecurity=False` never matches; lines naming a non-security purpose (etag, cache key, partition/shard) are downgraded to info<br>*exclude* `(?i)etag\|cache_?key\|checksum\|fingerprint\|dedup\|content_?hash\|partition\|shard\|bucket` | SHA-256/BLAKE2 for integrity, HMAC-SHA-256 for authenticity, a password KDF for passwords |
| `WS-CRY-002` | Password hashed with a fast digest instead of a password KDF | high | high | CWE-916 | A02 | py, js, ts, go | regex | **py** `\bhashlib\.(?:md5\|sha1\|sha224\|sha256\|sha384\|sha512\|sha3_\d{3}\|blake2[bs])\(\s*[^)\n]{0,80}(?i:passw(?:or)?d\|passwd\|\bpwd\b\|passphrase)`<br>**js** `\bcreateHash\(\s*["'][\w-]{2,12}["']\s*\)\s*\.update\(\s*[^)\n]{0,80}(?i:passw(?:or)?d\|passwd\|\bpwd\b\|passphrase)`<br>**go** `\b(?:md5\|sha1\|sha256\|sha512)\.Sum(?:224\|256\|384\|512)?\(\s*[^)\n]{0,80}(?i:passw(?:or)?d\|passwd\|\bpwd\b\|passphrase)` | KDF calls on the same line are excluded<br>*exclude* `(?i)\bhmac\|bcrypt\|scrypt\|argon2\|pbkdf2` | argon2id (`argon2-cffi`), scrypt, or bcrypt; PBKDF2-HMAC-SHA256 with >= 600k iterations only if FIPS forces it |
| `WS-CRY-003` | Broken cipher or ECB mode (DES/3DES/RC4/Blowfish, AES-ECB, Java `Cipher.getInstance("AES")`) | high | high | CWE-327 | A02 | py, js, ts, go, java | regex | **py** `\b(?:DES\|DES3\|ARC4\|ARC2\|Blowfish\|CAST)\.new\(\|\bAES\.new\([^)\n]{0,200}\bMODE_ECB\b\|\bmodes\.ECB\(\|\balgorithms\.(?:TripleDES\|ARC4\|Blowfish\|IDEA\|CAST5\|SEED)\(`<br>**js** `\bcrypto\.createCipher\(\|\bcreateCipheriv\(\s*["'](?:des\|rc4\|rc2\|bf\|blowfish\|aes-\d{3}-ecb)[^"']{0,20}["']`<br>**go** `\b(?:des\|rc4)\.New(?:Cipher\|TripleDESCipher)\(`<br>**java** `\bCipher\.getInstance\(\s*"(?:(?:DES\|DESede\|RC4\|ARCFOUR\|Blowfish\|RC2)(?:/[^"]{0,40})?\|AES(?:/ECB/[^"]{0,40})?)"` | `Cipher.getInstance("AES")` is reported because the provider default is ECB | AES-GCM or ChaCha20-Poly1305 via an AEAD API (`cryptography` AESGCM, `crypto.createCipheriv("aes-256-gcm")`, `cipher.NewGCM`) |
| `WS-CRY-004` | Non-cryptographic RNG used for tokens, OTPs, salts, nonces or IDs | medium | medium | CWE-338 | A02 | py, js, ts, go, java | regex | **py** `\brandom\.(?:random\|randint\|randrange\|choice\|choices\|getrandbits\|sample\|uniform)\(`<br>**js** `\bMath\.random\(\)`<br>**go** `\brand\.(?:Intn\|Int63n?\|Int31n?\|Uint32\|Uint64\|Int\|Perm\|Shuffle\|Read)\(`<br>**java** `\bnew\s+(?:java\.util\.)?Random\(\|\bThreadLocalRandom\.current\(\)\|\bRandomStringUtils\.random(?:Alphanumeric\|Alphabetic\|Numeric\|Ascii)?\(`<br>*require* `(?i)token\|secret\|passw\|otp\|nonce\|salt\|api_?key\|session\|csrf\|reset\|invite\|verification` | Require window is +-2 lines; Go requires a `"math/rand"` import (crypto/rand `Read` is fine); Monte Carlo/backtest code with no security keyword never matches | Python `secrets`, JS `crypto.randomUUID()`/`getRandomValues`, Go `crypto/rand`, Java `SecureRandom` |
| `WS-CRY-005` | TLS certificate or hostname verification disabled | high | high | CWE-295 | A02 | py, js, ts, go, java, sh/ci | regex | **py** `\bverify\s*=\s*False\b\|\bverify_certs\s*=\s*False\b\|\bssl\._create_unverified_context\(\|\b(?:cert_reqs\|verify_mode)\s*=\s*(?:ssl\.)?CERT_NONE\b\|\bcheck_hostname\s*=\s*False\b\|\bTCPConnector\([^)\n]{0,100}\bssl\s*=\s*False`<br>**js** `\brejectUnauthorized\s*:\s*false\b\|\bNODE_TLS_REJECT_UNAUTHORIZED\b["'\]]{0,2}\s*[=:]\s*["']?0\b\|\bstrictSSL\s*:\s*false\b`<br>**go** `\bInsecureSkipVerify\s*:\s*true\b`<br>**java** `\bALLOW_ALL_HOSTNAME_VERIFIER\b\|\bNoopHostnameVerifier\b\|\bsetHostnameVerifier\(\s*\(\s*\w*\s*,\s*\w*\s*\)\s*->\s*true\|\bTrustAllStrategy\b\|\bcheckServerTrusted\([^)\n]{0,200}\)\s*(?:throws\s+[\w.]+\s*)?\{\s*\}`<br>**sh** `\bcurl\b[^\n]{0,200}\s(?:-[a-zA-Z]{0,8}k[a-zA-Z]{0,8}\|--insecure)\b\|\bsslVerify\s*(?:=\s*)?false\b\|\bGIT_SSL_NO_VERIFY\s*[=:]\s*["']?(?:1\|true)` | Downgraded to low when the same line targets `localhost`/`127.0.0.1`; `verify="/path/ca.pem"` never matches<br>*exclude* `(?<![A-Za-z0-9])jwt\.decode\(` | Keep verification on and trust the private CA (`verify="/etc/ssl/certs/corp-ca.pem"`, `REQUESTS_CA_BUNDLE`, `tls.Config{RootCAs: pool}`) |
| `WS-CRY-006` | JWT signature verification disabled or `alg: none` accepted | critical | high | CWE-347 | A02, A07 | py, js, ts, go, java | regex | **py** `["']verify_signature["']\s*:\s*False\b\|(?<![A-Za-z0-9])jwt\.decode\([^)\n]{0,200}\bverify\s*=\s*False\b`<br>**any** `\balgorithms?\s*[=:]\s*\[?[^\]\n]{0,100}["']none["']`<br>**go** `\bUnsafeAllowNoneSignatureType\b\|\bSigningMethodNone\b\|\bParseUnverified\(`<br>**java** `\.parseClaimsJwt\(\|\.parseUnsecuredClaims\(\|\bJWT\.decode\(` | An unverified decode used only to read `kid` is downgraded to low when a verified decode follows within 10 lines (prefer `jwt.get_unverified_header`); Java `JWT.decode` is low unless the file has no `JWT.require(` | Always verify with a pinned algorithm list and key: `jwt.decode(tok, key, algorithms=["RS256"], audience=AUD)` |
| `WS-CRY-007` | JWT verified without an algorithm allowlist (algorithm confusion) | medium | medium | CWE-347 | A02, A07 | py, js, ts, go | regex | **py** `(?<![A-Za-z0-9])jwt\.decode\((?![^)\n]{0,300}\balgorithms\s*=)(?![^)\n]{0,300}verify_signature)`<br>**js** `\bjwt\.verify\(\s*[^,\n]{1,120},\s*[^,)\n]{1,120}\)\|\bjwt\.verify\(\s*[^,\n]{1,120},\s*[^,)\n]{1,120},\s*\{(?![^}\n]{0,200}\balgorithms\s*:)[^}\n]{0,200}\}`<br>**go** `\bjwt\.Parse(?:WithClaims)?\(` | Window is the call (`window: call`) for multi-line calls; Go is excluded when the key func checks `token.Method`<br>*exclude* `\bWithValidMethods\(\|\.Method\.\(\*jwt\.SigningMethod\|\.Method\.Alg\(\)` | Pass `algorithms=[...]` / `{ algorithms: [...] }` / `jwt.WithValidMethods([]string{"RS256"})` |

### 2.6 Web platform (`WS-WEB`)

| ID | Title | Sev | Conf | CWE | OWASP | Lang / kind | Matcher | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|---|
| `WS-WEB-001` | DOM XSS sink fed with dynamic HTML (`innerHTML`, `insertAdjacentHTML`, `document.write`, jQuery `.html()`) | high | medium | CWE-79 | A03 | js, ts, html | regex | **js** `\.(?:innerHTML\|outerHTML)\s*\+?=(?!=)\|\.insertAdjacentHTML\(\|\bdocument\.write(?:ln)?\(\|\.srcdoc\s*=(?!=)\|\bcreateContextualFragment\(\|\$\([^)\n]{0,100}\)\.(?:html\|append\|prepend\|after\|before\|replaceWith)\(\s*(?!["'][^"'\n]{0,300}["']\s*\))` | Static string literals and sanitizer-wrapped values are excluded<br>*exclude* ``` \bDOMPurify\.sanitize\(\|\bsanitizeHtml\(\|\.(?:inner\|outer)HTML\s*=\s*(?:""\|''\|``\|"[^"$+\n]{0,300}"\|'[^'$+\n]{0,300}')\s*;?\s*$ ``` | `textContent`/`createElement`; if HTML is required, `DOMPurify.sanitize` (and a Trusted Types policy) |
| `WS-WEB-002` | Framework raw-HTML escape hatch (React `dangerouslySetInnerHTML`, Vue `v-html`, Svelte `{@html}`, Angular `bypassSecurityTrust*`) | high | medium | CWE-79 | A03 | jsx, tsx, vue, svelte, ts | regex | **js** `\bdangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:(?!\s*(?:DOMPurify\.)?sanitize\w*\()\|\bv-html\s*=\|\{@html\s\|\bbypassSecurityTrust(?:Html\|Script\|Style\|Url\|ResourceUrl)\(` | Values wrapped in `DOMPurify.sanitize(...)` are excluded; raised to critical when the value is LLM output rendered from markdown (`marked(`, `markdown-it`) | Render markdown with a sanitizing renderer (`react-markdown` without `rehype-raw`), or sanitize first |
| `WS-WEB-003` | Server-side HTML built without escaping (`Markup`/`mark_safe`/`HTMLResponse` f-strings, Go `template.HTML`, servlet writers, Thymeleaf `th:utext`) | high | medium | CWE-79 | A03 | py, go, java, html | regex | **py** `\b(?:Markup\|mark_safe\|SafeString)\(\s*(?:[rR]?[fF]["']\|["'][^"'\n]{0,300}["']\s*(?:%\|\+\|\.format\()\|[A-Za-z_][\w.]*\s*[)+%])\|\bHTMLResponse\(\s*(?:content\s*=\s*)?(?:[rR]?[fF]["']\|["'][^"'\n]{0,300}["']\s*(?:%\|\+\|\.format\())`<br>**go** `\btemplate\.(?:HTML\|JS\|JSStr\|URL\|HTMLAttr\|CSS\|Srcset)\(\s*(?!"[^"\n]{0,300}"\s*\))`<br>**java** `\.getWriter\(\)\.(?:write\|print\|println\|printf\|append)\([^)\n]{0,200}\bgetParameter\(\|\bth:utext\s*=` | Constant literals never match; Go requires `"html/template"` in the file | Render through an auto-escaping template (`Jinja2Templates`, `html/template`, `th:text`); escape with `markupsafe.escape` |
| `WS-WEB-004` | Template auto-escaping disabled (`\|safe`, `{% autoescape false %}`, Handlebars `{{{ }}}`, EJS `<%-`, Jinja2 `Environment()` default) | medium | medium | CWE-79 | A03 | tmpl, py | regex | **tmpl** `\{\{[^{}\n]{0,200}[\|]\s*safe\s*\}\}\|\{%-?\s*autoescape\s+(?:false\|off)\s*-?%\}\|\{\{\{[^{}\n]{1,200}\}\}\}\|<%-`<br>**py** `\bEnvironment\(\|\bautoescape\s*=\s*False\b` | Python: `window: call` and file-level require `jinja2`; environments used only for prompt/text templates (variable or path contains `prompt`) are downgraded to info<br>*exclude* `\bautoescape\s*=\s*(?:True\|select_autoescape\()` | `Environment(autoescape=select_autoescape(["html", "xml"]))`; remove `\|safe` or sanitize the value first |
| `WS-WEB-005` | Open redirect to a request-supplied URL | medium | medium | CWE-601 | A01 | py, js, ts, go, java | regex + py_ast | **py** `\b(?:redirect\|RedirectResponse\|HttpResponseRedirect)\(\s*(?:url\s*=\s*)?request\.(?:args\|GET\|POST\|query_params\|form\|values\|headers)\b`<br>**js** `\bres\.redirect\(\s*(?:\d{3}\s*,\s*)?req\.(?:query\|body\|params\|headers)\b`<br>**go** `\bhttp\.Redirect\(\s*\w+\s*,\s*\w+\s*,\s*r\.(?:URL\.Query\(\)\.Get\|FormValue)\(\|\bc\.Redirect\(\s*[\w.]+\s*,\s*c\.(?:Query\|PostForm\|Param)\(`<br>**java** `\bsendRedirect\(\s*request\.getParameter\(\|["']redirect:["']\s*\+\s*request\.getParameter\(` | Exclude window is +-5 lines; py_ast also follows `next = request.args.get("next")` into `redirect(next)`<br>*exclude* `\burl_has_allowed_host_and_scheme\(\|\bis_safe_url\(\|\.netloc\b\|startswith\(\s*["']/["']\|ALLOWED_REDIRECT` | Accept only relative paths (`/` but not `//`) or hosts from an allowlist; otherwise redirect to a fixed page |
| `WS-WEB-006` | ReDoS-shaped regex (nested quantifier) or regex compiled from user input | medium | medium | CWE-1333 | A04 | py, js, ts, java | regex | **any** `\((?:[^()\\\n+*]\|\\.){0,80}[+*](?:[^()\\\n]\|\\.){0,80}\)(?:[+*]\|\{\d{1,4},\d{0,4}\})`<br>**py** `\bre\.(?:compile\|match\|search\|fullmatch\|findall\|finditer\|sub\|split)\(\s*(?:[rR]?[fF][rR]?["'][^"'\n]{0,200}\{\|request\.)`<br>**js** `` \bnew\s+RegExp\(\s*(?:req\.(?:query\|body\|params)\|`[^`]{0,200}\$\{) ``<br>*require* `\bre\.\w{3,9}\(\|\bregex\.\w{3,9}\(\|RegExp\(\|Pattern\.compile\(\|\.(?:test\|exec\|match\|matchAll\|replace\|replaceAll\|split\|matches)\(` | Go (RE2) and Pydantic v2 `Field(pattern=...)` (Rust regex) are linear-time and excluded; the nested-quantifier form needs a regex API on the same line<br>*exclude* `\bre\.escape\(\|\bescapeRegExp\(\|\bPattern\.quote\(\|\bField\(` | Remove the nested quantifier (`^[\w.+-]+@...$`), bound input length first, `re.escape` user text, or use `google-re2` |
| `WS-WEB-007` | Prototype pollution via deep merge/set of request data | high | medium | CWE-1321 | A08 | js, ts | regex + multiline | **js** `\b(?:_\|lodash)\.(?:merge\|mergeWith\|defaultsDeep\|set\|setWith\|zipObjectDeep)\(\s*[^,\n]{1,80},\s*(?:req\.(?:body\|query\|params)\|JSON\.parse\()\|\b(?:deepmerge\|deepExtend\|defaultsDeep)\(\s*[^,\n]{1,80},\s*(?:req\.(?:body\|query\|params)\|JSON\.parse\()\|\$\.extend\(\s*true\s*,[^)\n]{0,200}\breq\.(?:body\|query)`<br>**js** `for\s*\(\s*(?:const\|let\|var)\s+(\w+)\s+in\s+\w+\s*\)[^\n]{0,20}\n(?:[^\n]{0,200}\n){0,5}?[^\n]{0,200}\[\1\]\s*=(?!=)` | The hand-rolled merge form (second pattern) is low confidence and excluded when the loop body checks `__proto__`/`constructor`/own-property<br>*exclude* `__proto__\|["']constructor["']\|hasOwnProperty\|Object\.hasOwn\(\|Object\.create\(null\)` | Validate with a schema first; use `Object.create(null)` or `Map`; block `__proto__`, `constructor`, `prototype` keys |
| `WS-WEB-008` | CORS allows any origin with credentials, or reflects the `Origin` header | high | medium | CWE-942 | A05 | js, ts, go, py, java | multiline | **js** `\bcors\(\s*\{(?=[^}]{0,400}\bcredentials\s*:\s*true)(?=[^}]{0,400}\borigin\s*:\s*(?:true\|["']\*["']))`<br>**any** `["']Access-Control-Allow-Origin["']\s*,\s*(?:req\.headers\.origin\|req\.headers\[\s*["']origin["']\s*\]\|req\.(?:header\|get)\(\s*["']origin["']\s*\)\|r\.Header\.Get\(\s*"Origin"\s*\)\|request\.headers\.get\(\s*["'][Oo]rigin["']\s*\)\|request\.getHeader\(\s*"Origin"\s*\))`<br>**go** `\bcors\.(?:Options\|Config)\s*\{(?=[\s\S]{0,600}?\bAllowCredentials\s*:\s*true)(?=[\s\S]{0,600}?(?:\bAllowedOrigins\s*:\s*\[\]string\s*\{\s*"\*"\|\bAllowAllOrigins\s*:\s*true\|\bAllowOrigins\s*:\s*\[\]string\s*\{\s*"\*"))`<br>**py** `\bCORS\((?![^)\n]{0,300}\borigins\s*=\s*\[)[^)\n]{0,300}\bsupports_credentials\s*=\s*True`<br>**java** `@CrossOrigin\(\s*(?:origins\s*=\s*)?"\*"[^)\n]{0,200}allowCredentials\s*=\s*"true"\|\.allowedOriginPatterns\(\s*"\*"\s*\)[^;]{0,200}\.allowCredentials\(\s*true\s*\)` | Reflection is excluded when an allowlist check is within 5 lines; FastAPI `CORSMiddleware` is WS-API's job and never matches here<br>*exclude* `\b(?:ALLOWED_ORIGINS\|allowed_origins\|allowedOrigins\|originAllowlist)\b\|\.includes\(\s*origin\b\|\bin\s+ALLOWED` | Explicit origin allowlist; never combine `*`/reflection with credentials; add `Vary: Origin` |
| `WS-WEB-009` | Session/auth cookie set without `Secure` + `HttpOnly` (or insecure framework cookie settings) | medium | medium | CWE-614, CWE-1004 | A05 | py, js, ts, go, java | regex | **py** `\.set_cookie\(\|\b(?:SESSION_COOKIE_SECURE\|CSRF_COOKIE_SECURE\|SESSION_COOKIE_HTTPONLY)\s*=\s*False\b`<br>**js** `\bres\.cookie\(\|\bcookie\s*:\s*\{[^}\n]{0,200}\bsecure\s*:\s*false`<br>**go** `\bhttp\.Cookie\s*\{`<br>**java** `\bnew\s+Cookie\(` | Encoded as `any` of two `all` branches (cookie call + `not` Secure; cookie call + `not` HttpOnly) with `near_lines: 6`, so a hit is dropped only when both flags are present; non-sensitive cookie names are excluded<br>*exclude* `(?i)["'](?:theme\|lang\|locale\|consent\|tz)["']`<br>*exclude when all match* `(?i)\bsecure\b\s*[=:(]\s*(?:True\|true)`<br>`(?i)\bhttp_?only\b\s*[=:(]\s*(?:True\|true)` | `secure=True, httponly=True, samesite="lax"` (or `strict`); `__Host-` prefix for session cookies |
| `WS-WEB-010` | Debug mode or diagnostic endpoints enabled (Flask/Django debug, Werkzeug console, Go pprof, gin debug, Spring actuator `*`, H2 console) | high | medium | CWE-489 | A05 | py, go, java/props/yaml, js | regex + yaml_path | **py** `\b(?:app\|application\|server)\.run\([^)\n]{0,200}\bdebug\s*=\s*True\b\|^[ \t]{0,16}DEBUG\s*=\s*True\b\|\bapp\.debug\s*=\s*True\b\|\b(?:use_debugger\|evalex)\s*=\s*True\b\|\bFLASK_DEBUG\s*[=:]\s*["']?1\b`<br>**go** `(?:^\|\bimport)\s*_\s+"net/http/pprof"\|\bgin\.SetMode\(\s*gin\.DebugMode\s*\)`<br>**java** `^[ \t]{0,16}management\.endpoints\.web\.exposure\.include\s*[=:]\s*["']?\*\|^[ \t]{0,16}spring\.h2\.console\.enabled\s*[=:]\s*true\b`<br>**js** `\bapp\.use\(\s*errorhandler\(\s*\)\s*\)`<br>yaml_path: `management.endpoints.web.exposure.include` == `"*"` in `application*.y*ml` | `DEBUG = True` only in `settings*.py`/`config*.py`; downgraded to low in `*local*`/`*dev*` settings files; pprof downgraded when served on a separate `127.0.0.1` listener | Drive debug from env with a false default; expose `health,info` only; serve pprof on a localhost-only mux |
| `WS-WEB-011` | Secrets or credentials written to logs/stdout | medium | low | CWE-532 | A09 | py, js, ts, go, java | regex | **any** `(?i:passw(?:or)?d\|secret\|api_?key\|access_?token\|refresh_?token\|authorization\|private_?key\|client_?secret\|card_?number\|\bcvv\b\|\bssn\b)`<br>**any** `\b(?:print\|pprint\|logger\.\w+\|logging\.\w+\|console\.log)\(\s*(?:os\.environ\|dict\(os\.environ\)\|process\.env\|request\.headers\|req\.headers)\s*\)`<br>*require* `\b(?:logger\|logging\|log\|logrus\|zap\|slog\|console\|fmt\|print\|pprint\|println\|printf\|System\.out\|System\.err)\b[.\w]{0,20}\(` | The keyword must occur after the call's opening paren on the same line, inside an interpolation or argument (post-filter); masking helpers on the line exclude it<br>*exclude* `(?i)redact\|mask\|scrub\|sanitiz\|\*{3}\|\blen\(\|\bis\s+not\s+None\|\bbool\(` | Log identifiers, not values; add a logging filter that redacts `Authorization`, `*_KEY`, `*_SECRET`, `password` |
| `WS-WEB-012` | Exception details or stack traces returned to the client | medium | medium | CWE-209 | A05 | py, js, ts, go, java | regex | **py** `(?:\breturn\b\|\bResponse\(\|\bJSONResponse\(\|\bjsonify\(\|\bdetail\s*=)[^\n]{0,160}?(?:\btraceback\.format_exc\(\)\|\b(?:str\|repr)\(\s*(?:e\|ex\|exc\|err\|error)\s*\))`<br>**js** `\bres\.(?:status\(\s*\d{3}\s*\)\.)?(?:send\|json\|write\|end)\([^)\n]{0,160}?\b(?:err\|error\|e)\.stack\b\|\bres\.(?:status\(\s*\d{3}\s*\)\.)?(?:send\|json)\(\s*(?:err\|error\|e)\s*\)`<br>**go** `\bhttp\.Error\(\s*w\s*,\s*err\.Error\(\)`<br>**java** `\.printStackTrace\(\s*(?:response\.getWriter\(\)\|new\s+PrintWriter\(\s*response)\|\bserver\.error\.include-(?:stacktrace\|exception)\s*[=:]\s*(?:always\|true)` | Downgraded to low for 4xx validation errors whose message is built by the app; Go `http.Error(w, err.Error()...)` is low confidence | Log the exception server-side with a request ID; return a generic message plus the ID |

---

## 3. secrets pack

### 3.1 Detection pipeline (shared by every `WS-SEC-*` rule)

```
candidate (vendor-prefix regex | keyword-context regex | entropy)
  └─► value = last non-empty capture group
      └─► placeholder / reference filter  (rules/secrets/_filters.yaml, shared)
          └─► entropy gate                (context and generic rules only)
              └─► offline structural check (checksum, decode, magic bytes; §5.2)
                  └─► span dedupe: vendor > context > generic; the most specific rule wins
                      └─► REDACT (§5.1)  ← nothing downstream ever sees the raw value
```

On top of the engine's placeholder filter (engine.md §8.5), these values are always dropped.
They are anchored to the whole value:

```python
PLACEHOLDER = re.compile(
    r"(?i)^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\$\([A-Za-z_]+\)|\{\{[^}]{0,80}\}\}|<[^>]{1,60}>"
    r"|%\([a-z_]+\)s|\*{3,}|x{4,}|\.{3}|…|change_?me\w*|(?:your|my|example|sample|dummy|fake)[-_][\w-]{0,40}"
    r"|redacted|placeholder|todo|none|null|true|false)$")
REFERENCE = re.compile(
    r"^(?:arn:aws:secretsmanager:|projects/[\w-]+/secrets/|vault:|ref\+|secretref:|op://|ENC\[AES256_GCM,)")
```

Severity follows the blast radius:
- **critical**: can move money or place orders, has cloud admin scope, can push code or
  packages, can run up unbounded spend (LLM/cloud APIs), is a private key, or decrypts other
  secrets.
- **high**: read/write API access.
- **medium**: read-only or short-lived.
- **low**: test mode or a public-by-design key.

### 3.2 Cloud (`cloud.yaml`)

| ID | Title | Sev | Conf | CWE | OWASP | Lang / kind | Matcher | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|---|
| `WS-SEC-AWS-001` | AWS access key ID | critical | high | CWE-798 | A07 | any text | regex | **any** `\b(?:AKIA\|ASIA\|ABIA\|ACCA)[A-Z2-7]{16}\b` | `ASIA` (STS, short-lived) is high, not critical; the AWS documentation keys are excluded; the owning account ID is decoded offline from the key and reported (it is not secret)<br>*exclude* `\b(?:AKIA\|ASIA)[A-Z2-7]{9}EXAMPLE\b` | Deactivate and rotate in IAM now, review CloudTrail for the key, replace static keys with IAM roles (IRSA, SSO, GitHub OIDC) |
| `WS-SEC-AWS-002` | AWS secret access key (keyword context) | critical | high | CWE-798 | A07 | any text | regex | **any** `(?i)(?<![A-Za-z0-9])aws_?(?:secret_?access_?key\|secret_?key\|secret)\b["']?[ \t]{0,8}[:=][ \t]{0,8}["']?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])` | A bare 40-char base64 token within 3 lines of a WS-SEC-AWS-001 hit is also reported (co-location); `${{ secrets.X }}`/`${X}` values cannot match<br>*exclude* `EXAMPLEKEY` | Same as WS-SEC-AWS-001; the key pair is compromised as a unit |
| `WS-SEC-AWS-003` | Amazon Bedrock long-term API key | critical | medium | CWE-798 | A07 | any text | regex | **any** `\bABSK[A-Za-z0-9+/]{109,269}={0,2}(?![A-Za-z0-9+/=])` | Prefix and length bounds follow the published long-term key format and are re-checked at each quarterly rule review; short-term keys expire within hours and are not reported | Delete the key on its IAM user, call Bedrock with role credentials (SigV4) from the workload |
| `WS-SEC-AZ-001` | Azure Storage / Service Bus connection string with embedded key | critical | high | CWE-798 | A07 | any text | regex | **any** `\bDefaultEndpointsProtocol=https?;AccountName=[a-z0-9]{3,24};AccountKey=([A-Za-z0-9+/]{86}==)\|\bEndpoint=sb://[A-Za-z0-9.\-]{1,200};SharedAccessKeyName=[^;\s]{1,100};SharedAccessKey=([A-Za-z0-9+/]{43}=)` | The Azurite emulator account (`devstoreaccount1`, a published key) is excluded<br>*exclude* `AccountName=devstoreaccount1` | Rotate the account key / SAS policy, switch to Entra ID auth (managed identity) and disable shared-key access |
| `WS-SEC-AZ-002` | Microsoft Entra ID (Azure AD) client secret | high | medium | CWE-798 | A07 | any text | regex | **any** `` (?:^\|[\s"'`=:(,>])([A-Za-z0-9_~.\-]{3}\dQ~[A-Za-z0-9_~.\-]{31,34})(?=$\|[\s"'`<),;]) `` |  | Delete the secret on the app registration; use a managed identity or federated credential |
| `WS-SEC-GCP-001` | GCP service-account key JSON (plain or base64-encoded) | critical | high | CWE-798 | A07 | json, any text | multiline | **any** `"type"[ \t]{0,8}:[ \t]{0,8}"service_account"[\s\S]{0,3000}?"private_key"[ \t]{0,8}:[ \t]{0,8}"-{5}BEGIN`<br>**any** `\b(?:ewogICJ0eXBlIjogInNlcnZpY2VfYWNjb3VudCIs\|eyJ0eXBlIjoic2VydmljZV9hY2NvdW50\|eyJ0eXBlIjogInNlcnZpY2VfYWNjb3VudCIs)` | The base64 prefixes cover the pretty-printed and compact JSON that CI variables such as `GOOGLE_CREDENTIALS` usually hold | Delete the key (`gcloud iam service-accounts keys delete`), move to Workload Identity (GKE) or Workload Identity Federation (CI), enforce `iam.disableServiceAccountKeyCreation` |
| `WS-SEC-GCP-002` | Google API key | high | high | CWE-798 | A07 | any text | regex | **any** `\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])` | Downgraded to low inside a Firebase web config (`firebaseConfig`/`initializeApp(` within 5 lines): those keys are public by design and must be API/referrer-restricted | Regenerate, then restrict by API and by referrer/IP; prefer service identities for server calls to Vertex AI |
| `WS-SEC-GCP-003` | Google OAuth client secret | high | high | CWE-798 | A07 | any text | regex | **any** `\bGOCSPX-[0-9A-Za-z_\-]{28}(?![0-9A-Za-z_\-])` |  | Reset the secret on the OAuth client; load from Secret Manager at runtime |

### 3.3 Source control (`vcs.yaml`)

| ID | Title | Sev | Conf | CWE | OWASP | Lang / kind | Matcher | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|---|
| `WS-SEC-GH-001` | GitHub token (classic PAT, OAuth, user-to-server, server-to-server, refresh) | critical | high | CWE-798 | A07 | any text | regex | **any** `\bgh[pousr]_[A-Za-z0-9]{36,251}\b` | Offline check of the trailing 6-char base62 CRC32 checksum: pass keeps high confidence, fail drops to low (typical of docs and fakes) | Revoke the token, review the audit log; in CI use `GITHUB_TOKEN`, OIDC, or a GitHub App installation token |
| `WS-SEC-GH-002` | GitHub fine-grained personal access token | critical | high | CWE-798 | A07 | any text | regex | **any** `\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b` |  | Revoke under Settings, then Developer settings; scope replacements to single repos with an expiry |
| `WS-SEC-GL-001` | GitLab token (personal/deploy/runner/CI/trigger/OAuth/feed/agent/SCIM) or runner registration token | critical | high | CWE-798 | A07 | any text | regex | **any** `\bgl(?:pat\|dt\|rt\|cbt\|ptt\|oas\|imt\|ft\|agent\|soat\|ffct)-[A-Za-z0-9_\-]{20,300}(?![A-Za-z0-9_\-])\|\bGR1348941[A-Za-z0-9_\-]{20}(?![A-Za-z0-9_\-])` | `glft-` (feed) and `glimt-` (incoming mail) are medium | Revoke in the GitLab UI or API; prefer CI job tokens and project access tokens with expiry |

### 3.4 AI and vector databases (`ai.yaml`)

| ID | Title | Sev | Conf | CWE | OWASP | Lang / kind | Matcher | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|---|
| `WS-SEC-ANT-001` | Anthropic API or admin key | critical | high | CWE-798 | A07 | any text | regex | **any** `\bsk-ant-(?:api03\|admin01)-[A-Za-z0-9_\-]{93}AA(?![A-Za-z0-9_\-])` |  | Revoke in the console; inject at runtime from a secret manager, or call through Bedrock/Vertex AI with cloud IAM |
| `WS-SEC-HF-001` | Hugging Face user or org token | high | high | CWE-798 | A07 | any text | regex | **any** `\b(?:hf\|api_org)_[A-Za-z]{34}(?![A-Za-z0-9])` | Raised to critical when the token is used with write scopes (`push_to_hub`, `upload_file` in the file) | Revoke at huggingface.co settings; use fine-grained read-only tokens from env |
| `WS-SEC-OAI-001` | OpenAI API key (project, service-account, admin, legacy) | critical | high | CWE-798 | A07 | any text | regex | **any** `\bsk-(?:proj-\|svcacct-\|admin-)?[A-Za-z0-9_\-]{20,200}T3BlbkFJ[A-Za-z0-9_\-]{20,200}(?![A-Za-z0-9_\-])`<br>**any** `\bsk-(?:proj\|svcacct\|admin)-[A-Za-z0-9_\-]{40,250}(?![A-Za-z0-9_\-])` | The second pattern (no `T3BlbkFJ` marker) is medium confidence; overlapping hits are merged | Revoke in the provider dashboard; route calls through a server-side gateway that holds the key |
| `WS-SEC-VDB-001` | Vector-database API key (Pinecone prefix; Qdrant/Weaviate/Milvus/Zilliz/Chroma by context) | high | medium | CWE-798 | A07 | any text | regex | **any** `\bpcsk_[A-Za-z0-9_]{50,120}(?![A-Za-z0-9_])`<br>**any** `(?i)(?<![A-Za-z0-9])(?:pinecone\|qdrant\|weaviate\|milvus\|zilliz\|chroma)[\w.\-]{0,20}?api_?key\b["']?[ \t]{0,8}[:=][ \t]{0,8}["']([A-Za-z0-9_\-.]{20,200})["']` | Context values pass the placeholder and entropy filters of WS-SEC-GEN-001 | Rotate in the vector-DB console; scope keys per index/collection; load from env or a secret manager |

### 3.5 Payments and SaaS (`payments.yaml`, `saas.yaml`)

| ID | Title | Sev | Conf | CWE | OWASP | Lang / kind | Matcher | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|---|
| `WS-SEC-SG-001` | SendGrid API key | high | high | CWE-798 | A07 | any text | regex | **any** `\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}(?![A-Za-z0-9_\-])` |  | Delete the key in SendGrid; create a Mail-Send-only key held in a secret store |
| `WS-SEC-SLK-001` | Slack bot/user/app token or incoming-webhook URL | high | high | CWE-798 | A07 | any text | regex | **any** `\bxox[abposr]-[0-9]{6,15}-[0-9A-Za-z\-]{10,200}\|\bxapp-\d-[A-Z0-9]{9,12}-\d{10,16}-[a-f0-9]{64}\b\|https://hooks\.slack\.com/(?:services\|workflows\|triggers)/[A-Za-z0-9/_\-]{30,200}` |  | Revoke/regenerate in the Slack app config; keep webhook URLs in a secret store (they post as your app) |
| `WS-SEC-STR-001` | Stripe secret/restricted key or webhook signing secret | critical | high | CWE-798 | A07 | any text | regex | **any** `\b(?:sk\|rk)_(?:live\|test)_[A-Za-z0-9]{24,247}(?![A-Za-z0-9])\|\bwhsec_[A-Za-z0-9+/=]{32,100}(?![A-Za-z0-9+/=])` | `*_test_*` keys are low; publishable `pk_*` keys are public and never match | Roll the key in the Stripe dashboard; use restricted keys scoped per service |
| `WS-SEC-TG-001` | Telegram bot token (trading alerts / signal bots) | high | medium | CWE-798 | A07 | any text | regex | **any** `\bapi\.telegram\.org/bot\d{8,10}:A[A-Za-z0-9_\-]{34}(?![A-Za-z0-9_\-])`<br>**any** `\b\d{8,10}:A[A-Za-z0-9_\-]{34}(?![A-Za-z0-9_\-])`<br>*require* `(?i)telegram\|bot_?token\|\btg_` | The bare form requires Telegram context within 3 lines; the URL form does not | `/revoke` via @BotFather; keep the token in env/secret store; restrict the bot to known chat IDs |
| `WS-SEC-TWL-001` | Twilio API key SID or auth token | high | medium | CWE-798 | A07 | any text | regex | **any** `\bSK[0-9a-fA-F]{32}\b`<br>**any** `(?i)(?<![A-Za-z0-9])twilio_?auth_?token\b["']?[ \t]{0,8}[:=][ \t]{0,8}["']?([a-f0-9]{32})\b`<br>*require* `(?i)twilio\|\bAC[0-9a-f]{32}\b` | `SK...` alone is an identifier; it is reported only with Twilio context within 5 lines (the require) | Rotate the auth token / delete the API key in the Twilio console; use API keys per service |

### 3.6 Exchanges and brokers (`trading.yaml`)

Most exchange keys have no vendor prefix, so these rules depend on keyword context. They are
tuned to the naming used by the official SDKs, by ccxt and by the common container images
(IBC/IBeam/ib-gateway). A leaked trading key is always at least `high`. It is `critical` whenever
the key could place orders. Scope checks (withdrawal permission, IP allowlist) belong to the
`WS-TRD` domain rules. The whole family shares `WS-SEC-TRD-NNN`.

| ID | Title | Sev | Conf | CWE | OWASP | Lang / kind | Matcher | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|---|
| `WS-SEC-TRD-001` | Binance API key or secret | critical | high | CWE-798 | A07 | any text | regex | **any** `(?i)(?<![A-Za-z0-9])binance[\w.\-]{0,24}?(?:api_?)?(?:key\|secret)\b["']?[ \t]{0,8}[:=][ \t]{0,8}["']?([A-Za-z0-9]{64})(?![A-Za-z0-9])`<br>**any** `["']X-MBX-APIKEY["'][ \t]{0,8}:[ \t]{0,8}["']([A-Za-z0-9]{64})["']` | Binance Ed25519/RSA key files are caught by WS-SEC-PK-001; whether a key has withdrawal permission is checked by WS-TRD, not here | Delete the key in API Management; recreate it trade-only (no withdrawals), IP-restricted, on a sub-account; load from a secret manager |
| `WS-SEC-TRD-002` | Coinbase API key (CDP key name + secret, legacy secret/passphrase) | critical | medium | CWE-798 | A07 | any text | regex | **any** `\borganizations/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/apiKeys/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`<br>**any** `(?i)(?<![A-Za-z0-9])(?:coinbase\|cdp\|cb)[\w.\-]{0,24}?(?:api_?)?(?:secret\|private_?key\|passphrase)\b["']?[ \t]{0,8}[:=][ \t]{0,8}["']([A-Za-z0-9+/=_\-]{20,200})["']` | The CDP key name is an identifier: high alone, critical when a private key (WS-SEC-PK-001) or a context secret is in the same file | Delete the key in the developer portal; recreate with view/trade scope only and an IP allowlist |
| `WS-SEC-TRD-003` | Kraken API key or private key | critical | high | CWE-798 | A07 | any text | regex | **any** `(?i)(?<![A-Za-z0-9])kraken[\w.\-]{0,24}?(?:api_?)?(?:key\|secret\|private_?key)\b["']?[ \t]{0,8}[:=][ \t]{0,8}["']?([A-Za-z0-9+/]{56}(?:[A-Za-z0-9+/]{30}==)?)(?![A-Za-z0-9+/=])` | Matches the 56-char API key and the 88-char base64 private key | Delete the key; recreate without "Withdraw Funds", with an IP allowlist and a nonce window |
| `WS-SEC-TRD-004` | Alpaca API key ID / secret key | critical | high | CWE-798 | A07 | any text | regex | **any** `(?i)(?<![A-Za-z0-9])(?:APCA_API_SECRET_KEY\|alpaca[\w.\-]{0,24}?secret(?:_?key)?)\b["']?[ \t]{0,8}[:=][ \t]{0,8}["']?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])`<br>**any** `["']APCA-API-SECRET-KEY["'][ \t]{0,8}:[ \t]{0,8}["']([A-Za-z0-9/+]{40})["']`<br>**any** `\b(?:AK\|PK)[A-Z0-9]{18}\b`<br>*require* `(?i)alpaca\|apca` | Key IDs need Alpaca context (the require); `PK...` IDs or a `paper-api.alpaca.markets` URL in the file lower severity to medium (paper account) | Regenerate keys in the dashboard (this invalidates the old pair); keep live and paper keys in separate secret paths |
| `WS-SEC-TRD-005` | Interactive Brokers credentials (TWS/Gateway/IBC/IBeam login, Flex Web Service token) | critical | medium | CWE-798 | A07 | any text, ini, env, yaml | regex | **any** `(?i)(?<![A-Za-z0-9])(?:TWS_PASSWORD\|IB_PASSWORD\|IBKR_PASSWORD\|IBEAM_PASSWORD\|IbPassword)\b["']?[ \t]{0,8}[:=][ \t]{0,8}["']?([^\s"'#$]{4,128})`<br>**any** `(?i)(?<![A-Za-z0-9])(?:ib_?\|ibkr_?)?flex_?(?:web_?)?(?:service_?)?token\b["']?[ \t]{0,8}[:=][ \t]{0,8}["']?(\d{18,30})\b`<br>**any** `interactivebrokers\.com/[^\s"']{0,120}SendRequest\?t=(\d{18,30})` | Covers IBC `config.ini` (`IbPassword=`), IBeam and ib-gateway container env; `TradingMode=live` in the same file raises confidence to high; Flex tokens (read-only statements) are high, not critical<br>*exclude* `(?i)[:=][ \t]{0,8}["']?(?:changeme\|password\|<[^>]{1,40}>\|\{\{)` | Change the IBKR password and re-enrol 2FA; inject gateway credentials from a secret store at container start; rotate the Flex token |
| `WS-SEC-TRD-006` | Polygon.io market-data API key | high | medium | CWE-798 | A07 | any text | regex | **any** `(?i)(?<![A-Za-z0-9])polygon[\w.\-]{0,24}?(?:api_?)?key\b["']?[ \t]{0,8}[:=][ \t]{0,8}["']?([A-Za-z0-9_]{32})(?![A-Za-z0-9_])`<br>**any** `https?://api\.polygon\.io/[^\s"'<>]{0,300}?[?&]apiKey=([A-Za-z0-9_]{32})(?![A-Za-z0-9_])` | Medium confidence because "polygon" also names a blockchain whose RPC keys share the context; URL form is high | Regenerate in the dashboard; send the key in the `Authorization: Bearer` header from env, never in logged URLs |
| `WS-SEC-TRD-007` | Exchange credentials inline in a ccxt client constructor | critical | high | CWE-798 | A07 | py, js, ts | multiline | **any** `\bccxt(?:\.pro)?\.\w+\([ \t]{0,8}\{(?=[^}]{0,600}["'](?:secret\|password)["'][ \t]{0,8}:[ \t]{0,8}["'][A-Za-z0-9+/=_\-]{16,200}["'])`<br>**any** `\b\w{1,64}\.(?:secret\|password)[ \t]{0,8}=[ \t]{0,8}["'][A-Za-z0-9+/=_\-]{16,200}["']` | The attribute form needs `import ccxt`/`require("ccxt")` in the file; values from `os.environ`/`process.env` never match | Build the config from env/secret manager; use exchange sub-accounts with trade-only keys |

### 3.7 Generic (`generic.yaml`)

| ID | Title | Sev | Conf | CWE | OWASP | Lang / kind | Matcher | Detection | FP guards | Fix |
|---|---|---|---|---|---|---|---|---|---|---|
| `WS-SEC-AGE-001` | age secret key (SOPS/Flux decryption key) | critical | high | CWE-321 | A02, A07 | any text | regex | **any** `\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b` | Public recipients (`age1...`) are not secret and never match | New age key, `sops updatekeys` on every file, rotate every secret it protected; keep the key only in the cluster `sops-age` Secret or KMS |
| `WS-SEC-DB-001` | Database password in a JDBC URL, libpq/ODBC DSN, or SQL `CREATE/ALTER USER\|ROLE` DDL | high | high | CWE-798 | A07 | any text, sql | regex | **any** `` \bjdbc:[a-z0-9]+:[^\s"'`]{0,300}?[;?&]password=([^;&\s"'`]{1,128}) ``<br>**any** `(?i)\b(?:dbname\|host\|server\|data\s+source)[ \t]{0,8}=[^\n]{0,160}?[\s;](?:password\|pwd)[ \t]{0,8}=[ \t]{0,8}([^;\s"']{1,128})`<br>**sql** `(?i)\b(?:create\|alter)\s+(?:user\|role\|login)\b[^;\n]{0,200}?\b(?:identified\s+by\|password)\s+'([^'\n]{1,128})'` | A MySQL `*<40 hex>` / `SCRAM-SHA-256$...` / `md5<32 hex>` value is a hash: medium (still crackable offline)<br>*exclude* `(?i)(?:password\|pwd)[ \t]{0,8}=[ \t]{0,8}(?:\$\{?\w\|%\(\w+\)s\|\{\|<)` | Create roles in migrations without passwords and set them out-of-band (`\password`, IAM auth, Vault DB engine) |
| `WS-SEC-DB-002` | Credentials embedded in a connection URI (Postgres/MySQL/SingleStore/Mongo/Redis/AMQP/..., also HTTP(S)/FTP/SSH userinfo) | high | high | CWE-798 | A07 | any text | regex | **any** `` \b(?:postgres(?:ql)?\|mysql\|mariadb\|singlestoredb\|memsql\|mongodb(?:\+srv)?\|rediss?\|amqps?\|mssql\|sqlserver\|clickhouse\|cockroachdb\|snowflake\|oracle\|https?\|ftp\|sftp\|ssh)(?:\+[a-z0-9]+)?://([^\s:/@"'`<>]{0,128}):([^\s@/"'`<>]{1,256})@[^\s"'`<>]{1,256} `` | The line filter drops placeholders, env/template refs and ports in the password position; severity is low when the host is `localhost`/`127.0.0.1`/a compose service name and the password is a stock value (`postgres`, `root`, `example`, `dev`); a token in the userinfo is kept by its vendor rule and this hit goes to `properties.related`<br>*exclude* `://[^\s:/@]{0,128}:(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?\|\$\([A-Za-z_]+\)\|\{\{[^}]{0,80}\}\}\|<[^>]{1,40}>\|%\([a-z_]+\)s\|\*+\|[xX]+\|\d{1,5}\|(?i:password\|passw0rd\|pass\|changeme\|secret\|example\|redacted))@` | Build the DSN at runtime from a secret store (Secrets Manager, Secret Manager, Vault, k8s Secret via env); rotate the DB user's password |
| `WS-SEC-GEN-001` | Generic secret: credential-named assignment of a high-entropy literal | high | medium | CWE-798 | A07 | code, config | entropy | **any** `(?i)(?:api_?key\|secret\|token\|passw(?:or)?d\|pwd\|credentials?\|private_?key\|access_?key\|client_?secret\|auth_?key)[A-Za-z0-9_.\-]{0,40}["']?[ \t]{0,8}(?::=\|[:=]\|=>)[ \t]{0,8}[rbRB]?["']([^"'\s]{12,256})["']` | Shannon entropy of capture 1 >= 3.5 bits/char (>= 3.0 if hex-only), at least 2 character classes; env-var names, URLs, paths, secret *names/ARNs* and placeholders are excluded; suppressed when a vendor rule already covers the span<br>*exclude* `(?i)[:=>][ \t]{0,8}[rbRB]?["'](?:\$\{[^}]{1,80}\}\|\{\{[^}]{0,80}\}\}\|<[^>]{1,60}>\|%\(\w+\)s\|x{6,}\|\*{6,}\|(?:your\|my\|example\|sample\|dummy\|fake\|test)[-_][\w-]{0,40}\|change_?me\w*)["']`<br>`[:=>][ \t]{0,8}["'](?:[A-Z][A-Z0-9_]{3,80}\|https?://\|/\|\./\|~/)`<br>`(?i)(?:secret\|token\|key\|password)[\w.-]{0,20}?_(?:name\|id\|arn\|path\|file\|url\|uri\|type\|ttl\|length\|field\|header)["']?[ \t]{0,8}[:=]` | Move to the platform secret store and inject via env; rotate the value |
| `WS-SEC-GEN-002` | Secret value in a dotenv/properties/ini/tfvars/compose/Helm-values file | high | medium | CWE-798, CWE-312 | A07 | .env*, *.properties, *.ini, *.cfg, .pypirc, *.tfvars, compose, values*.yaml | entropy | **cfg** `(?i)^[ \t]{0,16}(?:export\s+)?[A-Za-z][A-Za-z0-9_.\-]{0,63}(?:key\|secret\|token\|password\|passwd\|pwd\|credentials?\|dsn\|webhook_url)[ \t]{0,8}[=:][ \t]{0,8}["']?([^\s"'#]{8,512})` | Only in the listed globs; `.env.example`/`.env.sample`/`.env.template` are skipped; lower entropy bar (2.5) because human passwords are low-entropy; secret references (Vault, ARNs, `ref+`) are excluded<br>*exclude* `(?i)[=:][ \t]{0,8}["']?(?:\$\{?\w\|\{\{\|<[^>]{1,60}>\|x{6,}\|\*{6,}\|change_?me\|(?:your\|example\|sample\|dummy)[-_])`<br>`(?i)[=:][ \t]{0,8}["']?(?:/\|\./\|~/\|file:\|vault:\|arn:aws:secretsmanager\|projects/[\w-]+/secrets/\|ref\+)` | Commit only `.env.example`; keep real values in a secret store, SOPS-encrypted files, or External Secrets |
| `WS-SEC-JWT-001` | JSON Web Token literal | medium | high | CWE-798 | A07 | any text | regex | **any** `\beyJ[A-Za-z0-9_\-]{10,4096}\.eyJ[A-Za-z0-9_\-]{10,8192}\.[A-Za-z0-9_\-]{0,4096}` | Header and payload are decoded offline (never verified or sent): `exp` in the past gives low; a public "anon" role claim gives low; `alg: none` is called out in the message | Remove the token, revoke the session/refresh token or rotate the signing key if it was long-lived |
| `WS-SEC-JWT-002` | Hard-coded JWT/session signing secret | high | medium | CWE-321 | A02, A07 | py, js, ts, go, any text | regex | **any** `(?<![A-Za-z0-9])jwt\.(?:encode\|decode\|sign\|verify)\([ \t]{0,8}[^,\n]{1,200},[ \t]{0,8}["']([^"'\n]{1,256})["']`<br>**any** `(?i)(?<![A-Za-z0-9])(?:jwt_?secret(?:_?key)?\|jwt_?signing_?key\|secret_?key\|signing_?key\|hmac_?secret\|session_?secret)\b["']?[ \t]{0,8}[:=][ \t]{0,8}["']([^"'\n]{8,256})["']` | Weak literals like `"secret"` are reported, not excluded (they are the bug); `django-insecure-` values are medium<br>*exclude* `["'](?:<[^>]{1,40}>\|\$\{\w+\}\|\{\{[^}]{0,80}\}\})["']` | Load the key from a secret store; prefer asymmetric signing (RS256/EdDSA) with key rotation via `kid` |
| `WS-SEC-K8S-001` | Kubernetes credentials committed (plain `Secret` manifest, kubeconfig with key/token) | high | high | CWE-312, CWE-798 | A07 | yaml (k8s, kubeconfig) | yaml_path | yaml_path any: (a) `kind` == `Secret` and (`data.*` matches `^[A-Za-z0-9+/]{4,}={0,2}$` or `stringData.*` non-empty); (b) `users[*].user.client-key-data` exists; (c) `users[*].user.token` matches `^[A-Za-z0-9._-]{20,}$` | Skipped when the document has a top-level `sops:` key or values start with `ENC[AES256_GCM,`; `SealedSecret`/`ExternalSecret` never match; `data` values decoded offline and passed through the placeholder filter; kubeconfig hits are critical | Use SOPS (age/KMS) with Flux decryption, Sealed Secrets, or External Secrets Operator; rotate every value that was committed |
| `WS-SEC-PK-001` | Private key block (PEM RSA/EC/DSA/OpenSSH/PKCS#8/PGP, PuTTY) | critical | high | CWE-321, CWE-798 | A07 | any text | regex + multiline | **any** `-{5}BEGIN[ A-Z0-9]{0,30}PRIVATE KEY(?: BLOCK)?-{5}\|\bPuTTY-User-Key-File-\d:\s` | The pattern starts with `-`: stored quoted in YAML, passed after `-e`/`--` to external tools, covered by `test_regressions.py`; `ENCRYPTED` in the header or `Proc-Type: 4,ENCRYPTED` within 2 lines gives medium; a placeholder body (`...`, `<key>`, fewer than 64 base64 chars in the next 3 lines) gives low | Treat as leaked: revoke/rotate (SSH authorized_keys, cert CA, exchange key), purge from history, load keys from a secret store or agent |
| `WS-SEC-PKG-001` | Package-registry credentials (npm/PyPI tokens, `.npmrc` `_authToken`, Docker `config.json` auth) | high | high | CWE-798 | A07 | any text, .npmrc, .docker/config.json | regex | **any** `\bnpm_[A-Za-z0-9]{36}(?![A-Za-z0-9])\|\bpypi-AgE(?:IcHlwaS5vcmc\|NdGVzdC5weXBpLm9yZw)[A-Za-z0-9_\-]{50,300}(?![A-Za-z0-9_\-])`<br>**any** `(?<=/):_authToken=([^\s$]{8,512})`<br>**any** `"auth"[ \t]{0,8}:[ \t]{0,8}"([A-Za-z0-9+/]{16,512}={0,2})"` | The `"auth"` pattern is restricted to `**/.docker/config.json` and `*.dockerconfigjson`; the npm token checksum is verified offline like GitHub's | Revoke on the registry, publish via trusted publishing (OIDC) and `docker login` with a credential helper |

---

## 4. Example rules with fixtures

The four rules below validate against the rule JSON Schema in engine.md §7.2 as written. Their
regexes are the same strings as in the tables; one source generates both and checks them against
the fixtures. Fixture conventions follow engine.md §3 (`rules test`):
- `# expect: <ID>` (or `//`, `--`, `<!--`) asserts a hit on that line.
- Positions that cannot carry a comment go in a sidecar `expect.json`.
- Every `pos*` file must hit exactly the expected lines, and every `neg*` file must produce zero
  hits.

### 4.1 `WS-INJ-001`: SQL built by string formatting (regex now, AST in P3)

```yaml
# rules/appsec/injection.yaml (excerpt)
- id: WS-INJ-001
  title: SQL built by string formatting (Python)
  pack: appsec/injection
  severity: high
  confidence: medium
  owner: "@whalesecurity/appsec"
  cwe: [CWE-89]
  owasp: [A03]
  tags: [sql]
  applies_to: { kind: code, lang: python }
  keywords: [execute, read_sql, "text(", "raw(", mogrify, exec_driver_sql]
  match:
    any:
      - all:
          - regex: |-
              \b(?:execute|executemany|executescript|mogrify|read_sql(?:_query)?|text|raw|exec_driver_sql)\(\s*(?:(?:[rR][fF]|[fF][rR]?)["']|["'][^"'\n]{0,300}["']\s*(?:%\s*[\w(]|\+\s*\w|\.format\())
          - regex: |-
              (?i)\b(?:select|insert|update|delete|merge|upsert|replace|truncate|drop|alter|with|call)\b
        near_lines: 0
      - py_ast:                                   # P3; same span as the regex hit, merged by dedupe (engine.md §9)
          call:
            callee: ["**.{execute,executemany,executescript,mogrify,exec_driver_sql,raw}",
                     "pandas.{read_sql,read_sql_query}", "sqlalchemy.text"]
            args: { "0": { dynamic_string: true } }
            sources: [web, airflow, llm, msg]     # a tainted hit is scored higher by severity.py (engine.md §10)
            sanitizers: [psycopg.sql.SQL, psycopg.sql.Identifier, sqlalchemy.bindparam]
  filters:
    line_not_regex: |-
      \bsql\.(?:SQL|Identifier|Literal)\(
  message: >-
    SQL text is assembled from runtime values, so a crafted value can change the query
    (read other accounts, cancel orders, drop tables).
  fix: >-
    Use driver placeholders (%s, :name) and pass values separately. Build identifiers with
    psycopg.sql.Identifier or pick them from an allowlist.
  references:
    - https://cwe.mitre.org/data/definitions/89.html
    - https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
  fixtures: auto
```

`tests/fixtures/WS-INJ-001/pos.py`

```python
# Fixture for WS-INJ-001. Attack-sample data, not production code.
import pandas as pd
from sqlalchemy import text


def open_orders(cur, client_id):
    cur.execute(f"SELECT * FROM orders WHERE client_id = '{client_id}' AND status = 'open'")  # expect: WS-INJ-001
    return cur.fetchall()


def fills_for(conn, sym):
    return pd.read_sql("SELECT * FROM fills WHERE sym = '%s'" % sym, conn)  # expect: WS-INJ-001


def cancel_position(conn, pid):
    conn.execute(text("DELETE FROM positions WHERE id = " + pid))  # expect: WS-INJ-001


def rebalance(cursor, bal, acct):
    cursor.execute("UPDATE accounts SET bal = {} WHERE id = {}".format(bal, acct))  # expect: WS-INJ-001
```

`tests/fixtures/WS-INJ-001/neg.py`

```python
# Fixture for WS-INJ-001: the safe equivalents must produce zero hits.
import pandas as pd
from psycopg import sql
from sqlalchemy import text


def open_orders(cur, client_id):
    cur.execute("SELECT * FROM orders WHERE client_id = %s AND status = 'open'", (client_id,))
    return cur.fetchall()


def fills_for(conn, sym):
    return pd.read_sql(text("SELECT * FROM fills WHERE sym = :sym"), conn, params={"sym": sym})


def table_count(cur, table):
    cur.execute(sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(table)))


def banner(st, name):
    st.text(f"Welcome back {name}")
```

### 4.2 `WS-CRY-005`: TLS verification disabled (one ID, five languages)

```yaml
# rules/appsec/crypto.yaml (excerpt)
- id: WS-CRY-005
  title: TLS certificate or hostname verification disabled
  pack: appsec/crypto
  severity: high
  confidence: high
  owner: "@whalesecurity/appsec"
  cwe: [CWE-295]
  owasp: [A02]
  applies_to:
    kind: [code, ci, iac, data]
    lang: [python, javascript, typescript, go, java, shell, dockerfile, yaml]
  match:
    any:
      - regex: |-   # python
          \bverify\s*=\s*False\b|\bverify_certs\s*=\s*False\b|\bssl\._create_unverified_context\(|\b(?:cert_reqs|verify_mode)\s*=\s*(?:ssl\.)?CERT_NONE\b|\bcheck_hostname\s*=\s*False\b|\bTCPConnector\([^)\n]{0,100}\bssl\s*=\s*False
      - regex: |-   # javascript/typescript, plus env/Dockerfile/manifests
          \brejectUnauthorized\s*:\s*false\b|\bNODE_TLS_REJECT_UNAUTHORIZED\b["'\]]{0,2}\s*[=:]\s*["']?0\b|\bstrictSSL\s*:\s*false\b
      - regex: |-   # go
          \bInsecureSkipVerify\s*:\s*true\b
      - regex: |-   # java
          \bALLOW_ALL_HOSTNAME_VERIFIER\b|\bNoopHostnameVerifier\b|\bsetHostnameVerifier\(\s*\(\s*\w*\s*,\s*\w*\s*\)\s*->\s*true|\bTrustAllStrategy\b|\bcheckServerTrusted\([^)\n]{0,200}\)\s*(?:throws\s+[\w.]+\s*)?\{\s*\}
      - regex: |-   # shell, Dockerfile, CI YAML
          \bcurl\b[^\n]{0,200}\s(?:-[a-zA-Z]{0,8}k[a-zA-Z]{0,8}|--insecure)\b|\bsslVerify\s*(?:=\s*)?false\b|\bGIT_SSL_NO_VERIFY\s*[=:]\s*["']?(?:1|true)
  filters:
    line_not_regex: |-
      (?<![A-Za-z0-9])jwt\.decode\(
  # proposed (§7): severity_overrides: [{when: {line_regex: '\b(?:localhost|127\.0\.0\.1|::1)\b'}, severity: low}]
  message: >-
    Certificate or hostname checks are off, so anyone on the network path can read or change
    this traffic (orders, credentials, model prompts).
  fix: >-
    Keep verification on and trust the private CA instead: verify="/etc/ssl/certs/corp-ca.pem",
    REQUESTS_CA_BUNDLE, or tls.Config{RootCAs: pool}.
  references:
    - https://cwe.mitre.org/data/definitions/295.html
  fixtures: auto        # pos.py, pos.go, neg.py, neg.go
```

`tests/fixtures/WS-CRY-005/pos.py`

```python
# Fixture for WS-CRY-005 (Python). Attack-sample data.
import ssl

import httpx
import requests


def submit(order, url):
    return requests.post(url, json=order, verify=False, timeout=5)  # expect: WS-CRY-005


def feed_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False  # expect: WS-CRY-005
    ctx.verify_mode = ssl.CERT_NONE  # expect: WS-CRY-005
    return ctx


client = httpx.Client(base_url="https://risk.internal", verify=False)  # expect: WS-CRY-005
```

`tests/fixtures/WS-CRY-005/pos.go`

```go
// Fixture for WS-CRY-005 (Go). Attack-sample data.
package feed

import (
	"crypto/tls"
	"net/http"
)

var client = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // expect: WS-CRY-005
	},
}
```

`tests/fixtures/WS-CRY-005/neg.py`

```python
# Fixture for WS-CRY-005: verification stays on with a private CA bundle.
import requests

CA_BUNDLE = "/etc/ssl/certs/corp-ca.pem"


def submit(order, url):
    return requests.post(url, json=order, verify=CA_BUNDLE, timeout=5)
```

`tests/fixtures/WS-CRY-005/neg.go`

```go
// Fixture for WS-CRY-005: a pinned root pool and TLS 1.2 floor.
package feed

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
)

func newClient(pool *x509.CertPool) *http.Client {
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
}
```

### 4.3 `WS-SEC-PK-001`: private key block (the dash-leading pattern)

This pattern starts with `-`, and that breaks three things if nobody handles it:
- A plain YAML scalar starting with `-` is read as a sequence item.
- `rg`/`grep` read `-----BEGIN` as a flag unless it comes after `-e`/`--`.
- An argv-based test harness does the same.

Three safeguards cover this. Patterns never go through argv. `rules explain --grep` emits
`-e PATTERN --`. `tests/test_regressions.py` runs this rule through the CLI and every adapter.
Here the pattern is a `|-` literal block, so its first character is data. Redaction keeps the
header line and hashes the body (engine.md §13).

```yaml
# rules/secrets/generic.yaml (excerpt)
- id: WS-SEC-PK-001
  title: Private key block (PEM, OpenSSH, PKCS#8, PGP, PuTTY)
  pack: secrets/generic
  severity: critical
  confidence: high
  owner: "@whalesecurity/secrets"
  cwe: [CWE-321, CWE-798]
  owasp: [A07]
  applies_to: { kind: [code, iac, ci, agent-config, doc, data] }
  keywords: ["PRIVATE KEY", "PuTTY-User-Key-File"]
  keywords_case: sensitive
  match:
    regex: |-
      -{5}BEGIN[ A-Z0-9]{0,30}PRIVATE KEY(?: BLOCK)?-{5}|\bPuTTY-User-Key-File-\d:\s
  # proposed (§7): validate: pem_body  -> confidence low on placeholder bodies; ENCRYPTED -> severity medium
  message: >-
    A private key is committed. Anyone with read access to the repo, its forks or CI caches can
    impersonate its owner.
  fix: >-
    Treat it as leaked. Revoke or rotate it (SSH authorized_keys, CA, exchange API key), purge it
    from git history, and load keys from a secret store or agent at runtime.
  references:
    - https://cwe.mitre.org/data/definitions/321.html
  fixtures: auto        # pos.py, pos.pem, pos.yml + expect.json; neg.pem, neg.md
```

`tests/fixtures/WS-SEC-PK-001/pos.py`

```python
# Fixture for WS-SEC-PK-001. Fake key material (random bytes, not a usable key).
GATEWAY_SIGNING_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAFLGCG6Xkx8RyOBJpCDVc010ReKJUKCuHO7HpIzwt\nxqMx1qwd0Ht4Q47+LCIgDRDTedjRdwbFbIInycmadP7CbQSyTQj9j40IpTozEOyC\n-----END RSA PRIVATE KEY-----\n"  # expect: WS-SEC-PK-001
```

`tests/fixtures/WS-SEC-PK-001/pos.pem`

```text
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
45lTl4y/xrLX2EhS2KNGNvadbQcV/5+ah7pT24IeWzXs444z998PU+hNxqkNZLRmtJsFR/
DF1LSj8L/NYgUIrh4mZ19ulp1k+ZCYl6SFbsgXFC3U5+rynly/+DmGuLWGW8n4BlTLU+sY
FZ6qMnGYmlQcey49SzObLl==
-----END OPENSSH PRIVATE KEY-----
```

`tests/fixtures/WS-SEC-PK-001/pos.yml`

```yaml
# Fixture for WS-SEC-PK-001 (fake key material).
signer_user: release
release_gpg_key: |
  -----BEGIN PGP PRIVATE KEY BLOCK-----

  lQOYBG4T9TCW31UevyCk/jV49w53WGHNmEo8ExZCSjqI4d7BI5PgD08N+xNZs64A
  v99CRM+9Jz5l5OX/vcH5gk+tSj3irONnPOoJEb9vYLFErQGnRR1Ei8lRerpqijZ+
  -----END PGP PRIVATE KEY BLOCK-----
```

`tests/fixtures/WS-SEC-PK-001/expect.json`

```json
{"pos.pem": {"WS-SEC-PK-001": [1]}, "pos.yml": {"WS-SEC-PK-001": [4]}}
```

`tests/fixtures/WS-SEC-PK-001/neg.pem`

```text
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAPfntymVutp/GVPkDs8NRwc+LKBgwxUEPzh9CoXfwifu=
-----END PUBLIC KEY-----
-----BEGIN CERTIFICATE-----
MIIBBM9sSdwDwlfjn9y0rMEmrnEvuLI1uTt5E/pZarYNtyk8+bQ5KnXqgCZztz2v
-----END CERTIFICATE-----
```

`tests/fixtures/WS-SEC-PK-001/neg.md`

```markdown
# Rotating the gateway signing key

Generate a new key with `ssh-keygen -t ed25519 -f gw_key`, store the private key in the
secret manager, and never paste the key block (the part that starts with five dashes and
the word BEGIN) into tickets or chat.
```

### 4.4 `WS-SEC-DB-002`: credentials in a connection URI

```yaml
# rules/secrets/generic.yaml (excerpt)
- id: WS-SEC-DB-002
  title: Credentials embedded in a connection URI
  pack: secrets/generic
  severity: high
  confidence: high
  owner: "@whalesecurity/secrets"
  cwe: [CWE-798]
  owasp: [A07]
  applies_to: { kind: [code, iac, ci, agent-config, doc, data] }
  keywords: ["://"]
  match:
    regex:
      pattern: |-
        \b(?:postgres(?:ql)?|mysql|mariadb|singlestoredb|memsql|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|clickhouse|cockroachdb|snowflake|oracle|https?|ftp|sftp|ssh)(?:\+[a-z0-9]+)?://(?P<user>[^\s:/@"'`<>]{0,128}):(?P<secret>[^\s@/"'`<>]{1,256})@[^\s"'`<>]{1,256}
      secret_group: secret                 # only the password is redacted; scheme, user and host stay readable
  filters:
    line_not_regex: |-
      ://[^\s:/@]{0,128}:(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\$\([A-Za-z_]+\)|\{\{[^}]{0,80}\}\}|<[^>]{1,40}>|%\([a-z_]+\)s|\*+|[xX]+|\d{1,5}|(?i:password|passw0rd|pass|changeme|secret|example|redacted))@
  supersedes: [WS-SEC-GEN-001, WS-SEC-GEN-002]
  message: >-
    Connection string for user {{user}} embeds a password. Airflow connections, Celery brokers
    and SQLAlchemy URLs get logged and echoed, so this spreads.
  fix: >-
    Build the DSN at runtime from a secret store (Secrets Manager, Secret Manager, Vault, or a
    k8s Secret via env) and rotate the database user's password.
  references:
    - https://cwe.mitre.org/data/definitions/798.html
  fixtures: auto
```

A `ghp_`/`glpat-`/`npm_` token in the userinfo is also hit by its vendor rule. Cross-rule dedupe
(engine.md §9) keeps the vendor finding and lists this one under `properties.related`.

`tests/fixtures/WS-SEC-DB-002/pos.env`

```dotenv
# Fixture for WS-SEC-DB-002 (fake credentials).
LEDGER_DB_URL=postgresql+asyncpg://ledger:SKMc9AB1fm1WC0qfZqkM@pg-primary.prod.internal:5432/ledger  # expect: WS-SEC-DB-002
TICKS_URL=singlestoredb://svc_ticks:WfT7FeP64dJdnOuZ7z@ss-agg.internal:3306/ticks  # expect: WS-SEC-DB-002
AIRFLOW_CONN_LEDGER_DB='postgresql://airflow_ro:tgxCoML9R3W53KEG@pg-replica.prod.internal:5432/ledger'  # expect: WS-SEC-DB-002
CELERY_BROKER_URL=amqps://orders:tVpIMbFzJr689IGS@mq.internal:5671/trading  # expect: WS-SEC-DB-002
REDIS_URL=rediss://:D7Dkfp114z0z1MWXh3oQ5uMx@cache.internal:6380/0  # expect: WS-SEC-DB-002
PIP_EXTRA_INDEX_URL=https://ci:rQs8K6zbvhRDclvjS9iYosPS@pypi.internal.example/simple  # expect: WS-SEC-DB-002
```

`tests/fixtures/WS-SEC-DB-002/neg.env`

```dotenv
# Fixture for WS-SEC-DB-002: references, placeholders and credential-free URIs.
LEDGER_DB_URL=postgresql+asyncpg://ledger:${LEDGER_DB_PASSWORD}@pg-primary.prod.internal:5432/ledger
TICKS_URL=singlestoredb://svc_ticks@ss-agg.internal:3306/ticks
LOCAL_DB_URL=postgresql://user:password@localhost:5432/dev
DOCS_EXAMPLE=mysql://<user>:<password>@<host>:3306/<db>
PIP_INDEX_URL=https://pypi.org/simple
HEALTHCHECK=http://localhost:8080/healthz
```

---

## 5. Secrets redaction and verification

### 5.1 Redaction (always on, cannot be disabled)

The format, the output sweep and the fingerprint inputs are defined once, in engine.md §13 and
§9. Examples: `AKIA…[sha256:1f3a9c0e]` for L ≥ 16, `…[REDACTED len=12]` below that, and a PEM
header with its body hashed. This pack adds these requirements:

| Requirement | Why |
|---|---|
| Every `WS-SEC-*` rule that captures a value names it `(?P<secret>…)` / `secret_group: secret`. Structured rules keep the rest readable, for example `postgresql+asyncpg://ledger:Qx7v…[sha256:3c1e09a7]@pg-primary.prod.internal:5432/ledger`. | Triage needs host and user, not the password. |
| Offline-validation results go into `properties` (`aws_account_id`, `jwt.{alg,exp,iss}`, `gcp_sa`, `verified`), never the value. | Useful context without the secret. |
| `scan_edit.py` / `scan_tool_output.py` put only rule ID, file:line, the redacted snippet and the fix into `additionalContext`. | The agent must not see the raw secret, because it could repeat it into a commit, a comment or a tool call. |
| `--debug` logs spans (`line:col-col`) for secrets-pack hits, never text. | Logs are outputs too. |
| `tests/test_redaction.py` runs every reporter and every hook on every `WS-SEC-*` fixture. It asserts that no substring of 8 or more characters of any raw fixture value appears. | The engine.md sweep catches whole values; this also catches partial leaks through truncation. |

### 5.2 Offline validation (default on, no network)

These checks only change `confidence`, and add non-secret metadata to
`properties`. They never contact a provider.

| Rule | Check (stdlib only) | Effect |
|---|---|---|
| WS-SEC-GH-001, WS-SEC-PKG-001 (`npm_`) | Base62 CRC32 checksum in the last 6 chars | pass: keep `high`; fail: `low` (docs, fakes) |
| WS-SEC-AWS-001 | Base32-decode the 16 chars after the prefix to get the account ID (newer key format) | `properties.aws_account_id` (not secret; helps triage) |
| WS-SEC-AGE-001 | Bech32 checksum | fail: `low` |
| WS-SEC-JWT-001 | Base64url + JSON decode of header and payload | `properties.jwt = {alg, exp, iss}`. An `exp` in the past or a public anon role gives `low`. `alg: none` is flagged in the message. |
| WS-SEC-PK-001 | Body is base64 and at least 64 chars; DER begins `0x30`, or the OpenSSH body begins `openssh-key-v1\0` | fail: `low` (placeholder / truncated) |
| WS-SEC-GCP-001 | JSON parse; `private_key_id` is 40 hex; `client_email` ends `.iam.gserviceaccount.com` | `properties.gcp_sa = client_email` |
| WS-SEC-STR-001, WS-SEC-TRD-004 | `live`/`test`, `AK`/`PK` | severity override (§3.5, §3.6) |
| entropy rules | Shannon entropy, char classes | gate, not metadata |

### 5.3 Live verification (off by default, opt-in, never for money-moving keys)

whalescan does **not** check keys against providers by default: not in hooks, not in CI and not
in `/whale-audit`. A report that says "valid key" is not worth the side effects: account lockouts,
exchange IP bans, security alerts at the provider, and one more copy of the secret sent over the
network.

The opt-in is explicit and narrow:

```toml
# .whalesecurity/config.toml
[secrets.verify]
enabled   = false                 # default; must be true AND the CLI flag below must be passed
providers = ["github", "aws"]     # explicit allowlist, nothing is implied
timeout_s = 5
# Invocation: whalescan secrets --verify <path>   (hooks and the GitHub Action ignore this section)
```

| Provider | Call (read-only identity endpoint only) |
|---|---|
| AWS (needs both key ID and secret) | `sts:GetCallerIdentity` (SigV4) |
| GitHub | `GET https://api.github.com/rate_limit` |
| GitLab | `GET /api/v4/personal_access_tokens/self` |
| Slack | `auth.test` |
| Hugging Face | `GET https://huggingface.co/api/whoami-v2` |
| OpenAI / Anthropic | `GET /v1/models` |

**Hard-coded never-verify list** (config cannot override it):
- Anything that can move money or place orders: Stripe, Binance, Coinbase, Kraken, Alpaca,
  Interactive Brokers, ccxt configs, and market-data keys with trading entitlements (Polygon).
  Exchanges ban IPs on bad signatures, and IBKR locks accounts after failed logins.
- Anything that means connecting to the owner's infrastructure: DB URIs, JDBC/DSN passwords,
  private keys, kubeconfigs, age keys.
- Generic/entropy hits, where the provider is unknown.

The verifier makes no retries and at most 1 request/s per provider, uses the configured HTTPS
proxy, and appends `{rule, provider, fingerprint, status}` (no value) to
`.whalesecurity/verify.log`. `properties.verified` is `true | false | error`. **`false` never lowers
severity**, because an IP-restricted or region-scoped key can fail from the scanner host and still
work from production.

The auditor agents never verify on their own. `guard_bash.py` runs the secrets pack over every
Bash command string and **denies** any command that contains a `WS-SEC-*` match, for example
`curl -H "Authorization: Bearer ghp_…"`. It returns the redacted form in the denial reason.

---

## 6. Quality gates specific to these packs

- **Contract** (`test_rules.py`): all 81 rules have fixtures. Multi-language rules need at least
  one `pos.*` per `lang` sub-matcher. `WS-SEC-K8S-001` uses `pos.yaml` (plain `Secret` +
  kubeconfig) and `neg.yaml` (SOPS-encrypted `Secret` + `SealedSecret`).
- **ReDoS** (`test_redos.py`): the adversarial set is 100 KB each of repeated
  `a`, space, `(`, `"`, `'`, `` `${ ``, `x=`, `{`, `-`, `A`, `0`, `(a+`, `log(`, `a:`, `a@`, `//`,
  `(+++…)`, `sk-aaa…`, `eyJaaa…` and `secret=aaa…`. Each rule's own positive samples are also
  repeated, whole and truncated at 2/3. Budget: 50 ms per regex; the catalog's current maximum is
  about 36 ms (WS-ACC-005).
- **Fixture hygiene**: vendor-format fixture values are random and fail provider checksums where
  a checksum exists. `tests/fixtures/**` is listed in `.whalescanignore` and in
  `.github/secret_scanning.yml` (`paths-ignore`). Each fixture header says "fake".
- **Eval targets** (DESIGN.md §9): secrets precision ≥ 0.97 on the clean corpus (vendor rules
  ≥ 0.99); appsec per-rule precision ≥ 0.80 before the verifier and ≥ 0.95 after it. Rules below
  target ship `confidence: low` until fixed.
- **Rule review**: every vendor-format rule (key prefixes and lengths change) is re-checked each
  quarter against the provider docs. `WS-SEC-AWS-003` and `WS-SEC-VDB-001` are flagged
  `review: quarterly-format` because their formats are the newest.

---

## 7. Refinements to DESIGN.md

These refine DESIGN.md. Items marked *proposed* would also be small additive changes to the rule
schema in engine.md §7.2. Every other part of this catalog uses the schema as it is.

1. **ID shape.**
   - Secrets use a sub-namespace, `WS-SEC-<VENDOR>-NNN`, as in DESIGN.md §8's `WS-SEC-AWS-001`.
     Exchange and broker credentials share `WS-SEC-TRD-NNN` so trading dashboards can filter one
     family.
   - appsec IDs are `WS-<NS>-NNN`. Path traversal, mass assignment and SQL privileges sit in
     `WS-ACC`; XXE sits in `WS-DES`; JWT and TLS sit in `WS-CRY`.
   - The IDs used as examples in engine.md (`WS-INJ-003` shell injection, `WS-SEC-DB-002` DB URL,
     `WS-SEC-TRD-001` exchange secret, `WS-SEC-GEN-001` entropy) mean the same rules here.
2. **New pack file.** Add `rules/secrets/saas.yaml` (Slack, Twilio, SendGrid, Telegram), which is
   not in the DESIGN.md §3 tree.
3. **Pack boundaries.**
   - `yaml.load` lives in WS-DES-002; the FastAPI/Python domain pack references it and does not
     duplicate it.
   - FastAPI `CORSMiddleware`/`debug=True` stay in WS-API.
   - `spark.sql(f"...")` stays in WS-SPK.
   - Committed `*.tfstate` belongs to WS-TF.
   - Withdrawal/IP-scope checks on exchange keys belong to WS-TRD (domain).
4. **Severity policy for secrets** (§3.1) is by blast radius, not by vendor.
5. **Proposed: per-child `lang`** on `regex`/`multiline` children, so multi-language rules
   (WS-CRY-005, WS-WEB-008) do not run Python patterns on Go files. Today the patterns are
   written so that cross-language hits are practically impossible.
6. **Proposed: `near_scope: call | sql_statement`** next to `near_lines`. It would be used by
   WS-CRY-007, WS-WEB-004, WS-WEB-009 and WS-ACC-006, which use `near_lines` for now.
7. **Proposed: `severity_overrides`** (`when: {value_regex | line_regex | path_glob}` →
   `severity`/`confidence`) for value-dependent cases:
   - `sk_test_`
   - `ASIA…`
   - Alpaca `PK…`
   - encrypted PEM
   - stock local DB passwords
   - Firebase web keys

   Until then these adjustments live in `secrets/validators.py`, keyed by rule ID.
8. **Proposed: offline validators** (§5.2) registered by rule ID in `secrets/validators.py`. They
   are stdlib-only, they never make network calls, and they write only to `properties` and
   `confidence`.
9. **Redaction.** Also omit the hash when the value's entropy is below 3.0 bits/char, even at
   L ≥ 16, because long human passwords can still be matched against a dictionary. This extends
   engine.md §13.
10. **Fixtures.** `expect.json` may annotate any fixture file whose hit line cannot hold a comment
    (PEM bodies, YAML block scalars), not only JSON. Multi-language rules ship one `pos*`/`neg*`
    per targeted language.
11. **Live verification** is opt-in, CLI-only and has a hard-coded never-verify list (§5.3). Add
    a `[secrets.verify]` section to the `.whalesecurity/config.toml` reference.
