---
name: breach-code-recon
description: "Map the attack surface of a codebase for security review. Use when the user wants to start a security audit, perform source code reconnaissance, enumerate entry points and routes, fingerprint the technology stack, map trust boundaries, inventory authentication and authorization mechanisms, trace data flows, audit secrets and configuration, analyze git history for security-relevant changes, build a threat model for the target application, or scope an engagement before vulnerability hunting. This is the first stage of the breach pipeline."
---

# Code Recon: Attack Surface Mapping

Perform the reconnaissance phase of a security code review. Produce a complete attack surface map of the target codebase before any vulnerability hunting begins. This is systematic enumeration — not a vulnerability scan. Catalog what exists, where trust changes, and where the most promising attack vectors lie.

Execute all eight phases below. Adapt scope to the codebase size but never skip the output format.

## When to Use

- Starting a new security audit or code review engagement
- Scoping a bug bounty target before hunting
- Building an attack surface map for a codebase you haven't reviewed before
- First stage of the `/breach:hunt` pipeline

## When NOT to Use

- The codebase has already been reconned and the attack surface map is current
- You need to analyze a specific vulnerability (use `/breach:code-analysis`)
- You need to validate a known finding (use `/breach:validate-finding`)
- You are reviewing infrastructure, cloud configs, or network assets (this skill is source code focused)

---

## Phase 0: Application Context & Threat Model

Before examining code, establish the application's business context. This frames every subsequent phase — what matters to an attacker depends on what the application does and what data it holds.

1. **Application purpose**: Determine the business function from README, docs, config, and code structure. What problem does this application solve? Who are its users?
2. **Data sensitivity classification**: Identify data types the application handles — PII, financial data, health records, credentials, session tokens, business-critical data. Classify each by sensitivity (public, internal, confidential, restricted).
3. **Attacker profiles**: Determine relevant threat actors:
   - External unauthenticated (internet-facing attack surface)
   - Authenticated user (privilege escalation, IDOR, horizontal access)
   - Insider / privileged user (admin abuse, data exfiltration)
   - Automated / bot (credential stuffing, scraping, API abuse)
4. **Attack motivation mapping**: For each sensitive data type and privileged function, identify what an attacker gains from compromise — financial theft, identity theft, lateral movement, service disruption, data ransom.
5. **Likely attack scenarios**: Based on application type, list the 3-5 most probable attack scenarios. An e-commerce app faces payment manipulation and account takeover; an API gateway faces auth bypass and SSRF; a CMS faces stored XSS and privilege escalation.

Record findings as a concise threat model summary.

---

## Phase 1: Technology Fingerprinting

Identify the full technology stack. Every framework version, dependency, and build tool constrains the vulnerability classes to hunt later.

1. **Language and runtime**: Check file extensions, shebang lines, package manifests (`package.json`, `requirements.txt`, `Gemfile`, `pom.xml`, `go.mod`, `Cargo.toml`, `*.csproj`). Note pinned language versions.
2. **Framework identification**: Look for framework-specific directory structures, configuration files, and import patterns. Identify primary web framework, secondary frameworks (admin panels, API layers, job processors), and versions.
3. **Dependency audit**: Parse dependency manifests. Flag dependencies with known CVE history — particularly serialization libraries, template engines, XML parsers, image processors, and cryptographic libraries. Note non-standard registries or ancient pinned versions.
4. **Build system and toolchain**: Identify build tools, CI/CD configs (`.github/workflows/`, `Jenkinsfile`, `.gitlab-ci.yml`), Dockerfiles, and infrastructure-as-code templates. These reveal deployment context and supply chain vectors.
5. **ORM and data layer**: Identify ORM or database driver. Note raw query capabilities alongside ORM. Check for caching layers (Redis, Memcached), message brokers (RabbitMQ, Kafka), and search engines (Elasticsearch).
6. **Templating and serialization**: Identify template engine and autoescape configuration. Catalog all serialization/deserialization paths — JSON, XML, YAML, Protocol Buffers, MessagePack, pickle, Marshal.

Record findings as a concise technology stack summary.

---

## Phase 2: Entry Point Enumeration

Enumerate every path by which external input reaches the application. Miss an entry point, miss a vulnerability.

1. **HTTP routes**: Grep for framework-specific route definitions (`@app.route`, `router.get/post`, `@RequestMapping`, `urlpatterns`, `Route::`, `pages/api/`). For each: HTTP method, URL path (note path parameters), handler function, middleware chain.
2. **GraphQL endpoints**: Search for schema definitions (`.graphql` files, type definitions in code). Map queries, mutations, subscriptions. Note sensitive operations. Check introspection in production config.
3. **WebSocket handlers**: Find WebSocket upgrade paths and message handlers. These frequently lack HTTP route auth middleware.
4. **CLI entry points**: Check for argument parsing (`argparse`, `commander`, `cobra`, `clap`). CLI tools accepting file paths, URLs, or format strings are injection vectors in server contexts.
5. **Message queue consumers**: Find queue subscription handlers (Celery tasks, SQS consumers, Kafka consumers, Bull jobs). These process data with implicit trust — often deserializing without validation.
6. **Cron jobs and scheduled tasks**: Identify periodic tasks. Check for elevated privileges or processing of accumulated external data.
7. **File watchers and upload handlers**: Find upload endpoints, file processing pipelines, filesystem watchers. Note accepted MIME types, size limits, storage destinations.
8. **Hidden/debug/admin endpoints**: Search for routes containing `debug`, `admin`, `internal`, `health`, `metrics`, `swagger`, `graphiql`, `__`, `test`, `dev`. Check conditional exclusion from production.

Produce an entry points table: endpoint, method, handler, auth status, input types, risk tier (Critical/High/Medium/Low).

---

## Phase 3: Trust Boundary Mapping

Identify every point where trust level of data or execution context changes. Vulnerabilities cluster at trust boundaries.

1. **External to application**: All entry points from Phase 2. Note which perform input validation at boundary vs deeper in call chain.
2. **Application to database**: All query construction points. Distinguish parameterized queries from string concatenation/interpolation. Note ORM methods accepting raw SQL fragments.
3. **Application to external services**: Outbound HTTP requests, SMTP, DNS lookups, LDAP queries, cloud SDK calls. User-controlled data flowing here is potential SSRF, injection, or exfiltration.
4. **Service to service**: In microservice architectures, identify inter-service communication. Check whether internal APIs enforce authentication or rely on network trust. Note shared secrets, service meshes, mTLS.
5. **Privilege transitions**: Map execution context changes — `sudo`, `setuid`, `runas`, role assumption (AWS STS), DB connection switching, impersonation tokens. Identify where user input can influence privilege context.
6. **Authenticated to unauthenticated boundaries**: Determine exactly which routes and resources are accessible without authentication. Cross-reference with Phase 2 auth status.

Produce a text-based trust boundary diagram showing major zones and transitions, annotated with validation status.

---

## Phase 4: Auth/AuthZ Inventory

Catalog the authentication and authorization architecture completely. Auth gaps are the highest-impact findings in most audits.

1. **Authentication mechanisms**: Identify all authn methods — session cookies, JWTs, API keys, OAuth/OIDC, mTLS, basic auth, SAML. For each: token issuance, validation, secret storage, expiration/rotation.
2. **Session management**: Session storage (server-side vs client-side), session ID entropy, cookie flags (HttpOnly, Secure, SameSite), fixation protections, concurrent session handling, logout/invalidation.
3. **Authorization enforcement points**: Map every authz check — middleware, decorators, guards, policy objects, RBAC/ABAC. Note the pattern: deny-by-default with explicit allows, or allow-by-default with explicit denies.
4. **Role and permission model**: Identify roles, permissions, and mappings. Check for horizontal privilege escalation — can user A access user B's resources by manipulating IDs or parameters.
5. **Auth gaps and inconsistencies**: Cross-reference entry points with authorization enforcement. Flag endpoints lacking auth that access sensitive data or perform state changes. Flag endpoints with weaker auth than peers. Check for bypass via method override, path traversal, or parameter manipulation.
6. **Token and credential handling**: Check auth token flow. Look for tokens logged, cached insecurely, passed via query string, or exposed in error messages.

---

## Phase 5: Data Flow Tracing Setup

Map how untrusted data moves from ingress to sensitive operations. This sets up tracing context for the hunt phase.

1. **Input parsing layers**: All input parsing — body parsers (JSON, XML, multipart, URL-encoded), query string parsers, header extraction, cookie parsing, file upload handling. Note configuration: size limits, depth limits, prototype pollution protections.
2. **Validation and sanitization**: Find validation layers — schema validation (Joi, Zod, Pydantic, Bean Validation), regex checks, type coercion, HTML sanitization. Map which inputs pass through validation and which bypass it. Note validation that happens after data use.
3. **Critical sinks**: Identify all security-sensitive operation locations:
   - **SQL/NoSQL queries**: Database query construction
   - **Template rendering**: Dynamic template compilation with user data
   - **File operations**: File path construction, read/write
   - **Command execution**: System calls, shell invocations, subprocess creation
   - **Outbound requests**: URL construction for HTTP requests, DNS lookups
   - **Deserialization**: Unmarshaling user-supplied data into objects
   - **Logging**: Sensitive data flowing into log outputs
4. **Transformation chain**: For each critical sink, trace backward through transformations between input and sink. Note where encoding, escaping, or sanitization is applied — and where it is not.

---

## Phase 6: Secrets & Configuration Audit

Search for exposed secrets and security misconfigurations. Often the fastest path to a critical finding.

1. **Hardcoded credentials**: Search for patterns matching API keys, passwords, tokens, connection strings, private keys in source code. Check literals, constants, config files, test fixtures, seed data, comments. Use regex: `(?i)(password|secret|token|api_key|apikey|auth|credential|private_key)\s*[=:]\s*['\"][^'\"]+['\"]`.
2. **Environment variable patterns**: Identify configuration loading. Check `.env`, `.env.example`, `docker-compose.yml`, CI/CD configs, Kubernetes manifests. Verify `.env` is in `.gitignore`.
3. **Security headers and policies**: Check CORS (overly permissive origins, credentials with wildcard), CSP, HSTS, X-Frame-Options, X-Content-Type-Options. Flag missing security headers.
4. **Cryptographic configuration**: Identify encryption algorithms, key sizes, hash functions, RNGs. Flag weak algorithms (MD5, SHA1 for security, DES, RC4), insufficient key sizes, non-CSPRNG for security purposes.
5. **Debug and development exposure**: Check for debug modes in production config, verbose errors, stack trace exposure, dev tools accessible in production.

---

## Phase 7: Git History Analysis

Analyze version control history for security-relevant signals. Git history reveals patching patterns, hot files, and secrets that static analysis of HEAD misses.

If git history is unavailable (e.g., shallow clone, no `.git` directory), note this limitation and skip to output.

1. **Recent security-relevant commits**: Search commit messages for keywords: `fix`, `vuln`, `CVE`, `security`, `patch`, `auth`, `sanitize`, `escape`, `inject`, `XSS`, `CSRF`, `SSRF`. Review the diffs of matching commits — these reveal what the developers considered security-sensitive and how they addressed it.
2. **Hot files**: Identify the most frequently changed security-critical files (auth modules, input handlers, query construction, session management). Files with high churn in security-critical areas are more likely to contain regressions or incomplete fixes.
3. **Blame analysis**: On critical files identified in earlier phases (auth, input validation, query builders), run blame to identify multiple authors and recent changes. Code written by many authors with frequent recent edits has higher defect probability.
4. **Reverted or re-fixed security patches**: Look for commits that revert security fixes, or multiple fix attempts for the same issue. These indicate incomplete remediations — the original vulnerability may still be partially exploitable.
5. **Secrets in history**: Search for `.env` files, key files, and credential patterns in older commits that were later removed. Secrets persist in git history even after deletion from HEAD.
6. **Recently introduced entry points**: Identify new routes, endpoints, or trust boundary changes in recent commits. New code has higher defect rates and may lack the security review applied to older code.

---

## Output Format

Produce the attack surface map in one of two modes:

### Executive Brief (quick scan)

Use when the user requests a quick scan, summary, or time-constrained overview. Approximately one page:

1. **Threat Model Summary**: Application purpose, data sensitivity, top attacker profiles (2-3 sentences)
2. **Technology Stack**: Concise table (component, technology, version, notes)
3. **Top Attack Vectors** (5-10): Ranked list with target, why it is promising, suggested vulnerability class, risk tier
4. **Critical Auth Gaps**: Bulleted list of the most significant authentication/authorization issues
5. **Start Hunting Here**: Prioritized shortlist of the 3-5 highest-value targets for immediate investigation

### Full Attack Surface Map (deep scan — DEFAULT)

Use by default for all scans unless the user explicitly requests a quick/brief scan.

#### Threat Model
Application context, data classification, attacker profiles, attack motivation mapping, and likely scenarios from Phase 0.

#### Technology Stack Summary
Table: component, technology, version (if known), security-relevant notes.

#### Entry Points Table

| Endpoint | Method | Handler | Auth | Input Types | Risk Tier |
|----------|--------|---------|------|-------------|-----------|

#### Trust Boundary Diagram
Text-based diagram showing major zones (External, Application, Database, External Services) and transitions, annotated with validation status.

#### Auth Gaps
Bulleted list of authentication and authorization inconsistencies, missing protections, and privilege escalation vectors.

#### Data Flow Summary
For each critical sink category, list input sources that reach it and validation/sanitization applied (or missing) en route.

#### Secrets and Configuration Findings
Bulleted list of exposed secrets, misconfigurations, or missing security controls.

#### Git History Insights
Security-relevant commits, hot files, reverted patches, secrets in history, and recently introduced attack surface.

#### Prioritized Hunt Targets
Ranked list of the most promising attack vectors, informed by threat model and all phases:
- Target description
- Why it is promising (e.g., "user input reaches SQL sink without parameterization")
- Suggested vulnerability class
- Risk estimate (Critical/High/Medium/Low)

---

## Fallback: Small Codebases

If the target is a single file or very small codebase (fewer than ~10 files), collapse the procedure proportionally. Skip phases that produce no findings (e.g., message queues in a single-file script) but always produce the output format with applicable sections filled and inapplicable sections marked "N/A — not applicable at this codebase scale."

---

## Next Step

Run `/breach:hunt` to begin systematic vulnerability hunting against the identified attack surface, or run `/breach:code-recon` again on a different scope to map additional targets.
