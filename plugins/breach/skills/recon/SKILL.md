---
description: "Map the attack surface of a codebase for security review. This skill should be used when the user wants to start a security audit, perform reconnaissance on a codebase, enumerate entry points and routes, fingerprint the technology stack, map trust boundaries, inventory authentication and authorization mechanisms, trace data flows, audit secrets and configuration, or scope an engagement before vulnerability hunting. This is the first stage of the breach pipeline."
---

# Recon: Attack Surface Mapping

You are performing the reconnaissance phase of a security code review. Your objective is to produce a complete attack surface map of the target codebase before any vulnerability hunting begins. This is a systematic enumeration — not a vulnerability scan. You are cataloging what exists, where trust changes, and where the most promising attack vectors lie.

Execute all seven steps below. Adapt scope to the codebase size but never skip the output format.

---

## Step 1: Technology Fingerprinting

Identify the full technology stack before anything else. Every framework version, every dependency, every build tool choice constrains the vulnerability classes you will hunt later.

1. **Language and runtime**: Check file extensions, shebang lines, `package.json`, `requirements.txt`, `Gemfile`, `pom.xml`, `go.mod`, `Cargo.toml`, `*.csproj`, or equivalent manifests. Note the language version if pinned.
2. **Framework identification**: Look for framework-specific directory structures, configuration files, and import patterns. Identify the primary web framework, any secondary frameworks (admin panels, API layers, background job processors), and their versions.
3. **Dependency audit**: Parse the dependency manifest. Flag dependencies with known CVE history — particularly serialization libraries (Jackson, pickle, Marshal, YAML), template engines, XML parsers, image processors, and cryptographic libraries. Note any dependencies pulled from non-standard registries or pinned to ancient versions.
4. **Build system and toolchain**: Identify build tools (webpack, esbuild, Maven, Gradle, Make), CI/CD configuration files (`.github/workflows/`, `Jenkinsfile`, `.gitlab-ci.yml`), Dockerfiles, and infrastructure-as-code templates. These reveal deployment context and potential supply chain vectors.
5. **ORM and data layer**: Identify the ORM or database driver in use. Note whether raw query capabilities are exposed alongside the ORM. Check for caching layers (Redis, Memcached), message brokers (RabbitMQ, Kafka), and search engines (Elasticsearch).
6. **Templating and serialization**: Identify the template engine and its autoescape configuration. Catalog all serialization/deserialization paths — JSON, XML, YAML, Protocol Buffers, MessagePack, pickle, Marshal.

Record findings as a concise technology stack summary.

---

## Step 2: Entry Point Enumeration

Enumerate every path by which external input reaches the application. Miss an entry point, miss a vulnerability.

1. **HTTP routes**: Grep for framework-specific route definitions — `@app.route`, `router.get/post`, `@RequestMapping`, `urlpatterns`, `Route::`, `pages/api/`, etc. For each route: extract the HTTP method, URL path (note path parameters), handler function reference, and any middleware chain applied.
2. **GraphQL endpoints**: Search for schema definitions (`.graphql` files, type definitions in code). Map queries, mutations, and subscriptions. Note which resolve to sensitive operations. Check for introspection enabled in production configuration.
3. **WebSocket handlers**: Find WebSocket upgrade paths and message handlers. These frequently lack the auth middleware applied to HTTP routes.
4. **CLI entry points**: Check for argument parsing (`argparse`, `commander`, `cobra`, `clap`). CLI tools that accept file paths, URLs, or format strings are injection vectors when exposed in server contexts.
5. **Message queue consumers**: Find queue subscription handlers (Celery tasks, SQS consumers, Kafka consumers, Bull jobs). These process data from internal services but often with implicit trust — deserializing without validation.
6. **Cron jobs and scheduled tasks**: Identify periodic tasks. Check whether they operate with elevated privileges or process external data that has accumulated since last run.
7. **File watchers and upload handlers**: Find file upload endpoints, file processing pipelines, and filesystem watchers. Note accepted MIME types, size limits, and storage destinations.
8. **Hidden/debug/admin endpoints**: Search for routes containing `debug`, `admin`, `internal`, `health`, `metrics`, `swagger`, `graphiql`, `__`, `test`, `dev`. Check whether these are conditionally excluded from production builds.

Produce an entry points table with columns: endpoint, method, handler, auth status, input types, risk tier (Critical/High/Medium/Low based on exposure and privilege).

---

## Step 3: Trust Boundary Mapping

Identify every point where the trust level of data or execution context changes. Vulnerabilities cluster at trust boundaries.

1. **External to application**: All entry points from Step 2 are external trust boundaries. Note which perform input validation at the boundary versus deeper in the call chain.
2. **Application to database**: Find all database query construction points. Distinguish parameterized queries from string concatenation or interpolation. Note ORM methods that accept raw SQL fragments.
3. **Application to external services**: Find outbound HTTP requests, SMTP calls, DNS lookups, LDAP queries, and cloud SDK invocations. Any user-controlled data flowing into these is a potential SSRF, injection, or data exfiltration vector.
4. **Service to service**: In microservice architectures, identify inter-service communication. Check whether internal APIs enforce authentication or rely on network-level trust. Note shared secrets, service meshes, or mTLS configurations.
5. **Privilege transitions**: Map where execution context changes privilege level — `sudo`, `setuid`, `runas`, role assumption (AWS STS), database connection switching, or impersonation tokens. Identify where user input can influence which privilege context is selected.
6. **Authenticated to unauthenticated boundaries**: Determine exactly which routes and resources are accessible without authentication. Cross-reference with Step 2's auth status column.

Produce a text-based trust boundary diagram showing the major zones and the transitions between them.

---

## Step 4: Auth/AuthZ Inventory

Catalog the authentication and authorization architecture completely. Auth gaps are the highest-impact findings in most audits.

1. **Authentication mechanisms**: Identify all authn methods — session cookies, JWTs, API keys, OAuth/OIDC flows, mTLS, basic auth, SAML. For each: where tokens are issued, how they are validated, where secrets/keys are stored, expiration/rotation policies.
2. **Session management**: Check session storage (server-side vs client-side), session ID entropy, cookie flags (HttpOnly, Secure, SameSite), session fixation protections, concurrent session handling, and logout/invalidation implementation.
3. **Authorization enforcement points**: Map every authorization check — middleware, decorators, guards, policy objects, RBAC/ABAC checks. Note the enforcement pattern: is it deny-by-default with explicit allows, or allow-by-default with explicit denies?
4. **Role and permission model**: Identify defined roles, permissions, and the mapping between them. Check for horizontal privilege escalation vectors — can user A access user B's resources by manipulating IDs or parameters?
5. **Auth gaps and inconsistencies**: Cross-reference the entry points table with authorization enforcement. Flag any endpoint that lacks auth but accesses sensitive data or performs state-changing operations. Flag endpoints with weaker auth than their peers in the same functional group. Check for auth bypass via HTTP method override, path traversal, or parameter manipulation.
6. **Token and credential handling**: Check how auth tokens flow through the system. Look for tokens logged, cached insecurely, passed via query string, or exposed in error messages.

---

## Step 5: Data Flow Tracing Setup

Map how untrusted data moves through the application from ingress to sensitive operations. This step sets up the tracing context for the hunt phase.

1. **Input parsing layers**: Identify all input parsing — body parsers (JSON, XML, multipart, URL-encoded), query string parsers, header extraction, cookie parsing, file upload handling. Note parser configuration: size limits, depth limits, prototype pollution protections.
2. **Validation and sanitization**: Find validation layers — schema validation (Joi, Zod, Pydantic, Bean Validation), manual regex checks, type coercion, HTML sanitization libraries. Map which inputs pass through validation and which bypass it. Note any validation that happens after the data has already been used.
3. **Critical sinks**: Identify all locations where data reaches a security-sensitive operation:
   - **SQL/NoSQL queries**: Database query construction points
   - **Template rendering**: Dynamic template compilation or rendering with user data
   - **File operations**: File path construction, file read/write operations
   - **Command execution**: System calls, shell invocations, subprocess creation
   - **Outbound requests**: URL construction for HTTP requests, DNS lookups
   - **Deserialization**: Unmarshaling of user-supplied data into objects
   - **Logging**: Sensitive data flowing into log outputs (log injection, data leaks)
4. **Transformation chain**: For each critical sink, trace backward to identify the transformations data undergoes between input and sink. Note where encoding, escaping, or sanitization is applied — and where it is not.

---

## Step 6: Secrets and Configuration Audit

Search for exposed secrets and security-relevant misconfigurations. These are often the fastest path to a critical finding.

1. **Hardcoded credentials**: Search for patterns matching API keys, passwords, tokens, connection strings, and private keys in source code. Check string literals, constants, configuration files, test fixtures, seed data, comments, and documentation. Use regex patterns: `(?i)(password|secret|token|api_key|apikey|auth|credential|private_key)\s*[=:]\s*['\"][^'\"]+['\"]`.
2. **Environment variable patterns**: Identify how the application loads configuration. Check `.env` files, `.env.example`, `docker-compose.yml`, CI/CD configs, and Kubernetes manifests for secrets passed as environment variables. Verify `.env` is in `.gitignore`.
3. **Version control leaks**: Check git history for secrets that were committed and later removed — they persist in history. Look for `.env` files, key files, and credential dumps in older commits if git history is available.
4. **Security headers and policies**: Check for CORS configuration (overly permissive origins, credentials with wildcard), CSP headers, HSTS, X-Frame-Options, X-Content-Type-Options. Check for missing security headers entirely.
5. **Cryptographic configuration**: Identify encryption algorithms, key sizes, hash functions, and random number generators in use. Flag weak algorithms (MD5, SHA1 for security purposes, DES, RC4), insufficient key sizes, and use of `Math.random()` or equivalent non-CSPRNG for security purposes.
6. **Debug and development exposure**: Check for debug modes enabled in production configuration, verbose error messages, stack trace exposure, development tools (debuggers, profilers, admin panels) accessible in production.

---

## Step 7: Framework-Specific Surface

Reference `framework-patterns.md` for the detected framework. Apply the framework-specific checklist to identify configuration weaknesses and anti-patterns that are unique to the technology stack identified in Step 1.

1. Load the patterns for the primary framework from the reference document.
2. Check each critical setting against the codebase configuration.
3. Verify framework-specific security defaults have not been weakened or disabled.
4. Note any framework-specific injection vectors relevant to the identified entry points.
5. Cross-reference framework auth patterns with the auth inventory from Step 4.

---

## Output Format

Produce the attack surface map as a single structured document with these sections:

### Technology Stack Summary
Concise table: component, technology, version (if known), security-relevant notes.

### Entry Points Table

| Endpoint | Method | Handler | Auth | Input Types | Risk Tier |
|----------|--------|---------|------|-------------|-----------|
| (populated from Step 2) | | | | | |

### Trust Boundary Diagram
Text-based diagram showing major zones (External, Application, Database, External Services) and the transitions between them, annotated with validation status.

### Auth Gaps
Bulleted list of identified authentication and authorization inconsistencies, missing protections, and privilege escalation vectors.

### Data Flow Summary
For each critical sink category, list the input sources that reach it and the validation/sanitization applied (or missing) en route.

### Secrets and Configuration Findings
Bulleted list of any exposed secrets, misconfigurations, or missing security controls.

### Prioritized Hunt Targets
Ranked list of the most promising attack vectors identified during recon, with:
- Target description
- Why it is promising (e.g., "user input reaches SQL sink without parameterization")
- Suggested vulnerability class to hunt
- Risk estimate (Critical/High/Medium/Low)

---

## Fallback: Small Codebases

If the target is a single file or a very small codebase (fewer than ~10 files), collapse the procedure proportionally. Skip steps that produce no findings (e.g., message queues in a single-file script) but always produce the output format with applicable sections filled and inapplicable sections marked "N/A — not applicable at this codebase scale."

---

## Next Step

Run `/breach:hunt` to begin systematic vulnerability hunting against the identified attack surface.
