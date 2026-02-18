---
description: "Systematically analyze code for security vulnerabilities. This skill should be used when the user asks to find vulnerabilities, perform code analysis for security issues, hunt for bugs in source code, check for injection flaws, look for authentication bypasses, trace user input to dangerous sinks, search for OWASP Top 10 issues, review code for security problems, or find exploitable weaknesses. Works best after attack surface reconnaissance but can operate standalone. This is the code analysis and vulnerability discovery phase in the breach pipeline."
---

# Code Analysis: Vulnerability Discovery

This skill implements a three-phase hybrid audit methodology designed for expert security researchers performing source code audits. The approach combines component mapping, risk-based prioritization, and systematic input tracing to maximize vulnerability discovery rates while maintaining efficient use of audit time.

## Phase 1: Component-to-Vulnerability Mapping

Begin by establishing a comprehensive map between application components and their applicable vulnerability classes. If recon output from a prior reconnaissance phase is available, use those identified entry points as the starting inventory. If no recon output exists, refer to the fallback clause at the end of this document.

For every entry point, endpoint, and component identified, construct a mapping table with the following columns:

| Component | Input Sources | Applicable Vulns | Existing Controls | Priority |
|-----------|--------------|-------------------|-------------------|----------|

Populate this table by reasoning about what each component does and what vulnerability classes naturally apply:

- **Data storage endpoints** (any component that writes to a database or data store): SQL injection, NoSQL injection, mass assignment, second-order injection. Look for query construction, ORM usage, raw query execution, and stored procedure invocation.

- **Rendering endpoints** (any component that produces HTML, templates, or formatted output): Cross-site scripting (reflected, stored, DOM-based), server-side template injection (SSTI), HTML injection. Look for template engines, output encoding functions, and user input flowing into rendered output.

- **File handling endpoints** (upload, download, read, write, or process files): Path traversal, unrestricted file upload, local file inclusion, remote file inclusion, zip slip, XML external entity injection via file parsing. Look for file path construction, MIME type validation, and file processing libraries.

- **Authentication endpoints** (login, registration, password reset, MFA, session management): Authentication bypass, credential stuffing, brute force, session fixation, session hijacking, insecure password recovery, JWT vulnerabilities. Look for session creation, token generation, credential validation, and password reset flows.

- **API endpoints** (REST, GraphQL, gRPC, or other programmatic interfaces): Insecure direct object references (IDOR), broken function-level authorization, mass assignment, excessive data exposure, lack of rate limiting, GraphQL introspection abuse, batch query attacks. Look for object ID parameters, authorization middleware, response filtering, and schema exposure.

- **Redirect endpoints** (any component that redirects the user to another URL): Open redirect, OAuth token theft via redirect manipulation. Look for redirect parameters, URL validation, and whitelist enforcement.

- **Administrative and privileged endpoints** (admin panels, internal tools, management interfaces): Missing access control, privilege escalation, exposed internal functionality, debug endpoints, default credentials.

- **Third-party integration endpoints** (webhooks, callbacks, payment processing, OAuth, SAML): SSRF via webhook URLs, callback URL manipulation, payment amount tampering, OAuth misconfiguration, SAML signature bypass.

- **Search and export endpoints** (search functionality, CSV/PDF export, reporting): Injection via search terms, CSV injection, information disclosure via export, denial of service via resource-intensive queries.

For each component, document the input sources comprehensively. Inputs are not limited to query parameters and POST bodies. Consider: URL path segments, HTTP headers (Host, Referer, X-Forwarded-For, custom headers), cookies, file contents (uploaded files, imported data), WebSocket messages, values retrieved from the database that originated from earlier user input (second-order), environment variables influenced by user actions, and DNS-based inputs.

Document existing security controls for each component. These include input validation, output encoding, parameterized queries, authentication middleware, authorization checks, rate limiting, CSRF tokens, security headers, and WAF rules. Note whether controls are applied server-side or client-side only, as client-side controls offer no real protection.

## Phase 2: Risk Prioritization

Organize the mapped components into three tiers based on potential impact and exploitability. This tiering determines the order of investigation during the hunt and ensures that the highest-value targets receive the most thorough analysis.

### Tier 1 -- Hunt First (Exhaustive Analysis Required)

These components represent the highest risk due to either requiring no authentication (maximizing the attacker pool) or guarding critical functionality (maximizing impact upon compromise):

- **Unauthenticated endpoints**: Any functionality accessible without authentication is reachable by any attacker on the internet. Vulnerabilities here have maximum exploitability.
- **Authentication and authorization logic**: The gatekeepers themselves. Flaws here undermine the entire security model. Includes login flows, registration, session management, role enforcement, and permission checks.
- **File upload handlers**: Historically one of the most reliable paths to remote code execution. Even with mitigations, bypass techniques are well-documented and frequently successful.
- **Deserialization points**: Insecure deserialization commonly leads directly to remote code execution with minimal exploitation complexity.
- **Direct database query construction**: Any location where SQL or NoSQL queries are built using string concatenation or interpolation with user-controlled input.
- **Admin and privileged functionality**: Compromise of admin functions grants maximum control. Often these have weaker security due to assumptions about trusted users.
- **Password reset flows**: A single flaw can enable account takeover at scale. These flows are complex and frequently contain subtle logic errors.
- **Payment and financial operations**: Direct financial impact. Logic flaws can enable price manipulation, duplicate transactions, or theft.

### Tier 2 -- Hunt Second (Thorough Analysis)

These components have moderate impact, typically requiring some level of authentication or involving less critical functionality:

- **Authenticated state-changing operations**: Any POST/PUT/DELETE action behind authentication. Look for CSRF, IDOR, business logic flaws, and missing authorization.
- **Payment integrations**: Third-party payment gateway interactions, webhook handling, transaction verification, and refund processing.
- **Third-party API integrations**: Outbound requests to external services. Look for SSRF, credential leakage, and insufficient response validation.
- **Email and notification sending**: Template injection, header injection, spoofing, and phishing vector creation.
- **Search functionality**: Injection via search terms, information disclosure via search results, denial of service through expensive queries.
- **Export and download features**: Path traversal, information disclosure, CSV injection, and resource exhaustion.

### Tier 3 -- Hunt Last (Standard Analysis)

Lower priority components that still warrant review but are less likely to yield critical findings:

- **Read-only authenticated endpoints**: Information disclosure is possible but impact is typically limited without a chaining opportunity.
- **Internal tooling**: Usually not internet-facing, reducing the attacker pool, but often has weaker security controls.
- **Logging infrastructure**: Log injection and information disclosure in logs.
- **Health check endpoints**: Typically minimal attack surface, but worth verifying they do not expose sensitive information.
- **Static content serving**: Rarely vulnerable, but check for misconfigured directory listing and sensitive file exposure.

**Hunt Tier 1 exhaustively before moving to Tier 2.** Complete Tier 2 before moving to Tier 3. The rationale is straightforward: Tier 1 targets have the highest impact (unauthenticated access or critical functionality), meaning findings here produce the most valuable results. Tier 2 targets have moderate impact and require more preconditions for exploitation. Tier 3 targets are lower priority but remain worth checking as they can serve as components in vulnerability chains.

## Phase 3: Input Tracing and Discovery

For each prioritized component, perform systematic input tracing. This is the core of the hunt -- follow every input from source to sink, documenting every transformation and control along the way.

### Step 1: Identify All Input Sources

For the component under analysis, enumerate every source of external data. Be exhaustive:

- URL parameters (query string and path segments)
- Request body (form data, JSON, XML, multipart)
- HTTP headers (standard and custom)
- Cookies and session data
- Uploaded file content and metadata (filename, content-type)
- Database values that originated from prior user input (second-order)
- Environment variables or configuration influenced by user actions
- WebSocket frames and event data
- Values from third-party APIs that may be attacker-influenced

### Step 2: Trace Through Transformations

Follow each input through every function call, variable assignment, and transformation. Document the path completely: which functions process the input, what validations are applied, what encoding or decoding occurs, what business logic modifies the value.

### Step 3: Check Against Vulnerability Patterns

At each transformation step, consult the applicable OWASP reference files for matching vulnerability patterns. The reference mapping below specifies which file to consult for each vulnerability class.

### Step 4: Assess Exploitability

For each potential finding, answer these questions:
- Can the attacker control the input? (If not, it is not exploitable.)
- Does the input reach a dangerous sink without adequate sanitization?
- Are there bypasses for existing controls? (Encoding tricks, alternate representations, logic flaws in validation.)
- What is the actual impact if exploited?

### Step 5: Document the Trace

Record the complete trace for each finding: `source -> transformation1 -> transformation2 -> ... -> sink`. At each step, note what controls are present and what potential bypasses exist.

## OWASP Reference File Mapping

When investigating a specific vulnerability class, consult the corresponding reference file for detailed patterns, indicators, and bypass techniques:

| Vulnerability Class | Reference File |
|---------------------|----------------|
| Broken access control (IDOR, privilege escalation, forced browsing, CORS) | `a01-broken-access-control.md` |
| Cryptographic failures (weak algorithms, hardcoded keys, poor randomness) | `a02-cryptographic-failures.md` |
| Injection (SQLi, NoSQLi, command injection, SSTI, LDAP, XPath) | `a03-injection.md` |
| Insecure design (business logic, race conditions, missing rate limits) | `a04-insecure-design.md` |
| Security misconfiguration (debug mode, default creds, missing headers) | `a05-security-misconfiguration.md` |
| Vulnerable and outdated components (known CVEs, outdated libraries) | `a06-vulnerable-components.md` |
| Authentication failures (credential stuffing, JWT flaws, session issues) | `a07-auth-failures.md` |
| Software and data integrity failures (deserialization, CI/CD, mass assignment) | `a08-integrity-failures.md` |
| Logging and monitoring failures (missing logs, log injection, data in logs) | `a09-logging-monitoring-failures.md` |
| Server-side request forgery (direct SSRF, blind SSRF, cloud metadata) | `a10-ssrf.md` |

## Vulnerability Chaining

Individual findings often combine into chains with significantly higher impact than any single vulnerability alone. Actively look for these common chain patterns during the hunt:

- **IDOR + Information Disclosure = Account Takeover**: An IDOR that leaks user data (email, security questions, tokens) combined with another IDOR or logic flaw in the password reset flow enables full account takeover.
- **SSRF + Cloud Metadata = Credential Theft**: An SSRF that can reach the cloud metadata endpoint (169.254.169.254) can extract IAM credentials, database passwords, and API keys, often leading to full infrastructure compromise.
- **Open Redirect + OAuth = Token Theft**: An open redirect on a whitelisted OAuth callback domain can intercept authorization codes or tokens, enabling account takeover.
- **XSS + CSRF = Authenticated Action Execution**: An XSS vulnerability can be used to bypass CSRF protections and execute arbitrary actions in the context of any user who triggers the XSS payload.
- **Path Traversal + File Upload = Remote Code Execution**: A file upload combined with a path traversal in the storage path can place executable content in web-accessible or executable directories.
- **Information Disclosure + Password Reset = Account Takeover**: Leaked tokens, predictable reset links, or exposed user data combined with flaws in the password reset flow enable account takeover.
- **Race Condition + Business Logic = Financial Fraud**: Race conditions in payment processing, coupon redemption, or balance operations can enable double-spending or resource duplication.

When a finding is identified, always evaluate whether it can serve as a component in a chain. Document the chain potential for each finding.

## Finding Documentation Format

For each vulnerability discovered during the hunt, record the following:

- **Vulnerability Class**: The category of the vulnerability (e.g., SQL Injection, IDOR, SSRF).
- **Affected Component**: The specific file and line number where the vulnerability exists (format: `file:line`).
- **Input Source**: Where the attacker-controlled data enters the application.
- **Dangerous Sink**: Where the attacker-controlled data reaches a security-sensitive operation.
- **Code Snippet**: The relevant vulnerable code, including sufficient context to understand the flaw.
- **Confidence Level**: Confirmed (verified through trace), High (strong indicators with minor uncertainty), Medium (probable but requires runtime verification), or Low (theoretical or requires specific conditions).
- **Preliminary Severity**: Critical, High, Medium, or Low, based on impact and exploitability.
- **Chain Potential**: Other vulnerability classes this finding could combine with to increase impact.

## Lifecycle-Aware Mode

Before beginning analysis, check whether a `findings/` directory exists in the current working directory or any parent directory (up to 5 levels). The `findings/` directory is recognized by having stage subdirectories (`potential/`, `confirmed/`, `validated/`, `verified/`, `reported/`, `rejected/`).

### If `findings/` directory is found: Lifecycle Mode

For each vulnerability discovered, create a finding folder in `findings/potential/` instead of outputting to conversation only:

1. **Assign an ID**: Scan all finding folders across all stage directories (`potential/`, `confirmed/`, `validated/`, `verified/`, `reported/`, `rejected/`), extract the highest numeric ID from folder names (pattern: `{SEVERITY}-{ID}-{VULN_TYPE}-{desc}/`), and increment by 1. Zero-pad to 3 digits. If no existing findings, start at `001`.

2. **Create the finding folder**: Name it `{SEVERITY}-{ID}-{VULN_TYPE}-{desc}/` where:
   - `SEVERITY`: `CRIT`, `HIGH`, `MED`, or `LOW`
   - `ID`: Zero-padded 3-digit sequential ID
   - `VULN_TYPE`: Freeform shorthand (XSS, SQLI, IDOR, RCE, SSRF, SSTI, etc.)
   - `desc`: Kebab-case description, ~40 characters max
   - Example: `MED-001-XSS-missing-sanitization/`

3. **Create `finding.md`**: Use the finding template from `finding-template.md` (in the hunt skill's references directory). Populate:
   - All frontmatter fields (id, title, severity, vuln_type, affected_component, stage as "potential", created_at, last_moved)
   - **Vulnerable Code** section: Code snippet with file path, line numbers, surrounding context
   - **Exploitability** section: Full exploit path from entry point through data flow to sink
   - Leave other sections present but with placeholder comments for later stages

4. **Create empty `poc/` directory** inside the finding folder.

After processing all findings, output a summary table:

| ID | Severity | Type | Component | Title |
|----|----------|------|-----------|-------|

### If no `findings/` directory is found: Standalone Mode

Operate identically to non-lifecycle behavior: output all findings to the conversation using the Finding Documentation Format above. No filesystem changes.

## Fallback: No Recon Output Available

If this skill is invoked without output from a prior reconnaissance phase, perform rapid technology fingerprinting and entry point enumeration before beginning the hunt:

1. **Technology Fingerprinting**: Identify the programming language(s), frameworks, libraries, database engines, and infrastructure components by examining package manifests, configuration files, import statements, and project structure.
2. **Entry Point Enumeration**: Identify all routes, endpoints, API definitions, and external interfaces by examining route definitions, controller files, API schemas (OpenAPI, GraphQL SDL), and middleware configurations.
3. **Architecture Mapping**: Determine the high-level architecture (monolith vs. microservices, frontend/backend separation, database access patterns) to understand trust boundaries and data flows.

Proceed to Phase 1 after completing this rapid assessment.

## Pipeline Continuation

After completing code analysis and documenting all findings:

- **Lifecycle mode**: Findings have been written to `findings/potential/`. Proceed to validation with `/breach:validate` to generate proof-of-concept exploits and move validated findings forward. Alternatively, run the full pipeline with `/breach:hunt`.
- **Standalone mode**: Findings have been output to conversation. Run `/breach:validate` to generate proof-of-concept exploits for your findings.
