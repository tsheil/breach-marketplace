---
description: "Validate security findings with proof-of-concept exploits and strict evidence. This skill should be used when the user wants to validate vulnerability findings, generate PoC exploits, prove a vulnerability is exploitable, verify findings are not false positives, confirm a vulnerability is real, build an exploit, triage security findings, create a PoC, or prepare evidence for a security report. This is the validation phase following the hunt phase in the breach pipeline."
---

# Validate

Validation turns raw findings into defensible evidence. Every finding that reaches the report must survive this phase — no exceptions, no shortcuts. If the evidence bar isn't met, the finding goes back to hunt, not forward to report.

## Evidence Bar (Non-Negotiable)

Every finding requires ALL 6 elements. Missing any one of them means the finding is incomplete and gets sent back to the hunt phase for further investigation. Do not attempt to "fill in the gaps" with assumptions — if the data isn't there, the finding isn't ready.

### 1. File Path

Exact file containing the vulnerability. Not "somewhere in the auth module" — the full path from repository root. If the vulnerability spans multiple files (e.g., a tainted input flows through three modules), document all files in the chain with the primary sink file listed first.

### 2. Line Numbers

Specific lines of vulnerable code. A range is acceptable when the vulnerability spans a block (e.g., lines 142-158), but "around line 150" is not. Pin it down.

### 3. Code Snippet

The actual vulnerable code with enough surrounding context to understand the function's purpose, input sources, and output destinations. Include the function signature, relevant variable assignments, and the vulnerable operation itself. Strip nothing that aids comprehension.

### 4. Exploitability Proof

How an attacker reaches this code with malicious input. This is the full trace:
- **Entry point**: The external interface (HTTP endpoint, CLI argument, file upload handler, message queue consumer, etc.)
- **Data flow**: Every transformation the input undergoes between entry and the vulnerable sink — parsing, decoding, sanitization (or lack thereof), type coercion, string concatenation
- **Controls assessment**: What security controls exist along this path (input validation, output encoding, parameterized queries, framework protections, WAF rules, rate limiters, authentication requirements, authorization checks) and whether each one is effective, bypassable, or absent
- **Bypass method**: If controls exist, exactly how they fail — regex that doesn't account for encoding, validation that runs after the vulnerable operation, allowlist that's too broad, check that can be raced

### 5. Severity Justification

Why this severity rating — not just "it's SQL injection so it's Critical." Address:
- **Worst-case impact**: What can an attacker actually achieve? Data exfiltration, RCE, privilege escalation, denial of service? Be specific about the scope — one user's data vs. the entire database.
- **Access required**: Unauthenticated, authenticated as any user, authenticated with specific role, requires knowledge of internal identifiers?
- **Attack complexity**: Single request vs. multi-step chain, timing dependencies, prerequisite conditions, user interaction required?
- **Scope**: Does exploitation affect only the vulnerable component or does it cascade to other systems?

Use CVSS v3.1 base metrics as the framework. Provide the vector string and resulting score. Do not inflate — a medium is a medium.

### 6. Remediation

Specific, actionable fix. Not generic advice — a concrete code change. Show the vulnerable line and the fixed line. If the fix requires architectural changes (e.g., switching from string concatenation to an ORM), provide the specific implementation for this codebase, not a textbook example.

Bad: "Use parameterized queries."
Good: "Change line 47 in `app/models/user.py` from `db.query(f"SELECT * FROM users WHERE id={user_id}")` to `db.query("SELECT * FROM users WHERE id = %s", (user_id,))`"

Bad: "Implement proper access controls."
Good: "Add ownership check at line 83 in `api/views/documents.py` before the query: `if document.owner_id != request.user.id: return HttpResponseForbidden()`"

## Validation Procedure

For each raw finding from the hunt phase, execute this procedure in order. Do not skip steps. Do not reorder.

### Step 1: Context Recovery

Re-read the vulnerable code in full context. Not just the flagged line — the entire function, the class definition, the module imports, and any relevant configuration. Understand what the code is supposed to do before assessing what it actually does. Check the git history for the file: was this code recently modified? Is it actively maintained or abandoned? Are there related tests that might reveal intended behavior?

Confirm the code path is reachable from an external entry point. Dead code and internal-only utilities are not vulnerabilities — they're technical debt. Trace backwards from the vulnerable function to at least one externally-accessible caller.

### Step 2: Control Enumeration

Identify ALL mitigating controls between the entry point and the vulnerable sink. Be thorough — a missed control is the most common cause of false positives. Check for:

- **Framework-level protections**: Django's ORM auto-escaping, Rails' strong parameters, Spring's CSRF tokens, Express's helmet headers, ASP.NET's request validation. These are often invisible in the application code itself.
- **Middleware**: Authentication middleware, authorization decorators, input sanitization layers, rate limiters, request size limits.
- **Application-level validation**: Input validation functions, allowlists/denylists, type checking, schema validation (JSON Schema, Pydantic, Marshmallow, Joi).
- **Infrastructure controls**: WAF rules, CSP headers, CORS configuration, network segmentation that limits exploitation scope.
- **Language/runtime protections**: Type safety, memory safety, automatic escaping in template engines.

For each control identified, assess whether it's effective against this specific attack vector. A CSRF token doesn't mitigate SQL injection. An XSS filter doesn't stop IDOR. Be precise about what each control actually prevents.

### Step 3: Exploit Path Construction

Determine the exact input that triggers the vulnerability. This is not theoretical — construct the actual HTTP request, CLI command, file content, or message payload that would exploit the vulnerability. Trace from entry point to vulnerable sink with every transformation noted.

Document:
- The raw input an attacker would provide
- Each transformation applied to that input (URL decoding, JSON parsing, string operations, etc.)
- The state of the input when it reaches the vulnerable operation
- Why the input is still malicious at the point of exploitation

### Step 4: Framework Protection Audit

Separately from Step 2, specifically check for framework-level protections that might not be visible in the application code. This is a dedicated step because these protections are the most commonly missed and the most frequent cause of false positives.

Check the framework's default configuration. Check whether the application has explicitly disabled any defaults. Check the framework's version for known bypass techniques. Check middleware ordering — a protection that runs after the vulnerable code is no protection at all.

### Step 5: PoC Generation

Generate a proof-of-concept exploit using the appropriate template from the references directory:

- **HTTP-based vulnerabilities** (injection, auth bypass, IDOR, SSRF, file upload): Use `poc-http-requester.md` for Python requests-based PoCs that handle sessions, authentication, and multi-step exploitation.
- **Quick verification** (single-request vulns, header checks, simple injections): Use `poc-curl-patterns.md` for curl one-liners that can be run immediately from the command line.
- **Data extraction and blind exploitation** (blind SQLi, error-based extraction, SSRF data retrieval, file read): Use `poc-data-extraction.md` for Python scripts with extraction loops, timing analysis, and result formatting.

Adapt the template to the specific finding. PoC requirements are non-negotiable:
- **Setup instructions**: What the tester needs before running — target URL, authentication tokens, test accounts, prerequisite state.
- **Exact payload**: The actual exploit string or request body. Not pseudocode, not "insert your payload here" — the real thing, ready to fire.
- **Expected behavior**: What a patched application would do vs. what the vulnerable application does. The tester must be able to distinguish success from failure unambiguously.
- **Self-contained**: Copy-paste-run. No external dependencies beyond `requests` or `curl`. No custom libraries, no separate config files, no manual steps between script sections.
- **Commented**: Every section explains what it does and why. The triager reproducing this may not have your context.

### Step 6: Confidence Assignment

Assign a confidence level based on evidence strength:

- **Confirmed**: Code path verified end-to-end, no mitigating controls found or all controls demonstrated bypassable, exploit path clear and reproducible. This finding will survive scrutiny.
- **High**: Code path verified, minor controls exist but are demonstrably bypassable or insufficient, exploit path clear. Minimal risk of false positive.
- **Medium**: Code path likely reachable based on static analysis, some controls present that may partially mitigate, exploit requires specific conditions (particular configuration, race timing, user interaction). Needs runtime verification to confirm.
- **Low**: Code path may be reachable but static analysis is inconclusive, controls may fully mitigate, exploitation is theoretical without runtime testing. Include in report only if the potential impact is Critical.

## Triage Validation

Apply these criteria strictly. False positives erode trust in the entire report.

### Discard the Finding If:

- **Self-exploitation only**: The attacker can only affect their own account or session. Modifying your own cookies to break your own session is not a vulnerability.
- **Framework mitigates by default**: The framework provides protection and the application has not explicitly disabled it. Verify by checking configuration, not by assuming.
- **Intended behavior**: The functionality works as designed, even if the design is risky. Document as a design concern in a separate section, not as a vulnerability.
- **Physical/local access required**: Requires physical device access or local network position without a demonstrated remote exploitation path.
- **Prerequisite compromise**: Requires already having compromised another account or system, unless you're explicitly documenting an attack chain where the prerequisite compromise is also a finding.

### Downgrade Severity If:

- **Authentication required**: Reduces attacker pool significantly. High becomes Medium unless the finding is privilege escalation (which inherently requires authentication).
- **Self-impact only**: User can modify their own data in unintended ways but cannot affect other users. This is a robustness issue, not typically a security vulnerability — but document it if the self-modification has security implications (e.g., elevating own privileges).
- **Significant preconditions**: Requires specific server configuration, race condition timing within narrow windows, or a particular application state that isn't the default. Each precondition reduces severity by one level, minimum Low.
- **No runtime verification**: Static analysis shows the vulnerability pattern but you couldn't confirm exploitation. Downgrade by one level and flag for runtime testing.

## Output Format

For each validated finding, produce the following structure. Do not deviate from this format — consistency enables automation and review.

```
### Finding [ID]: [Vulnerability Class] — [CWE-XXX]

**Component**: `path/to/file.ext:line_number`
**Confidence**: [Confirmed|High|Medium|Low] — [one-line justification]
**Severity**: [Critical|High|Medium|Low] — CVSS:[vector_string] ([score])

#### Vulnerable Code
[Code snippet with sufficient context]

#### Exploitability
[Full exploit path from entry point to sink, controls assessment, bypass method]

#### Proof of Concept
[Complete, copy-paste-ready PoC with setup instructions and expected output]

#### Impact
[Specific worst-case scenario for this vulnerability in this application]

#### Remediation
[Exact code change with before/after]

#### Chain Potential
[What other findings this combines with for increased impact, or "None identified"]

#### Triage Notes
[Potential rejection reasons and preemptive counter-arguments — why this isn't a false positive]
```

## Fallback

If invoked without hunt phase output — no findings list, no target files, no prior context — do not guess. Ask the user to point to specific code they want validated, then apply the evidence bar and validation procedure to whatever they provide. Partial input gets the full treatment; no finding gets a free pass just because it arrived outside the normal pipeline.

## Pipeline

Validation complete. Run `/breach:report` to generate the final security report.
