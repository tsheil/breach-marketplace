# Triager Analysis Reference

How bug bounty triagers evaluate submissions. Apply this perspective to every finding before marking it CONFIRMED.

## The "So What?" Test

Triagers ask these 7 questions. A finding that cannot answer all of them clearly will be marked as N/A or Informational:

1. **Can an external attacker reach this code path?** — Not internal tools, not debug endpoints, not localhost-only. A real attacker on the internet.
2. **What is the concrete impact?** — Not "could potentially lead to" but "this allows an attacker to [specific action]." Vague impact = N/A.
3. **What data or functionality is at risk?** — Name the specific data (PII, credentials, financial records) or functionality (admin access, account takeover). "Sensitive data" is not specific enough.
4. **Is this the default configuration?** — Vulnerabilities in non-default, unlikely, or explicitly-opted-into configurations are deprioritized or rejected.
5. **Does the PoC work end-to-end?** — A code snippet that "shows the pattern" is not a PoC. The triager needs to run it and see the exploit succeed.
6. **Is this already known or duplicate?** — Check hacktivity, CVE databases, and your own prior submissions. Duplicates waste everyone's time.
7. **Would you pay for this?** — Honest self-assessment. If the answer is "probably not," reconsider the severity or whether to submit at all.

## 4-Dimension Pass/Fail Checklist

Score each dimension as PASS or FAIL. All 4 must pass for CONFIRMED verdict.

### 1. Attacker Reachability

| Criterion | PASS | FAIL |
|-----------|------|------|
| Entry point is externally accessible | Unauthenticated HTTP endpoint, public API | Internal admin tool, localhost-only service |
| No extraordinary preconditions | Standard browser, standard tools | Requires physical access, insider knowledge, or unlikely config |
| Attack can be performed remotely | Network-based exploitation | Requires local file system access or same-network position |

### 2. Impact Concreteness

| Criterion | PASS | FAIL |
|-----------|------|------|
| Specific data at risk is named | "Exfiltrates user email addresses and hashed passwords from the users table" | "Could lead to data exposure" |
| Worst case is demonstrated | PoC shows actual data extraction or privilege change | PoC shows an error message or stack trace only |
| Business impact is quantifiable | "Affects all 50K users" or "Enables financial fraud" | "Could be bad" or "theoretical risk" |

### 3. Exploitation Realism

| Criterion | PASS | FAIL |
|-----------|------|------|
| PoC runs without manual intervention | Single command, clean output, deterministic | Requires editing scripts, manual steps, or "imagine that..." |
| No fabricated conditions | Tests against real code, real configurations | Mock servers, hardcoded responses, assumed misconfigurations |
| Payload is realistic | Attacker would actually use this payload | Contrived or unrealistic input that wouldn't occur naturally |

### 4. Scope Confidence

| Criterion | PASS | FAIL |
|-----------|------|------|
| Target is in scope | Confirmed against program scope definition | Might be out of scope, third-party, or shared infrastructure |
| Vulnerability is in first-party code | In the target's own codebase | In a dependency with no proof of exploitability in context |
| Not a design decision | Unintended behavior that violates security expectations | Intended behavior that the reporter disagrees with |

## Common N/A Patterns

These are the most frequent reasons triagers mark submissions as Not Applicable. Validate your finding against this list before submitting:

| Pattern | Why It's N/A | What Reporters Think |
|---------|-------------|---------------------|
| Self-XSS | Attacker can only exploit themselves | "But it's XSS!" |
| CSRF on non-state-changing endpoint | No security impact from replaying the request | "CSRF token is missing" |
| Missing rate limiting (no demonstrated impact) | Rate limiting is defense-in-depth, not a vulnerability | "I can send 1000 requests" |
| Clickjacking on non-sensitive page | No security-relevant action to trick the user into | "X-Frame-Options is missing" |
| Open redirect without a chain | Low impact on its own | "I can redirect users" |
| Verbose error messages (no sensitive data) | Stack traces without secrets are informational | "Internal paths are disclosed" |
| Missing security headers (no exploit) | Headers are defense-in-depth | "CSP is not configured" |
| Email enumeration via timing | Nearly impossible to prevent, widely accepted risk | "I can tell if an email exists" |
| Cookie without Secure flag (HTTPS-only site) | No interception vector on HTTPS-only deployment | "Cookie flags are wrong" |
| CORS misconfiguration (no credential access) | Wildcard CORS without `credentials: true` is harmless | "CORS allows *" |

## AI Slop Detection

Triagers are increasingly trained to spot AI-generated reports. These patterns trigger immediate skepticism:

| Red Flag | What Triagers See |
|----------|------------------|
| Generic vulnerability descriptions | "This could allow an attacker to..." without specifics |
| Template-like structure with unfilled details | Clearly a form letter with placeholders |
| Severity inflation | Every finding is Critical, no justification for the rating |
| No actual PoC, just "steps to reproduce" | Steps describe how to navigate to a page, not how to exploit |
| Copied-and-pasted remediation advice | "Use parameterized queries" without showing the specific fix |
| Findings that don't match the target | Generic web vulnerabilities reported against an API-only service |
| Excessive formality and hedging | "It is recommended that..." instead of direct statements |
| Multiple findings that are actually one | Same root cause split into separate reports for bounty multiplication |
| Perfect grammar but zero technical depth | Well-written but says nothing specific |
| Claims without evidence | "We confirmed that..." but no screenshot, no response, no proof |

**Counter-measure**: Every section of a finding must reference specific file paths, line numbers, function names, and real output from the target. Generic language is the enemy of credibility.
