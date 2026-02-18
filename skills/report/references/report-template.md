# Vulnerability Finding Template

Use this template for every individual finding in the report. Every field is required unless explicitly marked optional. Do not leave placeholders in the final report — if information is unavailable, note what is missing and why.

---

## [Finding-ID]: [Title]

> The Finding-ID follows the format: severity letter + sequential number (e.g., C-01, H-03, M-07, L-02).
> The Title must lead with impact, not technique. Write what an attacker can do, not what the bug is.
> Good: "Unauthenticated attacker can export all customer records"
> Bad: "IDOR in /api/v2/export endpoint"

**Severity**: [Critical / High / Medium / Low]
**CVSS Score**: [X.X] ([CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_])
**CWE**: [CWE-XXX — Full Name]

> Select the most specific CWE that applies. Prefer leaf nodes over category nodes.
> Example: CWE-89 (SQL Injection) over CWE-74 (Injection).

### Summary

[2-3 sentences maximum. Sentence 1: what an attacker can do and the impact. Sentence 2: what access or conditions are required. Sentence 3: scope of affected users or data. This paragraph determines whether the triager takes the finding seriously — write it as if the reader will not read anything else.]

### Affected Component

- **File**: [path/to/vulnerable/file.ext]
- **Lines**: [start-end]
- **Function/Route**: [function name, API route, or URL path]
- **Parameter**: [vulnerable parameter name, if applicable]

> Be as specific as possible. Include the full file path from the repository root.
> If multiple components are affected, list each one.

### Vulnerable Code

```[language]
[Exact vulnerable code snippet. Include enough surrounding context
for the reader to understand the code's purpose and location.
Highlight or comment the specific vulnerable line(s).]
```

> Pull the code directly from the source. Do not paraphrase or simplify.
> Add inline comments pointing to the exact vulnerability if it is not obvious.

### Steps to Reproduce

1. [Setup step — account creation, authentication, prerequisite state]
2. [Navigate or send request — exact URL, method, headers, cookies]
3. [Inject payload or trigger vulnerability — exact payload, parameter, value]
4. [Observe result — exact expected response, status code, data returned]

> Every step must be copy-paste reproducible. Do not write "navigate to the dashboard" — write
> "Navigate to https://target.example.com/dashboard". Do not write "use a valid session token" —
> write "Include the header: Authorization: Bearer [token from step 1]".
> Include expected output at each step so the reproducer knows they are on track.

### Proof of Concept

```[language]
[Full, self-contained PoC. This must run without modification
on a standard system. If it is a script, include shebang line
and dependency installation. If it is curl commands, include
all headers, cookies, and payloads.]
```

> PoC requirements:
> - Must be self-contained (no external dependencies beyond standard tools)
> - Must include comments explaining each step
> - Must target a safe/controlled endpoint or include a TARGET variable for customization
> - If the PoC is destructive, include a clear warning and a dry-run mode

### Impact

[Business impact narrative. Answer these questions in prose form:
- What is the worst realistic outcome of exploitation?
- What specific data is exposed or at risk? (PII, credentials, financial data, health records)
- How many users or records are potentially affected?
- What business operations could be disrupted?
- Are there regulatory or compliance implications? (GDPR, HIPAA, PCI-DSS)
- Could this be chained with other findings for greater impact?]

> Write in concrete, quantifiable terms. "All 2.3 million user records including email addresses
> and hashed passwords" is stronger than "user data." Reference the data model if known.

### Remediation

```[language]
[Exact code fix. Show the corrected version of the vulnerable code.
If the fix involves configuration changes, show the exact configuration.]
```

[Explanation of the fix. Why does this remediation work? Are there alternative approaches?
Reference security libraries or framework features where applicable.
Note any potential side effects of the fix that developers should test for.]

> Remediation guidelines:
> - Show before/after code when possible
> - Reference the framework's built-in security features (e.g., parameterized queries, CSRF tokens)
> - If multiple remediation options exist, list them in order of preference
> - Include testing guidance so developers can verify the fix

### References

- [CWE-XXX: Full Name](https://cwe.mitre.org/data/definitions/XXX.html)
- [OWASP: Relevant Testing Guide Section](https://owasp.org/www-project-web-security-testing-guide/)
- [Any relevant CVE, advisory, or prior disclosure]

> Optional: Include links to the program's security policy if it is relevant to the finding.
> Optional: Reference similar findings in public bug bounty disclosures for precedent.

---

## Template Usage Notes

- Fill every section completely before including the finding in the report.
- If a section cannot be filled (e.g., no PoC is possible for a design flaw), explain why in that section rather than leaving it blank.
- Maintain consistent formatting across all findings in the report.
- The finding must be self-contained — a reader should understand, reproduce, and fix the issue using only this finding's content.
