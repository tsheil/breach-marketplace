# Finding Template

This is the canonical template for `finding.md` files within the finding lifecycle. Every finding folder contains a `finding.md` that follows this structure.

## Template

```yaml
---
id: "001"
title: ""
severity: ""              # CRIT | HIGH | MED | LOW
cvss_score:               # null until validated
cvss_vector: ""           # CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_
cwe: ""                   # CWE-XXX
stage: "potential"        # potential | confirmed | validated | verified | reported | rejected
vuln_type: ""             # Freeform shorthand (XSS, SQLI, IDOR, RCE, SSRF, CHAIN, etc.)
affected_component: ""    # file:line format
confidence: ""            # Confirmed | High | Medium | Low (empty until validated)
source: ""                # "manual" | "semgrep" | "codeql" (default: "manual")
chain_components: []      # List of finding IDs this chain comprises (empty for non-chain findings)
created_at: ""            # ISO 8601
last_moved: ""            # ISO 8601
rejection_reason: ""      # Only when rejected
reviewer_notes: ""        # Human reviewer free text
---

## Vulnerable Code

<!-- Code snippet with file path, line numbers, and surrounding context -->

## Exploitability

<!-- Full exploit path: entry point, data flow, controls assessment, bypass method -->

## Proof of Concept

<!-- Copy-paste-ready PoC (also saved as script in poc/ directory) -->

## Impact

<!-- Business impact: worst-case outcome, affected data, blast radius -->

## Remediation

<!-- Specific code fix with before/after -->

## References

<!-- CWE link, OWASP reference, related CVEs -->
```

## Stage-by-Stage Population Guide

### potential (Code Analysis / Static Scan phase)

Populate these fields and sections:
- **Frontmatter**: `id`, `title`, `severity`, `cwe`, `stage` ("potential"), `vuln_type`, `affected_component`, `source` ("manual", "semgrep", or "codeql"), `created_at`, `last_moved`
- **Vulnerable Code**: Full code snippet with file path, line numbers, and surrounding context
- **Exploitability**: Entry point identification, data flow trace, initial controls assessment
- All other sections: Leave present with placeholder comments

### confirmed (PoC exists)

Add to the `potential` content:
- **Frontmatter**: Update `stage` to "confirmed", update `last_moved`
- **Proof of Concept**: Working PoC code (also save script to `poc/` directory)

### validated (Full evidence bar met)

Complete all remaining content:
- **Frontmatter**: Update `stage` to "validated", `last_moved`, `cvss_score`, `cvss_vector`, `confidence`. For chain findings: set `vuln_type` to "CHAIN", populate `chain_components` with component finding IDs
- **Exploitability**: Complete with full controls assessment and bypass method
- **Proof of Concept**: Refined and fully commented PoC
- **Impact**: Business impact with worst-case outcome, affected data, blast radius
- **Remediation**: Specific code fix with before/after
- **References**: CWE link, OWASP reference, related CVEs

### verified (Human-verified)

Human reviewer manually:
- Moves finding folder from `validated/` to `verified/`
- Updates `stage` to "verified" in frontmatter
- Updates `last_moved`
- Optionally adds `reviewer_notes`

### reported (Report generated)

After report generation:
- **Frontmatter**: Update `stage` to "reported", `last_moved`
- Finding folder moved to `reported/`

### rejected (Discarded)

When a finding fails validation:
- **Frontmatter**: Update `stage` to "rejected", `last_moved`, `rejection_reason`
- Finding folder moved to `rejected/`
