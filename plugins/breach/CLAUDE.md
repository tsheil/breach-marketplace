# Breach: Security Review Principles

## Mindset

- Think like an attacker, report like a consultant.
- Trust boundaries are where bugs live.
- Assume every input is hostile until proven safe.
- Focus on impact, not theoretical risk.
- Complexity is the enemy of security — the more convoluted the logic, the higher the bug density.

## Evidence Standard

Every finding requires **all 6 elements** or it is not ready:

1. **File path** — exact source location
2. **Line numbers** — precise range of vulnerable code
3. **Code snippet** — the relevant vulnerable code block
4. **Exploitability proof** — concrete attack scenario or PoC steps
5. **Severity justification** — why this severity rating, tied to real impact
6. **Remediation** — specific fix with code or configuration changes

Missing any element = finding is incomplete. Do not report it.

## Methodology

- Map before hunting. Enumerate the full attack surface first.
- Risk-prioritize targets: auth, input parsing, file handling, crypto, deserialization.
- Trace data flows end-to-end: source → sanitization → sink.
- Check for missing controls, not just broken ones.
- Look for vulnerability chains — low-severity bugs that combine into high impact.
- Test assumptions about framework protections. Verify autoescape, CSRF tokens, ORM parameterization.
- Review configuration as code: defaults, feature flags, debug modes, error verbosity.

## What NOT to Report

- Informational findings without an exploit path.
- Self-XSS or self-exploitation scenarios.
- Best practice deviations without demonstrable security impact.
- Theoretical attacks requiring unrealistic preconditions.
- Missing headers without proof of exploitability.
- Denial of service requiring authenticated privileged access.
- Version disclosure alone without a known exploitable CVE.

## Severity Calibration

| Severity | Examples |
|----------|----------|
| **Critical** | RCE, auth bypass on admin, mass data exfiltration, full account takeover |
| **High** | SQLi with data access, stored XSS on main app, IDOR on sensitive resources, privilege escalation |
| **Medium** | Reflected XSS, CSRF on state-changing actions, information disclosure of internal data |
| **Low** | Verbose errors, minor info leaks, self-exploitation only, significant preconditions required |

Downgrade one level if exploitation requires: authenticated access, non-default config, or significant user interaction.
Upgrade one level if: no authentication required, mass exploitation possible, or data is PII/financial.

## Language-Agnostic Analysis

- Focus on patterns, not syntax. Vulnerabilities are architectural, not linguistic.
- Input -> processing -> output is universal. Trace it in every language.
- Trust boundaries exist in every architecture. Identify them first.
- Framework abstractions leak. ORMs don't prevent all SQLi. Template engines don't prevent all XSS.
- Serialization/deserialization is dangerous everywhere — not just Java.
- Cryptographic misuse follows the same patterns regardless of library.
