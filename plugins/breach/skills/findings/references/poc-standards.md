# PoC Standards

Proof-of-concept authoring standards for the breach pipeline. Every PoC must meet these requirements to pass validation.

## PoC Requirements

### Exit Codes

Every PoC script must use deterministic exit codes:

| Exit Code | Meaning |
|-----------|---------|
| `0` | Vulnerable — exploit succeeded |
| `1` | Not vulnerable — exploit failed cleanly |
| `2` | Error — script could not complete (missing deps, network issue, etc.) |

### Output Markers

Every PoC must print these markers for automated parsing:

```
[VULNERABLE] — printed when exploitation succeeds
[NOT_VULNERABLE] — printed when target is patched or not exploitable
[ERROR] — printed when the script encounters a non-exploit failure
```

### Summary Block

Every PoC must end with a structured summary block:

```
=== SUMMARY ===
Target: <component or endpoint>
Vulnerability: <vuln type and CWE>
Result: VULNERABLE | NOT_VULNERABLE | ERROR
Evidence: <one-line description of what was observed>
===============
```

## Progressive Test Pattern

PoCs should follow a progressive approach, escalating from baseline to full exploitation:

1. **Baseline**: Confirm normal behavior with benign input. Establishes what "not vulnerable" looks like.
2. **Minimal trigger**: Simplest possible malicious input that demonstrates the vulnerability exists.
3. **Escalation**: More sophisticated payload that demonstrates real-world impact (data extraction, auth bypass, etc.).
4. **Execution proof**: Full exploitation demonstrating the claimed severity (RCE, account takeover, etc.).
5. **Summary**: Print the summary block with results.

Each step should print its result before proceeding to the next. If any step fails, the PoC should still print remaining steps as SKIPPED and produce a summary.

## Counter/Tracking Pattern

Use explicit pass/total counters for multi-check PoCs:

### JavaScript (.mjs)

```javascript
let passed = 0;
const total = 4;

// Test 1: Baseline
if (baselineResult) { passed++; console.log("[PASS] Baseline: normal behavior confirmed"); }
else { console.log("[FAIL] Baseline: unexpected behavior"); }

// ... more tests ...

console.log(`\n${passed}/${total} checks passed`);
process.exit(passed === total ? 0 : 1);
```

### Bash (.sh)

```bash
passed=0
total=4

# Test 1: Baseline
if baseline_check; then
  ((passed++))
  echo "[PASS] Baseline: normal behavior confirmed"
else
  echo "[FAIL] Baseline: unexpected behavior"
fi

# ... more tests ...

echo "${passed}/${total} checks passed"
[ "$passed" -eq "$total" ] && exit 0 || exit 1
```

## PoC Header Standard

Every PoC script must begin with a header block containing required metadata fields.

### JavaScript (.mjs)

```javascript
/**
 * PoC: {finding title}
 * Finding: {finding ID}
 * CWE: {CWE-XXX}
 * Target: {file path or endpoint}
 * Author: breach pipeline
 * Date: {ISO 8601}
 *
 * Usage: node poc.mjs [target-url]
 * Expected: Exit 0 if vulnerable, exit 1 if not
 */
```

### Bash (.sh)

```bash
#!/usr/bin/env bash
# PoC: {finding title}
# Finding: {finding ID}
# CWE: {CWE-XXX}
# Target: {file path or endpoint}
# Author: breach pipeline
# Date: {ISO 8601}
#
# Usage: ./poc.sh [target-url]
# Expected: Exit 0 if vulnerable, exit 1 if not
set -euo pipefail
```

### Python (.py)

```python
#!/usr/bin/env python3
"""
PoC: {finding title}
Finding: {finding ID}
CWE: {CWE-XXX}
Target: {file path or endpoint}
Author: breach pipeline
Date: {ISO 8601}

Usage: python poc.py [target-url]
Expected: Exit 0 if vulnerable, exit 1 if not
"""
```

## poc/README.md Standard Template

Every finding's `poc/` directory should contain a README:

```markdown
# PoC: {finding title}

## Prerequisites

- {runtime}: {version} (e.g., Node.js >= 18, Python >= 3.9, Bash >= 4)
- {dependency}: {version} (only if absolutely necessary)

## Setup

{Steps to prepare the test environment}

## Execution

\`\`\`bash
{exact command to run}
\`\`\`

## Expected Output

### Vulnerable (unpatched)
\`\`\`
{exact output when vulnerability is present}
\`\`\`

### Not Vulnerable (patched)
\`\`\`
{exact output when vulnerability is fixed}
\`\`\`

## Cleanup

{Any cleanup steps needed after running}
```

## Anti-Patterns

Avoid these common PoC mistakes that cause validation rejection:

| Anti-Pattern | Problem | Correct Approach |
|-------------|---------|------------------|
| Mock servers / fake endpoints | Proves nothing about the real target | Test against actual application code |
| Hardcoded output / `echo "VULNERABLE"` | No actual exploitation | Execute real payloads and observe real responses |
| Committed `node_modules/` or dependencies | Bloats repo, security risk | List deps in README, install at runtime |
| Silent errors (swallowed exceptions) | Hides failures, makes PoC unreliable | Let errors propagate, catch and report explicitly |
| `sleep` as timing proof | Unreliable, environment-dependent | Use measurable side effects (file creation, data extraction) |
| Requires manual steps mid-execution | Not reproducible, introduces human error | Fully automated from start to finish |
| No baseline/negative control | Cannot distinguish vulnerability from normal behavior | Always test benign input first |
| Payload in comments only | "Could be exploited" is not a PoC | Execute the payload and capture the result |
| External service dependencies | Third-party downtime breaks PoC | Self-contained against local/target code |
| Root/admin execution required | Unrealistic attacker position | Run with minimum necessary privileges |

## Format Selection

Choose the PoC format based on the vulnerability type and exploitation method:

| When to Use | Format | Rationale |
|------------|--------|-----------|
| HTTP-based vulns (XSS, SQLI via web, SSRF, IDOR) | `.mjs` | Native `fetch()`, async/await, clean HTTP handling |
| Source-code-level vulns (eval, prototype pollution, deserialization) | `.mjs` | Can import and invoke target code directly |
| System-level vulns (command injection, path traversal, file ops) | `.sh` | Direct system interaction, pipe-friendly |
| Quick single-command verification | `.sh` | Minimal overhead, curl one-liners |
| Complex multi-step exploitation with libraries | `.py` | Rich ecosystem (requests, pwntools, etc.) |
| Blind/timing-based exploitation | `.py` | Better timing control, statistical analysis |
| Binary/crypto exploitation | `.py` | struct, hashlib, crypto libraries |

**Default to `.mjs`** for web application vulnerabilities. Use `.sh` for system-level or quick verifications. Use `.py` only when JavaScript lacks necessary libraries.

## Negative Controls

Every PoC must include negative controls to prove the vulnerability is real and the exploit is specific:

### Benign Payload Test

Run the PoC flow with a benign (non-malicious) input. This must succeed normally (no error, no exploit trigger). This establishes the baseline behavior.

```
Test with benign input: "normal-user-input"
Expected: Normal application behavior, no vulnerability triggered
```

### Blocked Payload Test (When Applicable)

If the vulnerability involves bypassing a control, also test with a payload that the control should block:

```
Test with blocked payload: "<script>alert(1)</script>"  (if testing XSS bypass)
Expected: Blocked by sanitization — confirms the control exists
```

Then test with the actual bypass payload:

```
Test with bypass payload: "<img src=x onerror=alert(1)>"  (actual exploit)
Expected: Bypasses sanitization — confirms the vulnerability
```

This three-test pattern (benign → blocked → bypass) provides the strongest evidence that the vulnerability is real and the bypass is necessary.
