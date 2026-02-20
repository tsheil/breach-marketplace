---
finding_id: ""
verdict: ""              # CONFIRMED | REJECTED | NEEDS_INVESTIGATION
validated_at: ""         # ISO 8601
initial_cvss: ""         # CVSS:3.1 vector string
adjusted_cvss: ""        # CVSS:3.1 vector string (after devil's advocate)
---

## Scope Check

- [ ] Scope file checked: {path to scope.md or "no scope file found"}
- [ ] Target in scope: YES / NO / UNCERTAIN
- Notes:

## Code Reality Check

- [ ] Every file path in the finding exists and is readable
- [ ] Every function referenced exists at the stated line numbers
- [ ] Data flow chain verified: source → transform → sink traced end-to-end
- [ ] No hallucinated code, file paths, or function names
- Verified paths:
- Failed paths (if any):

## Reproduction Log

### Attempt 1 (Same Environment)
- Result: PASS / FAIL
- Output:

### Attempt 2 (Fresh Session)
- Result: PASS / FAIL
- Output:

### Attempt 3 (Different Context)
- Result: PASS / FAIL
- Output:

- Overall: {2/3 or 3/3} reproductions succeeded
- Notes on any failures:

## Production Configuration Check

- [ ] Application is not in debug/development mode
- [ ] Default security features are not disabled
- [ ] No non-standard configuration flags required
- Config verified against: {production defaults / documented config / unable to verify}
- Non-default settings required (if any):
- Evidence that non-default settings are common in real deployments (if applicable):
- Result: PASS / FAIL / UNABLE_TO_VERIFY

## Anti-Speculation Check

- [ ] No speculative language ("could potentially," "might allow," "it is possible that") remains in finding
- [ ] All impact claims backed by PoC evidence or reproduction output
- [ ] Chain claims reference validated component findings only
- Speculative claims found and resolved:
- Demonstrated vs. theoretical impact split:
  - Demonstrated: {what the PoC proves}
  - Theoretical maximum: {what could be possible, if applicable}
- Result: PASS / FAIL

## Footgun Assessment

Answer each question YES or NO:

1. Is the vulnerable configuration the application's default? YES / NO
2. Would a real-world deployment realistically use this configuration? YES / NO
3. Does exploitation produce meaningful attacker benefit? YES / NO
4. Is the exploit practical without insider knowledge? YES / NO
5. Would a security-aware developer consider this a bug (not a feature)? YES / NO

- Score: {count of NO answers}/5
- Decision: PROCEED (0-1) / BORDERLINE (2-3, justification required) / REJECT (4-5)
- Justification (if borderline):

## Triager Checklist

- [ ] Attacker reachability: PASS / FAIL
- [ ] Impact concreteness: PASS / FAIL
- [ ] Exploitation realism: PASS / FAIL
- [ ] Scope confidence: PASS / FAIL
- Overall: {count}/4 passed
- Notes:

## Severity Assessment

### Initial CVSS

- Vector: CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_
- Score:
- Severity:

### Devil's Advocate

Why should this severity be LOWER? (Must provide at least one argument)

-

### Adjusted CVSS

- Vector: CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_
- Score:
- Severity:
- Adjustment reason (if changed):

## Deduplication Check

- [ ] Hacktivity search: {platform} — {result}
- [ ] CVE database search: {query} — {result}
- [ ] Own prior reports: {result}
- [ ] Local findings directory: {result}
- [ ] Patch history (git log): {result}
- Duplicate found: YES / NO
- If duplicate: {ID or reference}

## Cross-Validation

- Tool used: {ask-gemini / ask-codex / none}
- Agreement: YES / NO / PARTIAL
- Notes:

## Final Verdict

**Verdict**: CONFIRMED / REJECTED / NEEDS_INVESTIGATION

**Reason**:

**Next action**:
- CONFIRMED → Move to `findings/validated/`, update finding.md frontmatter
- REJECTED → Move to `findings/rejected/`, set `rejection_reason` in finding.md
- NEEDS_INVESTIGATION → Keep in current stage, document what needs resolution
