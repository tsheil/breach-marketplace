---
name: breach-validate-finding
description: "Validate security findings with anti-hallucination gates, triager analysis, and strict evidence. This skill should be used when the user wants to validate vulnerability findings, verify PoC exploits, prove a vulnerability is exploitable, verify findings are not false positives, confirm a vulnerability is real, triage security findings, check scope compliance, run deduplication, apply footgun detection, prepare evidence for a security report, process findings through the validation stage, or advance findings in the finding lifecycle. This is the validation phase following the code analysis phase in the breach pipeline."
---

# Validate Finding

Validation turns raw findings into defensible evidence through a 4-phase, 12-step procedure with hard gates that reject hallucinated, out-of-scope, footgun, and duplicate findings. Every finding that reaches the report must survive this phase — no exceptions, no shortcuts. If the evidence bar isn't met, the finding goes to rejected, not forward to report.

## Evidence Bar (Non-Negotiable)

Every finding requires ALL 6 elements. Missing any one of them means the finding is incomplete and gets sent back for further investigation. Do not attempt to "fill in the gaps" with assumptions — if the data isn't there, the finding isn't ready.

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

For each raw finding, execute this 4-phase, 12-step procedure in order. Do not skip steps. Do not reorder. Hard gates halt processing on failure.

---

### Phase 0: Gates

#### Step 0: Scope Verification

**Type**: Hard gate — PASS / FAIL / UNCERTAIN

Check whether the finding's target is in scope:

1. Look for a `scope.md` file in the current working directory or parent directories (up to 5 levels).
2. If found, check whether the affected component (file path, endpoint, domain) falls within the defined scope.
3. **PASS**: Target is explicitly in scope. Proceed.
4. **FAIL**: Target is explicitly out of scope. REJECT the finding immediately with reason "out of scope."
5. **UNCERTAIN**: No scope file found, or scope is ambiguous. Proceed with a note — flag for human review.

#### Step 0.5: Quick Triage Gate

**Type**: Soft gate — deprioritize on failure, do not hard reject

Answer three questions about the finding:
1. **Default configuration?** Does the vulnerability exist in the application's default configuration, or does it require non-standard setup?
2. **Realistic scenario?** Would this vulnerability plausibly be triggered by a real attacker, or does it require contrived conditions?
3. **Meaningful impact?** If exploited, does the attacker gain something of value, or is the impact purely theoretical?

If any answer is "no," flag the finding as low-priority but continue validation. If all three are "no," consider rejecting early — but document the rationale.

---

### Phase 1: Verification

#### Step 1: Context Recovery

Re-read the vulnerable code in full context. Not just the flagged line — the entire function, the class definition, the module imports, and any relevant configuration. Understand what the code is supposed to do before assessing what it actually does. Check the git history for the file: was this code recently modified? Is it actively maintained or abandoned? Are there related tests that might reveal intended behavior?

Confirm the code path is reachable from an external entry point. Dead code and internal-only utilities are not vulnerabilities — they're technical debt. Trace backwards from the vulnerable function to at least one externally-accessible caller.

#### Step 2: Control Enumeration

Identify ALL mitigating controls between the entry point and the vulnerable sink. Be thorough — a missed control is the most common cause of false positives. Check for:

- **Framework-level protections**: Django's ORM auto-escaping, Rails' strong parameters, Spring's CSRF tokens, Express's helmet headers, ASP.NET's request validation. These are often invisible in the application code itself.
- **Middleware**: Authentication middleware, authorization decorators, input sanitization layers, rate limiters, request size limits.
- **Application-level validation**: Input validation functions, allowlists/denylists, type checking, schema validation (JSON Schema, Pydantic, Marshmallow, Joi).
- **Infrastructure controls**: WAF rules, CSP headers, CORS configuration, network segmentation that limits exploitation scope.
- **Language/runtime protections**: Type safety, memory safety, automatic escaping in template engines.

For each control identified, assess whether it's effective against this specific attack vector. A CSRF token doesn't mitigate SQL injection. An XSS filter doesn't stop IDOR. Be precise about what each control actually prevents.

#### Step 3: Exploit Path Construction

Determine the exact input that triggers the vulnerability. This is not theoretical — construct the actual HTTP request, CLI command, file content, or message payload that would exploit the vulnerability. Trace from entry point to vulnerable sink with every transformation noted.

Document:
- The raw input an attacker would provide
- Each transformation applied to that input (URL decoding, JSON parsing, string operations, etc.)
- The state of the input when it reaches the vulnerable operation
- Why the input is still malicious at the point of exploitation

#### Step 3.5: Code Reality Check

**Type**: Hard gate — HARD REJECT on failure

This is the anti-hallucination gate. For every claim in the finding:

1. **Read every file path** referenced in the finding. Use the Read tool. If a file doesn't exist, the finding is hallucinated.
2. **Grep every function name** referenced. Confirm it exists at or near the stated line numbers. If a function doesn't exist or is at a completely different location, the finding is hallucinated.
3. **Verify line numbers** are within ±5 lines of reality. Code changes since analysis are acceptable; completely wrong line numbers are not.
4. **Trace the data flow chain** end-to-end. Read each file in the chain and confirm that function A actually calls function B, that variable X is actually passed to function Y. If any link in the chain is fabricated, the finding is hallucinated.

**HARD REJECT** if any of the above checks fail. Set `rejection_reason` to the specific hallucination found (e.g., "Function `processInput` does not exist in `src/handlers/auth.js`"). Do not attempt to fix hallucinated findings — reject them cleanly.

#### Step 4: Framework Protection Audit

Separately from Step 2, specifically check for framework-level protections that might not be visible in the application code. This is a dedicated step because these protections are the most commonly missed and the most frequent cause of false positives.

Check the framework's default configuration. Check whether the application has explicitly disabled any defaults. Check the framework's version for known bypass techniques. Check middleware ordering — a protection that runs after the vulnerable code is no protection at all.

#### Step 4.5: Footgun vs Framework Gate

**Type**: Soft gate with scoring

Answer these 5 questions (YES = safe to proceed, NO = potential footgun):

1. Is the vulnerable configuration the application's **default**? (YES = default, NO = custom/non-standard)
2. Would a real-world deployment **realistically** use this configuration? (YES = common, NO = unusual)
3. Does exploitation produce **meaningful** attacker benefit? (YES = real impact, NO = trivial)
4. Is the exploit practical **without insider knowledge**? (YES = external attacker, NO = requires internals)
5. Would a security-aware developer consider this a **bug** (not a feature)? (YES = bug, NO = design choice)

**Scoring**:
- **0-1 "NO" answers**: Proceed — this is a real vulnerability.
- **2-3 "NO" answers**: Borderline. Proceed ONLY with written justification for why this is still worth reporting despite the footgun indicators. Include justification in the validation result.
- **4-5 "NO" answers**: REJECT. This is a footgun, not a vulnerability. Set `rejection_reason` to "footgun: [specific reasons]".

---

### Phase 2: Reproduction & PoC

#### Step 5: 3x Reproduction

Attempt to reproduce the vulnerability 3 times under different conditions:

1. **Same environment**: Reproduce using the exact same conditions as the original discovery. This confirms the finding is stable, not a fluke.
2. **Fresh session**: Clear any cached state, restart services if applicable, and reproduce. This confirms the finding doesn't depend on stale state.
3. **Different context**: Vary something — different user account, different input value (same vulnerability class), or different endpoint using the same vulnerable code path. This confirms the vulnerability is systematic, not a one-off.

**For source-code-only analysis** (no running application): 2/3 is acceptable if the static trace is strong. Document which reproduction was skipped and why. The code reality check (Step 3.5) serves as compensation.

**Results**: Record each attempt's outcome (PASS/FAIL) with output. 2/3 minimum to proceed. 1/3 or 0/3 = REJECT.

#### Step 6: PoC Verification

**Changed from old Step 5 (PoC Generation)**: This step now **verifies** existing PoCs rather than generating new ones. PoC authoring is the concern of the `findings` skill's PoC standards.

If a PoC exists in the finding's `poc/` directory:
1. Check that it meets the standards defined in `/breach:findings` → `references/poc-standards.md`: exit codes (0=vulnerable, 1=not), output markers (`[VULNERABLE]`/`[NOT_VULNERABLE]`), summary block, header with metadata.
2. Check for negative controls (benign input test).
3. Check that the PoC is self-contained and runs without manual intervention.
4. Note any gaps — don't silently accept a bad PoC.

If no PoC exists:
1. Note the gap in the validation result.
2. If the finding has strong evidence from Steps 1-4, proceed without a PoC but downgrade confidence by one level.
3. If the finding is borderline, a missing PoC tips it to REJECT.

#### Step 6.5: Real PoC Gate

**Type**: Hard gate (only if PoC exists)

If a PoC was provided or generated, verify all of these:

1. **Executes without errors**: Run the PoC. It must complete without uncaught exceptions, syntax errors, or missing dependencies.
2. **Runs against real code**: The PoC must target the actual vulnerable code path, not a mock server or contrived environment.
3. **Captures real output**: The PoC must show actual application responses, not hardcoded or fabricated output.
4. **Completes in <5 minutes**: A PoC that takes longer than 5 minutes is not practical for triager reproduction.

**HARD REJECT the PoC** (not necessarily the finding) if any check fails. The finding can still proceed if other evidence is strong enough, but confidence is downgraded.

---

### Phase 3: Assessment & Dedup

#### Step 7: Impact Verification

Verify that the claimed impact matches what the PoC (or reproduction attempts) actually demonstrates:

- If the finding claims "full database exfiltration" but the PoC only shows a single row, the severity justification is overstated.
- If the finding claims "RCE" but the PoC only shows command output, verify that arbitrary commands can be executed (not just the one in the PoC).
- If the finding claims "account takeover" but the PoC only shows information disclosure, the chain is incomplete.

Adjust the severity and impact description to match the **demonstrated** impact, not the theoretical maximum.

#### Step 7.5: Triager Perspective

**Type**: Pass/fail checklist

Load `references/triager-analysis.md` and evaluate the finding from a bug bounty triager's perspective.

Apply the 4-dimension checklist:
1. **Attacker reachability**: Can an external attacker reach this code path? PASS / FAIL
2. **Impact concreteness**: Is the impact specific and demonstrated? PASS / FAIL
3. **Exploitation realism**: Does the PoC work without fabricated conditions? PASS / FAIL
4. **Scope confidence**: Is the target in scope and the vuln in first-party code? PASS / FAIL

All 4 must PASS for CONFIRMED verdict. Any FAIL requires either fixing the gap or rejecting the finding.

Also check the finding against the "Common N/A Patterns" list and "AI Slop Detection" patterns in the reference file.

#### Step 8: Confidence & Severity

Assign a confidence level based on evidence strength:

- **Confirmed**: Code path verified end-to-end, no mitigating controls found or all controls demonstrated bypassable, exploit path clear and reproducible. This finding will survive scrutiny.
- **High**: Code path verified, minor controls exist but are demonstrably bypassable or insufficient, exploit path clear. Minimal risk of false positive.
- **Medium**: Code path likely reachable based on static analysis, some controls present that may partially mitigate, exploit requires specific conditions (particular configuration, race timing, user interaction). Needs runtime verification to confirm.
- **Low**: Code path may be reachable but static analysis is inconclusive, controls may fully mitigate, exploitation is theoretical without runtime testing. Include in report only if the potential impact is Critical.

**Devil's advocate (mandatory)**: Before finalizing severity, you MUST argue why the severity should be LOWER than your initial assessment. Consider:
- What if the control you dismissed actually works?
- What if the attacker pool is smaller than assumed?
- What if the impact is contained to a single user?
- What if the configuration is non-default?

Record the initial CVSS vector/score, the devil's advocate argument, and the adjusted CVSS vector/score (which may be the same if the argument doesn't hold). This is not optional — skipping the devil's advocate invalidates the validation.

#### Step 9: Deduplication Check

**Type**: Hard gate — REJECT if duplicate found

Run a 5-step deduplication check:

1. **Hacktivity search**: If the target has a bug bounty program, check public disclosures for similar vulnerabilities. Use `/breach:hackerone` if available.
2. **CVE database search**: Search for known CVEs affecting the same component, framework version, or library version.
3. **Own prior reports**: Check if you've already reported a similar finding to this program.
4. **Local findings directory**: If in lifecycle mode, scan all finding folders in all stages for findings affecting the same file:line range (±3 lines).
5. **Patch history**: Check git log for the affected file — was this vulnerability previously patched and reintroduced, or is there a pending fix?

If a duplicate is found:
- **Exact duplicate** (same root cause, same code location): REJECT with `rejection_reason: "duplicate of {ID or reference}"`.
- **Related but distinct** (same vulnerability class, different location): Proceed but note the relationship.
- **Previously patched**: Verify the patch was ineffective (regression) or was never deployed. If regression, this is a valid new finding.

#### Step 9.5: Cross-Validation (Optional)

If high-stakes or borderline findings need a second opinion, use external AI tools:

**ask-gemini template**:
```
I have a security finding claiming [vuln type] in [component]. The exploit path is [path]. What am I missing? What controls might I have overlooked? Is this severity justified?
```

**ask-codex template**:
```
Review this vulnerability finding for false positive indicators: [finding summary]. Check if [framework] has default protections against [attack type].
```

This step is not mandatory. Use it for findings where confidence is Medium or the footgun score was 2-3.

---

### Phase 4: Verdict

#### Step 10: Final Checklist & Verdict

Run the final checklist before rendering a verdict:

- [ ] Evidence bar: All 6 elements present and verified
- [ ] Scope: In scope (or UNCERTAIN with note)
- [ ] Code reality: All file paths, functions, and line numbers verified
- [ ] Reproduction: 2/3 or 3/3 attempts succeeded
- [ ] Footgun score: 0-1 (or 2-3 with justification)
- [ ] Triager checklist: 4/4 passed
- [ ] Devil's advocate: Argument recorded, severity adjusted if warranted
- [ ] Deduplication: Not a duplicate
- [ ] Impact: Claimed impact matches demonstrated impact

**CONFIRMED**: All checks pass. Create `validation-result.md` from `templates/validation-result-template.md`, update finding.md frontmatter, move to `findings/validated/`.

**REJECTED**: Any hard gate failed, or cumulative soft failures make the finding unreportable. Set `rejection_reason`, move to `findings/rejected/`.

**NEEDS_INVESTIGATION**: Evidence is strong but a specific gap needs resolution (e.g., need runtime access to confirm). Keep in current stage, document what's needed.

---

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

## Lifecycle-Aware Mode

Before processing findings, check whether a `findings/` directory exists in the current working directory or any parent directory (up to 5 levels). The `findings/` directory is recognized by having stage subdirectories (`potential/`, `confirmed/`, `validated/`, `verified/`, `reported/`, `rejected/`).

For finding structure, naming conventions, and lifecycle stage definitions, refer to `/breach:findings`.

### If `findings/` directory is found: Lifecycle Mode

Process findings from `findings/potential/` and `findings/confirmed/`:

1. **Read each finding**: Parse `finding.md` from each finding folder in `potential/` and `confirmed/`.
2. **Apply full validation procedure**: Execute all 4 phases (Gates, Verification, Reproduction & PoC, Assessment & Dedup) and triage criteria against each finding.
3. **On CONFIRMED verdict**:
   - Create `validation-result.md` in the finding folder from `templates/validation-result-template.md`
   - Verify PoC in `poc/` directory meets standards (see Step 6). If missing, note the gap.
   - Update `finding.md`: populate all sections (Proof of Concept, Impact, Remediation, References), update frontmatter fields (`cvss_score`, `cvss_vector`, `confidence`, `stage` to "validated", `last_moved` to current ISO 8601 timestamp)
   - Move the finding folder to `findings/validated/`
   - If severity changed during validation, rename the folder to match the new severity prefix and update `severity` in frontmatter (see `/breach:findings` for renaming rules)
4. **On REJECTED verdict**:
   - Update `finding.md` frontmatter: set `stage` to "rejected", `rejection_reason` explaining why, `last_moved` to current timestamp
   - Move the finding folder to `findings/rejected/`
5. **Output summary table** to conversation after processing all findings:

| ID | Severity | Type | Component | Result | Confidence/Reason |
|----|----------|------|-----------|--------|-------------------|

### If no `findings/` directory is found: Standalone Mode

Operate identically to non-lifecycle behavior: process findings from conversation context, output validated findings to conversation using the Output Format below. No filesystem changes.

## Output Format

In lifecycle mode, validated findings are written to `finding.md` files in the `findings/validated/` directory with accompanying `validation-result.md`. Conversation output is a summary table of results (see Lifecycle-Aware Mode above).

In standalone mode, for each validated finding, produce the following structure. Do not deviate from this format — consistency enables automation and review.

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

Validation complete.

- **Lifecycle mode**: Validated findings are in `findings/validated/` with `validation-result.md` artifacts. Human verification is required before reporting — move approved findings from `findings/validated/` to `findings/verified/` and update the `stage` field in frontmatter. Then run `/breach:report` or re-run `/breach:hunt` to generate the final security report.
- **Standalone mode**: Run `/breach:report` to generate the final security report from conversation context.
