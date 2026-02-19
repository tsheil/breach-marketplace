---
description: "Analyze validated findings for vulnerability chains. This skill should be used when the user asks to find vulnerability chains, analyze finding combinations, identify attack chains, check if findings combine for higher impact, escalate severity through chaining, perform chain analysis on validated findings, find multi-step attack paths, or determine if lower-severity findings combine into critical impact. Operates on validated findings to discover chains that elevate effective severity."
---

# Chain Analysis: Vulnerability Chain Discovery

This skill systematically analyzes validated security findings to identify vulnerability chains — combinations of two or more findings that, when exploited sequentially, produce impact greater than any individual finding alone. A medium-severity IDOR combined with a medium-severity information disclosure can become a critical account takeover chain.

Chain analysis is the bridge between individual finding validation and final reporting. It ensures the report reflects true risk by capturing escalated impact from finding combinations that would be missed by evaluating each finding in isolation.

## Input

### Lifecycle Mode

Read all findings from `findings/validated/`. Parse each finding's `finding.md` to extract:
- `id`, `severity`, `vuln_type`, `affected_component`, `confidence`
- Entry points and sinks from the Exploitability section
- Authentication requirements from the Impact section
- Data types affected from the Vulnerable Code and Impact sections

### Standalone Mode

Accept findings from conversation context. Extract the same fields from the conversation output format.

### Minimum Requirement

Chain analysis requires at least 2 validated findings to perform meaningful analysis. If fewer than 2 findings are available, report:

> Chain analysis skipped: fewer than 2 validated findings. Chain analysis identifies how findings combine for escalated impact and requires at least 2 findings to evaluate.

## Chain Discovery Procedure

### Step 1: Finding Inventory

Build an inventory table of all validated findings:

| ID | Severity | Type | Component | Entry Points | Sinks | Auth Required | Data Types |
|----|----------|------|-----------|-------------|-------|---------------|------------|

For each finding, extract:
- **Entry points**: Where attacker input enters (HTTP params, headers, file uploads, etc.)
- **Sinks**: Where the vulnerability manifests (SQL execution, command execution, file write, redirect, etc.)
- **Auth required**: None, any authenticated user, specific role, admin
- **Data types affected**: Credentials, PII, session tokens, financial data, internal config, etc.

### Step 2: Systematic Chain Pattern Matching

Check every pair of findings against known chain patterns from the `chain-patterns.md` reference file. For N findings, this is N×(N-1)/2 pairs.

Known chain patterns with their effective severity:

| Chain Pattern | Component A | Component B | Combined Impact | Effective Severity |
|---------------|-------------|-------------|-----------------|-------------------|
| IDOR + Info Disclosure | Access control flaw | Data leak | Account takeover | Critical |
| SSRF + Cloud Metadata | Outbound request control | Cloud environment | Infrastructure compromise | Critical |
| Open Redirect + OAuth | URL manipulation | Auth flow | Token theft / account takeover | Critical |
| XSS + CSRF | Script injection | Action forgery | Authenticated action as victim | Critical |
| Path Traversal + File Upload | Storage path control | File write | Remote code execution | Critical |
| Info Disclosure + Password Reset | Data leak | Reset flow flaw | Account takeover | Critical |
| Race Condition + Business Logic | Timing flaw | Financial operation | Financial fraud | Critical |
| SQLi + Privilege Data | Data read | Role/permission tables | Privilege escalation | Critical |
| SSRF + Internal API | Outbound request | No internal auth | Internal service compromise | Critical |
| XSS + Session | Script injection | Cookie access | Session hijacking | High |

For each pair of findings, check:
1. Do the vulnerability types match any known chain pattern (in either order)?
2. Is there a plausible connection between the two findings? (shared application, reachable from similar attack position)

Record all pattern matches for further analysis in Steps 3-4.

### Step 3: Adjacency Analysis

Beyond known patterns, analyze all finding pairs for potential chains based on proximity and data flow:

#### Shared Components
Findings in the same file, module, or service are more likely to chain. Check if:
- Two findings share the same file or directory
- One finding is in a module that imports or calls the other's module
- Both findings affect the same data model or database table

#### Data Flow Connections
Check if one finding's output could feed another finding's input:
- Finding A leaks data (info disclosure, error messages) → Finding B requires that data (IDOR needing valid IDs, auth bypass needing tokens)
- Finding A writes data (file upload, database write) → Finding B reads from that location (path traversal, SQL injection reading stored data)
- Finding A modifies state (race condition, business logic) → Finding B exploits that state

#### Auth Level Escalation
Check if a lower-privilege finding enables a higher-privilege finding:
- Finding A requires no auth → Finding B requires auth → A might provide credentials or session for B
- Finding A is user-level → Finding B is admin-level → A might enable privilege escalation to reach B

#### Sequential Exploitation
Check if finding A creates a precondition for finding B:
- A creates a file that B can then read/execute
- A modifies a configuration that B then exploits
- A establishes a network position that B leverages

### Step 4: Chain Validation

For each potential chain identified in Steps 2-3, validate that the chain is exploitable:

#### 4a: Verify Independent Validity
Confirm each component finding is independently valid. Both findings must be in `validated` status. If either finding was rejected or has low confidence, the chain is speculative.

#### 4b: Confirm Exploitable Connection
Verify the connection between findings is practical, not just theoretical:
- Can the attacker actually use the output of Finding A as input to Finding B?
- Are both findings exploitable from the same attack position (e.g., both reachable as an unauthenticated external attacker)?
- Is the timing feasible (e.g., if A is a race condition, can B be triggered within the race window)?

#### 4c: Construct Combined Attack Path
Build the full chain exploitation path:
1. Initial entry point (from Finding A or whichever is exploited first)
2. First exploitation step (what the attacker gains from the first finding)
3. Pivot or connection (how the output of step 2 feeds into the second finding)
4. Second exploitation step (what the attacker gains from the combined chain)
5. Final impact (the escalated outcome)

#### 4d: Calculate Effective Severity
The effective severity of a chain is always >= the highest individual component severity:

| Highest Component | Chain Impact | Effective Severity |
|-------------------|-------------|-------------------|
| HIGH + HIGH | Escalated impact | CRIT |
| HIGH + MED | Escalated impact | HIGH or CRIT |
| MED + MED | Escalated impact | HIGH or CRIT |
| MED + LOW | Modest escalation | MED or HIGH |
| LOW + LOW | Minimal escalation | MED |

The specific effective severity depends on the combined impact. If the chain achieves RCE, account takeover, or infrastructure compromise, it is CRIT regardless of component severities.

#### 4e: Assign Chain Confidence
- **Confirmed**: Both components confirmed, connection verified end-to-end
- **High**: Both components high confidence, connection is a known pattern
- **Medium**: At least one component is medium confidence, or connection requires specific conditions
- **Low**: Connection is theoretical or requires unusual circumstances

### Step 5: Chain Documentation

#### Lifecycle Mode

For each validated chain, create a chain finding in `findings/validated/`:

1. **Assign an ID**: Follow the same ID assignment as other findings — scan all stages for the highest ID and increment.

2. **Create the finding folder**: Name format `{EFFECTIVE_SEVERITY}-{ID}-CHAIN-{desc}/`
   - Example: `CRIT-008-CHAIN-idor-plus-info-disc-account-takeover/`

3. **Create `finding.md`** using the finding template with chain-specific fields:
   - **Frontmatter**:
     - `id`: The assigned chain ID
     - `title`: Descriptive chain title (e.g., "IDOR + Info Disclosure → Account Takeover")
     - `severity`: The effective severity
     - `vuln_type`: `"CHAIN"`
     - `affected_component`: Primary component from the first link in the chain
     - `stage`: `"validated"`
     - `confidence`: Chain confidence level
     - `chain_components`: List of component finding IDs (e.g., `["003", "005"]`)
     - `source`: `"manual"`
     - `created_at`, `last_moved`: Current ISO 8601 timestamp
   - **Vulnerable Code**: Code snippets from all component findings, clearly labeled, showing the connection point between them
   - **Exploitability**: The full combined attack path from Step 4c — entry point through first finding, pivot, through second finding, to final impact
   - **Impact**: The escalated impact narrative — what the chain achieves that neither finding achieves alone
   - **Remediation**: Fix for the weakest link in the chain. Breaking any single link breaks the entire chain. Recommend fixing the easiest-to-fix component.

4. **Create empty `poc/` directory** inside the finding folder.

#### Standalone Mode

Output each chain to the conversation:

```
### Chain [ID]: [Component A] + [Component B] → [Impact]

**Components**: [Finding IDs]
**Pattern**: [Known pattern name or "Novel chain"]
**Effective Severity**: [Severity] (escalated from [Component A severity] + [Component B severity])
**Confidence**: [Level]

#### Combined Attack Path
[Step-by-step exploitation from entry to final impact]

#### Escalated Impact
[What the chain achieves beyond individual findings]

#### Remediation
[Fix the weakest link]
```

## Output

### Chain Analysis Summary Table

Always output a summary table after analysis, regardless of mode:

| Chain | Components | Pattern | Effective Severity | Confidence |
|-------|-----------|---------|-------------------|------------|

If no chains were found, report that explicitly:

> **Chain analysis complete: no chains identified.**
>
> All [N] validated findings were analyzed for chain potential. No exploitable combinations were found — each finding's impact is accurately represented by its individual severity rating.

Not finding chains is a valid and useful result. It confirms that the individual severity ratings are accurate and do not undercount risk.

## Pipeline Continuation

After completing chain analysis:

- **Lifecycle mode**: Chain findings have been added to `findings/validated/` alongside individual findings. All findings (individual and chain) proceed to human verification in Phase D of the hunt pipeline. Run `/breach:hunt` to continue.
- **Standalone mode**: Chain findings have been output to conversation. Run `/breach:report` to generate the final security report covering both individual and chain findings.
