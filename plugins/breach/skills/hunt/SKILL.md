---
name: breach-hunt
description: "Hunt for vulnerabilities with an autonomous looping breach pipeline. This skill should be used when the user asks to hunt for vulnerabilities, perform a security audit, run a comprehensive code security review, execute the full breach pipeline, manage the finding lifecycle, run code-recon through reporting, or perform systematic vulnerability discovery and validation. Orchestrates initialization, then loops discovery-validation continuously — each pass finds different vulnerabilities through non-deterministic analysis. Runs until the user stops it."
---

# Hunt: Autonomous Breach Pipeline

This skill orchestrates the breach pipeline as an autonomous loop. After one-time initialization (recon + static scan), it continuously cycles through code analysis, deduplication, validation, and chain analysis. Each iteration intentionally varies its focus — different code areas, vulnerability classes, and attacker perspectives — exploiting the non-deterministic nature of AI analysis to maximize coverage over time.

The loop runs until the user stops it. Each phase invokes a specialized skill. All skills remain independently invocable outside this orchestrator.

## Findings Directory Detection

Before executing the pipeline, detect or create the findings directory:

1. Check the current working directory for a `findings/` directory containing stage subdirectories (`potential/`, `confirmed/`, `validated/`, `verified/`, `reported/`, `rejected/`).
2. If not found in the current directory, walk up parent directories (maximum 5 levels) looking for the same structure.
3. If no existing `findings/` directory is found anywhere, create one in the current working directory with all 6 stage subdirectories:

```
findings/
├── potential/
├── confirmed/
├── validated/
├── verified/
├── reported/
└── rejected/
```

Create this silently — do not prompt the user for confirmation.

Also check for `findings/hunt-coverage.md`. This file tracks strategy usage and component/vuln-class coverage across iterations. If it exists, resume tracking from its recorded state. If it does not exist, it will be created at the end of the first iteration.

## Pipeline Execution

### Phase A: Initialization (runs once)

#### A.1 Findings Directory

Detect or create the findings directory as described above.

#### A.2 Reconnaissance

Invoke `/breach:code-recon` on the target codebase to map the attack surface. This produces a prioritized map of entry points, trust boundaries, authentication mechanisms, and threat model context that feeds into the discovery loop.

If the user has already run code-recon or provides recon output, skip this step.

#### A.3 Custom Rule Generation

Invoke `/breach:custom-rules` using the code-recon output from A.2. This generates codebase-specific Semgrep rules and CodeQL queries targeting application-specific patterns that stock rulesets miss — custom auth decorators, homegrown sinks, framework-specific behaviors, and trust boundary violations.

Rules are written to `custom-rules/semgrep/` and `custom-rules/codeql/` in the project root. These are automatically picked up by static-scan in the next step.

If Semgrep and CodeQL are both unavailable, skip this step.

#### A.4 Static Scan

Invoke `/breach:static-scan` for deterministic pattern matching and dataflow analysis. Static scanning is deterministic — identical results every run — so it executes once during initialization, not inside the loop.

If `custom-rules/` exists in the project root, static-scan automatically includes custom rulesets alongside stock rules (see `/breach:static-scan` for details).

Tool-generated findings include a `source` field in frontmatter ("semgrep" or "codeql"). Findings are created in `findings/potential/`.

If static-scan tools are unavailable and the user declines installation, skip this step.

#### A.5 Validate Static-Scan Findings

Process all findings from static-scan in `findings/potential/` through `/breach:validate-finding`:

- **Validated findings**: Update finding.md with all sections (PoC, Impact, Remediation, References) and frontmatter fields (cvss_score, cvss_vector, confidence). Create `validation-result.md`. Verify PoC scripts in the `poc/` directory. Move to `findings/validated/`.
- **Rejected findings**: Set `rejection_reason` in finding.md frontmatter, update stage to "rejected", move to `findings/rejected/`.

### Phase B: Discovery Loop (repeats until user stops)

After initialization completes, begin the autonomous discovery loop. Repeat B.1 through B.5 continuously. Do not stop unless the user interrupts.

#### B.1 Code Analysis

Invoke `/breach:code-analysis` to discover vulnerabilities through manual code review. Manual findings have `source: "manual"` in frontmatter.

**Variant-hunt conditional.** When the selected analysis approach (B) is `variant-hunt`:
- Instead of invoking `/breach:code-analysis`, invoke `/breach:variant-analysis`
- Select a validated finding from `findings/validated/` (prefer findings not yet variant-analyzed, i.e., no existing findings with `variant_of` pointing to that ID)
- Continue with B.2 (dedup) and B.3 (validate) as normal

**Coverage-driven focus selection.** Before starting analysis, read `findings/hunt-coverage.md` (if it exists) and select focus across 4 dimensions, choosing the least-used values from the Strategy Usage Log:

- **A — Territory**: Select components from the Coverage Matrix gaps (cells marked `-`). Prioritize components with the fewest covered vuln classes.
- **B — Analysis Approach**: Pick the least-used from: `broad-sweep` (survey many components quickly), `deep-dive` (exhaustive review of one component), `variant-hunt` (find variations of validated findings), `reverse-trace` (start from dangerous functions and trace inputs backwards), `adversarial-rejections` (re-examine rejected findings from a different angle).
- **C — Attacker Perspective**: Pick the least-used from: `unauth-external` (unauthenticated external attacker), `auth-regular` (authenticated regular user), `privileged-admin` (privileged/admin user), `malicious-insider` (malicious insider with code access).
- **D — Vuln Class Focus**: Pick the least-used OWASP category from: `a01` (Broken Access Control), `a02` (Cryptographic Failures), `a03` (Injection), `a04` (Insecure Design), `a05` (Security Misconfiguration), `a06` (Vulnerable Components), `a07` (Auth Failures), `a08` (Data Integrity Failures), `a09` (Logging Failures), `a10` (SSRF).
- **E — Recency**: If code-recon output includes a Hot Components table, prioritize components listed there. When selecting Territory (A), prefer hot components that also have coverage gaps. Components with recent security-relevant commits, reverted patches, or newly introduced entry points should be analyzed before stable, well-tested components.

**Auto-shift on diminishing returns.** When `consecutive_dry_iterations >= 3` (three consecutive iterations with zero validated findings), trigger an auto-shift: select the least-used value in ALL five dimensions (A-E) simultaneously, reset the dry streak counter to 0, and announce the shift before proceeding.

Announce the selected focus before invoking code-analysis:
```
Focus: {approach} + {perspective} + {vuln_class} on {components}
```

If `findings/hunt-coverage.md` does not exist yet (first iteration), choose freely and the file will be created at the end of this iteration.

#### B.2 Deduplicate New Findings

Before validation, deduplicate new findings in `findings/potential/` against all existing findings across all stages (`validated/`, `rejected/`, `reported/`, `verified/`).

Check if two findings reference the same file:line range (allowing ±3 lines tolerance). When a duplicate is found, reject the new finding with `rejection_reason: "duplicate of {ID}"` and move it to `findings/rejected/`.

Keep the finding with richer context (typically the one with more detailed exploitability analysis). If the new finding has better analysis than the existing one, keep the new finding and reject the existing one.

#### B.3 Validate New Findings

Process remaining (non-duplicate) findings in `findings/potential/` through `/breach:validate-finding`:

- Apply the full 4-phase validation procedure (gates, verification, reproduction & PoC, assessment & dedup), triage criteria, CVSS scoring, and confidence assignment.
- **Validated findings**: Update finding.md with all sections and frontmatter fields. Create `validation-result.md`. Verify PoC scripts. Move to `findings/validated/`.
- **Rejected findings**: Set `rejection_reason`, update stage, move to `findings/rejected/`.

#### B.4 Chain Analysis

Invoke `/breach:chain-analysis` on all findings in `findings/validated/`. This identifies vulnerability chains where two or more findings combine for escalated impact. Chain findings are added to `findings/validated/`.

If fewer than 2 validated findings exist, skip chain analysis.

#### B.5 Iteration Summary

After completing B.4, update `findings/hunt-coverage.md`:

1. **Update YAML frontmatter**: Increment `total_iterations`, update `consecutive_dry_iterations` (reset to 0 if new validated findings this iteration, increment otherwise), set `last_updated` to current timestamp, set `current_strategy_focus` to this iteration's focus string.
2. **Append row to Strategy Usage Log**: Record iteration number, approach (B), perspective (C), vuln class (D), components targeted, new validated count, new rejected count.
3. **Update Coverage Matrix**: For each component-vuln class pair analyzed this iteration, write the iteration number into the corresponding cell (replacing `-`).
4. **Regenerate Uncovered Territory**: List components and vuln classes with no coverage (cells still `-`).

If `findings/hunt-coverage.md` does not exist, create it with the full format (see Coverage Tracking section below) and populate with this iteration's data.

Print a compact summary between iterations:

```
── Iteration {N} Complete ──────────────────────────
Focus this iteration:         {approach} + {perspective} + {vuln class} on {components}
New findings this iteration:  {count} discovered, {validated} validated, {rejected} rejected
Cumulative:                   {total_validated} validated, {total_rejected} rejected, {total_chains} chains
Coverage:                     {filled}/{total} component-vuln pairs ({percent}%)
Dry streak:                   {consecutive_dry} iterations ({remaining} until auto-shift)
Next iteration focus:         {planned focus}
────────────────────────────────────────────────────
```

When an auto-shift is triggered, use this variant instead:

```
── Iteration {N} Complete ── AUTO-SHIFT TRIGGERED ──
Focus this iteration:         {approach} + {perspective} + {vuln class} on {components}
New findings this iteration:  0 discovered, 0 validated, 0 rejected
Cumulative:                   {total_validated} validated, {total_rejected} rejected, {total_chains} chains
Coverage:                     {filled}/{total} component-vuln pairs ({percent}%)
Dry streak:                   3 iterations → AUTO-SHIFTING to least-explored dimensions
Next iteration focus:         {auto-selected focus across all 4 dimensions}
────────────────────────────────────────────────────
```

Then immediately begin the next iteration at B.1. Do not pause or ask for confirmation.

### Coverage Tracking

The `findings/hunt-coverage.md` file provides persistent strategy tracking across iterations. It is created automatically at the end of the first iteration and updated at the end of every subsequent iteration.

#### File Format

```markdown
---
created_at: ""
last_updated: ""
total_iterations: 0
consecutive_dry_iterations: 0
last_shift_iteration: 0
current_strategy_focus: ""
---

# Hunt Coverage Tracker

## Strategy Usage Log

| Iter | Analysis Approach (B) | Attacker Perspective (C) | Vuln Class Focus (D) | Recency (E) | Components Targeted | New Validated | New Rejected |
|------|----------------------|--------------------------|---------------------|-------------|---------------------|---------------|--------------|

## Coverage Matrix

| Component | A01 | A02 | A03 | A04 | A05 | A06 | A07 | A08 | A09 | A10 |
|-----------|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|

## Uncovered Territory

Components not yet analyzed: (derived from recon)
Vuln classes not yet applied: (derived from OWASP A01-A10)
```

#### YAML Frontmatter Fields

| Field | Description |
|-------|-------------|
| `created_at` | ISO 8601 timestamp when the file was created (first iteration) |
| `last_updated` | ISO 8601 timestamp of the most recent update |
| `total_iterations` | Total number of completed iterations |
| `consecutive_dry_iterations` | Number of consecutive iterations with zero validated findings |
| `last_shift_iteration` | Iteration number when auto-shift was last triggered (0 if never) |
| `current_strategy_focus` | Human-readable string of the current focus (e.g., "deep-dive + auth-regular + a01 on auth-module") |

#### Strategy Usage Log

One row per completed iteration. Used to determine least-used values across dimensions B, C, and D.

#### Coverage Matrix

Components (rows) are derived from code-recon output. OWASP categories A01-A10 are columns. Each cell contains the iteration number when that component-vuln class pair was analyzed, or `-` if not yet covered.

The matrix is populated from code-recon components at file creation. New components discovered during analysis are added as new rows.

#### Uncovered Territory

Derived section listing:
- Components with the most `-` cells (least coverage)
- Vuln classes (columns) with the most `-` cells
- Specific component-vuln pairs never analyzed

#### Auto-Shift Algorithm

When `consecutive_dry_iterations` reaches 3:
1. Select the analysis approach (B) with the fewest uses in Strategy Usage Log
2. Select the attacker perspective (C) with the fewest uses
3. Select the vuln class (D) with the fewest uses
4. Select the component (A) with the most `-` cells in Coverage Matrix, preferring hot components (E) when available
5. Reset `consecutive_dry_iterations` to 0
6. Record `last_shift_iteration` as the current iteration number
7. Announce the auto-shift before proceeding to B.1

#### Backward Compatibility

- First iteration: `hunt-coverage.md` does not exist — choose focus freely, create file at iteration end
- Missing file on subsequent invocations: treat as fresh start (no prior data)
- File exists: resume from recorded state

### Phase C: Review & Reporting (after user stops the loop)

When `/breach:hunt` is re-invoked after the user has stopped the loop:

1. Check `findings/verified/` first. If verified findings exist:
   - Invoke `/breach:report` to generate a complete security report covering all verified findings
   - For each reported finding, update finding.md (`stage` to "reported", `last_moved` to current timestamp) and move the folder to `findings/reported/`
2. After reporting, print a final summary and ask if the user wants to start a new discovery cycle on the same or different target.

If no verified findings exist on re-invocation, check for findings in other stages:
- If `validated/` has findings but `verified/` is empty: print the summary table of validated findings and instruct the user to verify before reporting:

> **Human verification required before reporting.**
>
> Review each validated finding. To approve a finding for reporting:
> 1. Move its folder from `findings/validated/` to `findings/verified/`
> 2. Update the `stage` field in `finding.md` frontmatter to `"verified"`
> 3. Update `last_moved` to the current timestamp
> 4. Optionally add `reviewer_notes` in the frontmatter
>
> To reject a finding: move it to `findings/rejected/` and set `rejection_reason`.
>
> When ready, re-run `/breach:hunt` to generate reports for verified findings.

- If `potential/` has findings: resume from validation (B.3)
- If all stages are empty: start a fresh pipeline from Phase A

## Standalone Skills Note

All breach skills remain independently invocable:

- `/breach:code-recon` — Attack surface mapping (standalone)
- `/breach:static-scan` — Automated Semgrep + CodeQL scanning (lifecycle-aware or standalone)
- `/breach:code-analysis` — Manual vulnerability discovery (lifecycle-aware or standalone)
- `/breach:validate-finding` — Finding validation with anti-hallucination gates, triager analysis, and PoC verification (lifecycle-aware or standalone)
- `/breach:findings` — Canonical reference for finding structure, naming, lifecycle, and PoC standards
- `/breach:custom-rules` — Custom Semgrep/CodeQL rule generation (standalone or pipeline)
- `/breach:variant-analysis` — Variant analysis from findings, CVEs, or patterns (lifecycle-aware or standalone)
- `/breach:chain-analysis` — Vulnerability chain discovery (lifecycle-aware or standalone)
- `/breach:report` — Report generation (lifecycle gate in lifecycle mode, no gate in standalone)

The orchestrator coordinates these skills but does not replace them.

## Edge Cases

### Severity Changes During Validation

If validation determines a different severity than initially assessed:
1. Rename the finding folder to reflect the new severity (e.g., `HIGH-003-SQLI-endpoint/` → `MED-003-SQLI-endpoint/`)
2. Update the `severity` field in finding.md frontmatter
3. The ID remains unchanged

### Partial Pipeline Resume

The orchestrator detects the current state by examining which stage directories contain findings:
- Findings in `potential/` only → resume from validation (B.3)
- Findings in `validated/` → instruct user to verify before reporting
- Findings in `verified/` → proceed to reporting (Phase C)
- Mix of stages → process each stage appropriately (validate potential, report verified)
- `hunt-coverage.md` exists → resume coverage tracking from recorded state

### Re-discovery with Existing Findings

When running a new discovery cycle while previous findings exist:
- New finding IDs continue the global sequence (scan all stages for max ID)
- Existing findings in any stage are not modified or re-processed
- Only new findings in `potential/` are validated

### Tool-Manual Deduplication

Tool findings may duplicate manual findings when both Semgrep/CodeQL and Claude identify the same vulnerability. During validation, deduplicate by checking if two findings reference the same file:line range (±3 lines tolerance). Keep the finding with richer context (typically the manual finding) and reject the duplicate with reason "duplicate of {ID}".

## References

- `security-review-principles.md` — Mindset, evidence standards, methodology, severity calibration, and exclusion criteria
- `/breach:findings` — Canonical finding.md template, lifecycle stages, naming conventions, ID assignment, and PoC standards
