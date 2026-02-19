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

## Pipeline Execution

### Phase A: Initialization (runs once)

#### A.1 Findings Directory

Detect or create the findings directory as described above.

#### A.2 Reconnaissance

Invoke `/breach:code-recon` on the target codebase to map the attack surface. This produces a prioritized map of entry points, trust boundaries, authentication mechanisms, and threat model context that feeds into the discovery loop.

If the user has already run code-recon or provides recon output, skip this step.

#### A.3 Static Scan

Invoke `/breach:static-scan` for deterministic pattern matching and dataflow analysis. Static scanning is deterministic — identical results every run — so it executes once during initialization, not inside the loop.

Tool-generated findings include a `source` field in frontmatter ("semgrep" or "codeql"). Findings are created in `findings/potential/`.

If static-scan tools are unavailable and the user declines installation, skip this step.

#### A.4 Validate Static-Scan Findings

Process all findings from static-scan in `findings/potential/` through `/breach:validate-finding`:

- **Validated findings**: Update finding.md with all sections (PoC, Impact, Remediation, References) and frontmatter fields (cvss_score, cvss_vector, confidence). Create `validation-result.md`. Verify PoC scripts in the `poc/` directory. Move to `findings/validated/`.
- **Rejected findings**: Set `rejection_reason` in finding.md frontmatter, update stage to "rejected", move to `findings/rejected/`.

### Phase B: Discovery Loop (repeats until user stops)

After initialization completes, begin the autonomous discovery loop. Repeat B.1 through B.5 continuously. Do not stop unless the user interrupts.

#### B.1 Code Analysis

Invoke `/breach:code-analysis` to discover vulnerabilities through manual code review. Manual findings have `source: "manual"` in frontmatter.

**Vary focus each iteration.** Before starting analysis, review what has already been found by scanning `findings/validated/` and `findings/rejected/`. Then intentionally shift focus using these strategies:

- **Explore uncovered territory**: Target components, modules, and vulnerability classes not yet represented in existing findings.
- **Rotate analysis approaches**: Alternate between broad sweeps (survey many components quickly), deep dives (exhaustive review of one component), variant hunting (find variations of validated findings), reverse trace from sinks (start from dangerous functions and trace inputs backwards), and adversarial review of rejections (re-examine rejected findings from a different angle).
- **Rotate attacker perspectives**: Cycle through unauthenticated external attacker, authenticated regular user, privileged/admin user, and malicious insider.
- **Explore different vulnerability classes**: Don't repeat the same OWASP categories — if prior iterations found injection flaws, focus on broken access control, cryptographic failures, or SSRF.

The agent uses its conversation context and the findings directory state to decide what to focus on. No formal tracking structure is needed — just be intentionally different each pass.

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

Print a compact summary between iterations:

```
── Iteration {N} Complete ──────────────────────────
New findings this iteration:  {count} discovered, {validated} validated, {rejected} rejected
Cumulative:                   {total_validated} validated, {total_rejected} rejected, {total_chains} chains
Next iteration focus:         {brief description of planned focus shift}
────────────────────────────────────────────────────
```

Then immediately begin the next iteration at B.1. Do not pause or ask for confirmation.

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
