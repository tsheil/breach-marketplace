---
description: "Hunt for vulnerabilities with a full breach pipeline. This skill should be used when the user asks to hunt for vulnerabilities, perform a security audit, run a comprehensive code security review, execute the full breach pipeline, manage the finding lifecycle, run code-recon through reporting, or perform systematic vulnerability discovery and validation. Orchestrates the complete workflow from reconnaissance through validated findings."
---

# Hunt: Breach Pipeline Orchestrator

This skill orchestrates the complete breach pipeline: reconnaissance, code analysis, validation, and reporting. It manages the finding lifecycle, coordinating the individual skills into a batch workflow while tracking findings through filesystem-based stages.

Each phase invokes a specialized skill. All skills remain independently invocable outside this orchestrator.

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

### Phase A: Reconnaissance

Invoke `/breach:code-recon` on the target codebase to map the attack surface. This produces a prioritized map of entry points, trust boundaries, authentication mechanisms, and threat model context that feeds into the discovery phase.

If the user has already run code-recon or provides recon output, skip this phase.

### Phase B: Discovery (Parallel)

Run two discovery methods in parallel:

1. **`/breach:static-scan`** — Automated Semgrep + CodeQL scanning for deterministic pattern matching and dataflow-validated findings. Tool-generated findings include a `source` field in frontmatter ("semgrep" or "codeql") to distinguish them from manual findings.
2. **`/breach:code-analysis`** — Claude's manual code review for logic flaws, design issues, and context-dependent vulnerabilities that tools miss. Manual findings have `source: "manual"` in frontmatter.

Both skills operate in lifecycle mode and create findings in `findings/potential/`. Running both in parallel maximizes coverage: tools catch well-known patterns reliably and at scale, while manual review catches logic flaws and context-dependent issues that tools miss.

If static-scan tools are unavailable and the user declines installation, proceed with code-analysis only.

Each finding gets:
- A sequentially assigned ID (scanning all existing findings across all stages)
- A finding folder with `finding.md` (Vulnerable Code and Exploitability sections populated) and an empty `poc/` directory
- Proper naming convention: `{SEVERITY}-{ID}-{VULN_TYPE}-{desc}/`

### Phase C: Validation and Deduplication

Process all findings in `findings/potential/` through the validation logic from `/breach:validate-finding`.

**Deduplication**: Tool findings may duplicate manual findings (same vulnerability found by both Semgrep/CodeQL and Claude). Before full validation, deduplicate by checking if two findings in `findings/potential/` reference the same file:line range (allowing ±3 lines). When a duplicate pair is found, keep the finding with richer context (typically the manual finding with more detailed exploitability analysis) and reject the duplicate with `rejection_reason: "duplicate of {ID}"`.

For each remaining finding, apply full validation:

- For each finding, apply the full 4-phase validation procedure (gates, verification, reproduction & PoC, assessment & dedup), triage criteria, CVSS scoring, and confidence assignment
- **Validated findings**: Update finding.md with all sections (PoC, Impact, Remediation, References) and frontmatter fields (cvss_score, cvss_vector, confidence). Create `validation-result.md`. Verify PoC scripts in the `poc/` directory. Move the finding folder to `findings/validated/` (the orchestrator skips the `confirmed/` stage since it performs validation in a single pass).
- **Rejected findings**: Set `rejection_reason` in finding.md frontmatter, update stage to "rejected", move the finding folder to `findings/rejected/`.

### Phase C.5: Chain Analysis

After validation completes, invoke `/breach:chain-analysis` on all findings in `findings/validated/`. This identifies vulnerability chains where two or more findings combine for escalated impact. Chain findings are added to `findings/validated/` alongside individual findings.

If fewer than 2 validated findings exist, skip chain analysis.

### Phase D: Pause for Human Verification

After validation completes, print a summary of results:

**Validated Findings** (in `findings/validated/`):

| ID | Severity | CVSS | Type | Component | Title | Confidence |
|----|----------|------|------|-----------|-------|------------|

**Rejected Findings** (in `findings/rejected/`):

| ID | Severity | Type | Component | Rejection Reason |
|----|----------|------|-----------|------------------|

Then instruct the user:

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

**Stop execution here.** Do not proceed to reporting without human verification.

### Phase E: Reporting (on re-invocation)

When `/breach:hunt` is invoked again after human verification:

1. Check `findings/verified/` first. If verified findings exist:
   - Invoke `/breach:report` to generate a complete security report covering all verified findings
   - For each reported finding, update finding.md (`stage` to "reported", `last_moved` to current timestamp) and move the folder to `findings/reported/`
2. After reporting, print a final summary and ask if the user wants to start a new discovery cycle on the same or different target.

If no verified findings exist on re-invocation, check for findings in other stages:
- If `potential/` has findings: resume from Phase C (validation)
- If `validated/` has findings but `verified/` is empty: remind the user to verify findings before reporting
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
- Findings in `potential/` only → resume from Phase C
- Findings in `validated/` → proceed to Phase D (pause for verification)
- Findings in `verified/` → proceed to Phase E (reporting)
- Mix of stages → process each stage appropriately (validate potential, report verified)

### Re-discovery with Existing Findings

When running a new discovery cycle while previous findings exist:
- New finding IDs continue the global sequence (scan all stages for max ID)
- Existing findings in any stage are not modified or re-processed
- Only new findings in `potential/` are validated in Phase C

### Tool-Manual Deduplication

Tool findings may duplicate manual findings when both Semgrep/CodeQL and Claude identify the same vulnerability. During validation (Phase C), deduplicate by checking if two findings in `findings/potential/` reference the same file:line range (±3 lines tolerance). Keep the finding with richer context (typically the manual finding) and reject the duplicate with reason "duplicate of {ID}".

## References

- `security-review-principles.md` — Mindset, evidence standards, methodology, severity calibration, and exclusion criteria
- `/breach:findings` — Canonical finding.md template, lifecycle stages, naming conventions, ID assignment, and PoC standards
