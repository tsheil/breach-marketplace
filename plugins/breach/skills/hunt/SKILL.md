---
description: "Hunt for vulnerabilities with a full breach pipeline. This skill should be used when the user asks to hunt for vulnerabilities, perform a security audit, run a comprehensive code security review, execute the full breach pipeline, manage the finding lifecycle, run recon through reporting, or perform systematic vulnerability discovery and validation. Orchestrates the complete workflow from reconnaissance through validated findings."
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

Invoke `/breach:recon` on the target codebase to map the attack surface. This produces a prioritized map of entry points, trust boundaries, authentication mechanisms, and framework patterns that feeds into the discovery phase.

If the user has already run recon or provides recon output, skip this phase.

### Phase B: Discovery

Invoke `/breach:code-analysis` to perform systematic vulnerability discovery. The code-analysis skill operates in lifecycle-aware mode (since the `findings/` directory exists) and creates finding folders in `findings/potential/` for each discovered vulnerability.

Each finding gets:
- A sequentially assigned ID (scanning all existing findings across all stages)
- A finding folder with `finding.md` (Vulnerable Code and Exploitability sections populated) and an empty `poc/` directory
- Proper naming convention: `{SEVERITY}-{ID}-{VULN_TYPE}-{desc}/`

### Phase C: Validation

Process all findings in `findings/potential/` through the validation logic from `/breach:validate`:

- For each finding, apply the full 6-element evidence bar, triage criteria, PoC generation, CVSS scoring, and confidence assignment
- **Validated findings**: Update finding.md with all sections (PoC, Impact, Remediation, References) and frontmatter fields (cvss_score, cvss_vector, confidence). Write PoC scripts to the `poc/` directory. Move the finding folder to `findings/validated/` (the orchestrator skips the `confirmed/` stage since it performs PoC generation and validation in a single pass).
- **Rejected findings**: Set `rejection_reason` in finding.md frontmatter, update stage to "rejected", move the finding folder to `findings/rejected/`.

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

- `/breach:recon` — Attack surface mapping (standalone)
- `/breach:code-analysis` — Vulnerability discovery (lifecycle-aware or standalone)
- `/breach:validate` — Finding validation with PoC (lifecycle-aware or standalone)
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

## References

- `finding-template.md` — Canonical finding.md template with stage-by-stage population guide
- `lifecycle-stages.md` — Stage definitions, transition rules, ID assignment, naming conventions
