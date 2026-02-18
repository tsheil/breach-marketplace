# Finding Lifecycle Stages

## Directory Structure

```
findings/
├── potential/       # Raw findings from code-analysis
├── confirmed/       # Working PoC exists
├── validated/       # AI-validated (6-element evidence bar, triage, CVSS)
├── verified/        # Human-verified (manual folder move)
├── reported/        # Report generated (hard gate on verified)
└── rejected/        # Discarded (reason in frontmatter)
```

## Stage Definitions

### potential

- **Entry condition**: New vulnerability discovered during code analysis
- **Contents**: finding.md with Vulnerable Code and Exploitability sections populated, empty `poc/` directory
- **Exit condition**: PoC created (move to `confirmed`) or validation attempted (move to `validated` or `rejected`)
- **Who moves**: Automated by code-analysis skill or validate skill

### confirmed

- **Entry condition**: Working proof-of-concept exploit exists for the finding
- **Contents**: finding.md with Proof of Concept section populated, PoC script(s) in `poc/` directory
- **Exit condition**: Full validation pass (move to `validated` or `rejected`)
- **Who moves**: Automated by validate skill

### validated

- **Entry condition**: Finding passes the full 6-element evidence bar, triage criteria, CVSS scoring, and confidence assignment
- **Contents**: finding.md fully populated (all sections), complete PoC in `poc/`, CVSS score and vector in frontmatter
- **Exit condition**: Human verification (move to `verified`) or demotion (move back to earlier stage or to `rejected`)
- **Who moves**: Human reviewer (manual)

### verified

- **Entry condition**: Human reviewer has examined the finding, confirmed it is valid, and manually moved the folder
- **Contents**: finding.md may include `reviewer_notes` in frontmatter
- **Exit condition**: Report generation (move to `reported`)
- **Who moves**: Automated by report skill
- **Note**: This is the only stage requiring human action. The report skill enforces a hard gate — only verified findings can be reported.

### reported

- **Entry condition**: Security report has been generated that includes this finding
- **Contents**: finding.md with `stage` updated to "reported"
- **Exit condition**: Terminal stage (finding lifecycle complete)
- **Who moves**: Automated by report skill

### rejected

- **Entry condition**: Finding failed validation, triage, or was discarded for any reason
- **Contents**: finding.md with `rejection_reason` populated in frontmatter
- **Exit condition**: Can be moved back to any earlier stage for re-evaluation
- **Who moves**: Automated by validate skill, or manual by human reviewer

## Transition Rules

### Forward Transitions

```
potential → confirmed → validated → verified → reported
```

- `potential → confirmed`: PoC created for the finding
- `potential → validated`: Orchestrator validates in one pass (skips confirmed)
- `confirmed → validated`: Full validation pass succeeds
- `validated → verified`: Human manually moves folder and updates frontmatter
- `verified → reported`: Report skill generates report and moves finding

### Backward Transitions (Demotion)

Any finding can be moved backward to an earlier stage:
- `validated → potential`: Finding needs re-analysis (e.g., new code changes affect it)
- `validated → confirmed`: Validation incomplete, needs more evidence
- `confirmed → potential`: PoC invalidated, needs re-discovery

When demoting, update the `stage` field in frontmatter and `last_moved` timestamp. Move the finding folder to the target stage directory.

### Rejection

Any finding can be moved to `rejected` from any stage:
- Set `rejection_reason` in frontmatter explaining why
- Update `stage` to "rejected" and `last_moved`
- Move folder to `rejected/`

A rejected finding can be un-rejected by moving it back to any stage.

## ID Assignment Procedure

1. Scan all finding folders across ALL stage directories: `potential/`, `confirmed/`, `validated/`, `verified/`, `reported/`, `rejected/`
2. Extract the numeric ID from each folder name (second segment: `{SEVERITY}-{ID}-{VULN_TYPE}-{desc}`)
3. Find the maximum ID value
4. Increment by 1
5. Zero-pad to 3 digits (001, 002, ..., 010, ..., 100, ...)
6. If no existing findings, start at 001
7. IDs are never reused, even for rejected findings

## Finding Folder Naming Convention

```
{SEVERITY}-{ID}-{VULN_TYPE}-{desc}/
```

- **SEVERITY**: `CRIT` | `HIGH` | `MED` | `LOW`
- **ID**: Zero-padded 3-digit sequential ID (001, 002, ...)
- **VULN_TYPE**: Freeform shorthand (XSS, SQLI, IDOR, RCE, SSRF, SSTI, CMDI, LFI, etc.)
- **desc**: Kebab-case description, approximately 40 characters max
- Example: `HIGH-003-SQLI-user-search-endpoint/`

## Severity Changes

If a finding's severity changes during validation (e.g., initially assessed as HIGH but validated as MED):

1. Rename the finding folder to reflect the new severity: `HIGH-003-SQLI-user-search-endpoint/` → `MED-003-SQLI-user-search-endpoint/`
2. Update the `severity` field in finding.md frontmatter
3. The ID remains the same — only the severity prefix changes
