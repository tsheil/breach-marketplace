---
name: breach-findings
description: "Canonical reference for finding structure, naming, lifecycle, and PoC standards. This skill should be used when the user asks about finding format, naming conventions, finding directory structure, finding lifecycle stages, how findings are organized, finding.md template, PoC standards, finding ID assignment, severity naming, finding folder layout, status directories, or how findings move through the pipeline. It is the single source of truth for all finding-related definitions consumed by hunt, code-analysis, static-scan, validate-finding, chain-analysis, and report."
---

# Findings: Structure, Lifecycle & Standards

This skill is the canonical reference for how findings are structured, named, stored, and moved through the breach pipeline. Every other skill that creates, reads, or modifies findings defers to the definitions here.

## Finding Folder Naming Convention

```
{SEVERITY}-{NNN}-{VULN_TYPE}-{short-description}/
```

| Segment | Format | Examples |
|---------|--------|----------|
| **SEVERITY** | Prefix shorthand | `CRIT`, `HIGH`, `MED`, `LOW`, `INFO` |
| **NNN** | Zero-padded 3-digit sequence | `001`, `002`, ..., `010`, ..., `100` |
| **VULN_TYPE** | Freeform shorthand | `XSS`, `SQLI`, `IDOR`, `RCE`, `SSRF`, `SSTI`, `CMDI`, `LFI`, `CHAIN`, `AUTH`, `CRYPTO`, `DESER`, `PATH-TRAV`, `OPEN-REDIR` |
| **short-description** | Kebab-case, ~40 chars max | `user-search-endpoint`, `admin-panel-bypass` |

Examples:
- `HIGH-003-SQLI-user-search-endpoint/`
- `CRIT-001-RCE-file-upload-handler/`
- `MED-007-XSS-comment-rendering/`
- `HIGH-012-CHAIN-idor-plus-info-disclosure/`

## Canonical Directory Structure

Each finding folder contains:

```
{SEVERITY}-{NNN}-{VULN_TYPE}-{short-description}/
├── finding.md          # Structured finding document (YAML frontmatter + markdown sections)
├── poc/                # Proof-of-concept scripts and supporting files
│   ├── poc.mjs         # or poc.sh, poc.py — primary exploit script
│   └── README.md       # Setup instructions, expected output, dependencies
├── evidence/           # Screenshots, logs, response captures (optional)
└── validation-result.md  # Created by validate-finding skill on CONFIRMED verdict
```

**Required**: `finding.md` and `poc/` directory (even if empty during early stages).
**Created during validation**: `validation-result.md` (by `/breach:validate-finding`).
**Optional**: `evidence/` directory for supplementary proof.

## Status Directories (Lifecycle Stages)

Findings move through stage directories within the `findings/` root:

```
findings/
├── potential/       # Raw findings from code-analysis and static-scan
├── confirmed/       # Working PoC exists (optional intermediate stage)
├── validated/       # AI-validated (full evidence bar, triage, CVSS) + chain findings
├── verified/        # Human-verified (manual folder move — the critical gate)
├── reported/        # Report generated (hard gate on verified)
└── rejected/        # Discarded (reason in frontmatter)
```

### Stage Definitions

| Stage | Entry Condition | Contents | Exit | Who Moves |
|-------|----------------|----------|------|-----------|
| **potential** | New vulnerability discovered during code analysis or static scan | finding.md with Vulnerable Code and Exploitability populated, empty `poc/` | PoC created → `confirmed`, or validation attempted → `validated`/`rejected` | Automated (code-analysis, static-scan, validate-finding) |
| **confirmed** | Working proof-of-concept exploit exists | finding.md with Proof of Concept populated, PoC script(s) in `poc/` | Full validation pass → `validated`/`rejected` | Automated (validate-finding) |
| **validated** | Finding passes full evidence bar, triage, CVSS scoring, and confidence assignment | finding.md fully populated, complete PoC, CVSS in frontmatter, `validation-result.md` | Human verification → `verified`, or demotion | Human reviewer (manual) |
| **verified** | Human reviewer has examined, confirmed, and manually moved the folder | finding.md may include `reviewer_notes` | Report generation → `reported` | Automated (report skill) |
| **reported** | Security report generated that includes this finding | finding.md with `stage` updated to "reported" | Terminal stage | Automated (report skill) |
| **rejected** | Failed validation, triage, or discarded for any reason | finding.md with `rejection_reason` populated | Can be un-rejected to any earlier stage | Automated or manual |

### Transition Rules

**Forward transitions:**
```
potential → confirmed → validated → verified → reported
potential → validated  (orchestrator validates in one pass, skipping confirmed)
```

**Backward transitions (demotion):**
Any finding can move backward — update `stage` and `last_moved` in frontmatter, move folder to target directory.

**Rejection:**
Any finding can move to `rejected/` from any stage. Set `rejection_reason`, update `stage` and `last_moved`.

**Un-rejection:**
Move from `rejected/` back to any stage for re-evaluation.

## finding.md Format

### YAML Frontmatter (Required Fields)

```yaml
---
id: "001"
title: ""
severity: ""              # CRIT | HIGH | MED | LOW | INFO
cvss_score:               # null until validated
cvss_vector: ""           # CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_
cwe: ""                   # CWE-XXX
stage: "potential"        # potential | confirmed | validated | verified | reported | rejected
vuln_type: ""             # Freeform shorthand (XSS, SQLI, IDOR, RCE, SSRF, CHAIN, etc.)
affected_component: ""    # file:line format
confidence: ""            # Confirmed | High | Medium | Low (empty until validated)
source: ""                # "manual" | "semgrep" | "codeql" | "custom-semgrep" | "custom-codeql" | "variant-analysis" (default: "manual")
variant_of: ""            # ID of source finding, CVE ID, or disclosure URL (empty for non-variant findings)
chain_components: []      # List of finding IDs this chain comprises (empty for non-chain findings)
created_at: ""            # ISO 8601
last_moved: ""            # ISO 8601
rejection_reason: ""      # Only when rejected
reviewer_notes: ""        # Human reviewer free text
---
```

### Markdown Sections

```markdown
## Vulnerable Code
<!-- Code snippet with file path, line numbers, and surrounding context -->

## Exploitability
<!-- Full exploit path: entry point, data flow, controls assessment, bypass method -->

## Proof of Concept
<!-- Copy-paste-ready PoC (also saved as script in poc/ directory) -->

## Impact
<!-- Business impact: worst-case outcome, affected data, blast radius -->

## Remediation
<!-- Specific code fix with before/after -->

## References
<!-- CWE link, OWASP reference, related CVEs -->
```

### Stage-by-Stage Population Guide

| Stage | Populate |
|-------|----------|
| **potential** | Frontmatter: `id`, `title`, `severity`, `cwe`, `stage`, `vuln_type`, `affected_component`, `source`, `created_at`, `last_moved`. Sections: Vulnerable Code, Exploitability. Leave others with placeholder comments. |
| **confirmed** | Add to potential: Update `stage` to "confirmed", `last_moved`. Populate Proof of Concept section. Save PoC script to `poc/`. |
| **validated** | Complete all: Update `stage`, `last_moved`, `cvss_score`, `cvss_vector`, `confidence`. For chains: `vuln_type` = "CHAIN", populate `chain_components`. Complete Exploitability, Proof of Concept, Impact, Remediation, References. Create `validation-result.md`. |
| **verified** | Human: Move folder, update `stage` to "verified", `last_moved`. Optionally add `reviewer_notes`. |
| **reported** | After report: Update `stage` to "reported", `last_moved`. |
| **rejected** | Update `stage` to "rejected", `last_moved`, `rejection_reason`. |

## File Ownership Table

Which skill creates which artifact within a finding folder:

| Artifact | Created By | Stage |
|----------|-----------|-------|
| `finding.md` (initial) | `/breach:code-analysis` or `/breach:static-scan` | potential |
| `poc/` directory (empty) | `/breach:code-analysis` or `/breach:static-scan` | potential |
| `poc/poc.mjs` (or .sh, .py) | `/breach:validate-finding` (verifies/creates) | confirmed → validated |
| `poc/README.md` | `/breach:validate-finding` | validated |
| `evidence/` | Human or `/breach:validate-finding` | any |
| `validation-result.md` | `/breach:validate-finding` | validated |
| `finding.md` (full update) | `/breach:validate-finding` | validated |
| Chain `finding.md` | `/breach:chain-analysis` | validated |
| `reviewer_notes` in frontmatter | Human reviewer | verified |

## ID Assignment Procedure

1. Scan all finding folders across ALL stage directories: `potential/`, `confirmed/`, `validated/`, `verified/`, `reported/`, `rejected/`
2. Extract the numeric ID from each folder name (second segment: `{SEVERITY}-{NNN}-{VULN_TYPE}-{desc}`)
3. Find the maximum ID value
4. Increment by 1
5. Zero-pad to 3 digits (001, 002, ..., 010, ..., 100, ...)
6. If no existing findings, start at 001
7. IDs are never reused, even for rejected findings

## Severity Changes

When a finding's severity changes during validation:

1. Rename the finding folder to reflect the new severity prefix: `HIGH-003-SQLI-user-search-endpoint/` → `MED-003-SQLI-user-search-endpoint/`
2. Update the `severity` field in finding.md frontmatter
3. The ID and all other segments remain unchanged

## Storage Hygiene

### Prohibited Artifacts

Never commit these inside a finding folder:

| Prohibited | Why |
|------------|-----|
| `node_modules/` | Dependency bloat — use package.json + install instructions |
| `dist/`, `build/` | Build artifacts — reproduce from source |
| Lock files (`package-lock.json`, `yarn.lock`) | Environment-specific, not portable |
| `.env`, credentials, API keys | Secrets must never be committed |
| Binary executables | Security risk — provide source code only |
| Large media files (>5 MB) | Use text descriptions or compress |
| IDE/editor configs (`.vscode/`, `.idea/`) | Personal preference, not finding data |

### PoC Dependencies

PoC scripts should be self-contained. If external packages are needed:
- List them in `poc/README.md` with exact versions
- Keep dependencies minimal (prefer stdlib)
- Never commit installed packages

## PoC Standards

See `references/poc-standards.md` for detailed PoC authoring requirements including exit codes, output markers, progressive test patterns, header standards, and anti-patterns.
