# breach

Security vulnerability hunting toolkit for Claude Code.

Five-skill pipeline for systematic source code security review with a filesystem-based finding lifecycle. Designed for expert security researchers and bug bounty hunters.

## Requirements

- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code)

## Installation

Load directly:

```
claude --plugin-dir ./breach
```

Or symlink for persistent use:

```
ln -s /path/to/breach ~/.claude/plugins/breach
```

## Skills / Pipeline

```
                        /breach:hunt (orchestrator)
                    ┌──────────┴──────────────────────────────────┐
                    │                                              │
/breach:recon  -->  /breach:code-analysis  -->  /breach:validate  -->  /breach:report
     |                       |                        |                      |
  attack surface        raw findings           validated findings +     complete markdown
  map + priorities      in findings/           PoC exploit scripts      security report
                        potential/             in findings/validated/   from findings/verified/
                                                                        │
                                          ┌─── human verification ───┘
                                          │    (manual folder move)
                                          ▼
                                    findings/verified/
```

The orchestrator (`/breach:hunt`) runs the full pipeline and manages the finding lifecycle. All skills also work standalone.

### /breach:recon -- Attack Surface Mapping

Maps the target codebase attack surface: technology fingerprinting, entry point enumeration, trust boundary mapping, auth/authz inventory, data flow tracing, secrets audit, and framework-specific security patterns.

Produces a prioritized attack surface map consumed by the discovery phase.

### /breach:hunt -- Pipeline Orchestrator

Orchestrates the complete breach pipeline: recon → code-analysis → validate → report. Manages the finding lifecycle, creates the `findings/` directory structure, coordinates discovery and validation in batch, and pauses for human verification before reporting.

On re-invocation after human verification, generates reports for verified findings.

### /breach:code-analysis -- Vulnerability Discovery

Systematic vulnerability discovery driven by the recon output. Component-to-vulnerability mapping, risk-prioritized hunting across three tiers, systematic input tracing, full OWASP Top 10 coverage, and vulnerability chaining analysis.

In lifecycle mode (when `findings/` directory exists), creates finding folders in `findings/potential/` with structured `finding.md` files. In standalone mode, outputs findings to conversation.

### /breach:validate -- PoC Validation

Validates each finding against a strict six-element evidence bar. Defines validation procedures, generates PoC exploit scripts from templates, applies triage criteria, and assigns confidence levels.

In lifecycle mode, processes findings from `findings/potential/` and `findings/confirmed/`, moving validated findings to `findings/validated/` and rejected findings to `findings/rejected/`. In standalone mode, operates from conversation context.

### /breach:report -- Report Generation

Generates a complete markdown security report. CVSS v3.1 scoring, structured findings with reproduction steps, bounty-optimized presentation, attack chain analysis, and prioritized remediation guidance.

In lifecycle mode, enforces a hard gate: only human-verified findings (in `findings/verified/`) can be reported. In standalone mode, accepts findings from conversation context without a gate.

## Finding Lifecycle

The finding lifecycle tracks vulnerabilities from discovery through human verification to reporting using a filesystem-based directory structure:

```
findings/
├── potential/       # Raw findings from code-analysis
├── confirmed/       # Working PoC exists
├── validated/       # AI-validated (6-element evidence bar, triage, CVSS)
├── verified/        # Human-verified (manual folder move)
├── reported/        # Report generated (hard gate on verified)
└── rejected/        # Discarded (reason in frontmatter)
```

**Finding folders** follow the naming convention `{SEVERITY}-{ID}-{VULN_TYPE}-{desc}/` (e.g., `HIGH-003-SQLI-user-search-endpoint/`) and contain a `finding.md` with YAML frontmatter and structured markdown sections, plus a `poc/` directory for exploit scripts.

**Human verification** is the critical gate between validation and reporting. After the orchestrator validates findings, a human reviewer must:
1. Review each finding in `findings/validated/`
2. Move approved findings to `findings/verified/`
3. Update the `stage` field in `finding.md` frontmatter
4. Re-run `/breach:hunt` to generate the report

This ensures no finding reaches the final report without human review.

## Design Principles

- **Expert audience** -- assumes working knowledge of application security; no hand-holding.
- **Language-agnostic** -- hunts universal vulnerability patterns across any stack.
- **Strict evidence bar** -- every finding requires six evidence elements or it is discarded.
- **Human-in-the-loop** -- AI discovers and validates, humans verify before reporting.
- **Suggested pipeline** -- each skill recommends the next stage but all five work independently.
- **OWASP Top 10 focused** -- hunting methodology maps directly to the OWASP Top 10 2021.
- **Template-based PoCs** -- validation generates exploit scripts from reusable templates.

## Reference Material

Each skill carries its own reference files under `skills/<skill>/references/`.

| Skill | Path | Contents |
|-------|------|----------|
| recon | `skills/recon/references/` | Framework security patterns (Django, Express, Spring, Rails, Laravel, Next.js, Flask, FastAPI) |
| code-analysis | `skills/code-analysis/references/` | OWASP Top 10 vulnerability reference files (A01 through A10) |
| hunt | `skills/hunt/references/` | Finding template, lifecycle stage definitions and transition rules |
| validate | `skills/validate/references/` | PoC templates (HTTP requests, curl patterns, data extraction) |
| report | `skills/report/references/` | Report template, CVSS v3.1 scoring guide, bounty writing wisdom |

## License

Apache-2.0. See [LICENSE](LICENSE).
