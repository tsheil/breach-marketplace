# breach

Security vulnerability hunting toolkit for Claude Code.

Eight-skill pipeline for systematic source code security review with a filesystem-based finding lifecycle. Designed for expert security researchers and bug bounty hunters.

## Requirements

- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code)
- [Semgrep](https://semgrep.dev/) (optional, for `/breach:static-scan`)
- [CodeQL](https://codeql.github.com/) (optional, for `/breach:static-scan`)

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
                ┌──────────────┴──────────────────────────────────────────────────────┐
                │                                                                      │
                │                ┌── parallel ──┐                                      │
/breach:code-recon --│--> /breach:static-scan   │--> /breach:validate-finding --> /breach:chain-analysis --> /breach:report
                │         /breach:code-analysis  │                                      │
                │                └──────────────┘                                      │
                │                                            ┌─ human verify ──────────┘
                │                                            ▼
                │                                      findings/verified/
                └──────────────────────────────────────────────────────────────────────┘
```

The orchestrator (`/breach:hunt`) runs the full pipeline and manages the finding lifecycle. All skills also work standalone. The `/breach:findings` skill provides the canonical reference for finding structure, naming, and lifecycle consumed by all other skills.

### breach-code-recon -- Attack Surface Mapping

Source code reconnaissance with threat modeling. Maps the target codebase attack surface: application context and threat model, technology fingerprinting, entry point enumeration, trust boundary mapping, auth/authz inventory, data flow tracing, secrets audit, and git history analysis.

Supports two output modes: executive brief (quick scan) and full attack surface map (default). Produces a prioritized attack surface map consumed by the discovery phase.

### breach-hunt -- Pipeline Orchestrator

Orchestrates the complete breach pipeline: code-recon → static-scan + code-analysis (parallel) → validate → chain-analysis → report. Manages the finding lifecycle, creates the `findings/` directory structure, coordinates discovery and validation in batch, and pauses for human verification before reporting.

On re-invocation after human verification, generates reports for verified findings.

### breach-static-scan -- Automated Security Scanning

Integrates Semgrep (pattern matching) and CodeQL (semantic dataflow analysis) for deterministic vulnerability detection. Detects tools on PATH, asks user consent before installing missing tools, runs security-focused rulesets, and maps results to breach severity and vulnerability types.

In lifecycle mode, creates finding folders in `findings/potential/` with `source` field set to "semgrep" or "codeql". Runs in parallel with code-analysis during the hunt pipeline.

### breach-code-analysis -- Vulnerability Discovery

Systematic vulnerability discovery driven by the code-recon output. Component-to-vulnerability mapping, risk-prioritized hunting across three tiers, systematic input tracing, full OWASP Top 10 coverage, and vulnerability chaining analysis.

In lifecycle mode (when `findings/` directory exists), creates finding folders in `findings/potential/` with structured `finding.md` files. In standalone mode, outputs findings to conversation.

### breach-findings -- Finding Structure & Lifecycle

Canonical reference for finding structure, naming conventions, lifecycle stages, PoC standards, and directory layout. Defines the finding.md template, YAML frontmatter fields, stage-by-stage population guide, ID assignment procedure, severity rename rules, file ownership table, and storage hygiene requirements. All other skills defer to this skill for finding-related definitions.

### breach-validate-finding -- Finding Validation

Validates each finding through a 4-phase, 12-step procedure with anti-hallucination gates, footgun detection, triager perspective analysis, 3x reproduction, deduplication, and mandatory devil's advocate severity challenge. Verifies existing PoCs against quality standards rather than generating new ones.

In lifecycle mode, processes findings from `findings/potential/` and `findings/confirmed/`, creates `validation-result.md` artifacts, and moves validated findings to `findings/validated/` or rejected findings to `findings/rejected/`. In standalone mode, operates from conversation context.

### breach-chain-analysis -- Vulnerability Chain Discovery

Systematically analyzes validated findings to identify vulnerability chains — combinations of two or more findings that produce escalated impact. Checks all finding pairs against known chain patterns (IDOR + info disclosure → account takeover, SSRF + cloud metadata → infra compromise, etc.) and performs adjacency analysis for novel chains.

In lifecycle mode, creates chain findings in `findings/validated/` with `vuln_type: "CHAIN"` and `chain_components` listing component IDs. In standalone mode, outputs chains to conversation.

### breach-report -- Report Generation

Generates a complete markdown security report. CVSS v3.1 scoring, structured findings with reproduction steps, bounty-optimized presentation, attack chain analysis, and prioritized remediation guidance.

In lifecycle mode, enforces a hard gate: only human-verified findings (in `findings/verified/`) can be reported. In standalone mode, accepts findings from conversation context without a gate.

## Finding Lifecycle

The finding lifecycle tracks vulnerabilities from discovery through human verification to reporting using a filesystem-based directory structure:

```
findings/
├── potential/       # Raw findings from code-analysis and static-scan
├── confirmed/       # Working PoC exists
├── validated/       # AI-validated (6-element evidence bar, triage, CVSS) + chain findings
├── verified/        # Human-verified (manual folder move)
├── reported/        # Report generated (hard gate on verified)
└── rejected/        # Discarded (reason in frontmatter)
```

**Finding folders** follow the naming convention `{SEVERITY}-{ID}-{VULN_TYPE}-{desc}/` (e.g., `HIGH-003-SQLI-user-search-endpoint/`) and contain a `finding.md` with YAML frontmatter and structured markdown sections, plus a `poc/` directory for exploit scripts. Chain findings use the convention `{SEVERITY}-{ID}-CHAIN-{desc}/`.

**Finding metadata** includes a `source` field ("manual", "semgrep", or "codeql") to track how each finding was discovered, and a `chain_components` field for chain findings that lists the IDs of component findings.

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
- **Tool-augmented** -- combines deterministic tool analysis with AI-driven manual review for maximum coverage.
- **Chain-aware** -- dedicated analysis identifies escalated impact from finding combinations.
- **Suggested pipeline** -- each skill recommends the next stage but all eight work independently.
- **OWASP Top 10 focused** -- hunting methodology maps directly to the OWASP Top 10 2021.
- **Standardized PoCs** -- findings skill defines PoC standards; validation verifies compliance.
- **Anti-hallucination** -- validation includes hard gates that reject fabricated file paths, functions, and data flows.

## Reference Material

Each skill carries its own reference files under `skills/<skill>/references/`.

| Skill | Path | Contents |
|-------|------|----------|
| static-scan | `skills/static-scan/references/` | Semgrep rulesets, CodeQL query suites, tool installation and setup |
| code-analysis | `skills/code-analysis/references/` | OWASP Top 10 vulnerability reference files (A01 through A10) |
| findings | `skills/findings/references/` | PoC standards, authoring requirements, format selection, anti-patterns |
| hunt | `skills/hunt/references/` | Security review principles (mindset, evidence, methodology, severity calibration) |
| validate-finding | `skills/validate-finding/references/` | Triager analysis reference (triager perspective, N/A patterns, AI slop detection) |
| chain-analysis | `skills/chain-analysis/references/` | Vulnerability chain pattern catalog |
| report | `skills/report/references/` | Report template, CVSS v3.1 scoring guide, bounty writing wisdom |

## License

Apache-2.0. See [LICENSE](LICENSE).
