# breach

Security vulnerability hunting toolkit for Claude Code.

Ten-skill pipeline for systematic source code security review with a filesystem-based finding lifecycle. Designed for expert security researchers and bug bounty hunters.

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
  Initialization (once):                                                               │
  /breach:code-recon --> /breach:custom-rules --> /breach:static-scan --> validate       │
                │                                                                      │
  Discovery Loop (repeats until user stops):                                           │
                │       ┌─────────────────────────────────────────────┐                │
                │       │  /breach:code-analysis (vary focus)         │                │
                │       │    ↳ or /breach:variant-analysis            │                │
                │       │  dedup → /breach:validate-finding           │                │
                │       │  /breach:chain-analysis                     │                │
                │       │  iteration summary → loop back              │                │
                │       └─────────────────────────────────────────────┘                │
                │                                                                      │
  Review & Reporting (after user stops):             ┌─ human verify ──────────────────┘
                │                                    ▼
                │                              findings/verified/
                │                                    │
                └── /breach:report ◄─────────────────┘
```

The orchestrator (`/breach:hunt`) runs one-time initialization, then loops discovery-validation continuously — each pass finds different vulnerabilities through non-deterministic analysis. When the `variant-hunt` approach is selected, it invokes `/breach:variant-analysis` instead of `/breach:code-analysis` to find variants of validated findings. The loop runs until the user stops it. All skills also work standalone. The `/breach:findings` skill provides the canonical reference for finding structure, naming, and lifecycle consumed by all other skills.

### breach-code-recon -- Attack Surface Mapping

Source code reconnaissance with threat modeling. Maps the target codebase attack surface: application context and threat model, technology fingerprinting, entry point enumeration, trust boundary mapping, auth/authz inventory, data flow tracing, secrets audit, and git history analysis.

Supports two output modes: executive brief (quick scan) and full attack surface map (default). Produces a prioritized attack surface map consumed by the discovery phase.

### breach-hunt -- Autonomous Pipeline Orchestrator

Orchestrates the breach pipeline as an autonomous loop. Initialization runs once: code-recon → custom-rules → static-scan → validate static findings. Then the discovery loop cycles continuously: code-analysis (with coverage-tracked focus selection) → deduplicate → validate → chain-analysis → iteration summary → loop back. Each pass selects focus across 5 dimensions (territory, analysis approach, attacker perspective, OWASP vuln class, git recency) using a persistent coverage tracker (`findings/hunt-coverage.md`), with auto-shift triggered after 3 consecutive dry iterations.

The loop runs until the user stops it. On re-invocation after human verification, generates reports for verified findings.

### breach-custom-rules -- Codebase-Specific Rule Generation

Generates custom Semgrep rules and CodeQL queries tailored to the target codebase. Analyzes code-recon output to identify gaps in stock ruleset coverage — custom auth decorators, homegrown sinks, framework-specific behaviors, trust boundary violations — and produces rules targeting those application-specific patterns. Rules are written to `custom-rules/semgrep/` and `custom-rules/codeql/` in the project root and automatically consumed by `/breach:static-scan`.

Invoked during initialization (between code-recon and static-scan) or standalone. Prioritizes 10 rule categories from auth enforcement gaps through error handling leaks.

### breach-static-scan -- Automated Security Scanning

Integrates Semgrep (pattern matching) and CodeQL (semantic dataflow analysis) for deterministic vulnerability detection. Detects tools on PATH, asks user consent before installing missing tools, runs security-focused rulesets, and maps results to breach severity and vulnerability types. Automatically includes custom rulesets from `custom-rules/` when present.

In lifecycle mode, creates finding folders in `findings/potential/` with `source` field set to "semgrep", "codeql", "custom-semgrep", or "custom-codeql". Runs once during initialization (deterministic — re-running produces identical results).

### breach-code-analysis -- Vulnerability Discovery

Systematic vulnerability discovery driven by the code-recon output. Component-to-vulnerability mapping, risk-prioritized hunting across three tiers, systematic input tracing, full OWASP Top 10 coverage, and vulnerability chaining analysis.

In lifecycle mode (when `findings/` directory exists), creates finding folders in `findings/potential/` with structured `finding.md` files. In standalone mode, outputs findings to conversation. In the hunt loop, each iteration varies focus to explore different code areas, vulnerability classes, and attacker perspectives.

### breach-findings -- Finding Structure & Lifecycle

Canonical reference for finding structure, naming conventions, lifecycle stages, PoC standards, and directory layout. Defines the finding.md template, YAML frontmatter fields, stage-by-stage population guide, ID assignment procedure, severity rename rules, file ownership table, and storage hygiene requirements. All other skills defer to this skill for finding-related definitions.

### breach-validate-finding -- Finding Validation

Validates each finding through a 5-phase, 17-step procedure with anti-hallucination gates, footgun detection, triager perspective analysis, 3x reproduction, deduplication, and mandatory devil's advocate severity challenge. Verifies existing PoCs against quality standards rather than generating new ones.

In lifecycle mode, processes findings from `findings/potential/` and `findings/confirmed/`, creates `validation-result.md` artifacts, and moves validated findings to `findings/validated/` or rejected findings to `findings/rejected/`. In standalone mode, operates from conversation context.

### breach-variant-analysis -- Pattern-Based Variant Discovery

Takes a known vulnerability instance — a validated finding, CVE ID, public disclosure, or raw pattern — extracts its structural essence, generates targeted Semgrep rules and CodeQL queries, and systematically searches the codebase for variants. Supports four input types: validated findings, CVE IDs (with automated patch diff analysis), public disclosure URLs, and raw vulnerability patterns.

Four-phase workflow: pattern extraction (vulnerability skeleton, variant space definition), rule generation (Semgrep/CodeQL, tool selection by pattern type), codebase scan (automated rules + AI-assisted manual review), and result triage (filtering, lightweight validation, finding creation with `source: "variant-analysis"` and `variant_of` linking).

In lifecycle mode, creates variant findings in `findings/potential/`. Integrated into the hunt loop as the `variant-hunt` analysis approach.

### breach-chain-analysis -- Vulnerability Chain Discovery

Systematically analyzes validated findings to identify vulnerability chains — combinations of two or more findings that produce escalated impact. Checks all finding pairs against known chain patterns (IDOR + info disclosure → account takeover, SSRF + cloud metadata → infra compromise, CRLF + SSRF → Redis RCE, SQLi + file privilege → RCE, etc.) and performs adjacency analysis for novel chains.

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

**Finding metadata** includes a `source` field ("manual", "semgrep", "codeql", "custom-semgrep", "custom-codeql", or "variant-analysis") to track how each finding was discovered, a `variant_of` field linking variant findings to their source finding/CVE/disclosure, and a `chain_components` field for chain findings that lists the IDs of component findings.

**Human verification** is the critical gate between validation and reporting. After the user stops the discovery loop, a human reviewer must:
1. Review each finding in `findings/validated/`
2. Move approved findings to `findings/verified/`
3. Update the `stage` field in `finding.md` frontmatter
4. Re-run `/breach:hunt` to generate the report

This ensures no finding reaches the final report without human review.

## Design Principles

- **Expert audience** -- assumes working knowledge of application security; no hand-holding.
- **Language-agnostic** -- hunts universal vulnerability patterns across any stack.
- **Non-deterministic coverage** -- AI code analysis produces different results each run; the autonomous loop exploits this by varying focus each iteration to maximize total vulnerability coverage over time.
- **Strict evidence bar** -- every finding requires six evidence elements or it is discarded.
- **Human-in-the-loop** -- AI discovers and validates in a loop, humans verify after stopping before reporting.
- **Tool-augmented** -- combines deterministic tool analysis (one-time) with AI-driven manual review (looped) for maximum coverage.
- **Chain-aware** -- dedicated analysis identifies escalated impact from finding combinations.
- **Variant-aware** -- variant analysis extracts vulnerability skeletons from findings, CVEs, or disclosures and systematically searches for similar patterns.
- **Suggested pipeline** -- each skill recommends the next stage but all ten work independently.
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
| variant-analysis | `skills/variant-analysis/references/` | Variant extraction patterns, CVE research guide |
| custom-rules | `skills/custom-rules/references/` | Rule categories taxonomy, Semgrep rule syntax, CodeQL query syntax |
| report | `skills/report/references/` | Report template, CVSS v3.1 scoring guide, bounty writing wisdom |

## License

Apache-2.0. See [LICENSE](LICENSE).
