# breach-marketplace

Security-focused plugin marketplace for [Claude Code](https://docs.anthropic.com/en/docs/claude-code).

## Installation

Add the marketplace:

```
/plugin marketplace add tsheil/breach-marketplace
```

Install the breach plugin:

```
/plugin install breach@breach-marketplace
```

## Available Plugins

| Plugin | Description | Version |
|--------|-------------|---------|
| [breach](plugins/breach/) | Security vulnerability hunting toolkit | 1.2.0 |

## breach

Seven-skill pipeline for systematic source code security review with a filesystem-based finding lifecycle. Designed for expert security researchers and bug bounty hunters.

```
                        /breach:hunt (orchestrator)
                ┌──────────┴──────────────────────────────────────────────────────┐
                │                                                                  │
                │           ┌── parallel ──┐                                       │
/breach:recon --│--> /breach:static-scan   │--> /breach:validate --> /breach:chain-analysis --> /breach:report
                │    /breach:code-analysis  │                                       │
                │           └──────────────┘                                       │
                │                                       ┌─ human verify ───────────┘
                │                                       ▼
                │                                 findings/verified/
                └──────────────────────────────────────────────────────────────────┘
```

| Skill | Purpose |
|-------|---------|
| `/breach:recon` | Attack surface mapping -- technology fingerprinting, entry points, trust boundaries, auth inventory |
| `/breach:hunt` | Pipeline orchestrator -- runs recon → static-scan + code-analysis (parallel) → validate → chain-analysis, manages finding lifecycle, pauses for human verification before reporting |
| `/breach:static-scan` | Automated scanning -- Semgrep pattern matching + CodeQL dataflow analysis, deterministic vulnerability detection, tool-sourced findings |
| `/breach:code-analysis` | Vulnerability discovery -- OWASP Top 10 coverage, risk-prioritized analysis, vulnerability chaining, lifecycle-aware output |
| `/breach:validate` | PoC validation -- six-element evidence bar, exploit script generation, triage and confidence levels, deduplication, lifecycle-aware processing |
| `/breach:chain-analysis` | Chain discovery -- analyzes validated finding pairs for escalated impact, known chain patterns, adjacency analysis, chain severity calculation |
| `/breach:report` | Report generation -- CVSS v3.1 scoring, reproduction steps, bounty-optimized presentation, hard gate on human-verified findings |

See [plugins/breach/README.md](plugins/breach/README.md) for full documentation.

## License

Apache-2.0. See [LICENSE](LICENSE).
