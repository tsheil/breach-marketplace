# breach-marketplace

Security-focused plugin marketplace for [Claude Code](https://docs.anthropic.com/en/docs/claude-code).

## Installation

Add the marketplace:

```
/plugin marketplace add tsheil/breach-marketplace
```

Install plugins:

```
/plugin install breach@breach-marketplace
```

## Available Plugins

| Plugin | Category | Description | Version |
|--------|----------|-------------|---------|
| [breach](plugins/breach/) | Core | Security vulnerability hunting toolkit | 1.5.0 |
| [hackerone](plugins/hackerone/) | Utility | HackerOne bug bounty platform integration | 0.1.0 |

## Core Plugins

### breach

Eight-skill pipeline for systematic source code security review with a filesystem-based finding lifecycle. Designed for expert security researchers and bug bounty hunters.

```mermaid
flowchart LR
    hunt["breach-hunt\n(orchestrator)"]

    subgraph init ["Initialization (once)"]
        recon["breach-code-recon"]
        static["breach-static-scan"]
        val_static["validate static\nfindings"]
        recon --> static --> val_static
    end

    subgraph loop ["Discovery Loop (repeats)"]
        code["breach-code-analysis\n(vary focus)"]
        dedup["deduplicate"]
        validate["breach-validate-finding"]
        chain["breach-chain-analysis"]
        code --> dedup --> validate --> chain
        chain -->|"loop back"| code
    end

    human{{"human verify"}}
    verified[("findings/verified/")]
    report["breach-report"]

    hunt -.->|manages| init
    init --> loop
    loop -->|"user stops"| human
    human --> verified
    verified --> report
```

| Skill | Purpose |
|-------|---------|
| `breach-code-recon` | Attack surface mapping -- threat modeling, technology fingerprinting, entry points, trust boundaries, auth inventory, git history analysis |
| `breach-hunt` | Autonomous pipeline orchestrator -- initialization (code-recon → static-scan → validate), then continuous discovery loop (code-analysis with varied focus → dedup → validate → chain-analysis), runs until user stops |
| `breach-static-scan` | Automated scanning -- Semgrep pattern matching + CodeQL dataflow analysis, deterministic vulnerability detection, runs once during initialization |
| `breach-code-analysis` | Vulnerability discovery -- OWASP Top 10 coverage, risk-prioritized analysis, vulnerability chaining, varies focus each loop iteration for non-deterministic coverage |
| `breach-findings` | Finding standards -- canonical reference for finding structure, naming, lifecycle stages, PoC standards, and directory layout |
| `breach-validate-finding` | Finding validation -- 4-phase 12-step procedure with anti-hallucination gates, footgun detection, triager analysis, 3x reproduction, deduplication |
| `breach-chain-analysis` | Chain discovery -- analyzes validated finding pairs for escalated impact, known chain patterns, adjacency analysis, chain severity calculation |
| `breach-report` | Report generation -- CVSS v3.1 scoring, reproduction steps, bounty-optimized presentation, hard gate on human-verified findings |

See [plugins/breach/README.md](plugins/breach/README.md) for full documentation.

## Utility Plugins

### hackerone

HackerOne bug bounty platform integration. Navigate programs, reports, hacktivity, and earnings via the HackerOne Hacker API.

**Requirements:** Python 3, HackerOne API credentials (username + API token).

| Skill | Purpose |
|-------|---------|
| `/hackerone` | Navigate HackerOne platform -- program research, report management, hacktivity intelligence, balance and earnings |

See [plugins/hackerone/README.md](plugins/hackerone/README.md) for full documentation.

## License

Apache-2.0. See [LICENSE](LICENSE).
