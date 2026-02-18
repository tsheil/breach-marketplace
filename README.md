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
| [breach](plugins/breach/) | Security vulnerability hunting toolkit | 1.0.0 |

## breach

Four-stage pipeline for systematic source code security review. Designed for expert security researchers and bug bounty hunters.

```
/breach:recon  -->  /breach:hunt  -->  /breach:validate  -->  /breach:report
     |                    |                    |                      |
  attack surface      raw findings      validated findings +     complete markdown
  map + priorities    with evidence     PoC exploit scripts      security report
```

| Skill | Purpose |
|-------|---------|
| `/breach:recon` | Attack surface mapping -- technology fingerprinting, entry points, trust boundaries, auth inventory |
| `/breach:hunt` | Vulnerability hunting -- OWASP Top 10 coverage, risk-prioritized discovery, vulnerability chaining |
| `/breach:validate` | PoC validation -- six-element evidence bar, exploit script generation, triage and confidence levels |
| `/breach:report` | Report generation -- CVSS v3.1 scoring, reproduction steps, bounty-optimized presentation |

See [plugins/breach/README.md](plugins/breach/README.md) for full documentation.

## License

Apache-2.0. See [LICENSE](LICENSE).
