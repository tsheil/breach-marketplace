# breach

Security vulnerability hunting toolkit for Claude Code.

Four-stage pipeline for systematic source code security review. Designed for expert security researchers and bug bounty hunters.

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
/breach:recon  -->  /breach:hunt  -->  /breach:validate  -->  /breach:report
     |                    |                    |                      |
  attack surface      raw findings      validated findings +     complete markdown
  map + priorities    with evidence     PoC exploit scripts      security report
```

Each skill recommends the next in the pipeline but all work standalone.

### /breach:recon -- Attack Surface Mapping

Maps the target codebase attack surface: technology fingerprinting, entry point enumeration, trust boundary mapping, auth/authz inventory, data flow tracing, secrets audit, and framework-specific security patterns.

Produces a prioritized attack surface map consumed by the hunt phase.

### /breach:hunt -- Vulnerability Hunting

Systematic vulnerability discovery driven by the recon output. Component-to-vulnerability mapping, risk-prioritized hunting across three tiers, systematic input tracing, full OWASP Top 10 coverage, and vulnerability chaining analysis.

Produces raw findings with evidence for validation.

### /breach:validate -- PoC Validation

Validates each finding against a strict six-element evidence bar. Defines validation procedures, generates PoC exploit scripts from templates, applies triage criteria, and assigns confidence levels.

Findings that do not meet the evidence bar are discarded.

### /breach:report -- Report Generation

Generates a complete markdown security report. CVSS v3.1 scoring, structured findings with reproduction steps, bounty-optimized presentation, attack chain analysis, and prioritized remediation guidance.

## Design Principles

- **Expert audience** -- assumes working knowledge of application security; no hand-holding.
- **Language-agnostic** -- hunts universal vulnerability patterns across any stack.
- **Strict evidence bar** -- every finding requires six evidence elements or it is discarded.
- **Suggested pipeline** -- each skill recommends the next stage but all four work independently.
- **OWASP Top 10 focused** -- hunting methodology maps directly to the OWASP Top 10 2021.
- **Template-based PoCs** -- validation generates exploit scripts from reusable templates.

## Reference Material

Each skill carries its own reference files under `skills/<skill>/references/`.

| Skill | Path | Contents |
|-------|------|----------|
| recon | `skills/recon/references/` | Framework security patterns (Django, Express, Spring, Rails, Laravel, Next.js, Flask, FastAPI) |
| hunt | `skills/hunt/references/` | OWASP Top 10 vulnerability reference files (A01 through A10) |
| validate | `skills/validate/references/` | PoC templates (HTTP requests, curl patterns, data extraction) |
| report | `skills/report/references/` | Report template, CVSS v3.1 scoring guide, bounty writing wisdom |

## License

Apache-2.0. See [LICENSE](LICENSE).
