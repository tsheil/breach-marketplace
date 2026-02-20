# ai-collaboration

Cross-model AI consultation and task delegation for [Claude Code](https://docs.anthropic.com/en/docs/claude-code). Invoke Codex CLI (OpenAI) and Gemini CLI (Google) from within Claude Code to get second opinions, delegate code reviews, cross-check vulnerability assessments, and hand off discrete tasks to other AI models.

## Requirements

- Node.js (v18+)
- At least one of the following CLI tools installed and configured:
  - [Codex CLI](https://github.com/openai/codex) with `OPENAI_API_KEY` set
  - [Gemini CLI](https://github.com/google-gemini/gemini-cli) with Google AI API key or Google Cloud credentials configured

## Installation

```
/plugin install ai-collaboration@breach-marketplace
```

## Setup

Install at least one CLI tool and verify it works:

```bash
# Codex CLI
npm install -g @openai/codex
codex exec --full-auto "respond with OK"

# Gemini CLI — check repo for current install command
npm install -g @google/gemini-cli
gemini -p "respond with OK"
```

The skill will detect available tools at invocation time and offer consent-based installation for any missing tools.

## Skill Commands

| Command | Purpose |
|---------|---------|
| `/ai-collaboration` | Consult or delegate to other AI models — second opinions, code review, vulnerability assessment, task handoff |

## Use Cases

### Consultation

- **Second opinion** — ask another model to independently assess a piece of code, a design decision, or a vulnerability finding
- **Code review** — send focused code to another model for security or correctness review
- **Architecture review** — get an alternative perspective on system design and trust boundaries

### Delegation

- **Structured tasks** — delegate well-defined tasks with clear inputs and expected output format
- **Research** — use another model's training data for information gathering on patterns, CVEs, or best practices

### Security

- **Vulnerability second opinion** — cross-check a potential vulnerability with another model
- **Attack surface analysis** — ask another model to identify attack vectors you may have missed
- **Remediation validation** — verify a proposed security fix with an independent review

## Tool Comparison

| | Codex CLI | Gemini CLI |
|---|-----------|------------|
| **Install** | `npm install -g @openai/codex` | Check [repo](https://github.com/google-gemini/gemini-cli) |
| **Invocation** | `codex exec --full-auto "<prompt>"` | `gemini -p "<prompt>"` |
| **Output control** | `--json`, `--output-schema`, `-o` | `--output-format`, stdout redirection |
| **Sandbox mode** | `--full-auto` (default) | `--sandbox` |
| **Default model** | Latest Codex model | Latest Gemini Pro model |
| **Fallback model** | `gpt-5.2` via `-m` | `gemini-3-flash` via `-m` |
| **Best for** | Code-focused tasks, structured output | Broad reasoning, research |

## Reference Material

| Resource | Path |
|----------|------|
| Codex CLI reference | [skills/ai-collaboration/references/codex-cli.md](skills/ai-collaboration/references/codex-cli.md) |
| Gemini CLI reference | [skills/ai-collaboration/references/gemini-cli.md](skills/ai-collaboration/references/gemini-cli.md) |

## License

Apache-2.0. See [LICENSE](LICENSE).
