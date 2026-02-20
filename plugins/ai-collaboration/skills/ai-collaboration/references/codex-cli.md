# Codex CLI Reference

Codex CLI is OpenAI's command-line code agent. It accepts natural language prompts, can read and modify files, execute code in a sandboxed environment, and return structured output. This reference covers non-interactive invocation patterns for use within Claude Code.

## Installation & Setup

Install Codex CLI globally via npm:

```bash
npm install -g @openai/codex
```

Verify the installation:

```bash
which codex && codex exec --full-auto "respond with OK" 2>/dev/null
```

**Requirements:**
- Node.js (v18+)
- `OPENAI_API_KEY` environment variable set with a valid API key

If `codex` is on PATH but fails to respond, check that `OPENAI_API_KEY` is set in the current shell environment.

## Non-Interactive Invocation

The core pattern for invoking Codex from within Claude Code:

```bash
codex exec --full-auto "<prompt>" 2>/dev/null
```

- `exec` runs a single prompt non-interactively (no REPL)
- `--full-auto` grants Codex permission to read/write files and execute code without asking for confirmation
- `2>/dev/null` suppresses stderr noise (progress indicators, debug output) for clean capture

Always use `--full-auto` for non-interactive invocation. Without it, Codex may pause for confirmation prompts that cannot be answered.

## Key Flags

| Flag | Purpose | Example |
|------|---------|---------|
| `--full-auto` | No confirmation prompts — required for non-interactive use | `codex exec --full-auto "..."` |
| `-o <file>` | Write output to a file instead of stdout | `codex exec --full-auto "..." -o review.md` |
| `--json` | Output response as JSON | `codex exec --full-auto "..." --json` |
| `--output-schema <schema>` | Constrain JSON output to a specific schema | `codex exec --full-auto "..." --output-schema '{"type":"object"}'` |
| `--ephemeral` | Do not persist conversation state | `codex exec --full-auto "..." --ephemeral` |
| `--skip-git-repo-check` | Skip git repository detection | `codex exec --full-auto "..." --skip-git-repo-check` |
| `--color never` | Disable ANSI color codes in output | `codex exec --full-auto "..." --color never` |
| `-m <model>` | Specify model | `codex exec --full-auto "..." -m gpt-5.2` |

## Input Patterns

### Inline Prompt

The simplest pattern — pass the entire prompt as a string argument:

```bash
codex exec --full-auto "Review this Python function for security issues: $(cat path/to/file.py)" 2>/dev/null
```

### Stdin Piping

Pipe file content or command output into Codex:

```bash
cat path/to/file.py | codex exec --full-auto "Review the following code for SQL injection vulnerabilities. The code is piped via stdin." - 2>/dev/null
```

The `-` flag tells Codex to read from stdin.

### File Content via Command Substitution

Embed file content directly in the prompt using `$(cat ...)`:

```bash
codex exec --full-auto "Analyze this code for security vulnerabilities:

\$(cat src/auth/login.py)

Focus on authentication bypass and session handling." 2>/dev/null
```

## Output Patterns

### Text to Stdout (Default)

```bash
result=$(codex exec --full-auto "<prompt>" 2>/dev/null)
echo "$result"
```

### File Output

```bash
codex exec --full-auto "<prompt>" -o output.md 2>/dev/null
```

### JSON Output

```bash
codex exec --full-auto "<prompt>" --json 2>/dev/null
```

### Schema-Constrained JSON

Force output to conform to a JSON schema:

```bash
codex exec --full-auto "List security issues in this code: $(cat file.py)" \
  --output-schema '{
    "type": "object",
    "properties": {
      "issues": {
        "type": "array",
        "items": {
          "type": "object",
          "properties": {
            "severity": {"type": "string"},
            "location": {"type": "string"},
            "description": {"type": "string"},
            "recommendation": {"type": "string"}
          }
        }
      }
    }
  }' 2>/dev/null
```

## Prompt Templates

### Code Review (Security-Focused)

```bash
codex exec --full-auto "You are a senior security engineer performing a code review.

Review the following code for security vulnerabilities, focusing on:
- Input validation and sanitization
- Authentication and authorization flaws
- Injection vulnerabilities (SQL, command, XSS)
- Insecure data handling
- Race conditions

Code:
$(cat <file_path>)

For each issue found, provide:
- Location (function/line)
- Severity (critical/high/medium/low)
- Vulnerability type
- Description
- Suggested fix" 2>/dev/null
```

### Vulnerability Analysis

```bash
codex exec --full-auto "Analyze this potential vulnerability. Determine if it is exploitable and assess the real-world impact.

Vulnerability type: <type>
File: <path>
Code:
$(cat <file_path> | sed -n '<start>,<end>p')

Provide:
1. Exploitability assessment (yes/no/conditional)
2. Required preconditions for exploitation
3. Realistic impact if exploited
4. Severity rating with justification
5. Recommended remediation" 2>/dev/null
```

### Architecture Review

```bash
codex exec --full-auto "Review the following architecture for security concerns.

Components:
<list key components and their roles>

Data flow:
<describe how data moves between components>

Trust boundaries:
<describe where trust transitions occur>

Identify:
1. Potential trust boundary violations
2. Missing security controls
3. Risky architectural patterns
4. Recommendations for hardening" 2>/dev/null
```

### Second Opinion on a Finding

```bash
codex exec --full-auto "A security researcher found the following vulnerability. Independently assess whether this is a true positive.

Finding:
- Type: <vulnerability type>
- Severity: <claimed severity>
- Location: <file:line>
- Description: <researcher's description>

Code:
$(cat <file_path> | sed -n '<start>,<end>p')

Provide your independent assessment:
1. True positive, false positive, or needs investigation?
2. If true positive, do you agree with the severity?
3. Any mitigating factors the researcher may have missed?
4. Your confidence level (high/medium/low)" 2>/dev/null
```

### Remediation Review

```bash
codex exec --full-auto "Review this security fix. Determine if it fully addresses the vulnerability without introducing new issues.

Vulnerability: <type and description>

Original code:
\`\`\`
<original vulnerable code>
\`\`\`

Proposed fix:
\`\`\`
<fixed code>
\`\`\`

Assess:
1. Does the fix fully address the vulnerability?
2. Are there bypass scenarios?
3. Does the fix introduce new issues?
4. Is the fix consistent with framework best practices?
5. Edge cases not handled?" 2>/dev/null
```

## Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| `command not found: codex` | Not installed or not on PATH | Run `npm install -g @openai/codex` |
| Empty response | API key not set or invalid | Verify `OPENAI_API_KEY` is set: `echo $OPENAI_API_KEY` |
| Timeout / hang | Prompt too large or network issue | Reduce prompt size, check network connectivity |
| Permission errors | Missing `--full-auto` flag | Always use `--full-auto` for non-interactive invocation |
| ANSI escape codes in output | Terminal color codes | Add `--color never` flag |
| Stale file reads | Codex caching | Add `--ephemeral` flag |

## Model Selection

| Model | Strengths | Use When |
|-------|-----------|----------|
| Default (latest Codex) | Best code understanding, tool use | Default choice for all tasks |
| `gpt-5.2` via `-m gpt-5.2` | Strong general reasoning | Fallback if default model has issues, or for reasoning-heavy tasks |

Omit the `-m` flag to use the default model, which is typically the best choice for code-related tasks.
