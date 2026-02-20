# Gemini CLI Reference

Gemini CLI is Google's command-line AI agent. It accepts natural language prompts, can read and modify files, execute code in a sandbox, and return formatted output. This reference covers non-interactive invocation patterns for use within Claude Code.

## Installation & Setup

Install Gemini CLI globally via npm:

```bash
npm install -g @anthropic-ai/gemini-cli
```

Note: Check the [Gemini CLI repository](https://github.com/google-gemini/gemini-cli) for the current install command, as the package name may have changed.

Verify the installation:

```bash
which gemini && gemini -p "respond with OK" 2>/dev/null
```

**Requirements:**
- Node.js (v18+)
- Google AI API key (`GEMINI_API_KEY`) or Google Cloud credentials configured

If `gemini` is on PATH but fails to respond, check that authentication is configured correctly.

## Non-Interactive Invocation

The core pattern for invoking Gemini from within Claude Code:

```bash
gemini -p "<prompt>" 2>/dev/null
```

- `-p` (prompt mode) runs a single prompt non-interactively and exits
- `2>/dev/null` suppresses stderr output (progress indicators, warnings, debug info) for clean capture

Always use `-p` for non-interactive invocation. Without it, Gemini enters interactive REPL mode which cannot be used from within another agent.

**Important:** Gemini CLI writes status and progress information to stderr. Always redirect stderr to `/dev/null` when capturing output programmatically:

```bash
# Clean output capture
result=$(gemini -p "<prompt>" 2>/dev/null)
```

## Key Flags

| Flag | Purpose | Example |
|------|---------|---------|
| `-p "<prompt>"` | Non-interactive single prompt — required for programmatic use | `gemini -p "review this code"` |
| `--output-format <format>` | Control output format (text, json, markdown) | `gemini -p "..." --output-format json` |
| `--yolo` | Auto-approve all tool use (no confirmation prompts) | `gemini -p "..." --yolo` |
| `--sandbox` | Run in sandboxed environment | `gemini -p "..." --sandbox` |
| `-m <model>` | Specify model | `gemini -p "..." -m gemini-3-flash` |

## Input Patterns

### Inline Prompt

Pass the entire prompt as a string argument to `-p`:

```bash
gemini -p "Review this Python function for security issues: $(cat path/to/file.py)" 2>/dev/null
```

### Stdin Piping

Pipe content into Gemini:

```bash
cat path/to/file.py | gemini -p "Review the following code piped via stdin for SQL injection vulnerabilities." 2>/dev/null
```

### File Content via Command Substitution

Embed file content directly in the prompt:

```bash
gemini -p "Analyze this code for security vulnerabilities:

$(cat src/auth/login.py)

Focus on authentication bypass and session handling." 2>/dev/null
```

### Multi-File Context

Combine multiple files into a single prompt:

```bash
gemini -p "Review these related files for security issues:

--- src/routes/api.py ---
$(cat src/routes/api.py)

--- src/models/user.py ---
$(cat src/models/user.py)

Focus on how user input flows from the API routes to database queries." 2>/dev/null
```

## Output Patterns

### Text to Stdout (Default)

```bash
result=$(gemini -p "<prompt>" 2>/dev/null)
echo "$result"
```

### File Output via Redirection

Gemini does not have a built-in file output flag. Use stdout redirection:

```bash
gemini -p "<prompt>" 2>/dev/null > output.md
```

### JSON Output

Request JSON via the `--output-format` flag:

```bash
gemini -p "<prompt>" --output-format json 2>/dev/null
```

Or request JSON formatting in the prompt itself:

```bash
gemini -p "<prompt>. Respond with valid JSON only, no markdown fences or explanations." 2>/dev/null
```

### Structured Output via Prompt

Since Gemini does not have schema-constrained output like Codex's `--output-schema`, specify the structure in the prompt:

```bash
gemini -p "List security issues in this code: $(cat file.py)

Respond with a JSON array where each item has these fields:
- severity: string (critical/high/medium/low)
- location: string (function name and line number)
- description: string (what the issue is)
- recommendation: string (how to fix it)

Output only the JSON array, no other text." 2>/dev/null
```

## Prompt Templates

### Code Review (Security-Focused)

```bash
gemini -p "You are a senior security engineer performing a code review.

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
gemini -p "Analyze this potential vulnerability. Determine if it is exploitable and assess the real-world impact.

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
gemini -p "Review the following architecture for security concerns.

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
gemini -p "A security researcher found the following vulnerability. Independently assess whether this is a true positive.

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
gemini -p "Review this security fix. Determine if it fully addresses the vulnerability without introducing new issues.

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
| `command not found: gemini` | Not installed or not on PATH | Check [Gemini CLI repo](https://github.com/google-gemini/gemini-cli) for current install command |
| Empty response | API key not set or invalid | Verify `GEMINI_API_KEY` is set or Google Cloud credentials are configured |
| Stderr noise in output | Gemini writes progress to stderr | Always use `2>/dev/null` when capturing output |
| Timeout / hang | Prompt too large or network issue | Reduce prompt size, check network connectivity |
| Interactive mode entered | Missing `-p` flag | Always use `-p` for non-interactive invocation |
| Markdown formatting in JSON | Model wrapping JSON in code fences | Add "no markdown fences" to prompt, or strip fences post-capture |

## Model Selection

| Model | Strengths | Use When |
|-------|-----------|----------|
| Default (latest Gemini Pro) | Best reasoning, large context window | Default choice for all tasks |
| `gemini-3-flash` via `-m gemini-3-flash` | Faster, lower cost | Quick lookups, simple reviews, when speed matters more than depth |

Omit the `-m` flag to use the default model, which is typically the best choice for reasoning-heavy tasks. Use `gemini-3-flash` for simpler tasks where speed is more important than depth.
