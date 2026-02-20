---
name: ai-collaboration
description: "Delegate tasks and consult other AI models via CLI tools (Codex CLI, Gemini CLI). Use when the user asks to get a second opinion from another model, consult Codex or Gemini, ask another AI for a code review, delegate a task to another model, get an alternative perspective on code or architecture, cross-check analysis with a different AI, use Codex CLI or Gemini CLI for a task, hand off work to another AI agent, get a second model's take on a vulnerability, or compare approaches across AI providers."
---

# AI Collaboration: Cross-Model Consultation & Task Delegation

Invoke other AI models via their CLI tools to get second opinions, cross-check analysis, or delegate discrete tasks. This skill supports two tools: **Codex CLI** (OpenAI) for code-focused tasks and **Gemini CLI** (Google) for broad reasoning and research tasks. Each tool runs non-interactively, receives a prompt, and returns output that can be captured and synthesized.

All invocations are user-initiated. Do not proactively suggest consulting another model. Wait for the user to request a second opinion, delegation, or cross-check before invoking any external tool.

## Prerequisites

Before invoking any external model, detect which CLI tools are available and verify they work.

### Step 1: Detect Available Tools

Run `which codex` and `which gemini` to determine which tools are on PATH. Record which are available and which are missing.

### Step 2: Verify Working Tools

For each detected tool, run a quick test to confirm it responds:

- **Codex CLI**: `codex exec --full-auto "respond with OK" 2>/dev/null`
- **Gemini CLI**: `gemini -p "respond with OK" 2>/dev/null`

If a tool is on PATH but fails the test, report the error to the user and skip that tool.

### Step 3: Install Missing Tools (User Consent Required)

For each missing tool the user wants to use, explain what it provides and **ask for confirmation** before installing:

- **Codex CLI** (OpenAI code agent): `npm install -g @openai/codex`
  - Requires: Node.js, `OPENAI_API_KEY` environment variable
- **Gemini CLI** (Google AI agent): `npm install -g @anthropic-ai/gemini-cli` is not correct — install via `npm install -g @anthropic-ai/claude` is also wrong. Install via: `npm install -g @anthropic-ai/gemini-cli` — check the current install command from the [Gemini CLI repo](https://github.com/google-gemini/gemini-cli). The standard install is: `npm install -g @anthropic-ai/gemini-cli`
  - Requires: Node.js, Google AI API key or Google Cloud credentials

If the user declines installation and no tools are available, exit with:

> Cross-model consultation requires at least one CLI tool (Codex CLI or Gemini CLI). Install either tool and re-run `/ai-collaboration`.

## Consultation Patterns

Use consultation when the user wants a second opinion or alternative perspective without delegating full control of the task.

### Second Opinion

Get another model's take on a specific question, code snippet, or analysis:

1. Extract the relevant context (code, finding, question) into a self-contained prompt
2. Invoke the chosen tool:
   - Codex: `codex exec --full-auto "<prompt>" 2>/dev/null`
   - Gemini: `gemini -p "<prompt>" 2>/dev/null`
3. Capture and present the response alongside your own analysis
4. Highlight areas of agreement and disagreement

**Prompt structure for second opinions:**
```
You are reviewing the following [code/analysis/finding]. Provide your independent assessment.

Context:
<paste relevant code or analysis>

Question:
<specific question to answer>

Respond with your assessment, noting confidence level and any caveats.
```

### Code Review Request

Send a focused code review request to another model:

1. Read the target file(s) and extract the relevant section
2. Construct a review prompt with the code, language, and specific focus areas
3. Invoke the tool and capture the response
4. Present the external review alongside your own observations

**Prompt structure for code reviews:**
```
Review the following <language> code for [security vulnerabilities / correctness / performance / readability]. Focus on: <specific concerns>.

File: <path>
```python
<code>
```

List each issue found with: location, severity (critical/high/medium/low), description, and suggested fix.
```

### Architecture Review

Request an architectural assessment of a design decision or system structure:

1. Summarize the architecture, components, and the specific decision under review
2. Include relevant code snippets, diagrams, or configuration
3. Ask for trade-off analysis and alternative approaches
4. Compare the external model's assessment with your own

## Task Delegation

Use delegation when the user wants another model to perform a self-contained unit of work with clear inputs and outputs.

### Structured Delegation

For well-defined tasks with clear inputs and expected output format:

1. Define the task with explicit boundaries — what to do, what not to do
2. Provide all necessary context inline (do not reference external files the tool cannot access)
3. Specify the expected output format precisely
4. Invoke the tool and capture the full output

**Prompt structure for structured delegation:**
```
Task: <one-sentence description>

Input:
<all necessary context, code, data>

Requirements:
- <requirement 1>
- <requirement 2>

Output format:
<exact format specification — JSON schema, markdown template, etc.>

Do not include explanations outside the specified format.
```

For Codex, use `--json` or `--output-schema` flags when JSON output is needed. See [references/codex-cli.md](references/codex-cli.md) for details.

### Research Delegation

For information gathering tasks where the model uses its training data:

1. Define the research question clearly
2. Specify what kind of information is needed (examples, patterns, best practices, known issues)
3. Ask for structured output with sources or reasoning
4. Evaluate the response critically — training data may be outdated

**Prompt structure for research delegation:**
```
Research question: <specific question>

Context: <why this matters, what project/technology is involved>

Provide:
- <specific deliverable 1>
- <specific deliverable 2>

Format each item with: <format specification>
```

## Security-Specific Patterns

These patterns are tailored for security analysis workflows. Each includes a ready-to-use prompt template.

### Vulnerability Second Opinion

Get another model's assessment of a potential vulnerability:

```
Analyze this potential vulnerability finding. Assess whether it is a true positive, false positive, or needs more investigation.

Vulnerability type: <type>
Affected component: <file:line>
Code:
```<language>
<vulnerable code with surrounding context>
```

Questions:
1. Is this exploitable? Under what conditions?
2. What is the realistic impact if exploited?
3. Are there mitigating factors (sanitization, access controls, framework protections)?
4. What severity would you assign (critical/high/medium/low) and why?
```

### Alternative Attack Surface Analysis

Ask another model to identify attack vectors you may have missed:

```
Given the following codebase summary and technology stack, identify potential attack surfaces not covered in the existing analysis.

Technology stack: <languages, frameworks, databases, APIs>
Architecture: <brief architecture description>
Already analyzed: <list of areas already reviewed>

Focus on:
1. Attack surfaces specific to this technology stack
2. Integration points between components
3. Trust boundary violations
4. Non-obvious data flows
```

### Remediation Validation

Cross-check a proposed fix with another model:

```
Review this proposed fix for a <vulnerability type> vulnerability.

Original vulnerable code:
```<language>
<original code>
```

Proposed fix:
```<language>
<fixed code>
```

Assess:
1. Does the fix fully address the vulnerability?
2. Does the fix introduce any new vulnerabilities or regressions?
3. Is the fix consistent with security best practices for this framework?
4. Are there edge cases the fix does not handle?
```

## Output Handling

### Text Output (Default)

Both tools write their response to stdout by default. Capture it directly:

```bash
# Codex
result=$(codex exec --full-auto "<prompt>" 2>/dev/null)

# Gemini
result=$(gemini -p "<prompt>" 2>/dev/null)
```

### File Output

Write the response directly to a file:

```bash
# Codex — built-in flag
codex exec --full-auto "<prompt>" -o output.md 2>/dev/null

# Gemini — stdout redirection
gemini -p "<prompt>" 2>/dev/null > output.md
```

### JSON Output

For structured data exchange:

```bash
# Codex — native JSON mode
codex exec --full-auto "<prompt>" --json 2>/dev/null

# Codex — schema-constrained output
codex exec --full-auto "<prompt>" --output-schema '{"type":"object","properties":{"issues":{"type":"array"}}}' 2>/dev/null

# Gemini — request JSON in prompt, parse from stdout
gemini -p "<prompt>. Respond with valid JSON only." 2>/dev/null
```

### Presenting Results

When presenting external model output to the user:

1. Identify the source model clearly (e.g., "Codex's assessment:" or "Gemini's response:")
2. Present the external response in a blockquote or code block
3. Follow with your own synthesis — areas of agreement, disagreement, and your recommendation
4. Let the user make the final decision on conflicting assessments

## Tool Selection Guidance

Choose the appropriate tool based on the task characteristics:

| Factor | Codex CLI | Gemini CLI |
|--------|-----------|------------|
| **Best for** | Code-focused tasks, structured output | Broad reasoning, research questions |
| **Output control** | `--json`, `--output-schema`, `-o` | Stdout with prompt-directed formatting |
| **Code execution** | Can execute code in sandbox (`--full-auto`) | Sandbox mode available (`--sandbox`) |
| **Context handling** | Reads files in working directory | Reads files in working directory |
| **Invocation** | `codex exec --full-auto "<prompt>"` | `gemini -p "<prompt>"` |
| **Default model** | Latest Codex model | Latest Gemini model |

When both tools are available and the user has no preference:
- Use **Codex** for code review, refactoring, implementation tasks, and structured output
- Use **Gemini** for research, broad analysis, alternative perspectives, and reasoning-heavy tasks
- Use **both** when the user explicitly requests cross-model validation

## Prompt Construction Principles

Follow these principles when constructing prompts for external models:

1. **Self-contained context**: Include all necessary code, configuration, and background directly in the prompt. External models cannot access your conversation history or read files unless explicitly told to.

2. **Explicit output format**: Specify exactly how the response should be structured. Unstructured free-text responses are harder to synthesize and compare.

3. **Scoped tasks**: Keep each invocation focused on a single, well-defined task. Broad prompts produce vague results.

4. **No ambiguity**: State what you want and what you do not want. Specify the programming language, framework version, and any constraints.

5. **Role and constraints**: Open with the model's role (e.g., "You are a security researcher reviewing...") and any constraints (e.g., "Do not suggest changes outside the affected function").

For detailed CLI flags, invocation patterns, and additional prompt templates, see the reference files:
- [references/codex-cli.md](references/codex-cli.md) — Codex CLI usage, flags, and templates
- [references/gemini-cli.md](references/gemini-cli.md) — Gemini CLI usage, flags, and templates
