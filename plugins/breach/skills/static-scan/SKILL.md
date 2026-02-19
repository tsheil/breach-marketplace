---
description: "Run static analysis tools on a codebase. This skill should be used when the user asks to run static analysis, scan with Semgrep, scan with CodeQL, run SAST tools, perform automated scanning, use automated security scanners, run deterministic pattern matching, perform dataflow analysis, use security scanning tools, or augment manual code review with tool-based analysis. Produces findings compatible with the breach finding lifecycle."
---

# Static Scan: Automated Security Analysis

This skill integrates Semgrep and CodeQL to augment Claude's manual code review with deterministic pattern matching and semantic dataflow analysis. Tool-generated findings catch well-known vulnerability patterns reliably and at scale, while Claude's manual review (via `/breach:code-analysis`) catches logic flaws and context-dependent issues that tools miss.

## Tool Detection & Installation

Before scanning, check tool availability and obtain user consent for any installations.

### Step 1: Check Available Tools

Run `which semgrep` and `which codeql` to determine which tools are on PATH. Record which are available and which are missing.

### Step 2: Install Missing Tools (User Consent Required)

For each missing tool, explain what it does and why it's useful, then **ask the user for confirmation** before installing:

- **Semgrep** (pattern-based static analysis): Matches code against security rule patterns. Fast, low false-positive rate for known vulnerability patterns.
  - macOS: `brew install semgrep`
  - pip: `pip install semgrep`
- **CodeQL** (semantic dataflow analysis): Builds a database of the codebase and runs queries that track tainted data from sources to sinks. Confirms whether attacker-controlled input actually reaches dangerous operations.
  - GitHub CLI: `gh extension install github/gh-codeql`
  - Direct: download from GitHub releases

If the user declines installation of a tool, skip that tool and continue with whatever is available.

If neither tool is available and the user declines both installations, exit with a message:

> Static scanning requires at least one tool (Semgrep or CodeQL). Install either tool and re-run `/breach:static-scan`, or use `/breach:code-analysis` for manual review.

## Semgrep Phase

Skip this phase if Semgrep is not available.

### Step 1: Run Security Rulesets

Execute Semgrep with security-focused rulesets against the target directory:

```
semgrep --config p/security-audit --config p/owasp-top-ten --json <target>
```

If the target is a specific language or framework, add relevant rulesets from the `semgrep-rulesets.md` reference file. Capture JSON output.

### Step 2: Parse Results

Extract from each Semgrep result:
- **Rule ID**: The Semgrep rule that matched (e.g., `python.lang.security.injection.sql-injection`)
- **File path and line range**: Exact location of the match
- **Message**: The rule's explanation of why this is a finding
- **Severity**: Semgrep's severity level (ERROR, WARNING, INFO)
- **Matched code**: The code snippet that triggered the rule
- **Metadata**: CWE IDs, OWASP categories, confidence level from the rule

### Step 3: Map to Breach Severity

| Semgrep Severity | Breach Severity |
|------------------|-----------------|
| ERROR | HIGH |
| WARNING | MED |
| INFO | LOW |

Upgrade to CRIT if the finding is unauthenticated RCE, auth bypass, or mass data exposure based on rule metadata and context.

### Step 4: Map Rule IDs to Vulnerability Types

Map Semgrep rule IDs to breach vulnerability type shorthands. Common mappings:

| Rule ID Pattern | Vuln Type |
|-----------------|-----------|
| `*.injection.sql*`, `*.sqli*` | SQLI |
| `*.injection.command*`, `*.exec*` | CMDI |
| `*.xss*`, `*.cross-site-scripting*` | XSS |
| `*.ssrf*` | SSRF |
| `*.path-traversal*`, `*.lfi*` | PATH-TRAV |
| `*.deserialization*` | DESER |
| `*.crypto*`, `*.hardcoded*` | CRYPTO |
| `*.auth*`, `*.jwt*`, `*.session*` | AUTH |
| `*.idor*`, `*.access-control*` | IDOR |
| `*.redirect*` | OPEN-REDIR |

For unmapped rules, derive a shorthand from the rule ID (e.g., `python.lang.security.dangerous-eval` → `EVAL`).

### Step 5: Deduplicate

Remove duplicate findings where the same file:line range is flagged by multiple rules for the same underlying issue. Keep the finding with the most specific rule match.

## CodeQL Phase

Skip this phase if CodeQL is not available.

### Step 1: Detect or Create Database

1. Check for an existing CodeQL database in `.codeql/`, `codeql-db/`, or `codeql-databases/` within the project root.
2. If no existing database is found:
   - Detect the primary language from project files (package.json → javascript, requirements.txt/setup.py → python, pom.xml/build.gradle → java, go.mod → go, Gemfile → ruby, *.csproj → csharp, Cargo.toml → rust)
   - Run: `codeql database create codeql-db --language=<detected-language> --source-root=<target>`
   - If multiple languages are detected, ask the user which to analyze or create databases for each

### Step 2: Run Security Query Suites

Execute the security and quality query suite for the detected language:

```
codeql database analyze codeql-db --format=sarif-latest --output=results.sarif <language>-security-and-quality.qls
```

Capture the SARIF output file.

### Step 3: Parse SARIF Results

Extract from each SARIF result:
- **Rule ID**: The CodeQL query that matched (e.g., `js/sql-injection`)
- **Message**: Description of the finding
- **Location**: File path, start line, end line, start column, end column
- **Severity**: SARIF level (error, warning, note)
- **Precision**: CodeQL's precision rating (very-high, high, medium, low)
- **Dataflow paths**: CodeQL's key advantage — the full path from tainted source to dangerous sink, with every intermediate step

### Step 4: Map to Breach Severity and Confidence

| SARIF Level | CodeQL Precision | Breach Severity | Breach Confidence |
|-------------|-----------------|-----------------|-------------------|
| error | very-high | CRIT or HIGH | Confirmed |
| error | high | HIGH | High |
| warning | very-high | HIGH | High |
| warning | high | MED | High |
| warning | medium | MED | Medium |
| note | any | LOW | Medium |

Adjust severity upward for unauthenticated attack vectors or findings affecting sensitive data (auth tokens, PII, financial data). Adjust downward if the dataflow path shows partial sanitization that may mitigate.

### Step 5: Extract Dataflow Paths

For each finding with a `codeFlow` in the SARIF output, extract the full taint path:

```
Source: user_input at file.py:10
  → transformation at file.py:15 (string concatenation)
  → passed to function at handler.py:42
  → reaches sink: db.execute() at handler.py:48
```

This is CodeQL's primary value — it confirms that attacker-controlled data actually reaches the dangerous sink through the specific code path, which is stronger evidence than pattern matching alone.

## Cross-Tool Deduplication

If both tools ran, deduplicate findings across Semgrep and CodeQL results:

1. Group findings by file:line range (allowing ±3 lines for overlap)
2. When both tools flag the same location:
   - Keep the CodeQL finding if it has a dataflow path (stronger evidence)
   - Keep the Semgrep finding if CodeQL's was lower precision
   - Merge metadata from both into the kept finding
3. Unique findings from either tool pass through as-is

## Lifecycle-Aware Mode

Before creating findings, check whether a `findings/` directory exists in the current working directory or any parent directory (up to 5 levels). The `findings/` directory is recognized by having stage subdirectories (`potential/`, `confirmed/`, `validated/`, `verified/`, `reported/`, `rejected/`).

### If `findings/` directory is found: Lifecycle Mode

For each deduplicated finding, create a finding folder in `findings/potential/`:

1. **Assign an ID**: Scan all finding folders across all stage directories (`potential/`, `confirmed/`, `validated/`, `verified/`, `reported/`, `rejected/`), extract the highest numeric ID from folder names (pattern: `{SEVERITY}-{ID}-{VULN_TYPE}-{desc}/`), and increment by 1. Zero-pad to 3 digits. If no existing findings, start at `001`.

2. **Create the finding folder**: Name it `{SEVERITY}-{ID}-{VULN_TYPE}-{desc}/` where:
   - `SEVERITY`: `CRIT`, `HIGH`, `MED`, or `LOW`
   - `ID`: Zero-padded 3-digit sequential ID
   - `VULN_TYPE`: Mapped shorthand from rule ID
   - `desc`: Kebab-case description derived from the rule message, ~40 characters max
   - Example: `HIGH-004-SQLI-raw-query-user-input/`

3. **Create `finding.md`**: Use the finding template from `finding-template.md` (in the hunt skill's references directory). Populate:
   - All standard frontmatter fields (`id`, `title`, `severity`, `vuln_type`, `affected_component`, `stage` as "potential", `created_at`, `last_moved`)
   - **`source`**: Set to `"semgrep"` or `"codeql"` to distinguish from manual findings
   - **Vulnerable Code** section: Code snippet from the tool output with file path, line numbers, and surrounding context
   - **Exploitability** section:
     - For CodeQL findings: include the full dataflow path from source to sink
     - For Semgrep findings: include the matched pattern and rule description
   - Leave other sections present with placeholder comments for later stages

4. **Create empty `poc/` directory** inside the finding folder.

After processing all findings, output a summary table:

| ID | Source | Severity | Type | Component | Title |
|----|--------|----------|------|-----------|-------|

### If no `findings/` directory is found: Standalone Mode

Output all findings to the conversation. For each finding, report:
- Source tool (Semgrep or CodeQL)
- Rule ID and message
- File path and line numbers
- Vulnerability type and severity
- Code snippet
- Dataflow path (CodeQL findings)

No filesystem changes.

## Pipeline Continuation

After completing static scanning and documenting all findings:

- **Lifecycle mode**: Findings have been written to `findings/potential/`. These will be processed alongside manual findings from `/breach:code-analysis` during the validation phase with `/breach:validate`. Run the full pipeline with `/breach:hunt` or proceed directly to validation.
- **Standalone mode**: Findings have been output to conversation. Run `/breach:validate` to validate findings or `/breach:code-analysis` for complementary manual review.
