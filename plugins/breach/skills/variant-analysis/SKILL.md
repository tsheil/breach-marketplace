---
name: breach-variant-analysis
description: "Find variants of known vulnerabilities across the codebase. This skill should be used when the user asks to find variants of a vulnerability, hunt for similar bugs, search for the same pattern elsewhere, analyze a CVE for local variants, perform variant analysis on a finding, find other instances of a vulnerability pattern, check if a known bug exists in other endpoints, find variations of a validated finding, research a CVE and check for local impact, or generate detection rules from a known vulnerability. Works with validated findings, CVE IDs, public disclosures, or raw vulnerability patterns."
---

# Variant Analysis: Pattern-Based Vulnerability Discovery

This skill takes a known vulnerability instance — a validated finding, CVE, public disclosure, or raw pattern — extracts its structural essence, generates targeted detection rules, and systematically searches the codebase for variants. Variant analysis is one of the most effective vulnerability discovery techniques: if one instance of a pattern exists, more are likely.

## Input Types

### Type A — Validated Finding

Read from `findings/validated/` or `findings/confirmed/`. Extract:
- Dangerous sink (the security-sensitive function/operation)
- Source type (where attacker input enters)
- Missing control (what sanitization/validation/authorization is absent)
- Code structure (how the vulnerability is arranged)
- Context constraints (framework, language, ORM, etc.)

### Type B — CVE ID

Research the CVE to find the vulnerability pattern:
1. Search NVD/MITRE for CVE details (description, CWE, affected product)
2. Find the patch commit (via GitHub advisory, vendor advisory, or commit search)
3. Analyze the patch diff: the "before" is the vulnerable pattern, the "after" is the safe pattern
4. Extract structural pattern from the vulnerable code
5. Assess whether the target codebase uses the same or similar technology

See `references/cve-research-guide.md` for detailed CVE research methodology.

### Type C — Public Disclosure

Fetch the disclosure URL or parse the provided description:
1. Extract the vulnerability type and affected component
2. Identify the vulnerable code pattern from the writeup
3. Abstract the pattern away from the specific application
4. Map to the target codebase's technology stack

### Type D — Raw Pattern

Accept a user-provided code pattern or vulnerability description:
1. Parse the pattern description
2. Identify the vulnerability class
3. Define the structural pattern (sink, source, missing control)
4. Proceed directly to Phase 1

## Phase 1: Pattern Extraction

### 1.1 Identify Vulnerability Skeleton

From the input (regardless of type), extract these elements:

| Element | Description | Example |
|---------|-------------|---------|
| **Dangerous sink** | The security-sensitive operation | `db.execute()` with string formatting |
| **Source type** | Where attacker input originates | HTTP query parameter |
| **Missing control** | What protection is absent | Parameterized query / input validation |
| **Code structure** | How the vulnerability is arranged | Controller → service → raw query |
| **Context constraint** | Framework/language/ORM specifics | Flask + SQLAlchemy raw text() |

### 1.2 Abstract Away Incidentals

Remove details that are specific to the original instance but not fundamental to the vulnerability:
- Specific variable names
- Specific endpoint paths
- Specific parameter names
- Specific table/column names
- Surrounding business logic

Keep only the structural pattern: "user input reaches [sink] without [control] via [code structure]."

### 1.3 Define Variant Space

Enumerate the dimensions along which variants may exist:

| Variant Dimension | Description | Example |
|-------------------|-------------|---------|
| **Same sink, different source** | Same dangerous function, different input origin | Same raw query, but input comes from header instead of query param |
| **Same pattern, different endpoint** | Identical vulnerability in another handler | Same SQL concatenation in `/api/users` and `/api/orders` |
| **Syntactic variants** | Same logical flaw with different syntax | f-string vs .format() vs % formatting in Python SQL |
| **Wrapper variants** | Pattern hidden behind a wrapper function | Custom `run_query()` that internally uses string concatenation |
| **Framework analogs** | Same pattern in a different framework feature | Raw SQL in ORM `.extra()`, `.raw()`, `.execute()` methods |

## Phase 2: Rule Generation

### 2.1 Tool Selection

Select detection tool based on pattern characteristics:

| Pattern Type | Best Tool | Rationale |
|--------------|-----------|-----------|
| Structural/syntactic (specific function call with specific argument pattern) | Semgrep | Pattern matching excels at structural matching |
| Dataflow (source reaches sink through transformations) | CodeQL | Semantic analysis tracks taint through data flow |
| Simple string patterns | Grep/Semgrep | When the pattern is a specific string or regex |
| Complex multi-step | Both | Semgrep for structural + CodeQL for flow confirmation |

### 2.2 Generate Semgrep Rules

For each identified pattern, generate a Semgrep rule:

- **Rule ID**: `breach-variant-{vuln_type}-{description}` (e.g., `breach-variant-sqli-raw-query-format`)
- **Severity**: Match the original finding's severity
- **Pattern**: Use Semgrep pattern syntax (metavariables, ellipsis operators, pattern-either)
- **Message**: Describe the variant pattern and reference the original finding
- **Metadata**: Include `source_finding` or `source_cve`, variant dimension

Write rules to `variant-rules/semgrep/` in the project root.

### 2.3 Generate CodeQL Queries (when dataflow patterns exist)

For dataflow patterns:
- **Query**: Define source, sink, and sanitizer predicates
- **Path problem**: Use `@kind path-problem` for taint tracking
- **Description**: Reference the original finding

Write queries to `variant-rules/codeql/` in the project root.

### 2.4 Manual Search Patterns

For patterns that don't translate well to tool rules, generate grep/search patterns:
- Dangerous function names to search for
- Import statements that indicate vulnerable library usage
- Configuration patterns that enable the vulnerability

## Phase 3: Codebase Scan

### 3.1 Run Generated Rules

Execute detection rules against the codebase:

**Semgrep** (if rules were generated):
```
semgrep --config variant-rules/semgrep/ --json
```

**CodeQL** (if queries were generated and database exists):
```
codeql database analyze <db> variant-rules/codeql/ --format=sarif
```

### 3.2 AI-Assisted Manual Review

Supplement automated scanning with manual review:

1. **Sink variant search**: Search for all instances of the dangerous sink function across the codebase (not just the original file). Use Grep to find all call sites.
2. **Source-sink co-occurrence**: Search for files that import/use both the dangerous sink and user input handling.
3. **Co-located code**: Examine other functions in the same file/module as the original vulnerability — developers often repeat patterns.
4. **Wrapper function tracing**: If the sink is called through a wrapper, find all callers of the wrapper.
5. **Configuration patterns**: Check if the vulnerability is enabled by a configuration that applies globally.

### 3.3 Parallelization

When analyzing multiple patterns, use subagent parallelization:
- Launch separate subagents for each independent pattern search
- Each subagent searches for one variant dimension
- Collect and deduplicate results

## Phase 4: Result Triage

### 4.1 Filter

Remove results that are not true variants:
- **Skip original instance**: Exclude the finding that was used as input
- **Skip test files**: Exclude test fixtures, mock data, and test helpers (unless test code runs in production)
- **Skip dead code**: Exclude unreachable functions, commented-out code, and unused imports
- **Skip existing findings**: Cross-reference with all findings in `findings/` stages to avoid duplicates

### 4.2 Lightweight Validation

For each remaining result, perform quick validation:
1. **Confirm reachability**: Is the code reachable from an entry point?
2. **Confirm pattern match**: Does the code actually match the vulnerability pattern (not just superficially)?
3. **Check mitigations**: Are there controls (validation, sanitization, authorization) that prevent exploitation?
4. **Assess confidence**: Rate as high (clear pattern match, no mitigations), medium (pattern match but some controls exist), or low (partial match, needs deeper analysis)

### 4.3 Create Findings

#### Lifecycle Mode (findings/ directory exists)

For each confirmed variant, create a finding in `findings/potential/`:
1. Follow standard ID assignment (scan all stages, increment highest ID)
2. Name format: `{SEVERITY}-{NNN}-{VULN_TYPE}-{desc}/`
3. Create `finding.md` with:
   - Standard frontmatter fields
   - `source: "variant-analysis"`
   - `variant_of: "{original finding ID, CVE ID, or disclosure URL}"`
   - Vulnerable Code section with the variant's code
   - Exploitability section referencing the original pattern
4. Create empty `poc/` directory

#### Standalone Mode (no findings/ directory)

Output variants to conversation using the standard finding documentation format, noting each is a variant of the original.

## Output

### Variant Analysis Summary

Always output a summary after analysis:

```
── Variant Analysis Complete ──────────────────────────
Source:              {finding ID / CVE / disclosure URL / pattern description}
Pattern:             {extracted vulnerability skeleton}
Rules generated:     {N} Semgrep rules, {N} CodeQL queries
Scan results:        {N} raw matches
After triage:        {N} confirmed variants, {N} filtered
Variants found:
  {SEVERITY}-{ID}-{TYPE}-{desc}: {brief description}
  ...
────────────────────────────────────────────────────────
```

If no variants are found:

```
── Variant Analysis Complete ──────────────────────────
Source:              {source}
Pattern:             {pattern}
Rules generated:     {N} Semgrep rules, {N} CodeQL queries
Scan results:        {N} raw matches
After triage:        0 confirmed variants
Conclusion:          No variants found. The original instance appears to be isolated
                     rather than part of a systemic pattern.
────────────────────────────────────────────────────────
```

## Lifecycle-Aware Mode

Before beginning analysis, check whether a `findings/` directory exists (same detection as other breach skills — check current directory and up to 5 parent levels for `findings/` with stage subdirectories).

- **Lifecycle mode** (findings/ found): Create findings in `findings/potential/` with `source: "variant-analysis"`. Cross-reference existing findings for deduplication.
- **Standalone mode** (no findings/): Output all results to conversation.

## Pipeline Integration

- **From hunt**: When `/breach:hunt` selects `variant-hunt` as the analysis approach in B.1, it invokes this skill instead of `/breach:code-analysis`. Select a validated finding from `findings/validated/` (prefer findings not yet variant-analyzed).
- **From validate-finding**: After a finding is validated, variant analysis can be run on it to find similar issues.
- **Standalone**: Can be invoked directly with any of the 4 input types.

## References

- `references/variant-extraction-patterns.md` — Pattern abstraction guide by vulnerability class
- `references/cve-research-guide.md` — CVE research methodology
