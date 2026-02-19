---
name: breach-custom-rules
description: "Generate codebase-specific Semgrep rules and CodeQL queries. This skill should be used when the user asks to create custom static analysis rules, generate Semgrep rules for their codebase, create CodeQL queries tailored to their application, augment stock rulesets with application-specific patterns, or improve static scan coverage with custom detection rules. Analyzes code-recon output to identify gaps in stock ruleset coverage and generates rules targeting application-specific patterns like custom auth decorators, homegrown sinks, and framework-specific behaviors."
---

# Custom Rules: Codebase-Specific Static Analysis

This skill generates custom Semgrep rules and CodeQL queries tailored to the target codebase. Stock rulesets cover generic vulnerability patterns but miss application-specific constructs — custom auth decorators, homegrown ORM wrappers, framework-specific behaviors, and trust boundary violations unique to the codebase. This skill bridges that gap by analyzing code-recon output and producing rules that catch what stock rulesets cannot.

## Phase 0: Input Collection

Parse code-recon output (preferred) or do rapid codebase fingerprinting (fallback) to extract:
- Technology stack (languages, frameworks, versions)
- Entry points (routes, handlers, API endpoints)
- Trust boundaries (external → internal, user → admin, service → service)
- Authentication patterns (decorators, middleware, guards)
- Critical sinks (database access patterns, command execution wrappers, file system operations)
- Custom abstractions (ORM wrappers, validation layers, template engines)

If `/breach:code-recon` output is available (in conversation context or as a file), parse it for the above. If not available, do a rapid fingerprint:
1. Scan for framework config files (package.json, requirements.txt, pom.xml, go.mod, etc.)
2. Identify auth patterns (grep for common decorator/middleware patterns)
3. Map entry points (grep for route definitions)
4. Identify custom sinks (grep for DB/exec/file operations)

## Phase 1: Gap Analysis

If prior `/breach:static-scan` results exist, analyze which vulnerability classes were covered vs. gaps:
1. List vuln types found by stock rules
2. Identify categories NOT covered (referencing the rule-categories.md reference)
3. Cross-reference with code-recon output for application-specific patterns

Produce a rule generation plan as a table:

```
| # | Rule Type | Target Pattern | Rationale | Tool |
|---|-----------|---------------|-----------|------|
| 1 | Auth enforcement | Routes missing @auth_required | Stock rules don't know app's auth decorator | Semgrep |
| 2 | Custom sink | db.raw_query() calls | App-specific DB wrapper bypasses ORM safety | CodeQL |
| ... | ... | ... | ... | ... |
```

Prioritize by rule category priority (1-10 from rule-categories.md reference). Generate rules for the top patterns — aim for 5-15 high-value rules rather than exhaustive coverage.

## Phase 2: Semgrep Rule Generation

For each target pattern suited to Semgrep (pattern matching without complex dataflow):

1. **Write the YAML rule** following the semgrep-rule-syntax.md reference:
   - `id: breach-custom-{category}-{description}` (e.g., `breach-custom-auth-missing-login-required`)
   - Appropriate `patterns`/`pattern-not`/`pattern-inside` combinators
   - `severity`: error, warning, or info
   - `metadata`: cwe, owasp, confidence, breach_category
   - `languages`: target language(s)
   - `paths`: include/exclude patterns if needed
   - `message`: Clear explanation of what the rule detects and why it matters

2. **Validate the rule mentally**:
   - Trace through the pattern against known-good code (should NOT match)
   - Trace through the pattern against known-vulnerable code (SHOULD match)
   - Check for common false positive scenarios and add `pattern-not` exclusions
   - Verify the language syntax is correct for the target language

3. **Test awareness**: Note that rules should be tested with `semgrep --config ./custom-rules/semgrep/ --test` if test files are provided.

## Phase 3: CodeQL Query Generation

For target patterns requiring dataflow analysis (taint tracking from source to sink):

1. **Write the QL query** following the codeql-query-syntax.md reference:
   - Metadata block with `@id breach-custom/{category}/{description}`
   - `@kind path-problem` for taint queries, `@kind problem` for pattern queries
   - `@problem.severity` and `@security-severity` ratings
   - `@tags security` plus relevant CWE/OWASP tags
   - Proper taint tracking configuration:
     - `isSource`: Define sources (user input, external data)
     - `isSink`: Define sinks (app-specific dangerous operations)
     - `isSanitizer`: Define sanitization functions the app uses
   - Language-specific imports

2. **Validate the query mentally**:
   - Verify source definitions match actual entry points
   - Verify sink definitions match the app's specific dangerous operations
   - Check that sanitizers correctly exclude safe patterns
   - Consider edge cases (indirect flows, wrapper functions)

## Phase 4: Output & Storage

1. **Write Semgrep rules** to `custom-rules/semgrep/` in the project root:
   - One file per category: `breach-custom-{category}.yml`
   - Each file can contain multiple rules in the `rules:` array
   - All rules follow the naming convention `breach-custom-{category}-{description}`

2. **Write CodeQL queries** to `custom-rules/codeql/` in the project root:
   - One file per query: `breach-custom-{category}-{description}.ql`
   - Include a `qlpack.yml` if multiple queries are generated

3. **Generate README.md** in `custom-rules/` with:
   - Summary of generated rules and their purpose
   - Usage instructions:
     ```
     # Run custom Semgrep rules
     semgrep --config ./custom-rules/semgrep/ <target>

     # Run custom CodeQL queries
     codeql database analyze <db> ./custom-rules/codeql/ --format=sarif-latest --output=custom-results.sarif
     ```
   - Table of rules: `| Rule ID | Category | Target Pattern | Tool | Severity |`
   - Notes on false positive tuning

4. **Output summary** to conversation:
   - Number of Semgrep rules generated
   - Number of CodeQL queries generated
   - Categories covered
   - Estimated coverage improvement

## Rule Categories (Priority Order)

Rules are generated in priority order based on the rule-categories.md reference:

1. Custom auth enforcement gaps
2. Application-specific sinks
3. Framework-specific patterns
4. Missing validation enforcement
5. Trust boundary violations
6. IDOR patterns
7. Configuration rules
8. Second-order sinks
9. Serialization & crypto misuse
10. Error handling leaks

Higher-priority categories are generated first. The skill aims for 5-15 high-value rules — quality over quantity.

## Integration with Pipeline

- **Invoked by**: `/breach:hunt` during initialization (Phase A.3), after code-recon and before static-scan
- **Output consumed by**: `/breach:static-scan` (detects `custom-rules/` directory and includes custom rulesets)
- **Standalone usage**: Can be run independently to generate rules for any codebase

## Backward Compatibility

- If code-recon output is not available, the skill falls back to rapid fingerprinting
- If Semgrep is not installed, only CodeQL queries are generated (and vice versa)
- If neither tool is available, the skill outputs rule definitions to conversation for manual use
- The `custom-rules/` directory is created only when rules are generated

## References

- `references/rule-categories.md` — Taxonomy of custom rule categories with rationale and examples
- `references/semgrep-rule-syntax.md` — Semgrep rule authoring reference
- `references/codeql-query-syntax.md` — CodeQL query authoring reference
- `/breach:code-recon` — Attack surface map providing input for rule generation
- `/breach:static-scan` — Consumes generated rules during scanning
