# Semgrep Rule Authoring Reference

This document is a comprehensive reference for writing custom Semgrep rules. It covers YAML structure, pattern syntax, combinators, advanced features, language-specific examples, metadata best practices, and common pitfalls.

---

## YAML Structure

Every Semgrep rule file is a YAML document with a top-level `rules:` array. Each element in the array is a single rule.

### Minimal Rule

```yaml
rules:
  - id: detect-hardcoded-secret
    pattern: |
      password = "..."
    message: >
      Hardcoded password detected. Use environment variables or a secrets manager instead.
    languages:
      - python
    severity: ERROR
```

### Required Fields

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique identifier. Use kebab-case. Must be unique across all loaded rules. |
| `pattern` or `patterns` or `pattern-either` | string or list | The matching logic (at least one pattern key is required at the rule top level). |
| `message` | string | Human-readable finding description. Can reference metavariables with `$VAR`. |
| `languages` | list of strings | Target languages. Use `generic` for language-agnostic text matching. |
| `severity` | string | One of `ERROR`, `WARNING`, or `INFO`. |

### Optional Fields

| Field | Type | Description |
|---|---|---|
| `metadata` | mapping | Arbitrary key-value data attached to findings. Used for CWE, OWASP, references, etc. |
| `paths` | mapping | Include/exclude file paths. Contains `include` and/or `exclude` lists of glob patterns. |
| `fix` | string | Auto-fix replacement text. Supports metavariable interpolation. |
| `fix-regex` | mapping | Regex-based auto-fix with `regex`, `replacement`, and optional `count`. |
| `options` | mapping | Tuning knobs such as `symbolic_propagation: true` or `generic_comment_style`. |
| `mode` | string | Execution mode. Default is `search`. Set to `taint` for taint analysis or `join` for join mode. |
| `min-version` | string | Minimum Semgrep version required to run this rule. |
| `max-version` | string | Maximum Semgrep version this rule supports. |

### Paths (Include / Exclude)

```yaml
rules:
  - id: example-with-paths
    pattern: dangerous_function(...)
    message: Do not use dangerous_function.
    languages: [python]
    severity: WARNING
    paths:
      include:
        - "src/**"
        - "lib/**"
      exclude:
        - "*_test.py"
        - "tests/**"
        - "vendor/**"
```

### Options

```yaml
rules:
  - id: example-with-options
    pattern: eval(...)
    message: Avoid eval.
    languages: [python]
    severity: ERROR
    options:
      symbolic_propagation: true
      ac_matching: false
```

---

## Pattern Syntax

Semgrep patterns are written in the target language's own syntax, augmented with special operators.

### Ellipsis Operator (`...`)

The ellipsis `...` matches zero or more arguments, statements, or other syntactic elements.

**Match any arguments to a function:**

```yaml
pattern: |
  requests.get(...)
```

Matches `requests.get("https://example.com")`, `requests.get(url, headers=h, timeout=30)`, etc.

**Match any statements between two calls:**

```yaml
pattern: |
  conn = get_connection(...)
  ...
  conn.execute($QUERY)
```

Matches any code where `conn.execute(...)` is called after `conn = get_connection(...)`, regardless of how many statements appear in between.

**Match any number of elements in a data structure:**

```yaml
pattern: |
  {"password": ..., ...}
```

Matches any dictionary literal containing a `"password"` key, with any value and any other keys.

### Metavariables

Metavariables capture matched code for reuse in the same rule (in other pattern clauses, in `message`, or in `fix`).

| Syntax | Name | What It Captures |
|---|---|---|
| `$VAR` | Named metavariable | A single expression, identifier, or syntactic unit. |
| `$...VAR` | Spread metavariable | Zero or more arguments, statements, or list elements. |
| `$_` | Wildcard metavariable | A single expression (anonymous, not referenceable). |

**Named metavariable -- captures and reuses a value:**

```yaml
pattern: |
  $FUNC($ARG, $ARG)
message: >
  Function `$FUNC` called with duplicate argument `$ARG`.
```

This matches any function call where the same expression appears as both arguments (e.g., `max(x, x)`).

**Spread metavariable -- captures multiple items:**

```yaml
pattern: |
  def $FUNC($...ARGS):
      ...
```

Captures the entire argument list into `$...ARGS`.

**Wildcard -- matches without capturing:**

```yaml
pattern: |
  os.system($_)
```

Matches any single-argument call to `os.system` without binding the argument to a named metavariable.

### String Matching in Patterns

Use literal string values in patterns to match specific strings:

```yaml
pattern: |
  hashlib.md5(...)
```

Use `"..."` to match any string literal:

```yaml
pattern: |
  connect("...")
```

This matches `connect("localhost")`, `connect("db.prod.internal")`, etc., but does NOT match `connect(variable)`.

---

## Pattern Combinators

Combinators compose multiple patterns into complex matching logic.

### `pattern` -- Single Match

The simplest form. The rule fires wherever this single pattern matches.

```yaml
rules:
  - id: use-of-eval
    pattern: eval(...)
    message: Avoid eval.
    languages: [python]
    severity: WARNING
```

### `patterns` -- AND (All Must Match)

An array of pattern clauses. ALL must match for the rule to fire. The match region is the intersection.

```yaml
rules:
  - id: unverified-db-query
    patterns:
      - pattern: |
          cursor.execute($QUERY, ...)
      - pattern-not: |
          cursor.execute("...", ...)
    message: >
      SQL query uses a non-literal string for `$QUERY`. Use parameterized queries.
    languages: [python]
    severity: ERROR
```

This matches `cursor.execute(query)` but NOT `cursor.execute("SELECT * FROM users")`.

### `pattern-either` -- OR (Any Must Match)

An array of pattern clauses. The rule fires if ANY of them match.

```yaml
rules:
  - id: dangerous-deserialization
    pattern-either:
      - pattern: pickle.loads(...)
      - pattern: pickle.load(...)
      - pattern: yaml.load($ARG)
      - pattern: marshal.loads(...)
    message: Dangerous deserialization function detected.
    languages: [python]
    severity: ERROR
```

### `pattern-not` -- Exclude Matches

Used inside a `patterns` array to exclude results that match a given pattern.

```yaml
rules:
  - id: open-redirect
    patterns:
      - pattern: redirect($URL)
      - pattern-not: redirect("/...")
    message: >
      Redirect to potentially user-controlled URL `$URL`.
    languages: [python]
    severity: WARNING
```

### `pattern-inside` -- Scope to Enclosing Code

Requires the match to be nested inside code matching the given pattern.

```yaml
rules:
  - id: flask-route-sql-injection
    patterns:
      - pattern: |
          cursor.execute($QUERY, ...)
      - pattern-inside: |
          @app.route(...)
          def $FUNC(...):
              ...
      - pattern-not: |
          cursor.execute("...", ...)
    message: >
      Non-parameterized SQL query in a Flask route handler.
    languages: [python]
    severity: ERROR
```

### `pattern-not-inside` -- Exclude by Enclosing Code

The match must NOT be nested inside code matching the given pattern.

```yaml
rules:
  - id: missing-error-handling
    patterns:
      - pattern: |
          requests.get(...)
      - pattern-not-inside: |
          try:
              ...
          except ...:
              ...
    message: >
      HTTP request without try/except error handling.
    languages: [python]
    severity: WARNING
```

### Combining Combinators

A `patterns` array can contain any mix of `pattern`, `pattern-either`, `pattern-not`, `pattern-inside`, and `pattern-not-inside`.

```yaml
rules:
  - id: complex-example
    patterns:
      # Must match one of these
      - pattern-either:
          - pattern: os.system($CMD)
          - pattern: subprocess.call($CMD, shell=True)
          - pattern: subprocess.run($CMD, shell=True, ...)
      # Must be inside a web handler
      - pattern-inside: |
          @app.route(...)
          def $HANDLER(...):
              ...
      # Exclude cases where input is validated
      - pattern-not-inside: |
          $CMD = sanitize(...)
          ...
    message: >
      OS command execution in a web handler with potentially unsanitized input.
    languages: [python]
    severity: ERROR
```

---

## Advanced Features

### `metavariable-pattern` -- Sub-Pattern on a Captured Metavariable

Apply an additional pattern match to the code captured by a metavariable.

```yaml
rules:
  - id: logging-sensitive-data
    patterns:
      - pattern: |
          logging.$METHOD($MSG, ...)
      - metavariable-pattern:
          metavariable: $MSG
          patterns:
            - pattern-either:
                - pattern: |
                    f"...{$DATA}..."
                - pattern: |
                    "..." % $DATA
            - metavariable-regex:
                metavariable: $DATA
                regex: (?i)(password|secret|token|api_key|ssn)
    message: >
      Logging potentially sensitive data via `$DATA`.
    languages: [python]
    severity: WARNING
```

### `metavariable-regex` -- Regex on Captured Metavariable

Match captured metavariable text against a regular expression.

```yaml
rules:
  - id: weak-hash-algorithm
    patterns:
      - pattern: hashlib.$ALGO(...)
      - metavariable-regex:
          metavariable: $ALGO
          regex: ^(md5|sha1)$
    message: >
      Weak hash algorithm `$ALGO` detected. Use SHA-256 or stronger.
    languages: [python]
    severity: WARNING
```

### `metavariable-comparison` -- Numeric Comparison

Compare a numeric metavariable value against a threshold.

```yaml
rules:
  - id: insufficient-bcrypt-rounds
    patterns:
      - pattern: bcrypt.hashpw($PW, bcrypt.gensalt(rounds=$ROUNDS))
      - metavariable-comparison:
          metavariable: $ROUNDS
          comparison: $ROUNDS < 12
    message: >
      bcrypt rounds set to $ROUNDS. Use at least 12 rounds.
    languages: [python]
    severity: WARNING
```

### `focus-metavariable` -- Narrow the Match Location

By default, the entire matched region is reported. `focus-metavariable` narrows the reported location to just the code captured by the specified metavariable.

```yaml
rules:
  - id: insecure-cookie
    patterns:
      - pattern: |
          response.set_cookie($NAME, ..., secure=False, ...)
      - focus-metavariable: $NAME
    message: >
      Cookie `$NAME` is set without the secure flag.
    languages: [python]
    severity: WARNING
```

### Taint Mode

Taint mode tracks data flow from sources to sinks through the program. It is more powerful than purely structural matching for injection vulnerabilities.

```yaml
rules:
  - id: sql-injection-taint
    mode: taint
    message: >
      User input flows into a SQL query without sanitization.
    languages: [python]
    severity: ERROR
    metadata:
      cwe:
        - "CWE-89: Improper Neutralization of Special Elements used in an SQL Command"
    pattern-sources:
      - patterns:
          - pattern: request.$ATTR.$METHOD(...)
          - metavariable-regex:
              metavariable: $ATTR
              regex: ^(args|form|values|json|data|headers|cookies)$
      - pattern: request.get_json(...)
    pattern-sinks:
      - patterns:
          - pattern: cursor.execute($QUERY, ...)
          - focus-metavariable: $QUERY
      - patterns:
          - pattern: db.engine.execute($QUERY)
          - focus-metavariable: $QUERY
    pattern-sanitizers:
      - pattern: sanitize_sql(...)
      - pattern: bleach.clean(...)
      - pattern: escape(...)
```

**Taint mode fields:**

| Field | Description |
|---|---|
| `mode: taint` | Enables taint tracking. |
| `pattern-sources` | List of patterns identifying where tainted data originates. |
| `pattern-sinks` | List of patterns identifying dangerous destinations for tainted data. |
| `pattern-sanitizers` | (Optional) List of patterns for functions/operations that remove taint. |
| `pattern-propagators` | (Optional) List of patterns that propagate taint through custom functions. |

**Taint propagators** are useful when taint passes through helper functions that Semgrep cannot track automatically:

```yaml
pattern-propagators:
  - pattern: |
      $TO = transform($FROM)
    from: $FROM
    to: $TO
```

---

## Language-Specific Examples

### Python

**Detecting a missing decorator on a Django view:**

```yaml
rules:
  - id: django-missing-login-required
    patterns:
      - pattern: |
          def $VIEW(request, ...):
              ...
      - pattern-inside: |
          # views.py scope
          ...
      - pattern-not-inside: |
          @login_required
          def $VIEW(...):
              ...
      - pattern-not-inside: |
          @csrf_exempt
          def $VIEW(...):
              ...
    message: >
      Django view `$VIEW` may be missing `@login_required`.
    languages: [python]
    severity: WARNING
```

**Matching f-string interpolation with user input:**

```yaml
rules:
  - id: fstring-sql
    patterns:
      - pattern: |
          cursor.execute(f"...${{$VAR}}...")
    message: >
      SQL query built with f-string interpolation of `$VAR`. Use parameterized queries.
    languages: [python]
    severity: ERROR
```

**Matching class methods:**

```yaml
rules:
  - id: class-method-no-auth-check
    patterns:
      - pattern: |
          class $CLS(...):
              ...
              def $METHOD(self, ...):
                  ...
                  $OBJ.delete(...)
                  ...
      - pattern-not: |
          class $CLS(...):
              ...
              def $METHOD(self, ...):
                  ...
                  self.check_permissions(...)
                  ...
                  $OBJ.delete(...)
                  ...
    message: >
      `$CLS.$METHOD` calls `.delete()` without `check_permissions`.
    languages: [python]
    severity: WARNING
```

### JavaScript / TypeScript

**Arrow function with dangerous sink:**

```yaml
rules:
  - id: express-xss-response
    patterns:
      - pattern: |
          $APP.$METHOD($PATH, ($REQ, $RES) => {
              ...
              $RES.send($INPUT)
              ...
          })
      - metavariable-regex:
          metavariable: $METHOD
          regex: ^(get|post|put|patch|delete)$
      - pattern-not: |
          $APP.$METHOD($PATH, ($REQ, $RES) => {
              ...
              $RES.send(sanitize($INPUT))
              ...
          })
    message: >
      Express route sends potentially unsanitized data in the response.
    languages: [javascript, typescript]
    severity: WARNING
```

**Template literal injection:**

```yaml
rules:
  - id: template-literal-in-query
    patterns:
      - pattern: |
          $DB.query(`...${$VAR}...`)
    message: >
      SQL query built with template literal interpolation of `$VAR`.
    languages: [javascript, typescript]
    severity: ERROR
```

**Async/await missing error handling:**

```yaml
rules:
  - id: unhandled-async-rejection
    patterns:
      - pattern: |
          async ($...PARAMS) => {
              ...
              await $PROMISE
              ...
          }
      - pattern-not-inside: |
          try {
              ...
          } catch ($ERR) {
              ...
          }
    message: >
      Async function uses `await` without try/catch error handling.
    languages: [javascript, typescript]
    severity: WARNING
```

### Java

**Missing annotation on a Spring endpoint:**

```yaml
rules:
  - id: spring-missing-auth-annotation
    patterns:
      - pattern-either:
          - pattern: |
              @GetMapping(...)
              public $RET $METHOD(...) { ... }
          - pattern: |
              @PostMapping(...)
              public $RET $METHOD(...) { ... }
          - pattern: |
              @RequestMapping(...)
              public $RET $METHOD(...) { ... }
      - pattern-not-inside: |
          @PreAuthorize(...)
          ...
      - pattern-not-inside: |
          @Secured(...)
          ...
    message: >
      Spring endpoint `$METHOD` is missing `@PreAuthorize` or `@Secured` annotation.
    languages: [java]
    severity: WARNING
```

**Generic type misuse:**

```yaml
rules:
  - id: raw-type-usage
    pattern: |
      List $VAR = ...;
    message: >
      Raw `List` type used. Prefer `List<Type>` to enable type safety.
    languages: [java]
    severity: INFO
```

### Go

**Unchecked error return:**

```yaml
rules:
  - id: unchecked-error
    patterns:
      - pattern: |
          $VAL, $ERR := $FUNC(...)
          ...
      - pattern-not: |
          $VAL, $ERR := $FUNC(...)
          ...
          if $ERR != nil { ... }
          ...
    message: >
      Error from `$FUNC` is not checked. Always handle errors in Go.
    languages: [go]
    severity: WARNING
```

**SQL injection in Go:**

```yaml
rules:
  - id: go-sql-injection
    patterns:
      - pattern-either:
          - pattern: |
              $DB.Query(fmt.Sprintf("...", $ARG, ...), ...)
          - pattern: |
              $DB.Exec(fmt.Sprintf("...", $ARG, ...), ...)
          - pattern: |
              $DB.QueryRow(fmt.Sprintf("...", $ARG, ...), ...)
    message: >
      SQL query built with `fmt.Sprintf`. Use parameterized queries with `$1` placeholders.
    languages: [go]
    severity: ERROR
```

**Missing defer on resource cleanup:**

```yaml
rules:
  - id: missing-defer-close
    patterns:
      - pattern: |
          $RESP, $ERR := http.Get(...)
          ...
      - pattern-not: |
          $RESP, $ERR := http.Get(...)
          ...
          defer $RESP.Body.Close()
          ...
    message: >
      HTTP response body is not closed with `defer`. This causes resource leaks.
    languages: [go]
    severity: WARNING
```

---

## Metadata Best Practices

Metadata does not affect matching but enriches findings for triaging, filtering, and reporting.

### Recommended Metadata Fields

```yaml
rules:
  - id: example-with-full-metadata
    pattern: eval(...)
    message: Use of eval detected.
    languages: [python]
    severity: ERROR
    metadata:
      # Vulnerability classification
      cwe:
        - "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code"
      owasp:
        - "A03:2021 - Injection"

      # Risk assessment
      confidence: HIGH        # HIGH, MEDIUM, or LOW
      impact: HIGH             # HIGH, MEDIUM, or LOW
      likelihood: MEDIUM       # HIGH, MEDIUM, or LOW

      # Categorization
      category: security       # security, correctness, performance, best-practice
      subcategory:
        - vuln                 # vuln, audit, guardrail
      technology:
        - python
        - flask

      # References for humans reviewing findings
      references:
        - https://owasp.org/Top10/A03_2021-Injection/
        - https://cwe.mitre.org/data/definitions/95.html
        - https://docs.python.org/3/library/functions.html#eval

      # Authorship
      source: custom
      author: security-team
```

### CWE and OWASP Mapping

Always provide CWE IDs for security rules. Common mappings:

| Vulnerability Type | CWE | OWASP 2021 |
|---|---|---|
| SQL Injection | CWE-89 | A03 Injection |
| XSS | CWE-79 | A03 Injection |
| Command Injection | CWE-78 | A03 Injection |
| Path Traversal | CWE-22 | A01 Broken Access Control |
| Deserialization | CWE-502 | A08 Software and Data Integrity |
| SSRF | CWE-918 | A10 Server-Side Request Forgery |
| Hardcoded Credentials | CWE-798 | A07 Identification and Authentication |
| Broken Auth | CWE-287 | A07 Identification and Authentication |
| Open Redirect | CWE-601 | A01 Broken Access Control |
| XXE | CWE-611 | A05 Security Misconfiguration |

### Confidence, Impact, Likelihood

Use these three fields together for prioritization:

- **confidence** -- How likely is this finding a true positive? `HIGH` = almost certain, `LOW` = might be a false positive.
- **impact** -- If exploited, how bad is it? `HIGH` = RCE, data breach. `LOW` = information disclosure, minor DoS.
- **likelihood** -- How easy is this to exploit in practice? `HIGH` = trivially exploitable, `LOW` = requires complex preconditions.

---

## Auto-Fix

### Simple Replacement

```yaml
rules:
  - id: use-safe-yaml-load
    pattern: yaml.load($ARG)
    fix: yaml.safe_load($ARG)
    message: Use yaml.safe_load instead of yaml.load.
    languages: [python]
    severity: ERROR
```

### Regex-Based Fix

```yaml
rules:
  - id: http-to-https
    pattern: '"http://$URL"'
    fix-regex:
      regex: 'http://'
      replacement: 'https://'
    message: Use HTTPS instead of HTTP.
    languages: [generic]
    severity: WARNING
```

---

## Common Pitfalls

### 1. Over-Broad Patterns Causing False Positives

**Problem:** Pattern matches too many things.

```yaml
# BAD: matches every print statement
pattern: print(...)

# BETTER: scope to specific context
patterns:
  - pattern: print($SENSITIVE)
  - metavariable-regex:
      metavariable: $SENSITIVE
      regex: (?i)(password|secret|token|key)
```

**Fix:** Use `metavariable-regex`, `metavariable-pattern`, `pattern-inside`, or `pattern-not` to narrow results.

### 2. Missing Language-Specific Syntax Variations

**Problem:** Only matching one form when the language has multiple equivalent forms.

```yaml
# BAD: misses require() and dynamic imports in JS
pattern: import $MOD from "..."

# BETTER: cover all import forms
pattern-either:
  - pattern: import $MOD from "..."
  - pattern: import("...")
  - pattern: require("...")
```

**Fix:** Use `pattern-either` to cover all syntactic variations of the same semantic operation.

### 3. Forgetting `pattern-not` to Exclude Safe Patterns

**Problem:** Flagging code that is already safe.

```yaml
# BAD: flags parameterized queries too
pattern: cursor.execute($Q)

# BETTER: exclude parameterized queries
patterns:
  - pattern: cursor.execute($Q)
  - pattern-not: cursor.execute("...", ...)
  - pattern-not: cursor.execute($Q, $PARAMS)
```

**Fix:** Always think about what the safe version looks like and add `pattern-not` to exclude it.

### 4. Not Using `pattern-inside` to Scope Matches

**Problem:** Finding matches in irrelevant code (test files, configuration, dead code).

```yaml
# BAD: matches eval() everywhere including tests
pattern: eval(...)

# BETTER: scope to production web handler code
patterns:
  - pattern: eval(...)
  - pattern-inside: |
      @app.route(...)
      def $FUNC(...):
          ...
```

**Fix:** Use `pattern-inside` to limit matches to relevant scopes (e.g., web handlers, specific classes). Use `paths` to exclude test and vendor directories.

### 5. Incorrect Ellipsis Usage

**Problem:** Using `...` where it does not work or misunderstanding what it matches.

```yaml
# BAD: ... cannot match across function boundaries
pattern: |
  $X = user_input()
  ...
  other_function_in_different_file($X)
# Semgrep is intra-file and intra-function for search mode

# BAD: ... in a string literal matches literal "..."
pattern: |
  print("...")
# This matches print("any string literal"), NOT print(anything)

# GOOD: to match any argument (not just strings), do not quote
pattern: |
  print(...)
```

**Key rules for ellipsis:**
- `...` inside function call parens matches zero or more arguments.
- `...` as a standalone statement matches zero or more statements.
- `...` inside a string literal (`"..."`) matches any string content -- it does NOT match non-string expressions.
- `...` does NOT cross function or file boundaries in search mode. Use taint mode for cross-function data flow.

### 6. Metavariable Reuse Gotcha

**Problem:** Expecting metavariables to match different values when the same name is used.

```yaml
# This matches ONLY when both arguments are identical
pattern: |
  copy($X, $X)

# To match any two arguments (even different), use different names
pattern: |
  copy($SRC, $DST)
```

**Fix:** Same-name metavariables enforce equality. Use different names for independent captures.

### 7. Language Field Errors

**Problem:** Rule does not run because the language string is wrong.

Common language identifiers:
- Python: `python`
- JavaScript: `javascript` or `js`
- TypeScript: `typescript` or `ts`
- Java: `java`
- Go: `go`
- Ruby: `ruby`
- PHP: `php`
- C: `c`
- C++: `cpp`
- C#: `csharp`
- Rust: `rust`
- Kotlin: `kotlin` or `kt`
- Swift: `swift`
- Scala: `scala`
- Terraform: `terraform` or `hcl`
- JSON: `json`
- YAML: `yaml`
- Generic (text): `generic`

**Fix:** Use the correct language identifier. When a rule should apply to both JavaScript and TypeScript, list both: `languages: [javascript, typescript]`.

### 8. Forgetting That Search Mode Is Intraprocedural

**Problem:** Expecting search-mode patterns to track data across function calls.

```yaml
# BAD: search mode cannot follow data through helper()
pattern: |
  $X = request.args.get(...)
  ...
  $Y = helper($X)
  ...
  db.query($Y)
```

**Fix:** Use `mode: taint` with `pattern-sources`, `pattern-sinks`, and `pattern-propagators` for cross-function data flow tracking.

---

## Rule Testing

Semgrep supports inline test annotations in target files. Use these to validate rules during development.

### Test Annotation Format

```python
# ruleid: my-rule-id
vulnerable_call(user_input)

# ok: my-rule-id
safe_call(sanitize(user_input))

# todoruleid: my-rule-id
edge_case_not_yet_handled()
```

| Annotation | Meaning |
|---|---|
| `# ruleid: <id>` | This line MUST be flagged by the rule. Test fails if not. |
| `# ok: <id>` | This line must NOT be flagged. Test fails if it is. |
| `# todoruleid: <id>` | Known gap. Not flagged now, but ideally should be in the future. |

### Running Tests

```bash
semgrep --test --config rules/ tests/
```

Place rule files in `rules/` and corresponding test files in `tests/` with matching filenames.

---

## Complete Rule Template

Use this as a starting point for new rules:

```yaml
rules:
  - id: <category>-<language>-<vulnerability-type>
    # Choose ONE of the following top-level pattern keys:
    #   pattern:          single pattern
    #   patterns:         AND logic (all must match)
    #   pattern-either:   OR logic (any must match)
    patterns:
      - pattern: |
          <your pattern here>
      # Add pattern-not, pattern-inside, pattern-not-inside as needed
    message: >
      <Clear description of the issue and how to fix it.
       Reference $METAVARIABLES captured in patterns.>
    languages:
      - <language>
    severity: <ERROR|WARNING|INFO>
    metadata:
      cwe:
        - "CWE-XXX: Description"
      owasp:
        - "A0X:2021 - Category"
      confidence: <HIGH|MEDIUM|LOW>
      impact: <HIGH|MEDIUM|LOW>
      likelihood: <HIGH|MEDIUM|LOW>
      category: security
      technology:
        - <framework or language>
      references:
        - <url>
    # Optional:
    # fix: <auto-fix replacement>
    # paths:
    #   include: [...]
    #   exclude: [...]
```
