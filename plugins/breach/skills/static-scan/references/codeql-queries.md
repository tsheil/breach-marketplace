# CodeQL Query Suites Reference

CodeQL query suite descriptions, language coverage, dataflow analysis explanation, and SARIF result interpretation.

## Query Suites

CodeQL ships with pre-built query suites. The primary suite for security work:

### `<language>-security-and-quality.qls`

The recommended suite for breach scanning. Includes all security queries plus code quality checks that have security implications. Available for every supported language.

```bash
codeql database analyze <db> python-security-and-quality.qls --format=sarif-latest --output=results.sarif
```

### `<language>-security-extended.qls`

Broader coverage with more experimental queries. Higher recall but may include more false positives. Use when thoroughness is more important than precision.

### `<language>-code-scanning.qls`

The default suite used by GitHub Code Scanning. Good balance of precision and recall. Suitable when scanning large codebases where manual triage of false positives is costly.

## Language Coverage

| Language | ID | Common Frameworks |
|----------|----|-------------------|
| JavaScript / TypeScript | `javascript` | Express, React, Next.js, Angular, Vue |
| Python | `python` | Django, Flask, FastAPI, SQLAlchemy |
| Java | `java` | Spring, Struts, Hibernate, JSP |
| C# | `csharp` | ASP.NET, Entity Framework |
| Go | `go` | Gin, Echo, net/http |
| Ruby | `ruby` | Rails, Sinatra |
| C / C++ | `cpp` | Various (memory safety focus) |
| Swift | `swift` | iOS/macOS applications |

## Dataflow Analysis

CodeQL's primary advantage over pattern-matching tools is **semantic dataflow analysis**. Rather than matching syntactic patterns, CodeQL:

1. **Builds a database** of the entire codebase — every function, variable, type, and call relationship
2. **Models taint sources** — points where external (attacker-controlled) data enters the application (HTTP parameters, file reads, environment variables, database results from prior user input)
3. **Models taint sinks** — security-sensitive operations (SQL execution, command execution, file writes, HTML rendering, redirects)
4. **Traces dataflow paths** — follows tainted data through function calls, variable assignments, string operations, and transformations to determine if it reaches a sink
5. **Tracks sanitizers** — recognizes when tainted data passes through a sanitization function (escaping, validation, parameterization) that removes the taint

This means CodeQL can distinguish between:
- ❌ `db.execute("SELECT * FROM users WHERE id=" + user_id)` — tainted input reaches SQL sink unsanitized
- ✅ `db.execute("SELECT * FROM users WHERE id=?", [user_id])` — parameterized query sanitizes the input

### Dataflow Path Interpretation

A CodeQL dataflow path looks like:

```
Source: request.args.get("id") at app/views.py:10
  → assigned to variable `user_id` at app/views.py:11
  → passed as argument to `get_user(user_id)` at app/views.py:12
  → received as parameter `uid` at app/models.py:25
  → concatenated into string at app/models.py:28
  → passed to `db.execute(query)` at app/models.py:30 [SINK]
```

Each step in the path is a **node** that shows:
- The expression or variable holding the tainted data
- The file and line number
- The transformation applied (assignment, function call, concatenation, etc.)

**Confidence from path length**: Shorter paths (2-3 steps) are almost always true positives. Longer paths (5+ steps) may include sanitization steps that CodeQL missed, warranting manual verification.

## SARIF Output Format

CodeQL outputs results in SARIF (Static Analysis Results Interchange Format). Key fields:

### Result Object
```json
{
  "ruleId": "js/sql-injection",
  "level": "error",
  "message": { "text": "This query depends on a user-provided value." },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": { "uri": "src/db.js" },
      "region": { "startLine": 42, "startColumn": 5, "endLine": 42, "endColumn": 35 }
    }
  }],
  "codeFlows": [{ ... }]
}
```

### Rule Object (in `tool.driver.rules`)
```json
{
  "id": "js/sql-injection",
  "name": "SqlInjection",
  "shortDescription": { "text": "SQL injection" },
  "properties": {
    "precision": "very-high",
    "severity": "error",
    "tags": ["security", "external/cwe/cwe-089"],
    "problem.severity": "error"
  }
}
```

### CodeFlow Object (dataflow paths)
```json
{
  "codeFlows": [{
    "threadFlows": [{
      "locations": [
        { "location": { "physicalLocation": { "artifactLocation": { "uri": "src/routes.js" }, "region": { "startLine": 10 } }, "message": { "text": "user input" } } },
        { "location": { "physicalLocation": { "artifactLocation": { "uri": "src/db.js" }, "region": { "startLine": 42 } }, "message": { "text": "reaches sql query" } } }
      ]
    }]
  }]
}
```

## Severity and Precision Mapping

### SARIF Level → Breach Severity

| SARIF Level | CodeQL Precision | Breach Severity | Breach Confidence |
|-------------|-----------------|-----------------|-------------------|
| error | very-high | CRIT or HIGH | Confirmed |
| error | high | HIGH | High |
| warning | very-high | HIGH | High |
| warning | high | MED | High |
| warning | medium | MED | Medium |
| note | any | LOW | Medium |

### Precision Definitions

- **very-high**: Less than 10% false positive rate. Can be treated as confirmed without manual verification in most cases.
- **high**: Less than 30% false positive rate. Worth investigating, most will be true positives.
- **medium**: 30-60% false positive rate. Requires manual verification. Use as leads for manual review.
- **low**: Over 60% false positive rate. Only include if the potential impact is Critical.

## Common CodeQL Rule IDs

| Rule ID | Vuln Type | Description |
|---------|-----------|-------------|
| `*/sql-injection` | SQLI | SQL query built from user input |
| `*/command-line-injection` | CMDI | OS command with user input |
| `*/xss` | XSS | User input rendered in HTML without escaping |
| `*/ssrf` | SSRF | User-controlled URL in server-side request |
| `*/path-injection` | PATH-TRAV | User input in file system path |
| `*/unsafe-deserialization` | DESER | Deserialization of untrusted data |
| `*/insecure-randomness` | CRYPTO | Weak random number generation for security use |
| `*/hardcoded-credentials` | SECRETS | Credentials in source code |
| `*/open-redirect` | OPEN-REDIR | Redirect to user-controlled URL |
| `*/xxe` | XXE | XML parsing with external entities enabled |
| `*/code-injection` | EVAL | Dynamic code execution with user input |
| `*/log-injection` | LOG-INJ | User input in log messages |
| `*/regex-injection` | REGEX-INJ | User input in regex patterns |
| `*/missing-rate-limiting` | RATE-LIMIT | Auth endpoints without rate limiting |

## Database Creation

### Auto-detect language and create
```bash
codeql database create codeql-db --language=<language> --source-root=.
```

### Multi-language project
```bash
codeql database create codeql-db-js --language=javascript --source-root=.
codeql database create codeql-db-py --language=python --source-root=.
```

### With build command (compiled languages)
```bash
codeql database create codeql-db --language=java --command="mvn clean package -DskipTests"
```

### Upgrade existing database
```bash
codeql database upgrade codeql-db
```
