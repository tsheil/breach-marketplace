# Semgrep Rulesets Reference

Recommended Semgrep rulesets organized by language and framework, with severity mapping and custom rule patterns for breach-specific checks.

## Universal Rulesets (All Languages)

These rulesets apply across languages and should always be included:

| Ruleset | Description | Focus |
|---------|-------------|-------|
| `p/security-audit` | Broad security audit rules | General vulnerability patterns |
| `p/owasp-top-ten` | OWASP Top 10 2021 coverage | Industry-standard vulnerability classes |
| `p/secrets` | Hardcoded secrets and credentials | API keys, passwords, tokens in source |
| `p/command-injection` | Command injection patterns | OS command execution with user input |
| `p/sql-injection` | SQL injection patterns | Raw SQL with user-controlled input |
| `p/xss` | Cross-site scripting patterns | Unescaped output in HTML contexts |

## Language-Specific Rulesets

### Python
| Ruleset | Description |
|---------|-------------|
| `p/python` | General Python security |
| `p/django` | Django-specific security patterns |
| `p/flask` | Flask-specific security patterns |
| `p/bandit` | Bandit-equivalent rules in Semgrep |

### JavaScript / TypeScript
| Ruleset | Description |
|---------|-------------|
| `p/javascript` | General JS security |
| `p/typescript` | TypeScript-specific patterns |
| `p/nodejs` | Node.js server-side security |
| `p/react` | React-specific XSS and security |
| `p/nextjs` | Next.js security patterns |
| `p/expressjs` | Express.js security patterns |

### Java
| Ruleset | Description |
|---------|-------------|
| `p/java` | General Java security |
| `p/spring` | Spring Framework security |

### Go
| Ruleset | Description |
|---------|-------------|
| `p/golang` | General Go security |

### Ruby
| Ruleset | Description |
|---------|-------------|
| `p/ruby` | General Ruby security |
| `p/rails` | Rails-specific security patterns |

### PHP
| Ruleset | Description |
|---------|-------------|
| `p/php` | General PHP security |
| `p/laravel` | Laravel-specific security |
| `p/wordpress` | WordPress security patterns |

### C# / .NET
| Ruleset | Description |
|---------|-------------|
| `p/csharp` | General C# security |

## Severity Mapping

Semgrep uses three severity levels. Map to breach severity:

| Semgrep Severity | Breach Severity | Notes |
|------------------|-----------------|-------|
| ERROR | HIGH | Upgrade to CRIT for unauth RCE, auth bypass, mass data exposure |
| WARNING | MED | Upgrade to HIGH if no authentication required |
| INFO | LOW | Upgrade to MED if finding affects sensitive data handling |

## Rule ID to Vulnerability Type Mapping

Common Semgrep rule ID patterns and their breach vulnerability type shorthand:

| Rule ID Pattern | Vuln Type | OWASP Category |
|-----------------|-----------|----------------|
| `*.injection.sql*` | SQLI | A03 Injection |
| `*.injection.command*` | CMDI | A03 Injection |
| `*.injection.xpath*` | XPATH-INJ | A03 Injection |
| `*.injection.ldap*` | LDAP-INJ | A03 Injection |
| `*.xss*`, `*.cross-site*` | XSS | A03 Injection |
| `*.ssrf*` | SSRF | A10 SSRF |
| `*.path-traversal*`, `*.lfi*` | PATH-TRAV | A01 Broken Access Control |
| `*.deserialization*` | DESER | A08 Integrity Failures |
| `*.crypto*`, `*.weak-hash*` | CRYPTO | A02 Cryptographic Failures |
| `*.hardcoded*`, `*.secret*` | SECRETS | A02 Cryptographic Failures |
| `*.auth*`, `*.jwt*` | AUTH | A07 Auth Failures |
| `*.session*` | SESSION | A07 Auth Failures |
| `*.idor*`, `*.access-control*` | IDOR | A01 Broken Access Control |
| `*.redirect*`, `*.open-redirect*` | OPEN-REDIR | A01 Broken Access Control |
| `*.ssti*`, `*.template*` | SSTI | A03 Injection |
| `*.xxe*`, `*.xml*` | XXE | A05 Misconfiguration |
| `*.cors*` | CORS | A05 Misconfiguration |
| `*.csrf*` | CSRF | A01 Broken Access Control |
| `*.file-upload*` | FILE-UPLOAD | A04 Insecure Design |
| `*.race-condition*` | RACE | A04 Insecure Design |
| `*.eval*`, `*.code-exec*` | EVAL | A03 Injection |

## Custom Rule Patterns

For targets not well covered by public rulesets, Semgrep supports custom rules. Common patterns to check:

### Mass Assignment
```yaml
rules:
  - id: mass-assignment
    pattern: |
      $MODEL.update($INPUT)
    message: "Potential mass assignment — user input passed directly to model update"
    severity: WARNING
```

### Insecure Direct Object Reference
```yaml
rules:
  - id: idor-no-ownership-check
    patterns:
      - pattern: |
          $OBJ = $MODEL.objects.get(id=$REQUEST)
      - pattern-not-inside: |
          if $OBJ.owner == $USER: ...
    message: "Object retrieved by user-supplied ID without ownership verification"
    severity: ERROR
```

### Debug Mode in Production Config
```yaml
rules:
  - id: debug-mode-enabled
    pattern: |
      DEBUG = True
    paths:
      include:
        - "**/settings.py"
        - "**/config.py"
    message: "Debug mode enabled in configuration file"
    severity: WARNING
```

## Running Semgrep

### Basic security scan
```bash
semgrep --config p/security-audit --config p/owasp-top-ten --json <target>
```

### Language-targeted scan
```bash
semgrep --config p/security-audit --config p/python --config p/django --json <target>
```

### With custom rules
```bash
semgrep --config p/security-audit --config ./custom-rules/ --json <target>
```

### Exclude test files and dependencies
```bash
semgrep --config p/security-audit --exclude="*_test.*" --exclude="test_*" --exclude="node_modules" --exclude="vendor" --json <target>
```
