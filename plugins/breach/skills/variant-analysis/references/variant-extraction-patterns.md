# Variant Extraction Patterns

Guide for abstracting the structural essence from a specific vulnerability instance. Organized by vulnerability class with extraction methodology for each.

## General Methodology

For any vulnerability instance:

1. **Identify the sink**: What security-sensitive operation is being performed?
2. **Identify the source**: Where does attacker-controlled data enter?
3. **Identify the missing control**: What validation, sanitization, or authorization is absent?
4. **Map the path**: How does data flow from source to sink?
5. **Abstract the structure**: Remove instance-specific details, keep the pattern

## Injection Patterns

### SQL Injection

**Extraction from instance**:
- Sink: The specific query execution method (e.g., `cursor.execute()`, `db.raw()`, `entityManager.createNativeQuery()`)
- Source: How user input reaches the query (direct parameter, via service layer, from stored data)
- Missing control: Parameterized queries, ORM method usage, input validation
- Structure: String concatenation/interpolation vs parameterized

**Variant dimensions**:
- Other query methods in the same codebase (search for all `.execute(`, `.query(`, `.raw(`)
- Other string formatting patterns (f-strings, .format(), %, +, template literals)
- ORM bypass methods (`.extra()`, `.raw()`, raw SQL in migrations)
- Stored procedures with string concatenation
- Dynamic table/column names (not parameterizable — require whitelist validation)
- Second-order: data stored safely but used unsafely later in a different query

### Command Injection

**Extraction from instance**:
- Sink: Shell execution function (`subprocess.call`, `os.system`, `exec`, `child_process.exec`)
- Source: User input reaching the shell command
- Missing control: Use of array form (subprocess.call with list), input validation, shell=False

**Variant dimensions**:
- Other shell execution functions in the codebase
- Indirect shell access (via os.popen, backticks, system())
- Commands built with user input for different operations (imagemagick, ffmpeg, curl, git)
- Environment variable injection (if env vars are user-controlled and reach shell)

### Server-Side Template Injection (SSTI)

**Extraction from instance**:
- Sink: Template rendering with user input in the template string (not just template data)
- Source: User input that becomes part of the template, not just a template variable
- Missing control: Sandboxed template engine, input validation, avoiding user input in templates

**Variant dimensions**:
- Other template rendering calls in the codebase
- Different template engines if multiple are used
- Email templates, PDF templates, report templates (not just web page templates)
- Partial templates or includes with user-controlled paths

## Broken Access Control Patterns

### IDOR (Insecure Direct Object Reference)

**Extraction from instance**:
- Sink: Data access using user-supplied identifier without ownership check
- Source: Object ID from URL parameter, query parameter, or request body
- Missing control: Authorization check verifying the requesting user owns/can access the object

**Variant dimensions**:
- Other endpoints using the same object type (GET, PUT, DELETE on same resource)
- Other object types with similar access patterns
- Nested resources (e.g., `/users/{id}/orders/{order_id}` — both IDs need auth)
- Bulk/list endpoints that don't filter by ownership
- GraphQL resolvers for the same data model

### Missing Authorization

**Extraction from instance**:
- Sink: Privileged operation without auth check
- Source: Direct endpoint access
- Missing control: Auth middleware, decorator, or inline check

**Variant dimensions**:
- Other admin/privileged endpoints
- Endpoints added after the auth middleware was configured (might be missed)
- API versions (v2 might lack auth that v1 has)
- Internal/debug endpoints accessible externally

## Authentication Failure Patterns

### JWT Vulnerabilities

**Extraction from instance**:
- Sink: JWT verification with algorithm confusion, missing verification, weak secret
- Source: JWT token from Authorization header or cookie
- Missing control: Algorithm pinning, proper verification, strong secret

**Variant dimensions**:
- Other JWT verification points in the codebase
- Different JWT libraries used in different services
- Token refresh endpoints with weaker verification
- JWK endpoints that accept untrusted keys

## SSRF Patterns

**Extraction from instance**:
- Sink: HTTP client making request with user-controlled URL
- Source: URL from user input (direct or constructed from parts)
- Missing control: URL validation, allowlist, blocked internal ranges

**Variant dimensions**:
- Other HTTP client calls in the codebase (requests.get, urllib, fetch, axios)
- URL construction from user-supplied parts (scheme, host, path separately)
- Redirect following that bypasses URL validation
- DNS rebinding if validation is done before request
- Protocol handlers (file://, gopher://, dict://)

## Cross-Cutting Variant Dimensions

These dimensions apply across all vulnerability classes:

| Dimension | Description |
|-----------|-------------|
| **Same file, different function** | Developer repeated the pattern in another function |
| **Same module, different file** | Pattern is a team-level habit |
| **Copy-paste propagation** | Code was copied to another service or endpoint |
| **Framework analog** | Same logic flaw using a different framework feature |
| **Language port** | Pattern exists in another language's implementation of the same feature |
| **Configuration-wide** | A global setting enables the vulnerability across all endpoints |
| **Library wrapper** | Pattern hidden behind an abstraction layer |
| **Test code in production** | Vulnerable pattern in test helpers that run in production |
