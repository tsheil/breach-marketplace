# Custom Rule Categories Taxonomy

A prioritized taxonomy of codebase-specific rule categories for Semgrep and CodeQL. These categories target patterns that generic, off-the-shelf rulesets consistently miss because they require knowledge of the specific codebase's architecture, frameworks, and conventions.

---

## Priority 1: Custom Auth Enforcement Gaps

**Rationale:** Stock rules know about generic authentication functions but have no knowledge of *your* codebase's auth decorators, middleware chains, or permission-checking conventions. A route handler missing `@login_required` looks syntactically valid to any generic linter. This is the highest-priority category because a single missing auth check can expose an entire endpoint to unauthenticated access.

**Example patterns:**

- **Missing decorator on route handlers.** A Flask app uses `@login_required` on all `/api/` routes, but a newly added endpoint omits it. The rule matches any function decorated with `@app.route("/api/...")` that is *not* also decorated with `@login_required`.
- **Express route without auth middleware.** An Express app requires `authMiddleware` in the middleware chain for all `/admin/` routes. The rule detects `router.get("/admin/...", handler)` calls where `authMiddleware` does not appear in the argument list before the final handler.
- **Missing RBAC check in controller methods.** A Spring Boot app expects `@PreAuthorize` on all controller methods in `AdminController`. The rule flags any public method in classes annotated with `@RestController` under the `admin` package that lacks a `@PreAuthorize` annotation.

**Best tool:** Semgrep. These are structural/syntactic patterns -- checking for the presence or absence of decorators, middleware arguments, and annotations. No dataflow analysis needed.

**Rule sketch:**
```
pattern: function with @app.route("/api/...") decorator
filter:  NOT decorated with @login_required
message: "API route handler missing @login_required decorator"
```

---

## Priority 2: Application-Specific Sinks

**Rationale:** Most codebases wrap dangerous operations behind custom helper functions or ORM methods. Stock rules track known sinks like `subprocess.run()` or `cursor.execute()`, but they have no awareness that `db.rawQuery()` is your codebase's wrapper around raw SQL execution, or that `run_shell()` eventually calls `os.system()`. These custom sinks are invisible to generic rulesets, yet they are the actual entry points to dangerous operations.

**Example patterns:**

- **Custom raw SQL wrapper.** The codebase has a `db.rawQuery(sql_string)` method that passes its argument directly to the database driver. The rule tracks taint from user input to any call to `db.rawQuery()`.
- **Homegrown shell execution helper.** A utility module exposes `run_shell(cmd)` which internally calls `subprocess.Popen(cmd, shell=True)`. The rule marks `run_shell` as a sink and traces user-controlled data flowing into its argument.
- **Custom template rendering that bypasses auto-escaping.** The codebase has a `render_raw_html(template_string)` function that disables the framework's auto-escaping. The rule flags any call to this function where the argument includes user-controlled data.

**Best tool:** CodeQL for full taint tracking from sources to these custom sinks. Semgrep can handle simpler cases where the dangerous call is directly visible without multi-step dataflow.

**Rule sketch:**
```
source:  request parameters, form data, query strings
sink:    db.rawQuery(...), run_shell(...), render_raw_html(...)
message: "User-controlled data flows into custom sink without sanitization"
```

---

## Priority 3: Framework-Specific Patterns

**Rationale:** Frameworks introduce security-relevant behavior changes across versions, and deprecated APIs often carry known vulnerabilities in specific version ranges. Stock rules either target the latest version or cast too wide a net. Knowing the exact framework version pinned in the codebase's dependency file lets you write precise rules for *that* version's known pitfalls.

**Example patterns:**

- **Django < 3.1 JSONField injection.** In Django versions prior to 3.1, `JSONField` lookups with user-controlled keys can lead to SQL injection via key-path traversal. The rule checks that the project uses Django < 3.1 (from `requirements.txt`) and flags `JSONField` lookups with dynamic keys.
- **Express `res.redirect()` open redirect.** In Express 4.x, `res.redirect(user_input)` does not validate the target URL, allowing open redirects. The rule detects calls to `res.redirect()` where the argument originates from `req.query`, `req.params`, or `req.body`.
- **Rails `render inline:` with user data.** Using `render inline: params[:template]` in any Rails version executes ERB, leading to server-side template injection. The rule flags `render inline:` where the value traces back to `params`.

**Best tool:** Semgrep for pattern-matching deprecated API calls. CodeQL when the vulnerability requires tracing user input through framework-specific routing into the dangerous API.

**Rule sketch:**
```
condition: project uses express@4.x (from package.json)
pattern:   res.redirect($USER_INPUT)
source:    req.query, req.params, req.body
message:   "Open redirect via res.redirect() with user-controlled URL"
```

---

## Priority 4: Missing Validation Enforcement

**Rationale:** Many codebases have a validation layer -- schema validators, form validation methods, middleware that enforces input constraints -- but the enforcement is convention-based, not compiler-enforced. Stock rules do not know that your codebase requires every form handler to call `form.validate()` or every API endpoint to pass through `validateSchema()` middleware. A developer can skip the validation call and the code still compiles and runs, silently accepting unvalidated input.

**Example patterns:**

- **Form handler skipping `validate()`.** A Django app convention requires calling `form.is_valid()` before accessing `form.cleaned_data`. The rule detects any view function that accesses `form.cleaned_data` without a preceding call to `form.is_valid()`.
- **API endpoint missing schema validation middleware.** An Express app requires `validateBody(schema)` middleware on all POST/PUT routes. The rule flags router definitions for POST or PUT that do not include `validateBody` in the middleware chain.
- **GraphQL resolver without input validation.** The codebase convention requires calling `validateInput(args)` at the start of every resolver function. The rule matches resolver functions that access `args` without first calling `validateInput`.

**Best tool:** Semgrep for checking structural patterns (presence/absence of validation calls relative to data access). CodeQL if you need to verify that the validation call actually covers the specific fields being used downstream.

**Rule sketch:**
```
pattern: function accesses form.cleaned_data
filter:  NOT preceded by form.is_valid() call in same function
message: "Form data accessed without calling is_valid() first"
```

---

## Priority 5: Trust Boundary Violations

**Rationale:** Stock rules track well-known source-to-sink paths within a single application, but they have no understanding of the codebase's trust boundaries -- where external user input ends and internal service communication begins, or where third-party API responses are treated as trusted. These boundaries are architecture-specific and invisible to generic tools. Data from `breach-code-recon`'s trust boundary map defines exactly where these transitions occur.

**Example patterns:**

- **User input forwarded to internal microservice.** An API gateway takes `req.body.filter` from the external user and passes it directly as a parameter in an internal gRPC or HTTP call to a downstream service. The internal service trusts this input because it came from an "internal" caller.
- **External API response used unsanitized.** The codebase calls a third-party API and renders the response body directly in HTML without escaping, assuming external APIs return safe data.
- **Webhook payload processed without verification.** An incoming webhook handler reads `req.body` and uses the payload fields to update database records without verifying the webhook signature or validating the payload against an expected schema.

**Best tool:** CodeQL. Trust boundary violations are fundamentally dataflow problems -- tracking data from an external source, across a trust boundary, into an internal sink. CodeQL's inter-procedural taint analysis handles this well.

**Rule sketch:**
```
source:     req.body (external user input)
passthrough: httpClient.post(internalServiceUrl, { filter: source })
sink:        internal service processes filter without re-validation
boundary:    external -> internal service call
message:     "User input crosses trust boundary into internal service unsanitized"
```

---

## Priority 6: IDOR Patterns

**Rationale:** Insecure Direct Object Reference vulnerabilities are among the most common findings in application security assessments, yet stock rules rarely catch them because detecting IDOR requires understanding the codebase's authorization model. A generic rule sees `getById(req.params.id)` and has no way to know whether the calling code also verifies that `req.user` owns or has access to that resource. These rules must be tuned to the specific ORM methods and authorization checks the codebase uses.

**Example patterns:**

- **Database lookup by route parameter without ownership check.** An Express handler calls `User.findById(req.params.userId)` and returns the result, but never compares `req.params.userId` against `req.user.id` or calls an authorization function.
- **Bulk data retrieval without tenant scoping.** A multi-tenant SaaS app calls `Order.find({ status: "pending" })` without adding a `tenantId` filter, potentially returning records belonging to other tenants.
- **File access by user-supplied path or ID.** A handler serves files via `getFile(req.query.fileId)` without verifying the authenticated user has access to that file.

**Best tool:** CodeQL for tracing the flow from route parameter to data access and verifying the absence of an authorization check along the path. Semgrep can handle simpler structural cases where the authorization check is expected to appear in the same function.

**Rule sketch:**
```
pattern:   handler reads req.params.id AND calls Model.findById(req.params.id)
filter:    NOT preceded by authorization check comparing req.user against resource
message:   "Data access by user-supplied ID without ownership verification"
```

---

## Priority 7: Configuration Rules

**Rationale:** Security-relevant configuration is deeply codebase-specific. The settings file paths, environment variable names, configuration key names, and expected values differ across every project. Stock rules may check for generic patterns like `DEBUG = True`, but they miss project-specific settings like custom CORS configurations, session timeout values, cookie security flags set through the application's own config layer, or feature flags that disable security controls.

**Example patterns:**

- **Debug mode or verbose logging enabled.** The codebase uses a custom config object where `config.debug_mode = true` or `settings.LOG_LEVEL = "DEBUG"` should never appear in production configuration files. The rule scans configuration files for these specific keys with insecure values.
- **CORS wildcard or overly permissive origin list.** The app configures CORS via `cors({ origin: "*" })` or includes `localhost` origins in production config. The rule checks CORS configuration calls and config files for wildcard or development origins.
- **Insecure cookie settings.** The codebase sets session cookies via `session({ cookie: { secure: false, httpOnly: false } })`. The rule flags cookie configuration where `secure`, `httpOnly`, or `sameSite` are set to insecure values.

**Best tool:** Semgrep. Configuration rules are pattern-matching problems -- looking for specific key-value pairs in known configuration files or function calls. No dataflow analysis needed.

**Rule sketch:**
```
file:    config/*, settings.*, .env*
pattern: cors({ origin: "*" }) OR cookie: { secure: false }
message: "Insecure configuration: CORS wildcard / cookies without secure flag"
```

---

## Priority 8: Second-Order Sinks

**Rationale:** Second-order vulnerabilities occur when user-controlled data is stored safely (e.g., written to a database with parameterized queries) but later retrieved and used in a dangerous operation without re-validation. Stock rules focus on direct source-to-sink flows within a single request. They miss the pattern where data is written in one request and read in another, with the dangerous sink appearing only in the read path. These are among the hardest bugs to find and the most impactful when exploited.

**Example patterns:**

- **Stored XSS via database round-trip.** A user submits a profile bio that is safely stored in the database, but an admin dashboard later retrieves the bio via `user.bio` and renders it with `| safe` (Jinja2) or `dangerouslySetInnerHTML` (React), bypassing output encoding.
- **Stored data passed to `eval()` or template engine.** A user-defined "formula" field is stored in the database and later retrieved by a background job that passes it to `eval()` or a template engine for processing.
- **Stored filename used in file operations.** A user uploads a file and the original filename is stored in the database. A later export function retrieves this filename and uses it in `os.path.join()` or `fs.readFile()` without re-validating for path traversal characters.

**Best tool:** CodeQL. Second-order flows require inter-procedural, cross-function taint tracking that spans write and read operations. CodeQL's dataflow library can model database stores and retrievals as taint steps. Semgrep is insufficient here because it cannot track data through a database round-trip.

**Rule sketch:**
```
source:     database retrieval: user.bio, record.formula, file.original_name
sink:       dangerouslySetInnerHTML(source), eval(source), fs.readFile(source)
condition:  the retrieved field was originally populated from user input
message:    "Stored user data retrieved from DB and used in dangerous operation"
```

---

## Priority 9: Serialization & Crypto Misuse

**Rationale:** While stock rules cover some well-known insecure deserialization and weak crypto patterns, they miss codebase-specific wrappers and context-dependent misuse. A codebase might wrap `pickle.loads()` inside a `deserialize_message()` helper, making it invisible to generic rules. Similarly, `MD5` might be acceptable for checksums but not for password hashing -- context matters, and stock rules lack the codebase knowledge to distinguish these uses.

**Example patterns:**

- **Insecure deserialization via custom wrapper.** The codebase has a `deserialize_message(data)` function that calls `pickle.loads()` internally. The rule marks this wrapper as a deserialization sink and flags any path where untrusted data reaches it.
- **Weak hashing for security-sensitive operations.** The codebase uses `MD5` or `SHA1` for password hashing or token generation. The rule differentiates between security-sensitive uses (password hashing, HMAC for authentication) and acceptable uses (content checksums, cache keys).
- **Insecure random number generation for security tokens.** The codebase generates session tokens, CSRF tokens, or password reset tokens using `Math.random()` (JavaScript), `random.random()` (Python), or `rand()` (Go) instead of cryptographically secure alternatives.

**Best tool:** Semgrep for detecting direct use of insecure functions in security-sensitive contexts. CodeQL for tracing untrusted data into deserialization sinks through custom wrappers and for distinguishing security-sensitive crypto uses from benign ones via dataflow context.

**Rule sketch:**
```
pattern:   hashlib.md5(password) OR crypto.createHash("md5").update(password)
context:   variable name contains "password", "token", "secret", "key"
message:   "Weak hash algorithm used for security-sensitive data"

pattern:   pickle.loads($DATA) OR yaml.load($DATA, Loader=yaml.Loader)
source:    network input, file upload, message queue
message:   "Untrusted data passed to insecure deserialization function"
```

---

## Priority 10: Error Handling Leaks

**Rationale:** Stock rules may flag broad patterns like "don't catch generic exceptions," but they miss the codebase-specific patterns where error details are exposed to users. The critical question is not whether exceptions are caught, but whether the error message content -- stack traces, internal paths, database errors, configuration details -- is included in HTTP responses. This requires knowing the codebase's response-building patterns and distinguishing between user-facing responses and internal logging.

**Example patterns:**

- **Exception message in API response.** A catch block returns `res.status(500).json({ error: err.message })` or `return JsonResponse({"error": str(e)})`, exposing internal error details (SQL errors, file paths, class names) to the client.
- **Stack trace in production error page.** The error-handling middleware renders a detailed error page with `err.stack` when `NODE_ENV` is not explicitly checked, or the Django `DEBUG` setting leaks through to a custom error view.
- **Differential error responses enabling enumeration.** A login endpoint returns "User not found" for invalid usernames but "Invalid password" for valid usernames with wrong passwords, enabling user enumeration. The rule checks that authentication error responses use a single, consistent message.

**Best tool:** Semgrep for detecting structural patterns where exception objects or their properties are passed directly into response-building functions. CodeQL for more complex cases where the error information flows through multiple functions before reaching the response.

**Rule sketch:**
```
pattern:   catch(e) { ... res.json({ error: e.message }) }
           OR
           except Exception as e: ... return JsonResponse({"error": str(e)})
filter:    response is user-facing (HTTP response, API response)
message:   "Exception details exposed in user-facing error response"
```

---

## Tool Selection Guide

| Category | Primary Tool | Rationale |
|---|---|---|
| Auth Enforcement Gaps | Semgrep | Structural: presence/absence of decorators and middleware |
| Application-Specific Sinks | CodeQL | Taint tracking from sources to custom sinks |
| Framework-Specific Patterns | Both | Semgrep for API pattern matching; CodeQL when dataflow is needed |
| Missing Validation | Semgrep | Structural: checking for validation calls before data access |
| Trust Boundary Violations | CodeQL | Cross-boundary dataflow tracking |
| IDOR Patterns | CodeQL | Verifying absence of authorization checks along data paths |
| Configuration Rules | Semgrep | Pattern matching in config files and setup calls |
| Second-Order Sinks | CodeQL | Cross-request taint tracking through storage |
| Serialization & Crypto Misuse | Both | Semgrep for direct misuse; CodeQL for flows through wrappers |
| Error Handling Leaks | Semgrep | Structural: exception data in response-building calls |

---

## Priority Rationale

The ordering reflects two factors: **likelihood of exploitation** and **how badly stock rules miss the pattern**.

- **Priorities 1-3** (Auth Gaps, Custom Sinks, Framework Patterns) represent the highest-impact findings that are almost entirely invisible to stock rules. A missing auth decorator is a guaranteed unauthenticated access vulnerability, and custom sinks are by definition unknown to generic tools.
- **Priorities 4-6** (Validation, Trust Boundaries, IDOR) are common vulnerability classes where stock rules provide partial coverage, but codebase-specific rules dramatically improve detection accuracy.
- **Priorities 7-10** (Configuration, Second-Order, Crypto, Error Handling) are categories where stock rules provide some baseline coverage, but codebase-specific tuning catches the cases that slip through -- particularly second-order sinks, which are nearly impossible to detect without custom dataflow modeling.
