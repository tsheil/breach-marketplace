# A05: Security Misconfiguration

Security misconfiguration covers any improperly configured security control across the application stack: web servers, frameworks, databases, cloud services, containers, and application code. This includes default credentials, unnecessary features, missing security headers, verbose errors, and overly permissive configurations.

## Key Patterns to Search For

Search for these patterns to identify potential security misconfigurations:

- **Debug Mode**: `DEBUG = True`, `debug: true`, `NODE_ENV=development`, `FLASK_DEBUG=1`, `DJANGO_DEBUG=True`, `APP_DEBUG=true`, `<debug>true</debug>`
- **Default Credentials**: `admin:admin`, `root:root`, `password`, `changeme`, `default`, `test123`, `admin123` in configuration files
- **Missing Security Headers**: Check for absence of `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`
- **CORS Configuration**: `Access-Control-Allow-Origin: *`, reflected origin without validation, `Access-Control-Allow-Credentials: true` with wildcard or reflected origin
- **Exposed Endpoints**: `/debug/`, `/admin/`, `/console/`, `/phpinfo`, `/server-status`, `/elmah`, `/.env`, `/.git/`, `/swagger`, `/graphql` (with introspection enabled), `/actuator/`
- **Verbose Errors**: Stack traces in HTTP responses, database error messages, file paths in errors, framework version disclosure
- **Directory Listing**: `autoindex on`, `Options +Indexes`, directory listing enabled in web server config
- **Unnecessary HTTP Methods**: `TRACE`, `OPTIONS` revealing internal routes, `PUT`/`DELETE` on static file servers
- **Cloud Misconfigurations**: Public S3 buckets, open security groups, exposed metadata endpoints, overly permissive IAM policies
- **Exposed Sensitive Files**: `.env`, `.git/config`, `wp-config.php`, `web.config`, `.DS_Store`, `composer.json`, `package.json`, `Dockerfile`, `docker-compose.yml`

## Common Vulnerable Patterns

**Debug Mode in Production:**
```
# Vulnerable: debug mode exposes interactive console and stack traces
# Django
DEBUG = True

# Flask
app.run(debug=True)

# Laravel
APP_DEBUG=true

# Express
app.set('env', 'development')
```

**Overly Permissive CORS:**
```
# Vulnerable: reflects any origin with credentials
origin = request.headers.get('Origin')
response.headers['Access-Control-Allow-Origin'] = origin
response.headers['Access-Control-Allow-Credentials'] = 'true'

# Allows any website to make authenticated requests to this API
```

**Default Admin Credentials:**
```
# Vulnerable: default credentials in config
database:
  host: localhost
  username: root
  password: ""

admin:
  username: admin
  password: admin
```

**Missing Security Headers:**
```
# Vulnerable: no CSP, HSTS, or frame protection
# Response headers contain no security-related headers
# Enables: clickjacking, content injection, protocol downgrade
```

**Exposed Environment Files:**
```
# .env committed to repository
DATABASE_URL=postgres://admin:password123@db.internal:5432/prod
AWS_SECRET_ACCESS_KEY=EXAMPLE_KEY_CHECK_FOR_REAL_VALUES
STRIPE_SECRET_KEY=sk_live_EXAMPLE_KEY_PLACEHOLDER
```

## Exploitability Indicators

A security misconfiguration is exploitable when:

- Debug mode is enabled in production (interactive consoles allow code execution)
- Default credentials are active on admin interfaces, databases, or management tools
- CORS allows arbitrary origins with credentials (enables cross-origin data theft)
- Stack traces reveal file paths, framework versions, and query structure (aids other attacks)
- Admin or management interfaces are accessible without authentication or with default credentials
- .env or .git directories are accessible via the web (directly leaks secrets)
- Directory listing exposes file structure and potentially sensitive files
- Security headers are absent (enables clickjacking, content-type sniffing, protocol downgrade attacks)

## Common Mitigations and Their Bypasses

**Mitigation: Setting DEBUG = False in the main config**
Bypass: Check for environment variable overrides, secondary debug flags (TEMPLATE_DEBUG, SQL_DEBUG), debug toolbars that are conditionally enabled, and debug endpoints that remain registered.

**Mitigation: Restricting admin panel access by IP**
Bypass: X-Forwarded-For spoofing if the application trusts proxy headers. SSRF from an internal network. Also check if the restriction applies to all admin routes or just the login page.

**Mitigation: Custom error pages hiding stack traces**
Bypass: Trigger unexpected error types (malformed input, unusual HTTP methods, oversized requests) that may bypass the custom error handler and fall through to the framework's default handler.

**Mitigation: CORS whitelist for allowed origins**
Bypass: Subdomain takeover on a whitelisted domain, regex bypass (if the whitelist uses pattern matching: `evil.com.attacker.com` matching `*.evil.com`), null origin exploitation.

**Mitigation: Removing .env from web root**
Bypass: Check backup files (.env.bak, .env.old, .env.production), version control (.git/), Docker layers, CI/CD artifacts, and error messages that may still expose these values.

## Rejection Rationalizations and Counter-Arguments

**"Debug mode is only enabled in development, not production."**
Counter: Verify the actual deployed configuration. Check environment variable precedence, deployment scripts, and Docker configurations. Many production breaches have resulted from accidentally deployed debug configurations.

**"The admin panel is not linked from anywhere on the site."**
Counter: Security through obscurity is not a control. Automated scanners check common admin paths. Path discovery tools and search engines index these endpoints.

**"Our CORS configuration is fine because we do not use cookies."**
Counter: Bearer tokens in Authorization headers are also accessible cross-origin if CORS is misconfigured. Check whether the API uses any form of credential that CORS could expose.

**"Stack traces only show to developers who trigger errors."**
Counter: Attackers intentionally trigger errors with malformed input to extract information from stack traces. Any externally triggerable error path is an information disclosure vector.

## Chaining Opportunities

- **Debug Mode + RCE**: Interactive debug consoles (Werkzeug, Django debug toolbar, Rails console) provide direct code execution.
- **Exposed .env + Full Compromise**: Leaked database credentials, API keys, and encryption secrets enable lateral access to every connected service.
- **CORS Misconfiguration + Data Theft**: Overly permissive CORS allows attacker-controlled websites to read authenticated API responses, exfiltrating user data.
- **Default Credentials + Privilege Escalation**: Access admin panels with default credentials, then leverage admin functionality for further compromise.
- **Verbose Errors + Injection**: Stack traces revealing query structure and database type make SQL injection exploitation significantly easier.
