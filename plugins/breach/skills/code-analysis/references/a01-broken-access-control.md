# A01: Broken Access Control

Broken access control encompasses any flaw that allows users to act outside their intended permissions. This includes accessing other users' data, performing actions reserved for privileged roles, and bypassing authentication or authorization enforcement entirely.

## Key Patterns to Search For

Search for these patterns in the codebase to identify potential broken access control:

- Parameters containing object identifiers: `id`, `user_id`, `account_id`, `order_id`, `doc_id`, `file_id`, `uuid`
- Route definitions missing authentication or authorization middleware
- Authorization checks performed in frontend/client code but not server-side
- Direct database queries using user-supplied IDs without ownership validation
- Role or permission checks using client-supplied values (cookies, hidden fields, JWT claims without server validation)
- Path parameters used to construct file paths or resource lookups
- CORS configuration with wildcard origins or reflected origin with credentials
- Endpoint patterns like `/admin/*`, `/api/internal/*`, `/debug/*`, `/management/*`
- Functions or decorators related to access control: `@login_required`, `@admin_only`, `authorize()`, `checkPermission()`, `isAuthenticated()`
- Missing access control on HTTP methods (e.g., GET is protected but PUT is not)

## Common Vulnerable Patterns

**Insecure Direct Object Reference (IDOR):**
```
# Vulnerable: no ownership check
def get_document(request, doc_id):
    return Document.objects.get(id=doc_id)

# Should verify: document.owner == request.user
```

**Missing Function-Level Access Control:**
```
# Vulnerable: admin route without role check
@app.route('/admin/delete_user/<user_id>')
def delete_user(user_id):
    User.delete(user_id)
```

**Horizontal Privilege Escalation:**
```
# Vulnerable: user can modify another user's profile
PUT /api/users/12345/profile
# Attacker changes 12345 to 12346 to edit another user
```

**Forced Browsing:**
```
# Protected page accessible by guessing URL
/reports/2024/financial-summary.pdf
/backups/database-dump.sql
```

**Metadata Manipulation:**
```
# Vulnerable: role from JWT claim trusted without server verification
role = decode_jwt(token)['role']
if role == 'admin':
    grant_admin_access()
```

## Exploitability Indicators

A broken access control finding is exploitable when:

- Object IDs are sequential or predictable (auto-increment integers)
- No server-side ownership check exists between the authenticated user and the requested resource
- Authorization middleware is applied inconsistently (some routes protected, others not)
- Role checks rely on client-controlled values that can be tampered with
- Different HTTP methods on the same endpoint have different access control (GET protected, DELETE unprotected)
- API endpoints return data for any valid ID regardless of the requesting user's relationship to that resource
- CORS allows credential-bearing requests from attacker-controlled origins

## Common Mitigations and Their Bypasses

**Mitigation: Frontend-only access control (hiding UI elements)**
Bypass: Directly call the API endpoint. Frontend visibility controls do not enforce server-side access.

**Mitigation: Checking user role from JWT or cookie**
Bypass: If the JWT secret is weak or the signature is not validated, forge a token with elevated claims. If the role is in an unsigned cookie, modify it directly.

**Mitigation: UUID instead of sequential IDs**
Bypass: UUIDs prevent enumeration but not access control bypass if leaked through other endpoints, error messages, URLs, or logs. Search for UUID leakage vectors.

**Mitigation: IP-based access restriction for admin endpoints**
Bypass: X-Forwarded-For header injection if the application trusts proxy headers without validation. Also check for SSRF that could reach the endpoint from a trusted IP.

**Mitigation: Referrer-based access control**
Bypass: Referrer header is attacker-controlled. Set it to the expected value to bypass the check.

## Rejection Rationalizations and Counter-Arguments

**"Users would never guess other users' IDs."**
Counter: Sequential IDs are trivially enumerable. Even UUIDs leak through API responses, emails, URLs, logs, and error messages. Automated tools enumerate at scale.

**"This endpoint requires authentication so it is protected."**
Counter: Authentication (who you are) is not authorization (what you can do). An authenticated user accessing another user's data is a critical access control failure.

**"We check permissions on the frontend."**
Counter: Any client-side check can be bypassed by directly calling the API. Server-side enforcement is mandatory.

**"The data exposed is not sensitive."**
Counter: Even non-sensitive data can be chained with other vulnerabilities. User enumeration enables credential stuffing. Internal IDs enable IDOR on more sensitive endpoints.

## Chaining Opportunities

- **IDOR + Information Disclosure**: Access another user's data, then use leaked tokens, emails, or security answers to take over their account.
- **Broken Access Control + SSRF**: Access internal admin endpoints through SSRF to bypass network-level access restrictions.
- **Missing Authorization + CSRF**: If an endpoint lacks both authorization and CSRF protection, any authenticated user can be tricked into performing the action.
- **Forced Browsing + Path Traversal**: Combine directory guessing with path traversal to access protected files outside the web root.
- **Privilege Escalation + Business Logic Flaw**: Escalate to admin, then exploit admin-only business logic flaws for maximum impact.
