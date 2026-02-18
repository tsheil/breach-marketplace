# A07: Identification and Authentication Failures

Authentication failures encompass weaknesses in how an application identifies users and manages their sessions. This includes credential stuffing, weak password policies, insecure session management, JWT implementation flaws, and enumeration vulnerabilities that leak information about valid accounts.

## Key Patterns to Search For

Search for these patterns to identify potential authentication failures:

- **Login Endpoints**: `/login`, `/signin`, `/authenticate`, `/api/auth`, `/oauth/token`, registration endpoints
- **Session Management**: `session_id`, `JSESSIONID`, `PHPSESSID`, `connect.sid`, `Set-Cookie`, session creation and destruction logic
- **JWT Handling**: `jwt.sign(`, `jwt.verify(`, `jwt.decode(`, `jose.`, `jsonwebtoken`, `pyjwt`, `JWT.decode`, algorithm specification, secret/key management
- **Password Reset**: `/forgot-password`, `/reset-password`, token generation for resets, reset link construction, token expiration logic
- **Remember Me**: `remember_me`, `keep_logged_in`, persistent cookie creation, long-lived tokens
- **MFA Implementation**: `/verify-otp`, `/mfa/verify`, TOTP validation, SMS code verification, backup code handling
- **Password Storage**: `bcrypt`, `argon2`, `scrypt`, `PBKDF2`, `password_hash`, `hashpw`, hashing function calls at user creation and login
- **User Enumeration**: Different error messages for "user not found" vs "wrong password", timing differences in auth responses, registration endpoint revealing existing usernames
- **OAuth/OIDC**: `client_id`, `client_secret`, `redirect_uri`, `authorization_code`, `state` parameter, token exchange logic

## Common Vulnerable Patterns

**JWT None Algorithm Attack:**
```
# Vulnerable: accepts 'none' algorithm
token = jwt.decode(token_string, options={"verify_signature": False})
# Or: library that accepts alg: "none" in the header

# Attacker crafts token with {"alg": "none"} and empty signature
```

**JWT Weak Secret:**
```
# Vulnerable: weak/guessable JWT secret
jwt.sign(payload, "secret")
jwt.sign(payload, "your-256-bit-secret")
jwt.sign(payload, process.env.JWT_SECRET || "default-secret")
```

**JWT Algorithm Confusion:**
```
# Vulnerable: RS256 token validated with HS256 using public key as secret
# If server accepts HS256 when RS256 is expected, attacker signs with public key
token = jwt.sign(payload, public_key, {algorithm: 'HS256'})
```

**User Enumeration via Error Messages:**
```
# Vulnerable: different messages reveal valid usernames
if not user_exists(username):
    return "User not found"          # Reveals: username is invalid
if not check_password(user, password):
    return "Incorrect password"      # Reveals: username is valid
```

**Session Fixation:**
```
# Vulnerable: session ID not regenerated after login
def login(request):
    # Session ID stays the same before and after authentication
    user = authenticate(request.form['username'], request.form['password'])
    session['user'] = user.id
    # Attacker who set the session ID pre-auth now has an authenticated session
```

**Missing Session Invalidation:**
```
# Vulnerable: logout does not destroy server-side session
def logout(request):
    # Only clears client-side cookie, session remains valid on server
    response.delete_cookie('session_id')
    return redirect('/login')
```

## Exploitability Indicators

An authentication failure is exploitable when:

- No rate limiting or account lockout exists on the login endpoint (enables brute force and credential stuffing)
- JWT uses a weak or default secret (tools like jwt_tool and hashcat can crack weak secrets)
- JWT accepts the "none" algorithm or allows algorithm confusion (HS256 vs RS256)
- JWT has no expiration claim or the expiration is not validated
- Password reset tokens are predictable (timestamp-based, sequential, or short)
- Password reset tokens do not expire or can be reused
- Session IDs are not regenerated after authentication state changes
- Different error messages or response times reveal valid usernames
- "Remember me" tokens are long-lived and not bound to the session or revocable
- OAuth redirect_uri validation is incomplete (allows subdomain matching, path traversal, or fragment manipulation)

## Common Mitigations and Their Bypasses

**Mitigation: Account lockout after N failed attempts**
Bypass: Distributed brute force (different source IPs), credential stuffing from breach databases (each credential is tried only once per account), lockout abuse as a denial-of-service vector against legitimate users, username/password spray across many accounts.

**Mitigation: JWT expiration (exp claim)**
Bypass: If the server does not validate the exp claim, expiration has no effect. Also check if token refresh allows indefinite session extension and if revocation is possible.

**Mitigation: Generic error messages ("Invalid credentials")**
Bypass: Timing side channels may still differentiate between valid and invalid usernames. Registration endpoints may reveal whether an email is already registered. Password reset may behave differently for valid vs invalid emails.

**Mitigation: CAPTCHA on login**
Bypass: CAPTCHA solving services, CAPTCHA bypass via API endpoints that do not require CAPTCHA, session reuse to bypass per-session CAPTCHA, audio CAPTCHA solvers.

**Mitigation: HTTP-only session cookies**
Bypass: HTTP-only prevents JavaScript access but does not prevent CSRF (the cookie is still sent automatically). Session fixation and session hijacking via network interception (without Secure flag) are still possible.

## Rejection Rationalizations and Counter-Arguments

**"We use JWT so sessions are secure."**
Counter: JWT is a token format, not a security guarantee. Weak secrets, missing algorithm validation, absent expiration, and lack of revocation are all common JWT implementation flaws.

**"Brute force is impractical against our login."**
Counter: Credential stuffing uses known username/password pairs from other breaches, dramatically reducing the attempt count. Even with rate limiting, a slow credential stuffing attack over days or weeks can succeed.

**"The timing difference is only a few milliseconds."**
Counter: Statistical analysis over many requests can reliably detect millisecond-scale timing differences. Dedicated tools automate this analysis.

**"Password reset tokens expire after 24 hours so they are safe."**
Counter: If the token is predictable or has insufficient entropy, it can be brute-forced within the expiration window. Also check if tokens are single-use and if previous tokens are invalidated when a new one is generated.

## Chaining Opportunities

- **User Enumeration + Credential Stuffing = Account Compromise**: Confirmed valid usernames fed into credential stuffing attacks dramatically improve success rates.
- **JWT Flaw + Privilege Escalation = Admin Access**: Forging a JWT with admin claims or no signature provides immediate admin access.
- **Session Fixation + Social Engineering = Session Hijacking**: Set a known session ID for the victim, trick them into logging in, then use the now-authenticated session.
- **OAuth Misconfiguration + Open Redirect = Token Theft**: Manipulated redirect_uri in OAuth flow sends the authorization code or token to the attacker.
- **Weak Password Reset + Information Disclosure = Account Takeover**: Predictable reset tokens combined with leaked user emails enable mass account takeover.
