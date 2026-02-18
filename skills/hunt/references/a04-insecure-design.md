# A04: Insecure Design

Insecure design refers to fundamental flaws in the application's architecture and business logic that cannot be fixed by correct implementation alone. These are missing or ineffective security controls that should have been designed into the application from the start: rate limiting, anti-automation, abuse case handling, proper workflow enforcement, and server-side validation.

## Key Patterns to Search For

Search for these patterns to identify potential insecure design flaws:

- **Missing Rate Limiting**: Login endpoints, password reset, OTP/MFA verification, API endpoints, registration, and any sensitive operation without rate limiting middleware (`rateLimit`, `throttle`, `RateLimiter`, `@rate_limit`)
- **Sequential/Predictable IDs**: Auto-increment primary keys used as external identifiers: `id SERIAL`, `AUTO_INCREMENT`, sequential order numbers, predictable invoice IDs
- **Missing Server-Side Validation**: Validation only in frontend JavaScript, no server-side check on price/quantity/discount, client-computed totals trusted by server
- **Race Conditions (TOCTOU)**: Check-then-act patterns without locking: read balance then debit, check availability then reserve, verify coupon then apply. Look for: `SELECT ... UPDATE` without `FOR UPDATE`, non-atomic read-modify-write sequences
- **Workflow Bypass**: Multi-step processes that do not enforce step ordering: skip payment in checkout, bypass email verification, jump to final step
- **Missing Re-authentication**: Sensitive operations (password change, email change, account deletion, payment) that do not require re-entering the current password or MFA
- **Missing CAPTCHA/Anti-automation**: Forms vulnerable to automated submission: registration, contact forms, password reset requests
- **Business Logic**: Negative quantities, zero-price items, discount stacking, self-referral, duplicate transaction submission

## Common Vulnerable Patterns

**Missing Rate Limiting on Authentication:**
```
# Vulnerable: no rate limit on login
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        return create_session(user)
    return "Invalid credentials", 401

# Allows unlimited brute force attempts
```

**Race Condition in Balance Operations:**
```
# Vulnerable: non-atomic balance check and debit
balance = get_balance(user_id)        # Read: $100
if balance >= amount:                  # Check: $100 >= $90
    debit_balance(user_id, amount)     # Write: $100 - $90 = $10

# Two concurrent requests both read $100, both pass the check, both debit $90
# Result: user debited $180 from $100 balance
```

**Client-Side Price Validation:**
```
// Vulnerable: price sent from client
fetch('/api/checkout', {
    body: JSON.stringify({
        item_id: 42,
        price: 0.01,  // Attacker modifies from $99.99
        quantity: 1
    })
});
```

**Workflow Step Bypass:**
```
# Vulnerable: steps are independent endpoints without state enforcement
POST /checkout/step1  # Add items to cart
POST /checkout/step2  # Enter shipping info
POST /checkout/step3  # Enter payment
POST /checkout/step4  # Confirm order

# Attacker skips step3, goes directly from step2 to step4
```

**Missing Account Lockout:**
```
# Vulnerable: no lockout after failed attempts
def verify_otp(user_id, otp):
    stored_otp = get_stored_otp(user_id)
    return otp == stored_otp

# 6-digit OTP bruteforceable in at most 1,000,000 attempts
```

## Exploitability Indicators

An insecure design flaw is exploitable when:

- No rate limiting exists on authentication endpoints (brute force is feasible)
- OTP/MFA codes are short (4-6 digits) and have no attempt limits or lockout
- Business logic allows negative values, zero prices, or impossible states
- Multi-step workflows can be completed out of order by directly accessing later steps
- Race conditions exist in financial operations or resource allocation without database-level locking
- Server accepts client-supplied prices, totals, or discount calculations without recalculating server-side
- Predictable identifiers allow enumeration of resources (orders, invoices, users)
- Sensitive operations (password change, account deletion) do not require re-authentication

## Common Mitigations and Their Bypasses

**Mitigation: CAPTCHA on forms**
Bypass: CAPTCHA solving services, machine learning-based solvers, audio CAPTCHA bypasses, and CAPTCHA token reuse if the server does not invalidate after single use.

**Mitigation: Rate limiting by IP address**
Bypass: IP rotation through proxies, cloud functions, or botnets. Also check if the rate limiter trusts X-Forwarded-For (attacker can supply arbitrary IPs). Check if rate limiting is applied per-IP but the attack is distributed.

**Mitigation: Sequential workflow enforcement via session state**
Bypass: Check if the state can be manipulated (cookie-based session, client-side state). Verify enforcement is server-side and tamper-proof.

**Mitigation: Database transactions for atomicity**
Bypass: Verify the isolation level is sufficient. READ COMMITTED may still allow race conditions. Check if the application uses SELECT ... FOR UPDATE or equivalent row-level locking.

**Mitigation: Server-side validation added alongside client validation**
Bypass: Verify the server-side validation covers all the same checks. Often the server validates presence but not business logic constraints (minimum price, maximum quantity, valid combinations).

## Rejection Rationalizations and Counter-Arguments

**"No one would try millions of combinations against our OTP."**
Counter: Automated tools make millions of requests trivially. A 6-digit OTP with no rate limit can be brute-forced in minutes. Demonstrate with a simple script showing request rate.

**"Race conditions are theoretical and unreliable."**
Counter: Race conditions in web applications are reliably exploitable. HTTP/2 single-packet attacks and parallel request tooling make timing-based races practical. Demonstrate with concurrent requests.

**"We validate on the frontend to prevent bad input."**
Counter: Frontend validation is a user experience feature, not a security control. Any HTTP client (curl, Burp, Postman) bypasses all frontend validation. Show the raw request with manipulated values.

**"This is an unlikely attack scenario."**
Counter: Business logic flaws are the most commonly exploited vulnerability class in bug bounty programs because they are application-specific and cannot be detected by automated scanners.

## Chaining Opportunities

- **Race Condition + Financial Operations = Fraud**: Double-spend attacks on payment processing, coupon redemption, or point systems.
- **Missing Rate Limit + Weak Password Policy = Account Compromise**: Brute-force attacks succeed when passwords are not required to be strong.
- **Workflow Bypass + Missing Payment = Theft**: Skipping payment steps in e-commerce checkout flows.
- **Predictable IDs + IDOR = Data Breach**: Sequential IDs make IDOR exploitation trivial by enumerating all valid IDs.
- **Missing Re-auth + XSS/CSRF = Account Takeover**: If password change does not require current password, XSS or CSRF can change the password of any user.
