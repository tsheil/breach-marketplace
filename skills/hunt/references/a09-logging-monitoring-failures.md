# A09: Security Logging and Monitoring Failures

Logging and monitoring failures cover insufficient recording of security-relevant events, sensitive data exposure through logs, log injection attacks, and the absence of alerting mechanisms that would detect active attacks. While not directly exploitable, these failures enable attackers to operate undetected and hinder incident response.

## Key Patterns to Search For

Search for these patterns to identify logging and monitoring failures:

- **Authentication Event Logging**: Search for logging around login success, login failure, password change, password reset, MFA enable/disable, account lockout, and session creation/destruction. Absence of logging at these points is the finding.
- **Sensitive Data in Logs**: `log.info(password`, `logger.debug(token`, `console.log(req.body)`, `print(user.password)`, `logging.info(f"...{secret}")`, `Log.d("API_KEY", apiKey)`
- **Log Injection**: User input concatenated directly into log messages without sanitization: `logger.info("User " + username + " logged in")`, `log.info(f"Request from {user_input}")`
- **Missing Logging on Sensitive Operations**: Search for financial operations, admin actions, data exports, permission changes, and configuration changes that do not produce log entries
- **Log File Access**: Log file permissions, log file paths, log file rotation, whether logs are written to world-readable locations
- **Alert Configuration**: Search for alerting rules, monitoring configurations, threshold-based alerts on failed auth, anomaly detection setup
- **Request Tracing**: Absence of correlation IDs, request IDs, or trace IDs that link related log entries across services
- **Logging Frameworks**: `log4j`, `logback`, `winston`, `bunyan`, `pino`, `serilog`, `NLog`, Python `logging`, `log4net`

## Common Vulnerable Patterns

**Sensitive Data Logged:**
```
# Vulnerable: password logged in plaintext
logger.info(f"Login attempt for user {username} with password {password}")

# Vulnerable: full request body logged including auth tokens
logger.debug(f"Request body: {request.body}")

# Vulnerable: session token in logs
app.logger.info(f"Created session: {session_token}")
```

**Log Injection:**
```
# Vulnerable: unsanitized user input in log message
username = request.form['username']
logger.info(f"Login failed for user: {username}")

# Attacker input: "admin\n[INFO] Login successful for user: admin"
# This creates a forged log entry that appears to show a successful login
```

**Missing Authentication Logging:**
```
# Vulnerable: no logging of failed authentication
def login(username, password):
    user = db.get_user(username)
    if user and user.check_password(password):
        return create_session(user)
    return error_response("Invalid credentials")
    # No log entry for the failed attempt
    # Brute force attacks will be invisible
```

**Overly Verbose Debug Logging in Production:**
```
# Vulnerable: debug logging exposing internal state
logger.debug(f"Database query: SELECT * FROM users WHERE id = {user_id}")
logger.debug(f"JWT payload: {decoded_token}")
logger.debug(f"API response from payment provider: {response.json()}")
```

**Missing Audit Trail for Admin Actions:**
```
# Vulnerable: admin deletes user with no audit log
@admin_required
def delete_user(user_id):
    User.objects.get(id=user_id).delete()
    return {"status": "deleted"}
    # No record of who deleted which user or when
```

## Exploitability Indicators

A logging failure is exploitable (or enables exploitation) when:

- Failed login attempts are not logged, allowing brute force attacks to go undetected
- Admin and privileged actions have no audit trail, enabling insider threats to operate without accountability
- Sensitive data in logs is accessible to unauthorized users (shared log aggregation systems, world-readable log files, logs exposed through debug endpoints)
- Log injection can forge entries that mislead incident response teams or trigger false alerts
- Missing monitoring means security events (mass account lockout, data exfiltration, privilege escalation) produce no alerts
- Log files contain credentials, tokens, or PII that can be harvested by anyone with log access
- No request correlation IDs exist, making it impossible to trace an attack across multiple services during incident response

## Common Mitigations and Their Bypasses

**Mitigation: Logging all requests to a central log aggregation system**
Bypass: Check if log aggregation is properly secured. Can log data be modified or deleted? Are there gaps in what is logged? Does the aggregation system itself have authentication and access controls?

**Mitigation: Sanitizing user input before logging**
Bypass: Check if the sanitization is comprehensive. Does it handle all encoding formats? Are there code paths that log before sanitization occurs? Is the sanitization applied consistently across all logging calls?

**Mitigation: Masking sensitive data in logs (e.g., showing only last 4 digits)**
Bypass: Check if masking is applied consistently. Search for log statements that bypass the masking utility. Check if the unmasked data appears in exception stack traces or error messages that are also logged.

**Mitigation: Log file rotation and retention policies**
Bypass: Even with rotation, archived log files may be accessible. Check if old log files are properly secured or if they are stored in accessible locations (S3 buckets, shared drives, backup systems).

**Mitigation: Alerting on failed login attempts**
Bypass: Distributed credential stuffing (low volume per IP) may fall below alert thresholds. Check if alerts cover all authentication mechanisms (API keys, OAuth tokens, SSO) not just password-based login.

## Rejection Rationalizations and Counter-Arguments

**"Logging is not a vulnerability; it does not enable an attack."**
Counter: Missing logging enables attackers to operate undetected. It is categorized as a security weakness by OWASP because it directly impacts the ability to detect, respond to, and investigate security incidents. Some regulations (PCI DSS, SOC 2) mandate specific logging requirements.

**"We log to stdout and the container platform collects it."**
Counter: Verify what is actually collected. Container platforms may truncate, drop, or fail to collect log entries under high load. Also verify that security-relevant events are specifically logged, not just application errors.

**"Sensitive data in logs is only accessible to operations staff."**
Counter: Operations staff should not have access to plaintext passwords or authentication tokens. Principle of least privilege applies. Also, log aggregation systems are high-value targets that may be compromised independently.

**"We will add monitoring later; the application works fine without it."**
Counter: Detection capability is a security requirement, not an enhancement. The average time to detect a breach without monitoring is measured in months, dramatically increasing the impact.

## Chaining Opportunities

- **Missing Logging + Any Attack = Undetected Compromise**: The absence of logging makes any successful attack significantly more damaging because the attacker can operate, persist, and exfiltrate without detection.
- **Log Injection + SIEM Manipulation = Alert Suppression**: Injecting crafted log entries can trigger false positives that desensitize operations teams, or inject entries that suppress genuine alerts in automated systems.
- **Sensitive Data in Logs + Log Access = Credential Theft**: If logs contain credentials or tokens and are accessible (through SSRF, directory traversal, misconfigured log endpoints), this becomes a direct credential disclosure.
- **Missing Audit Trail + Insider Threat = Unaccountable Abuse**: Without audit logging, malicious insiders can abuse their access without leaving evidence.
- **Debug Logging + Information Disclosure = Attack Enablement**: Verbose debug logs revealing query structures, internal IPs, file paths, and API endpoints provide attackers with detailed intelligence for targeted attacks.
