# A03: Injection

Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data tricks the interpreter into executing unintended commands or accessing unauthorized data. This category covers all forms of injection: SQL, NoSQL, OS command, LDAP, XPath, expression language, template, header, and log injection.

## Key Patterns to Search For

Search for these patterns to identify potential injection vulnerabilities:

- **SQL Injection**: String concatenation in queries: `"SELECT * FROM users WHERE id = " + id`, `f"SELECT ... {user_input}"`, `query = "... " + req.params.id`, `$"SELECT ... {input}"`, `String.format("SELECT ... %s", input)`
- **ORM Bypass**: Raw query methods: `.raw(`, `.execute(`, `Sequelize.literal(`, `knex.raw(`, `ActiveRecord.connection.execute`, `$wpdb->query(`
- **NoSQL Injection**: MongoDB operators in user input: `$gt`, `$ne`, `$regex`, `$where`. Query construction: `{username: req.body.username}` (allows object injection)
- **Command Injection**: `exec(`, `system(`, `popen(`, `subprocess.call(`, `child_process.exec(`, `Runtime.getRuntime().exec(`, backticks, `os.system(`, `Process.Start(`
- **SSTI (Server-Side Template Injection)**: `render(template_string)`, `render_template_string(`, `Jinja2(user_input)`, `new Function(user_input)`, `eval(`, `{{`, `${`, `#{` in user-controlled template content
- **LDAP Injection**: `"(uid=" + username + ")"`, LDAP search filters with concatenated user input
- **XPath Injection**: `"//users/user[name='" + input + "']"`
- **Header Injection (CRLF)**: User input in HTTP response headers, `\r\n` in redirect URLs, `Location:` header with user input
- **Log Injection**: User input written directly to log files without sanitization

## Common Vulnerable Patterns

**SQL Injection via String Concatenation:**
```
# Vulnerable
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
cursor.execute(query)

# Safe: parameterized query
cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
```

**Command Injection:**
```
# Vulnerable
os.system("ping -c 1 " + user_supplied_host)
exec("nslookup " + domain)

# Attacker input: "127.0.0.1; cat /etc/passwd"
```

**NoSQL Injection:**
```
# Vulnerable: MongoDB query with unsanitized object
db.users.find({username: req.body.username, password: req.body.password})

# Attacker sends: {"username": "admin", "password": {"$ne": ""}}
```

**Server-Side Template Injection:**
```
# Vulnerable: user input rendered as template
template = Template(request.args.get('name'))
return template.render()

# Attacker input: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**Second-Order SQL Injection:**
```
# Step 1: attacker registers with username: admin'--
# Step 2: application retrieves stored username and uses it in a query
query = "UPDATE users SET password = '" + new_pass + "' WHERE username = '" + stored_username + "'"
```

## Exploitability Indicators

An injection finding is exploitable when:

- User input reaches a query, command, or template without parameterization or sanitization
- The application constructs queries using string concatenation, interpolation, or format strings
- ORM raw query methods accept user input directly
- Command execution functions receive user-controlled arguments without strict whitelisting
- Template engines render user-supplied template strings rather than pre-defined templates with user data as context
- Error messages reveal query structure, database type, or command output (aids exploitation)
- The application runs with elevated database or OS privileges (increases impact)
- WAF or input filtering uses a deny-list approach rather than parameterization (bypassable)

## Common Mitigations and Their Bypasses

**Mitigation: Input validation (deny-listing dangerous characters)**
Bypass: Encoding variations (URL encoding, double encoding, Unicode normalization), alternate syntax (using `/**/` instead of spaces in SQL, using `$()` instead of backticks in commands), case variation, and null byte injection.

**Mitigation: ORM usage (assuming ORM prevents injection)**
Bypass: ORMs that allow raw queries, literal expressions, or custom where clauses still permit injection. Search for `.raw(`, `.literal(`, `.where("string " + input)`, and similar patterns.

**Mitigation: Prepared statements / parameterized queries**
Bypass: Correctly implemented parameterized queries prevent injection. However, verify that ALL queries are parameterized. A single missed query is sufficient for exploitation. Also check for dynamic table or column names that cannot be parameterized.

**Mitigation: Escaping special characters**
Bypass: Escaping is error-prone and context-dependent. Different interpreters require different escaping. Character set mismatches (GBK encoding bypass in MySQL) and alternate representations can defeat escaping.

**Mitigation: WAF (Web Application Firewall)**
Bypass: WAFs use pattern matching that can be defeated with encoding, case mixing, comment insertion, alternate syntax, chunked transfer encoding, and numerous other documented bypass techniques.

## Rejection Rationalizations and Counter-Arguments

**"We use an ORM so SQL injection is not possible."**
Counter: ORMs that support raw queries, literal expressions, or dynamic query construction are still vulnerable. Document the specific raw query usage and demonstrate the injection path.

**"The input is validated before reaching the query."**
Counter: Verify the validation is comprehensive, server-side, and cannot be bypassed. Check for encoding bypasses, type confusion, and alternate input paths that skip validation.

**"Command injection requires shell metacharacters, and we sanitize those."**
Counter: Deny-list approaches are incomplete. Show which characters or patterns bypass the filter. Also check for indirect command injection via filenames, environment variables, or configuration values.

**"This is a NoSQL database so SQL injection does not apply."**
Counter: NoSQL databases have their own injection vectors. MongoDB operator injection, JavaScript execution in $where clauses, and query object manipulation are all documented attack vectors.

## Chaining Opportunities

- **SQL Injection + File Read/Write**: SQLi can read files (LOAD_FILE), write files (INTO OUTFILE), or execute OS commands (xp_cmdshell, UDF) depending on the database and privileges.
- **Command Injection + Lateral Movement**: OS command execution provides a foothold for pivoting to internal systems, reading configuration files, and exfiltrating data.
- **SSTI + RCE**: Template injection in most frameworks provides a direct path to arbitrary code execution through template engine internals.
- **Header Injection + XSS**: CRLF injection in response headers can inject arbitrary headers including crafted Set-Cookie or Content-Type headers, or inject an entire response body containing JavaScript.
- **Log Injection + Log Forgery**: Injecting crafted log entries can hide attack evidence, frame other users, or exploit log processing tools that parse log content.
