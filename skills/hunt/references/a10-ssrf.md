# A10: Server-Side Request Forgery (SSRF)

Server-Side Request Forgery occurs when an application makes HTTP requests (or other protocol requests) to a destination controlled by the attacker. The server acts as a proxy, allowing the attacker to reach internal services, cloud metadata endpoints, and other resources that are not directly accessible from the internet.

## Key Patterns to Search For

Search for these patterns to identify potential SSRF vulnerabilities:

- **URL Parameters in Server Requests**: `url=`, `uri=`, `path=`, `dest=`, `redirect=`, `site=`, `html=`, `feed=`, `to=`, `out=`, `domain=`, `callback=`, `return=`, `page=`, `next=`, `data=`, `reference=`, `host=`, `link=`, `img=`, `src=`
- **HTTP Client Libraries**: `requests.get(`, `urllib.urlopen(`, `http.get(`, `fetch(`, `HttpClient`, `curl_exec(`, `file_get_contents(`, `fopen(`, `RestTemplate`, `WebClient`, `OkHttpClient`, `axios.get(`
- **Webhook Functionality**: `/webhooks/`, `webhook_url`, `callback_url`, `notification_url`, `postback_url`, endpoints accepting URLs for server-side callbacks
- **File Fetching from URL**: Import from URL, fetch avatar from URL, download file from URL, URL preview/unfurling, image proxy, PDF generation from URL
- **URL Parsing**: `urllib.parse`, `URL()`, `URI()`, `new URL(`, `parse_url(`, URL validation functions (check for inconsistent parsing)
- **DNS Resolution**: Custom DNS resolution, DNS rebinding potential, `getaddrinfo`, `dns.resolve`
- **Internal Service Indicators**: References to internal hostnames, `localhost`, `127.0.0.1`, `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`, `169.254.169.254`, `metadata.google.internal`

## Common Vulnerable Patterns

**Direct SSRF via URL Parameter:**
```
# Vulnerable: user-controlled URL passed to server-side HTTP request
@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    response = requests.get(url)
    return response.content

# Attacker: /proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**SSRF via Webhook URL:**
```
# Vulnerable: user registers webhook URL, server makes POST request
def register_webhook(user_id, webhook_url):
    # No validation of webhook_url target
    save_webhook(user_id, webhook_url)

def trigger_webhook(event, webhook_url):
    requests.post(webhook_url, json=event)
    # Attacker registers: http://169.254.169.254/latest/meta-data/
```

**SSRF via Image/File Fetch:**
```
# Vulnerable: avatar URL fetched server-side
def set_avatar(user_id, avatar_url):
    image_data = requests.get(avatar_url).content
    save_avatar(user_id, image_data)

# Attacker: avatar_url = "http://internal-admin-panel:8080/api/users"
```

**SSRF via PDF Generation:**
```
# Vulnerable: HTML-to-PDF with user-controlled content
def generate_report(html_content):
    # HTML may contain: <img src="http://169.254.169.254/latest/meta-data/">
    # Or: <iframe src="http://internal-service/admin">
    pdf = html_to_pdf(html_content)
    return pdf
```

**Blind SSRF (No Response Returned):**
```
# Vulnerable: server makes request but does not return response
def validate_url(url):
    try:
        response = requests.head(url, timeout=5)
        return response.status_code == 200
    except:
        return False

# Attacker cannot see response but server still makes the request
# Detectable via timing, DNS interaction, or out-of-band channels
```

## Exploitability Indicators

An SSRF finding is exploitable when:

- User-controlled input (URL, hostname, IP) is used in a server-side HTTP request
- The server has network access to internal services, cloud metadata, or other restricted resources
- URL validation is absent or uses a deny-list approach (bypassable)
- The application runs in a cloud environment with metadata services accessible at `169.254.169.254`
- Internal services accessible from the server do not require authentication (common for service-to-service communication)
- The response from the server-side request is returned to the user (full SSRF, maximum impact)
- Even without response (blind SSRF), the server can be used to scan internal ports, interact with internal services, or exfiltrate data via DNS

## Common Mitigations and Their Bypasses

**Mitigation: Deny-list of internal IP ranges (127.0.0.1, 10.0.0.0/8, etc.)**
Bypass techniques:
- Decimal IP encoding: `http://2130706433` (127.0.0.1 as a 32-bit integer)
- Octal encoding: `http://0177.0.0.1` (127.0.0.1)
- Hex encoding: `http://0x7f000001` (127.0.0.1)
- IPv6 representations: `http://[::1]`, `http://[0:0:0:0:0:ffff:127.0.0.1]`
- DNS rebinding: Register a domain that resolves to 127.0.0.1
- URL shorteners and redirect services that resolve to internal IPs
- Enclosed alphanumeric: `http://127.0.0.1` using Unicode characters that normalize to digits

**Mitigation: Allow-list of permitted domains**
Bypass techniques:
- Open redirect on a whitelisted domain: `https://allowed-domain.com/redirect?url=http://169.254.169.254`
- Subdomain of whitelisted domain: If `*.allowed-domain.com` is permitted, register `evil.allowed-domain.com` via subdomain takeover
- URL parser inconsistencies: `http://allowed-domain.com@evil.com`, `http://evil.com#allowed-domain.com`
- DNS CNAME: A whitelisted domain with a CNAME pointing to an attacker-controlled domain

**Mitigation: Blocking requests to 169.254.169.254 specifically**
Bypass techniques:
- Alternative metadata endpoints: `http://metadata.google.internal` (GCP), `http://169.254.169.254` with different paths
- IPv6 metadata: `http://[fd00:ec2::254]` (AWS IPv6 metadata)
- DNS rebinding: First resolution returns an allowed IP, second resolution returns 169.254.169.254

**Mitigation: Validating URL scheme (HTTP/HTTPS only)**
Bypass techniques:
- `file:///etc/passwd` if not properly blocked
- `gopher://` for protocol smuggling to internal services
- `dict://` for information gathering
- `tftp://`, `ldap://`, and other protocol handlers depending on the HTTP client

**Mitigation: Resolving DNS before making the request and checking the IP**
Bypass techniques:
- DNS rebinding with short TTL: First resolution passes the check, DNS changes before the actual request
- Time-of-check-time-of-use between DNS resolution and HTTP request

## Rejection Rationalizations and Counter-Arguments

**"This is only blind SSRF; the attacker cannot see the response."**
Counter: Blind SSRF can still scan internal networks (port scanning via timing), interact with internal services that have side effects (Redis, Memcached, internal APIs), exfiltrate data via DNS queries, and access cloud metadata (AWS credentials via IMDSv1 do not require seeing the response if combined with DNS exfiltration).

**"We block internal IP ranges so the server cannot reach internal services."**
Counter: Demonstrate bypass via DNS rebinding, IP encoding tricks, or redirect chains. IP-based blocking is one of the most frequently bypassed SSRF mitigations.

**"The attacker can only reach services that require authentication."**
Counter: Many internal services trust requests from the internal network without authentication. Cloud metadata endpoints require no authentication. Even authenticated services may be vulnerable to CSRF-like attacks via SSRF.

**"This is just a URL preview feature; the impact is limited."**
Counter: URL preview features provide full SSRF: the server fetches any URL and typically returns at least the page title, description, and images. This is sufficient to exfiltrate data from internal services and cloud metadata.

## Chaining Opportunities

- **SSRF + Cloud Metadata = Full Infrastructure Compromise**: Accessing `169.254.169.254` on AWS retrieves IAM credentials that may grant access to S3 buckets, databases, and other cloud resources. This is one of the most impactful SSRF chains.
- **SSRF + Internal Service Access = Lateral Movement**: Reaching internal services (Redis, Elasticsearch, internal APIs, admin panels) enables further exploitation of those services from a trusted network position.
- **SSRF + Redis/Memcached = RCE**: Using gopher:// or direct TCP via SSRF to send commands to Redis or Memcached can write cron jobs, SSH keys, or web shells.
- **Blind SSRF + DNS Exfiltration = Data Theft**: Even without seeing the response, data can be exfiltrated by embedding it in DNS queries to an attacker-controlled domain.
- **SSRF + Open Redirect = Filter Bypass**: An open redirect on an allowed domain can redirect the server-side request to any target, bypassing domain-based SSRF filters.
- **SSRF + Internal Admin Panel = Privilege Escalation**: Accessing admin interfaces that are only available from the internal network, executing admin operations through the SSRF proxy.
