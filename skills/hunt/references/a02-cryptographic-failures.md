# A02: Cryptographic Failures

Cryptographic failures occur when sensitive data is inadequately protected through weak, misused, or absent cryptographic mechanisms. This category covers everything from using broken algorithms to hardcoding secrets in source code.

## Key Patterns to Search For

Search for these patterns to identify potential cryptographic failures:

- Hash functions: `md5(`, `sha1(`, `MD5.Create`, `hashlib.md5`, `DigestUtils.md5`, `crypto.createHash('md5')`
- Weak ciphers: `DES`, `RC4`, `RC2`, `Blowfish`, `ECB`, `3DES`
- Hardcoded keys or secrets: `secret_key = "`, `api_key = "`, `password = "`, `PRIVATE_KEY`, `encryption_key`
- Hardcoded IVs: `iv = "`, `nonce = "`, `IV = bytes(`
- Weak random generation: `Math.random()`, `rand()`, `random.random()`, `srand(time(`, `java.util.Random`
- Certificate validation: `verify=False`, `InsecureRequestWarning`, `NODE_TLS_REJECT_UNAUTHORIZED`, `CURLOPT_SSL_VERIFYPEER`
- Base64 used as "encryption": `btoa(`, `base64.encode`, `Base64.encode` applied to sensitive data
- Password storage: `bcrypt`, `scrypt`, `argon2`, `PBKDF2`, `password_hash` (check if used correctly or absent)
- Key derivation: `PBKDF2`, `scrypt`, `HKDF` parameters (iteration count, salt usage)

## Common Vulnerable Patterns

**Weak Password Hashing:**
```
# Vulnerable: MD5 without salt
password_hash = md5(password)

# Vulnerable: SHA256 but no salt or iteration
password_hash = sha256(password)

# Should use: bcrypt, scrypt, or argon2 with appropriate work factor
```

**Hardcoded Encryption Keys:**
```
# Vulnerable: key in source code
SECRET_KEY = "my-super-secret-key-12345"
cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
```

**ECB Mode Encryption:**
```
# Vulnerable: ECB mode preserves patterns
cipher = AES.new(key, AES.MODE_ECB)
# Identical plaintext blocks produce identical ciphertext blocks
```

**Weak Random for Security Purposes:**
```
# Vulnerable: predictable token generation
token = str(random.randint(100000, 999999))
reset_token = hashlib.md5(str(time.time()).encode()).hexdigest()
```

**Disabled Certificate Validation:**
```
# Vulnerable: TLS verification disabled
requests.get(url, verify=False)
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
```

## Exploitability Indicators

A cryptographic failure is exploitable when:

- MD5 or SHA1 is used for password storage (rainbow tables and hashcat make cracking trivial)
- Encryption keys are hardcoded in source code (anyone with code access can decrypt all data)
- ECB mode is used for anything other than single-block encryption (pattern leakage is demonstrable)
- Math.random() or equivalent generates security tokens (output is predictable with sufficient samples)
- Certificate validation is disabled in production code (enables man-in-the-middle attacks)
- Password reset tokens use timestamps or sequential values (predictable, enumerable)
- Encryption is applied without authentication (AES-CBC without HMAC enables padding oracle attacks)
- The same key and IV pair is reused across multiple encryptions

## Common Mitigations and Their Bypasses

**Mitigation: Using SHA256 instead of MD5 for passwords**
Bypass: SHA256 is fast and unsuitable for password hashing. GPU-based cracking can test billions of SHA256 hashes per second. Password hashing requires a slow, memory-hard algorithm (bcrypt, scrypt, argon2).

**Mitigation: Encrypting sensitive data at rest**
Bypass: If the encryption key is stored alongside the encrypted data (same database, same config file, same server), compromising the storage gives the attacker both. Check key management practices.

**Mitigation: Using AES-256 encryption**
Bypass: AES-256 with ECB mode, a hardcoded key, or a static IV is broken regardless of the key length. The algorithm is correct but the usage is flawed.

**Mitigation: Generating tokens with UUID**
Bypass: UUIDv1 is time-based and partially predictable. Only UUIDv4 provides sufficient randomness, and even then, verify the underlying random source is cryptographically secure.

**Mitigation: Environment variables for secrets**
Bypass: Verify that .env files are not committed to the repository, that secrets are not logged, and that environment variables are not exposed through debug endpoints or error messages.

## Rejection Rationalizations and Counter-Arguments

**"MD5 is only used for checksums, not security."**
Counter: Verify the actual usage. If MD5 hashes passwords, session tokens, or any security-sensitive value, it is a vulnerability regardless of the developer's stated intent.

**"The encryption key is not in the repository; it is in the environment."**
Counter: Check .env files in the repo, Docker files that set environment variables, CI/CD configs that expose secrets, and documentation that includes example keys. Also verify the key is not logged or exposed through other means.

**"We use HTTPS so data is encrypted in transit."**
Counter: HTTPS protects data in transit but not at rest. Also verify that certificate validation is not disabled, that HSTS is enforced, and that there are no mixed-content issues.

**"This is just an internal service."**
Counter: Internal services are accessed after an initial breach. Weak cryptography on internal services accelerates lateral movement and data exfiltration.

## Chaining Opportunities

- **Hardcoded Key + Data Breach**: If the database is exfiltrated (via SQLi or other means), hardcoded encryption keys allow decrypting all sensitive data.
- **Weak Password Hash + Credential Stuffing**: Cracked password hashes from a database breach enable credential reuse attacks on other services.
- **Predictable Tokens + Account Takeover**: Predictable password reset tokens or session tokens enable direct account takeover without any other vulnerability.
- **Disabled TLS Verification + MITM**: Position on the network (via SSRF, ARP spoofing, or DNS hijacking) combined with disabled certificate validation enables interception of all traffic.
- **Weak Random + CSRF Token Bypass**: If CSRF tokens use predictable random generation, an attacker can predict and include valid tokens in forged requests.
