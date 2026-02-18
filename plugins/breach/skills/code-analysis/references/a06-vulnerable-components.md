# A06: Vulnerable and Outdated Components

This category covers the use of software components (libraries, frameworks, runtime environments, and other dependencies) with known vulnerabilities. Applications inherit every vulnerability present in their dependency tree, including transitive dependencies the development team may not even be aware of.

## Key Patterns to Search For

Search for these patterns to identify potentially vulnerable components:

- **Package Manifests**: `package.json`, `package-lock.json`, `yarn.lock`, `requirements.txt`, `Pipfile.lock`, `Gemfile.lock`, `pom.xml`, `build.gradle`, `go.mod`, `go.sum`, `Cargo.lock`, `composer.lock`, `*.csproj`, `packages.config`
- **Known Vulnerable Libraries**: Check versions of commonly vulnerable packages: `lodash` (< 4.17.21), `jQuery` (< 3.5.0), `moment` (deprecated), `minimist`, `node-fetch`, `express` (old versions), `Spring Framework`, `Apache Struts`, `Apache Log4j`, `Jackson-databind`
- **Docker Base Images**: `Dockerfile`, `FROM` directives referencing outdated or oversized base images (`ubuntu:18.04`, `node:14`, `python:3.6`), images without version pinning (`FROM node:latest`)
- **Deprecated APIs**: Usage of deprecated functions or libraries that have been superseded by secure alternatives
- **Version Pinning**: Look for unpinned dependencies (`*`, `latest`, `>=`), loose version constraints (`^`, `~`), and missing lock files
- **Client-Side Libraries**: Script tags loading outdated CDN-hosted libraries, embedded JavaScript libraries without version tracking
- **Framework Version Detection**: Version strings in comments, HTTP headers (`X-Powered-By`, `Server`), and framework-specific files

## Common Vulnerable Patterns

**Outdated Dependency with Known CVE:**
```
# package.json with known vulnerable dependency
{
  "dependencies": {
    "lodash": "4.17.15",     # CVE-2020-8203: prototype pollution
    "axios": "0.18.0",       # Multiple known vulnerabilities
    "tar": "4.4.0",          # CVE-2021-32803: path traversal
    "node-fetch": "2.6.0"    # CVE-2022-0235: credential leak
  }
}
```

**Unpinned Dependencies:**
```
# requirements.txt without version pinning
flask
requests
sqlalchemy
jinja2

# Any future install could pull a compromised version
```

**Outdated Docker Base Image:**
```
# Dockerfile with outdated base
FROM ubuntu:18.04           # EOL, hundreds of unpatched CVEs
FROM node:12-alpine         # EOL Node.js version
FROM python:3.6-slim        # EOL Python version
```

**Embedded Client-Side Libraries:**
```
<!-- Vulnerable jQuery loaded from CDN -->
<script src="https://code.jquery.com/jquery-2.1.4.min.js"></script>
<!-- jQuery < 3.5.0 vulnerable to XSS via HTML manipulation -->
```

**Transitive Dependency Vulnerability:**
```
# Direct dependency is safe, but its dependency is vulnerable
safe-package@1.0.0
  └── vulnerable-sub-dependency@0.1.0  # Known RCE vulnerability
```

## Exploitability Indicators

A vulnerable component finding is exploitable when:

- A public CVE exists with a published proof-of-concept exploit
- The vulnerable code path in the dependency is actually reachable from the application (not just present but unused)
- The vulnerable functionality is exposed to user input or external data
- No compensating controls exist (WAF rules, input validation) that would block the specific exploit
- The vulnerability is in a commonly attacked component (Log4j, Struts, Spring, Jackson) with well-known exploitation techniques
- The component is internet-facing rather than internal-only
- The vulnerability allows remote code execution, authentication bypass, or data exfiltration

## Common Mitigations and Their Bypasses

**Mitigation: Running automated dependency scanning (Dependabot, Snyk)**
Bypass: Verify that the scanner covers all dependency types including transitive dependencies, development dependencies that end up in production, and client-side libraries. Check if scan results are actually acted upon.

**Mitigation: Using the latest version of all dependencies**
Bypass: Latest does not mean secure. Verify that the "latest" version actually patches known vulnerabilities. Also check for zero-day vulnerabilities in current versions.

**Mitigation: Removing unused dependencies from the manifest**
Bypass: Check if the removed dependency is still present in the lock file, still installed in the deployment artifact, or still loaded at runtime. Also check for dependencies bundled in vendor directories.

**Mitigation: WAF rules blocking known exploits**
Bypass: WAF rules are signature-based and can be bypassed with payload variations. New exploits for the same vulnerability may not be covered by existing rules.

**Mitigation: Version pinning to avoid supply chain attacks**
Bypass: Pinning prevents automatic updates but also prevents security patches. Verify that pinned versions are actively maintained and updated when vulnerabilities are discovered.

## Rejection Rationalizations and Counter-Arguments

**"We do not use the vulnerable function in that library."**
Counter: Verify this claim by tracing all code paths that use the library. Transitive usage through other dependencies may invoke the vulnerable function. Also consider that future code changes could begin using the vulnerable path.

**"This is only a development dependency."**
Counter: Verify that development dependencies are not included in the production build. Many build processes include devDependencies. Also, some "dev" tools run in CI/CD pipelines where a vulnerability could enable supply chain attacks.

**"We are behind a WAF that blocks this exploit."**
Counter: WAF bypass techniques exist for most known exploits. Defense in depth requires patching the underlying vulnerability, not relying solely on edge-layer protection.

**"Upgrading would break our application."**
Counter: A breaking upgrade that requires development effort is preferable to a known exploitable vulnerability. Document the specific CVE, its CVSS score, and the availability of public exploits to justify the upgrade effort.

## Chaining Opportunities

- **Vulnerable Library + Application Feature = RCE**: A deserialization vulnerability in Jackson-databind combined with an endpoint that accepts JSON input provides a direct path to code execution.
- **Outdated Framework + Known Exploit = Initial Access**: Publicly known exploits for outdated frameworks (Struts, Spring, Rails) provide reliable initial access.
- **Vulnerable Dependency + Supply Chain Attack**: A dependency with a known vulnerability that has been "patched" with a malicious version (dependency confusion, typosquatting) can introduce backdoors.
- **Client-Side Library Vulnerability + XSS**: An outdated jQuery with known XSS gadgets can be leveraged to build XSS payloads even when the application itself escapes output correctly.
- **Outdated TLS Library + Network Position = Data Interception**: Outdated TLS implementations vulnerable to POODLE, BEAST, or similar attacks enable traffic interception.
