# CVSS v3.1 Scoring Reference

Use this reference when calculating CVSS scores for each finding. Walk through every base metric — do not skip any. The vector string and numeric score must be consistent with each other and verifiable in any standard CVSS calculator.

## Base Metrics

### Attack Vector (AV)

How the vulnerability is exploited.

| Value | Score | Description |
|-------|-------|-------------|
| Network (N) | 0.85 | Exploitable remotely over the network (e.g., internet-facing web endpoint) |
| Adjacent (A) | 0.62 | Requires access to the local network segment (e.g., same WiFi, VLAN) |
| Local (L) | 0.55 | Requires local system access (e.g., malicious file opened by user) |
| Physical (P) | 0.20 | Requires physical access to the device |

### Attack Complexity (AC)

Conditions beyond the attacker's control that must exist for exploitation.

| Value | Score | Description |
|-------|-------|-------------|
| Low (L) | 0.77 | No special conditions — attack can be performed reliably at will |
| High (H) | 0.44 | Requires specific conditions (race condition, non-default config, MitM position) |

### Privileges Required (PR)

Level of access the attacker needs before exploiting the vulnerability.

| Value | Score (Scope Unchanged) | Score (Scope Changed) | Description |
|-------|------------------------|----------------------|-------------|
| None (N) | 0.85 | 0.85 | No authentication required |
| Low (L) | 0.62 | 0.68 | Requires basic user-level access |
| High (H) | 0.27 | 0.50 | Requires admin or privileged access |

### User Interaction (UI)

Whether a user other than the attacker must participate.

| Value | Score | Description |
|-------|-------|-------------|
| None (N) | 0.85 | No user action required — fully autonomous exploitation |
| Required (R) | 0.62 | A user must perform an action (click a link, open a file, visit a page) |

### Scope (S)

Whether the vulnerability can affect resources beyond its authorization scope.

| Value | Description |
|-------|-------------|
| Unchanged (U) | Impact is limited to the vulnerable component's scope |
| Changed (C) | Impact extends beyond the vulnerable component (e.g., web app vuln leads to server compromise, sandbox escape) |

### Confidentiality Impact (C)

Impact to the confidentiality of information.

| Value | Score | Description |
|-------|-------|-------------|
| None (N) | 0 | No confidentiality impact |
| Low (L) | 0.22 | Some restricted data disclosed, limited scope |
| High (H) | 0.56 | All data within the component disclosed, or critical data exposed |

### Integrity Impact (I)

Impact to the trustworthiness of information.

| Value | Score | Description |
|-------|-------|-------------|
| None (N) | 0 | No integrity impact |
| Low (L) | 0.22 | Some data can be modified, limited consequences |
| High (H) | 0.56 | All data within the component can be modified, or critical data tampered |

### Availability Impact (A)

Impact to the availability of the affected component.

| Value | Score | Description |
|-------|-------|-------------|
| None (N) | 0 | No availability impact |
| Low (L) | 0.22 | Degraded performance or partial interruption |
| High (H) | 0.56 | Complete denial of service or resource destruction |

## Severity Rating Scale

| Score Range | Severity | Typical Bounty Tier |
|------------|----------|-------------------|
| 9.0 - 10.0 | Critical | Top tier payout |
| 7.0 - 8.9 | High | Second tier payout |
| 4.0 - 6.9 | Medium | Third tier payout |
| 0.1 - 3.9 | Low | Minimum payout or recognition |

## Common Vulnerability Score Benchmarks

Use these as sanity checks. If your calculated score deviates significantly from these benchmarks for the same vulnerability class, re-examine your metric selections.

| Vulnerability Type | Typical Score | Severity | Typical Vector |
|-------------------|--------------|----------|----------------|
| Unauthenticated RCE | 9.8 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Unauthenticated SQLi (data access) | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| Authentication bypass | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| Stored XSS (main application) | 8.1 | High | AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N |
| IDOR on sensitive data | 7.5 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| SSRF to internal services | 7.2 | High | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N |
| CSRF on state-changing action | 6.5 | Medium | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N |
| Reflected XSS | 6.1 | Medium | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
| Information disclosure (sensitive) | 5.3 | Medium | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N |
| Open redirect | 4.7 | Medium | AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N |
| Verbose error messages | 3.7 | Low | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N |

## Scoring Principles

1. **Be honest.** Do not inflate scores to chase larger bounties. Inflated scores damage credibility with security teams and lead to score adjustments, disputes, and reputation loss. An accurate score with strong justification earns more over time than inflated scores.

2. **Use worst realistic case.** Score based on the worst outcome that a competent attacker could realistically achieve, not the worst theoretically possible outcome. If SQL injection could theoretically lead to RCE via `xp_cmdshell` but the database is PostgreSQL, score for data access, not RCE.

3. **Scope changes matter.** If exploiting a vulnerability in one component (e.g., a web application) allows impacting a different component (e.g., the underlying server, a different application, or a different user's session), use Scope: Changed. This is common with XSS (web app vulnerability impacts the user's browser context) and SSRF (web app vulnerability impacts internal services).

4. **When in doubt, score conservatively.** Use the lower score and include a note explaining why the effective severity might be higher given specific environmental factors. This approach builds trust — the security team may upgrade the severity themselves based on your reasoning, which is a better outcome than having them downgrade an inflated score.

5. **Document your reasoning.** For each metric selection, be prepared to explain why you chose that value. "PR:N because no authentication is required to access the /api/public/export endpoint" is defensible. "PR:N because it's a web app" is not.

## CVSS v4.0 Notes

Some programs are beginning to adopt CVSS v4.0. Key differences to be aware of:

- **Supplemental Metrics**: v4.0 adds Safety, Automatable, Recovery, Value Density, Vulnerability Response Effort, and Provider Urgency metrics that can refine the score.
- **Threat Metrics**: The Exploit Maturity (E) metric replaces the v3.1 Temporal metrics, with values of Unreported, PoC, Attacked, or Not Defined.
- **Revised Scoring**: The mathematical model is entirely different — do not attempt to convert v3.1 scores to v4.0 by simple mapping.
- **No More Scope**: v4.0 replaces the Scope metric with separate assessment of Vulnerable System and Subsequent System impact.

When a program specifies CVSS v4.0, calculate using the official FIRST v4.0 calculator and note both v3.1 and v4.0 scores for reference during the transition period.
