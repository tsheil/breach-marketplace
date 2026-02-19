---
name: hackerone
description: Navigate HackerOne bug bounty platform via API. Use when working with HackerOne for (1) researching bug bounty programs - scope, rewards, policies, weaknesses; (2) viewing submitted vulnerability reports and their status; (3) checking account info - balance, earnings, payouts; (4) browsing hacktivity - public disclosures filtered by severity, program, CWE; (5) checking if a finding is a duplicate before reporting; (6) monitoring report triage status and program response times.
---

# HackerOne

Interact with HackerOne's Hacker API via `scripts/h1api.py`. Source credentials before use:

```bash
source .env  # must set HACKERONE_API_USERNAME and HACKERONE_API_TOKEN
```

## Quick Reference

| Task | Command |
|------|---------|
| Program info | `h1api.py /hackers/programs/{handle} --format table` |
| Program scope | `h1api.py /hackers/programs/{handle}/structured_scopes --format table` |
| My reports | `h1api.py /hackers/me/reports --format table` |
| Report details | `h1api.py /hackers/reports/{id} --format table` |
| Recent hacktivity | `h1api.py /hackers/hacktivity --format table --page 1 --size 25` |
| Disclosed reports | `h1api.py /hackers/hacktivity --scan-pages 10 --disclosed-only` |
| Top bounties | `h1api.py /hackers/hacktivity --scan-pages 10 --min-bounty 1000` |
| Balance | `h1api.py /hackers/payments/balance --format table` |

All commands use `python3 scripts/h1api.py` from the skill directory.

For full endpoint docs, see [references/api_reference.md](references/api_reference.md).

## Output Formats

- `--format table` — human-readable, auto-detects endpoint type
- `--format json` (default) — raw JSON for piping to scripts

## Hacktivity as Intelligence Source

Disclosed hacktivity reports are a high-value intel source for bug bounty hunting. Use them to:

- **Learn what pays** — see which vuln classes and severity levels earn bounties on your target program
- **Study winning report style** — read disclosed reports to understand what triagers expect
- **Seed variant analysis** — a disclosed XSS in one program reveals a pattern to hunt in others
- **Spot trends** — batch disclosures (e.g. Node.js CVE drops) signal patched areas ripe for variant hunting in downstream consumers
- **Dedup before reporting** — check if your finding matches a recently resolved report

The feed is sorted by most recent activity. Most reports are undisclosed (limited metadata visible). Disclosed reports include title, severity, CWE, CVE, and URL.

### Multi-Page Scan (preferred)

```bash
# Disclosed reports across 10 pages (~250 items)
h1api.py /hackers/hacktivity --scan-pages 10 --disclosed-only

# High-value bounties
h1api.py /hackers/hacktivity --scan-pages 10 --min-bounty 1000

# Combine filters
h1api.py /hackers/hacktivity --scan-pages 20 --disclosed-only --min-bounty 500
```

### Query Filters (unreliable)

Lucene syntax via `--query-string`. The `team:` filter often returns unfiltered results. Prefer `--scan-pages` with `--disclosed-only` / `--min-bounty` for reliable filtering.

```bash
h1api.py /hackers/hacktivity --query-string "cwe:CWE-79" --format table
h1api.py /hackers/hacktivity --query-string "reporter:username" --format table
```

## Report Details

`--format table` extracts CVSS score, attack vector, CWE from relationships, bounty amounts, CVE IDs, and shows activity timeline:

```bash
h1api.py /hackers/reports/3473882 --format table
```

## API Notes

- Rate limits: 600 reads/min, 25 writes/20s
- Pagination: `--page N --size N` (max size 100)
- Generate API tokens at: HackerOne Settings > API Token

## Program Handle Discovery

Program handles differ from display names. "Acme Corporation" may have handle `acme` or `acme_corp`. To find a program's handle:

```bash
# Search your enrolled programs for the handle
h1api.py /hackers/programs --format table | grep -i "acme"

# Once you have the handle, use --team for filtering
h1api.py /hackers/hacktivity --scan-pages 10 --team acme --format table
```

The `--team` flag performs client-side filtering by program handle on scan results. It's reliable unlike the API's `team:` Lucene query which often returns unfiltered results.

