# hackerone

HackerOne bug bounty platform integration for [Claude Code](https://docs.anthropic.com/en/docs/claude-code). Navigate programs, reports, hacktivity, and earnings via the HackerOne Hacker API.

## Requirements

- Python 3
- HackerOne API credentials (username + API token)

## Installation

```
/plugin install hackerone@breach-marketplace
```

## Setup

Create a `.env` file in the plugin skill directory with your HackerOne credentials:

```bash
export HACKERONE_API_USERNAME="your_username"
export HACKERONE_API_TOKEN="your_api_token"
```

Generate an API token at: HackerOne Settings > API Token.

## Skill Commands

| Command | Purpose |
|---------|---------|
| `/hackerone` | Navigate HackerOne platform -- program research, report management, hacktivity intelligence, balance and earnings |

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

## Hacktivity Scanning

Disclosed hacktivity reports are a high-value intelligence source. Use multi-page scanning for reliable filtering:

```bash
# Disclosed reports across 10 pages (~250 items)
h1api.py /hackers/hacktivity --scan-pages 10 --disclosed-only

# High-value bounties
h1api.py /hackers/hacktivity --scan-pages 10 --min-bounty 1000

# Filter by program handle
h1api.py /hackers/hacktivity --scan-pages 10 --team acme --format table
```

## API Notes

- Rate limits: 600 reads/min, 25 writes/20s
- Pagination: `--page N --size N` (max size 100)
- Output formats: `--format table` (human-readable) or `--format json` (raw)

## Reference Material

| Resource | Path |
|----------|------|
| API reference | [skills/hackerone/references/api_reference.md](skills/hackerone/references/api_reference.md) |
| Python wrapper | [skills/hackerone/scripts/h1api.py](skills/hackerone/scripts/h1api.py) |

## License

Apache-2.0. See [LICENSE](LICENSE).
