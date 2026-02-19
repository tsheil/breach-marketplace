# HackerOne API Reference

## Table of Contents

1. [Authentication](#authentication)
2. [Programs](#programs)
3. [Reports](#reports)
4. [Hacktivity](#hacktivity)
5. [Earnings & Payments](#earnings--payments)
6. [Report Intents (Drafts)](#report-intents-drafts)
7. [Error Handling](#error-handling)
8. [Rate Limits](#rate-limits)

---

## Authentication

Base URL: `https://api.hackerone.com/v1`

Use HTTP Basic Auth with API token credentials:

```bash
curl "https://api.hackerone.com/v1/hackers/me/reports" \
  -u "$HACKERONE_API_USERNAME:$HACKERONE_API_TOKEN"
```

Generate tokens at: Settings > API Token

---

## Programs

### List All Programs

```bash
GET /hackers/programs
```

Parameters:
- `page[number]` - Page number (default: 1)
- `page[size]` - Items per page (default: 25, max: 100)

Response includes: handle, name, currency, policy, submission_state

### Get Program Details

```bash
GET /hackers/programs/{handle}
```

Returns full program info including relationships to structured scopes.

### Get Program Scope

```bash
GET /hackers/programs/{handle}/structured_scopes
```

Parameters:
- `filter[id__gt]` - Filter by ID greater than
- `filter[created_at__gt]` - Filter by creation date
- `filter[updated_at__gt]` - Filter by update date
- Pagination parameters

Returns asset identifiers, types (url, cidr, app_store_app, etc.), and eligibility.

### Get Program Weaknesses

```bash
GET /hackers/programs/{handle}/weaknesses
```

Returns applicable CWE types for the program.

---

## Reports

### List Your Reports

```bash
GET /hackers/me/reports
```

Parameters:
- `page[number]` - Page number
- `page[size]` - Items per page

Returns your submitted reports with state, title, and metadata.

### Get Single Report

```bash
GET /hackers/reports/{id}
```

Returns full report details:
- Title, vulnerability_information, impact
- State (new, triaged, resolved, etc.)
- Bounties awarded
- Severity rating and CVSS
- Activity timeline
- Reporter and program info

---

## Hacktivity

### Query Public Disclosures

```bash
GET /hackers/hacktivity
```

Supports Lucene query syntax for filtering:

| Field | Example |
|-------|---------|
| `severity_rating` | `severity_rating:critical` |
| `asset_type` | `asset_type:URL` |
| `substate` | `substate:resolved` |
| `cwe` | `cwe:CWE-79` |
| `cve_ids` | `cve_ids:CVE-2024-1234` |
| `reporter` | `reporter:username` |
| `team` | `team:hackerone` |
| `disclosed_at` | `disclosed_at:[2024-01-01 TO *]` |

Example:
```bash
GET /hackers/hacktivity?query_string=severity_rating:critical%20AND%20team:shopify
```

---

## Earnings & Payments

### Get Balance

```bash
GET /hackers/payments/balance
```

Returns current account balance.

### List Earnings

```bash
GET /hackers/payments/earnings
```

Returns earning records linked to bounties and programs.

### List Payouts

```bash
GET /hackers/payments/payouts
```

Returns payout history with amounts, payment providers, and status.

---

## Report Intents (Drafts)

### List Drafts

```bash
GET /hackers/report_intents
```

### Create Draft

```bash
POST /hackers/report_intents
```

Body:
```json
{
  "data": {
    "type": "report-intent",
    "attributes": {
      "team_handle": "program-handle",
      "description": "Initial vulnerability description"
    }
  }
}
```

### Get/Update/Delete Draft

```bash
GET /hackers/report_intents/{id}
PATCH /hackers/report_intents/{id}
DELETE /hackers/report_intents/{id}
```

### Manage Attachments

```bash
GET /hackers/report_intents/{id}/attachments
POST /hackers/report_intents/{id}/attachments  # multipart form with files[]
DELETE /hackers/report_intents/{id}/attachments/{attachment_id}
```

---

## Error Handling

| Code | Meaning |
|------|---------|
| 400 | Invalid request format |
| 401 | Missing/invalid credentials |
| 403 | Insufficient permissions |
| 404 | Resource not found |
| 429 | Rate limit exceeded |
| 500 | Server error |
| 503 | Service unavailable |

---

## Rate Limits

- **Read operations**: 600 requests/minute
- **Write operations**: 25 requests/20 seconds

On 429 response, check `Retry-After` header.
