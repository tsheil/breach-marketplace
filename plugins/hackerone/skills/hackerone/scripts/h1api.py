#!/usr/bin/env python3
"""
HackerOne API Client

A wrapper for the HackerOne Hacker API with formatted output support.

Usage:
    python3 h1api.py <endpoint> [--query KEY=VALUE ...] [--page N] [--size N] [--format table|json]

Examples:
    python3 h1api.py /hackers/hacktivity --format table
    python3 h1api.py /hackers/hacktivity --query-string "disclosed:true" --format table
    python3 h1api.py /hackers/hacktivity --query-string "severity_rating:critical"
    python3 h1api.py /hackers/programs
    python3 h1api.py /hackers/programs/shopify --format table
    python3 h1api.py /hackers/programs/shopify/structured_scopes --format table
    python3 h1api.py /hackers/me/reports --format table
    python3 h1api.py /hackers/reports/12345
    python3 h1api.py /hackers/payments/balance
    python3 h1api.py /hackers/payments/earnings --format table

Environment variables:
    HACKERONE_API_USERNAME - API token identifier
    HACKERONE_API_TOKEN    - API token value
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.parse
import base64


BASE_URL = "https://api.hackerone.com/v1"


def get_credentials():
    """Get API credentials from environment variables."""
    username = os.environ.get("HACKERONE_API_USERNAME")
    token = os.environ.get("HACKERONE_API_TOKEN")

    if not username or not token:
        print("Error: Set HACKERONE_API_USERNAME and HACKERONE_API_TOKEN environment variables", file=sys.stderr)
        print("\nGenerate an API token at: https://hackerone.com/settings/api_token/edit", file=sys.stderr)
        sys.exit(1)

    return username, token


def make_request(endpoint, params=None):
    """Make authenticated request to HackerOne API."""
    username, token = get_credentials()

    url = f"{BASE_URL}{endpoint}"
    if params:
        url += "?" + urllib.parse.urlencode(params)

    # Create Basic Auth header
    credentials = f"{username}:{token}"
    encoded = base64.b64encode(credentials.encode()).decode()

    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Basic {encoded}")
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else ""
        print(f"HTTP {e.code}: {e.reason}", file=sys.stderr)
        if error_body:
            try:
                print(json.dumps(json.loads(error_body), indent=2), file=sys.stderr)
            except json.JSONDecodeError:
                print(error_body, file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Network error: {e.reason}", file=sys.stderr)
        sys.exit(1)


# --- Formatters ---

def format_hacktivity(data):
    """Format hacktivity items as a readable table."""
    items = data.get("data", [])
    if not items:
        print("No hacktivity items found.")
        return

    disclosed = [i for i in items if i["attributes"].get("disclosed")]
    with_bounty = [i for i in items if i["attributes"].get("total_awarded_amount")]
    print(f"Items: {len(items)} | Disclosed: {len(disclosed)} | With bounty: {len(with_bounty)}\n")

    for item in items:
        a = item["attributes"]
        r = item["relationships"]
        reporter = r.get("reporter", {}).get("data", {}).get("attributes", {}).get("username", "?")
        program = r.get("program", {}).get("data", {}).get("attributes", {}).get("handle", "?")
        title = a.get("title") or "(undisclosed)"
        severity = (a.get("severity_rating") or "-").upper()
        bounty = a.get("total_awarded_amount") or 0
        action = (a.get("latest_disclosable_action") or "").split("::")[-1]
        activity_date = (a.get("latest_disclosable_activity_at") or "")[:10]
        submitted = (a.get("submitted_at") or "")[:10]
        disclosed_at = (a.get("disclosed_at") or "")[:10]
        url = a.get("url") or ""
        cwe = a.get("cwe") or "-"
        cve_ids = a.get("cve_ids") or []
        visibility = "PUBLIC" if a.get("disclosed") else "PRIVATE"

        bounty_str = f"${bounty}" if bounty else "no bounty"
        print(f"[{visibility}] [{severity}] {bounty_str} | {program} | {action} {activity_date}")
        print(f"  {title}")
        print(f"  Reporter: {reporter} | Submitted: {submitted}", end="")
        if cwe != "-":
            print(f" | CWE: {cwe}", end="")
        if cve_ids:
            print(f" | CVE: {', '.join(cve_ids)}", end="")
        if disclosed_at:
            print(f" | Disclosed: {disclosed_at}", end="")
        print()
        if url:
            print(f"  {url}")
        print()


def format_programs(data):
    """Format program list as a readable table."""
    items = data.get("data", [])
    if not items:
        print("No programs found.")
        return

    print(f"Programs: {len(items)}\n")
    for item in items:
        a = item.get("attributes", {})
        handle = a.get("handle", "?")
        name = a.get("name", "?")
        state = a.get("submission_state", "?")
        print(f"  {handle:<30} | {name} | {state}")


def format_program_detail(data):
    """Format single program details."""
    item = data.get("data", data)
    a = item.get("attributes", {})
    handle = a.get("handle", "?")
    name = a.get("name", "?")
    state = a.get("submission_state", "?")
    policy = a.get("policy", "")

    print(f"Program: {name} ({handle})")
    print(f"State: {state}")
    if policy:
        print(f"\nPolicy:\n{policy[:2000]}")
        if len(policy) > 2000:
            print(f"\n... (truncated, {len(policy)} chars total)")


def format_scopes(data):
    """Format structured scopes as a readable table."""
    items = data.get("data", [])
    if not items:
        print("No scopes found.")
        return

    print(f"Scopes: {len(items)}\n")
    for item in items:
        a = item.get("attributes", {})
        asset = a.get("asset_identifier", "?")
        asset_type = a.get("asset_type", "?")
        eligible = a.get("eligible_for_bounty", False)
        eligible_str = "BOUNTY" if eligible else "no bounty"
        instruction = a.get("instruction") or ""
        max_severity = a.get("max_severity") or "-"
        print(f"  [{eligible_str}] [{max_severity}] {asset_type}: {asset}")
        if instruction:
            print(f"    {instruction[:200]}")


def format_reports(data):
    """Format report list as a readable table."""
    items = data.get("data", [])
    if not items:
        print("No reports found.")
        return

    print(f"Reports: {len(items)}\n")
    for item in items:
        a = item.get("attributes", {})
        r = item.get("relationships", {})
        title = a.get("title", "(no title)")
        state = a.get("state", "?")
        created = (a.get("created_at") or "")[:10]
        severity = a.get("severity_rating") or "-"
        bounty = a.get("total_awarded_amount") or 0
        program = r.get("program", {}).get("data", {}).get("attributes", {}).get("handle", "?")
        report_id = item.get("id", "?")

        bounty_str = f"${bounty}" if bounty else "-"
        print(f"  #{report_id} [{state}] [{severity}] {bounty_str} | {program}")
        print(f"    {title}")
        print(f"    Created: {created}")
        print()


def format_report_detail(data):
    """Format single report details with full relationship data."""
    item = data.get("data", data)
    a = item.get("attributes", {})
    r = item.get("relationships", {})
    title = a.get("title", "(no title)")
    state = a.get("state", "?")
    created = (a.get("created_at") or "")[:10]
    closed = (a.get("closed_at") or "")[:10]
    disclosed = (a.get("disclosed_at") or "")[:10]
    cve_ids = a.get("cve_ids") or []
    vuln_info = a.get("vulnerability_information") or ""
    impact = a.get("impact") or ""
    program = r.get("program", {}).get("data", {}).get("attributes", {}).get("handle", "?")
    reporter = r.get("reporter", {}).get("data", {}).get("attributes", {}).get("username", "?")
    report_id = item.get("id", "?")

    # Extract severity from relationships
    sev_data = r.get("severity", {}).get("data", {}).get("attributes", {})
    severity_rating = sev_data.get("rating") or a.get("severity_rating") or "-"
    cvss_score = sev_data.get("score")
    attack_vector = sev_data.get("attack_vector")
    attack_complexity = sev_data.get("attack_complexity")

    # Extract weakness from relationships
    weakness_data = r.get("weakness", {}).get("data", {}).get("attributes", {})
    weakness_name = weakness_data.get("name") or ""
    weakness_id = r.get("weakness", {}).get("data", {}).get("id") or ""

    # Extract bounties
    bounties = r.get("bounties", {}).get("data", [])
    total_bounty = sum(float(b.get("attributes", {}).get("amount", 0) or 0) for b in bounties)

    print(f"Report #{report_id}: {title}")
    print(f"Program: {program} | Reporter: {reporter} | State: {state}")

    sev_line = f"Severity: {severity_rating.upper()}"
    if cvss_score:
        sev_line += f" (CVSS {cvss_score})"
    if attack_vector:
        sev_line += f" | AV: {attack_vector} | AC: {attack_complexity}"
    print(sev_line)

    if weakness_name:
        cwe_str = f"CWE-{weakness_id}" if weakness_id else ""
        print(f"Weakness: {weakness_name} {cwe_str}")

    dates_line = f"Created: {created}"
    if closed:
        dates_line += f" | Closed: {closed}"
    if disclosed:
        dates_line += f" | Disclosed: {disclosed}"
    print(dates_line)

    if cve_ids:
        print(f"CVE: {', '.join(cve_ids)}")
    if total_bounty:
        print(f"Bounty: ${total_bounty}")

    if vuln_info:
        print(f"\n--- Vulnerability Information ---\n{vuln_info[:3000]}")
        if len(vuln_info) > 3000:
            print(f"\n... (truncated, {len(vuln_info)} chars total)")
    if impact:
        print(f"\n--- Impact ---\n{impact[:1000]}")

    # Show activity summary
    activities = r.get("activities", {}).get("data", [])
    if activities:
        print(f"\n--- Activity Timeline ({len(activities)} events) ---")
        for act in activities[:20]:
            act_type = act.get("type", "?").replace("activity-", "")
            act_attrs = act.get("attributes", {})
            act_date = (act_attrs.get("created_at") or "")[:16].replace("T", " ")
            message = act_attrs.get("message") or ""
            actor = act.get("relationships", {}).get("actor", {}).get("data", {}).get("attributes", {}).get("username", "")
            line = f"  [{act_date}] {act_type}"
            if actor:
                line += f" by {actor}"
            print(line)
            if message:
                preview = message[:200].replace("\n", " ")
                print(f"    {preview}")
        if len(activities) > 20:
            print(f"  ... and {len(activities) - 20} more events")


def format_earnings(data):
    """Format earnings/balance/payouts data."""
    # Balance endpoint returns a single object
    if "data" in data and isinstance(data["data"], list):
        items = data["data"]
        print(f"Items: {len(items)}\n")
        for item in items:
            a = item.get("attributes", {})
            amount = a.get("amount") or a.get("total_amount") or "?"
            currency = a.get("currency") or ""
            date = (a.get("created_at") or a.get("paid_out_at") or "")[:10]
            status = a.get("status") or ""
            print(f"  {amount} {currency} | {date} | {status}")
    else:
        # Single object (balance)
        a = data.get("data", {}).get("attributes", data.get("data", {}))
        if isinstance(a, dict):
            for key, value in a.items():
                if key != "type":
                    print(f"  {key}: {value}")
        else:
            print(json.dumps(data, indent=2))


def detect_and_format(endpoint, data):
    """Auto-detect endpoint type and format accordingly."""
    ep = endpoint.rstrip("/")

    if "/hacktivity" in ep:
        format_hacktivity(data)
    elif "/structured_scopes" in ep:
        format_scopes(data)
    elif "/weaknesses" in ep:
        print(json.dumps(data, indent=2))
    elif ep.endswith("/reports") or "/me/reports" in ep:
        format_reports(data)
    elif "/reports/" in ep:
        format_report_detail(data)
    elif "/programs" == ep.split("?")[0].replace("/hackers", "") or ep.endswith("/programs"):
        format_programs(data)
    elif "/programs/" in ep and "/structured_scopes" not in ep and "/weaknesses" not in ep:
        format_program_detail(data)
    elif "/balance" in ep or "/earnings" in ep or "/payouts" in ep:
        format_earnings(data)
    else:
        print(json.dumps(data, indent=2))


def scan_hacktivity(params, max_pages=10, disclosed_only=False, min_bounty=0, team_filter=""):
    """Scan multiple pages of hacktivity and aggregate results."""
    all_items = []
    for page in range(1, max_pages + 1):
        p = dict(params)
        p["page[number]"] = page
        if "page[size]" not in p:
            p["page[size]"] = 25
        try:
            data = make_request("/hackers/hacktivity", p)
        except SystemExit:
            break
        items = data.get("data", [])
        if not items:
            break
        all_items.extend(items)
        print(f"  Scanned page {page}: {len(items)} items", file=sys.stderr)

    # Filter
    filtered = all_items
    if disclosed_only:
        filtered = [i for i in filtered if i["attributes"].get("disclosed")]
    if min_bounty > 0:
        filtered = [i for i in filtered if (i["attributes"].get("total_awarded_amount") or 0) >= min_bounty]
    if team_filter:
        team_lower = team_filter.lower()
        filtered = [i for i in filtered if
                    i.get("relationships", {}).get("program", {}).get("data", {}).get("attributes", {}).get("handle", "").lower() == team_lower]

    print(f"\nScanned {len(all_items)} items across {min(max_pages, len(all_items) // 25 + 1)} pages")
    print(f"Matching: {len(filtered)} items\n")

    format_hacktivity({"data": filtered})


def main():
    parser = argparse.ArgumentParser(description="HackerOne API Client")
    parser.add_argument("endpoint", help="API endpoint (e.g., /hackers/programs)")
    parser.add_argument("--query", "-q", action="append", default=[],
                        help="Query parameters as KEY=VALUE (can repeat)")
    parser.add_argument("--page", "-p", type=int, help="Page number")
    parser.add_argument("--size", "-s", type=int, help="Page size")
    parser.add_argument("--query-string", help="Lucene query string for hacktivity")
    parser.add_argument("--format", "-f", choices=["json", "table"], default="json",
                        help="Output format: json (raw) or table (formatted)")
    parser.add_argument("--scan-pages", type=int, default=0,
                        help="Scan N pages of hacktivity (use with /hackers/hacktivity)")
    parser.add_argument("--disclosed-only", action="store_true",
                        help="Filter to only disclosed reports (use with --scan-pages)")
    parser.add_argument("--min-bounty", type=float, default=0,
                        help="Filter to reports with bounty >= N (use with --scan-pages)")
    parser.add_argument("--team", type=str, default="",
                        help="Filter to a specific program handle (use with --scan-pages)")

    args = parser.parse_args()

    # Build params
    params = {}

    for q in args.query:
        if "=" in q:
            key, value = q.split("=", 1)
            params[key] = value

    if args.page:
        params["page[number]"] = args.page
    if args.size:
        params["page[size]"] = args.size
    if args.query_string:
        params["query_string"] = args.query_string

    # Multi-page scan mode for hacktivity
    if args.scan_pages > 0 and "/hacktivity" in args.endpoint:
        scan_hacktivity(params, max_pages=args.scan_pages,
                        disclosed_only=args.disclosed_only,
                        min_bounty=args.min_bounty,
                        team_filter=args.team)
        return

    # Make request
    result = make_request(args.endpoint, params if params else None)

    # Output
    if args.format == "table":
        detect_and_format(args.endpoint, result)
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
