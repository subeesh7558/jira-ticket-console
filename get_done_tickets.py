#!/usr/bin/env python3
"""Fetch your Done Jira issues and show who resolved each one.

The "Resolved By" column is derived from the ticket's changelog — the author
of the last status transition is compared against your credentials:

  - "You"             — the transition was made by you
  - "Jira Automation" — the author is an app/bot account or has "automation"
                        in its display name
  - "<display name>"  — any other person

Credentials are shared with get_todo_tickets.py via the same config file.
Run `python3 get_done_tickets.py --setup` once if you haven't already.
"""

import argparse
import configparser
import getpass
import os
import re
import stat
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

PAGE_SIZE = 100
CONFIG_PATH = os.path.expanduser("~/.config/jira-pull-script/config")
FIELDS = ["summary", "description", "comment", "status"]


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

def run_setup() -> None:
    print("This saves your Jira credentials to", CONFIG_PATH)
    print("Get an API token from https://id.atlassian.com/manage-profile/security/api-tokens\n")

    jira_url = input("Jira URL (e.g. https://yourcompany.atlassian.net): ").strip().rstrip("/")
    email = input("Jira email: ").strip()
    api_token = getpass.getpass("Jira API token (input hidden): ").strip()

    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)

    config = configparser.ConfigParser()
    config["jira"] = {"url": jira_url, "email": email, "api_token": api_token}
    with open(CONFIG_PATH, "w") as f:
        config.write(f)
    os.chmod(CONFIG_PATH, stat.S_IRUSR | stat.S_IWUSR)

    print("\nSaved. You can now run this script without any credentials flags/env vars.")


def load_credentials() -> tuple[str, str, str]:
    jira_url = os.environ.get("JIRA_URL")
    email = os.environ.get("JIRA_EMAIL")
    api_token = os.environ.get("JIRA_API_TOKEN")

    if not (jira_url and email and api_token) and os.path.exists(CONFIG_PATH):
        config = configparser.ConfigParser()
        config.read(CONFIG_PATH)
        section = config["jira"]
        jira_url = jira_url or section.get("url")
        email = email or section.get("email")
        api_token = api_token or section.get("api_token")

    missing = [
        name
        for name, val in [("JIRA_URL", jira_url), ("JIRA_EMAIL", email), ("JIRA_API_TOKEN", api_token)]
        if not val
    ]
    if missing:
        sys.exit(
            f"Missing credential(s): {', '.join(missing)}. "
            f"Run `python3 {os.path.basename(__file__)} --setup` to save them, "
            "or set the matching environment variable(s)."
        )

    return jira_url.rstrip("/"), email, api_token


# ---------------------------------------------------------------------------
# Jira API
# ---------------------------------------------------------------------------

def get_done_issues(jira_url: str, email: str, api_token: str, jql: str) -> list[dict]:
    """Fetch issues matching jql, including their full changelog."""
    issues = []
    body = {"jql": jql, "fields": FIELDS, "maxResults": PAGE_SIZE}

    while True:
        response = requests.post(
            f"{jira_url}/rest/api/3/search/jql",
            auth=(email, api_token),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            json=body,
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        issues.extend(data["issues"])
        next_token = data.get("nextPageToken")
        if not next_token:
            break
        body["nextPageToken"] = next_token

    # Fetch changelogs in parallel (the search endpoint ignores expand=changelog)
    auth = (email, api_token)
    hdrs = {"Accept": "application/json"}

    def fetch_changelog(issue: dict) -> None:
        histories = []
        url = f"{jira_url}/rest/api/3/issue/{issue['key']}/changelog"
        while url:
            resp = requests.get(url, auth=auth, headers=hdrs, timeout=30)
            resp.raise_for_status()
            page = resp.json()
            histories.extend(page.get("values", []))
            url = page.get("nextPage")
        issue["changelog"] = {"histories": histories}

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(fetch_changelog, issue) for issue in issues]
        for future in as_completed(futures):
            future.result()  # re-raise any exception

    return issues


# ---------------------------------------------------------------------------
# Field helpers (identical to get_todo_tickets.py)
# ---------------------------------------------------------------------------

def parse_description_fields(description: dict | None) -> dict[str, str]:
    if not description:
        return {}
    result = {}
    for block in description.get("content", []):
        text = "".join(
            node.get("text", "")
            for node in block.get("content", [])
            if node.get("type") == "text"
        )
        key, sep, value = text.partition(":")
        if sep:
            result[key.strip()] = value.strip()
    return result


def package_name(desc: dict[str, str]) -> str:
    return desc.get("Package Name") or desc.get("Package Source Name", "")


def vulnerable_version(desc: dict[str, str]) -> str:
    return desc.get("Vulnerable Version") or desc.get("OS Distro release", "")


def extract_vulnerability_id(summary: str) -> str:
    match = re.match(r"(?:CVE|GHSA|AIKIDO)-ID:\s*(\S+)", summary, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.match(r"[\w-]+-ID:\s*(\S+)", summary)
    return match.group(1) if match else summary


def ticket_sort_key(ticket_url: str) -> int:
    match = re.search(r"-(\d+)$", ticket_url)
    return int(match.group(1)) if match else 0


# ---------------------------------------------------------------------------
# Changelog → "Resolved By"
# ---------------------------------------------------------------------------

def last_status_history(issue: dict) -> dict:
    """Return the most recent changelog history entry that contains a status change."""
    histories = issue.get("changelog", {}).get("histories", [])
    for history in reversed(histories):
        if any(item.get("field") == "status" for item in history.get("items", [])):
            return history
    return {}


def resolved_by(issue: dict, current_email: str) -> str:
    """Return who made the last status transition on this issue."""
    history = last_status_history(issue)
    if not history:
        return "Unknown"

    author = history.get("author", {})
    account_type = author.get("accountType", "")
    display_name = author.get("displayName", "")
    author_email = author.get("emailAddress", "")

    if account_type == "app" or "automation" in display_name.lower():
        return "Jira Automation"
    if author_email.lower() == current_email.lower():
        return "You"
    return display_name or "Unknown"


def done_date(issue: dict) -> str:
    """Return the ISO timestamp of the last status transition (used for sorting)."""
    history = last_status_history(issue)
    return history.get("created", "")


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def format_issues(issues: list[dict], jira_url: str, current_email: str) -> str:
    if not issues:
        return "No tickets found in Done status.\n"

    from datetime import date
    import datetime as dt

    today = date.today()
    yesterday = today - dt.timedelta(days=1)

    def label_for_date(d: date) -> str:
        if d == today:
            return f"{d}  (Today)"
        if d == yesterday:
            return f"{d}  (Yesterday)"
        return str(d)

    # Build rows with parsed date for grouping/sorting
    rows = []
    for issue in issues:
        raw_date = done_date(issue)
        # raw_date is ISO 8601 e.g. "2026-11-11T14:32:00.000+0000"
        try:
            ticket_date = dt.datetime.fromisoformat(raw_date.replace("Z", "+00:00")).astimezone().date()
        except (ValueError, AttributeError):
            ticket_date = date.min
        rows.append({
            "ticket": f"{jira_url}/browse/{issue['key']}",
            "resolved_by": resolved_by(issue, current_email),
            "date": ticket_date,
        })

    rows.sort(key=lambda r: r["date"], reverse=True)

    headers = ["Jira Ticket", "Resolved By"]
    # Column widths across all rows
    widths = [
        max(len(headers[0]), *(len(r["ticket"]) for r in rows)),
        max(len(headers[1]), *(len(r["resolved_by"]) for r in rows)),
    ]

    def format_row(cells: list[str]) -> str:
        return " | ".join(cell.ljust(width) for cell, width in zip(cells, widths))

    separator = "-+-".join("-" * w for w in widths)

    # Group by date
    from itertools import groupby
    lines = []
    total = 0
    for ticket_date, group in groupby(rows, key=lambda r: r["date"]):
        group_rows = list(group)
        total += len(group_rows)
        lines.append(f"--- {label_for_date(ticket_date)}  ({len(group_rows)} ticket(s)) ---")
        lines.append(format_row(headers))
        lines.append(separator)
        for r in group_rows:
            lines.append(format_row([r["ticket"], r["resolved_by"]]))
        lines.append("")

    lines.append(f"Total: {total} ticket(s)")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch Done Jira tickets and show who resolved each one.")
    parser.add_argument("--setup", action="store_true", help="Save Jira credentials and exit")
    parser.add_argument("--project", help='Restrict to a project key, e.g. TP')
    parser.add_argument("--all-assignees", action="store_true", help="Include tickets not assigned to you")
    parser.add_argument("--text", default="done_issues.txt", help="Output file (default: done_issues.txt)")
    parser.add_argument("days", nargs="?", type=int, default=30, help="How many days back to look (default: 30)")
    args = parser.parse_args()

    if args.setup:
        run_setup()
        return

    jira_url, email, api_token = load_credentials()

    jql_parts = []
    if not args.all_assignees:
        jql_parts.append("assignee = currentUser()")
    if args.project:
        jql_parts.append(f'project = "{args.project}"')
    jql_parts.append('statusCategory = Done')
    # Fetch 1 extra day as buffer to handle UTC vs local timezone edge cases,
    # then filter to exact requested days client-side using the changelog timestamp.
    jql_parts.append(f'status changed AFTER -{args.days + 1}d')
    jql = " AND ".join(jql_parts) + " ORDER BY key DESC"

    import datetime as _dt
    cutoff = _dt.date.today() - _dt.timedelta(days=args.days - 1)

    issues = get_done_issues(jira_url, email, api_token, jql)
    # Keep only tickets whose actual done date (local time) is within the requested window
    issues = [i for i in issues if done_date(i)[:10] and
              _dt.date.fromisoformat(
                  _dt.datetime.fromisoformat(done_date(i).replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d")
              ) >= cutoff]

    with open(args.text, "w") as f:
        f.write(format_issues(issues, jira_url, email))
    print(f"Wrote {len(issues)} ticket(s) to {args.text}")


if __name__ == "__main__":
    main()
