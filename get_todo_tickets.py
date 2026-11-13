#!/usr/bin/env python3
"""Fetch your Jira issues currently in "To Do" status.

Credentials are read, in order of precedence, from:
    1. JIRA_URL / JIRA_EMAIL / JIRA_API_TOKEN environment variables
    2. ~/.config/jira-pull-script/config (created by --setup)

Run `python3 get_todo_tickets.py --setup` once to save your credentials so
you never have to pass them again.
"""

import argparse
import configparser
import getpass
import json
import os
import re
import stat
import sys

import requests

PAGE_SIZE = 100
CONFIG_PATH = os.path.expanduser("~/.config/jira-pull-script/config")
FIELDS = ["summary", "description", "project", "assignee", "priority", "updated", "attachment", "comment"]


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
    os.chmod(CONFIG_PATH, stat.S_IRUSR | stat.S_IWUSR)  # 600: owner read/write only

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

    missing = [name for name, val in [("JIRA_URL", jira_url), ("JIRA_EMAIL", email), ("JIRA_API_TOKEN", api_token)] if not val]
    if missing:
        sys.exit(
            f"Missing credential(s): {', '.join(missing)}. "
            f"Run `python3 {os.path.basename(__file__)} --setup` to save them, "
            "or set the matching environment variable(s)."
        )

    return jira_url.rstrip("/"), email, api_token


def get_todo_issues(jira_url: str, email: str, api_token: str, jql: str) -> list[dict]:
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

    return issues


def parse_description_fields(description: dict | None) -> dict[str, str]:
    """Pull "Key: value" lines out of a Jira ADF description.

    App tickets use Ecosystem / Package Name / Vulnerable Version.
    OS tickets use Ecosystem / Package Source Name / OS Distro release.
    """
    if not description:
        return {}

    result = {}
    for block in description.get("content", []):
        text = "".join(node.get("text", "") for node in block.get("content", []) if node.get("type") == "text")
        key, sep, value = text.partition(":")
        if sep:
            result[key.strip()] = value.strip()
    return result


def package_name(desc: dict[str, str]) -> str:
    """App tickets name the package directly; OS tickets name the source package."""
    return desc.get("Package Name") or desc.get("Package Source Name", "")


def vulnerable_version(desc: dict[str, str]) -> str:
    """App tickets carry a package version; OS tickets carry the distro release."""
    return desc.get("Vulnerable Version") or desc.get("OS Distro release", "")


def extract_vulnerability_id(summary: str) -> str:
    """Get the advisory ID out of the summary, whichever scheme it uses (CVE-ID:, GHSA-ID:, AIKIDO-ID:, ...)."""
    match = re.match(r"(?:CVE|GHSA|AIKIDO)-ID:\s*(\S+)", summary, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.match(r"[\w-]+-ID:\s*(\S+)", summary)
    return match.group(1) if match else summary


def ticket_sort_key(ticket_url: str) -> int:
    match = re.search(r"-(\d+)$", ticket_url)
    return int(match.group(1)) if match else 0


def _cell_text(cell: dict) -> str:
    """Extract all plain text from an ADF tableCell/tableHeader node."""
    parts = []
    for block in cell.get("content", []):
        for node in block.get("content", []):
            if node.get("type") != "text":
                continue
            # If this node has a link mark, use the href (avoids doubling when text == href)
            link_href = next(
                (m.get("attrs", {}).get("href", "") for m in node.get("marks", []) if m.get("type") == "link"),
                None,
            )
            parts.append(link_href if link_href else node.get("text", ""))
    return "".join(parts).strip()


def _mr_link_from_adf(adf: dict | None) -> str:
    """Scan an ADF document for a table row whose first cell is 'MR Link'."""
    if not adf:
        return ""
    for block in adf.get("content", []):
        if block.get("type") != "table":
            continue
        for row in block.get("content", []):
            cells = row.get("content", [])
            if len(cells) < 2:
                continue
            if _cell_text(cells[0]).lower() == "mr link":
                return _cell_text(cells[1])
    return ""


def extract_mr_link(issue: dict) -> str:
    """Find the MR Link from the RPT Patch Creation Results table posted as a comment."""
    comments = issue["fields"].get("comment", {}).get("comments", [])
    for comment in comments:
        url = _mr_link_from_adf(comment.get("body"))
        # The table says "N/A" when no MR was created; only accept real links.
        if url.lower().startswith(("http://", "https://")):
            return url
    return ""


def has_patch_attachment(issue: dict, vuln_id: str) -> str:
    """Return 'yes' if the issue has an attachment named patches_{vuln_id}.patch."""
    attachments = issue["fields"].get("attachment") or []
    expected = f"patches_{vuln_id}.patch"
    return "yes" if any(a.get("filename") == expected for a in attachments) else "no"


def format_issues(issues: list[dict], jira_url: str) -> str:
    if not issues:
        return "No tickets found in To Do status.\n"

    headers = ["Jira Ticket", "Vulnerability ID", "Ecosystem", "Package Name", "Vulnerable Version", "Patch", "MR"]
    rows = []
    for issue in issues:
        fields = issue["fields"]
        desc = parse_description_fields(fields.get("description"))
        vuln_id = extract_vulnerability_id(fields["summary"])
        rows.append([
            f"{jira_url}/browse/{issue['key']}",
            vuln_id,
            desc.get("Ecosystem", ""),
            package_name(desc),
            vulnerable_version(desc),
            has_patch_attachment(issue, vuln_id),
            extract_mr_link(issue),
        ])

    rows.sort(key=lambda row: (row[3].lower(), row[4], row[1].lower(), ticket_sort_key(row[0])))

    widths = [max(len(h), *(len(row[i]) for row in rows)) for i, h in enumerate(headers)]

    def format_row(cells: list[str]) -> str:
        return " | ".join(cell.ljust(width) for cell, width in zip(cells, widths))

    separator = "-+-".join("-" * width for width in widths)

    lines = [format_row(headers), separator]
    lines.extend(format_row(row) for row in rows)
    lines.append("")
    lines.append(f"Total: {len(issues)} ticket(s) in To Do")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch your Jira tickets in To Do status.")
    parser.add_argument("--setup", action="store_true", help="Save Jira credentials to ~/.config/jira-pull-script/config and exit")
    parser.add_argument("--project", help='Restrict results to a project key, e.g. TP (adds AND project="TP")')
    parser.add_argument("--all-assignees", action="store_true", help="Include tickets not assigned to you (default: only your tickets)")
    parser.add_argument("--output", help="Write raw issue JSON to this file (e.g. issues.json) instead of printing a summary")
    parser.add_argument("--text", default="issues.txt", help="Write the summary to this text file (default: issues.txt)")
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
    jql_parts.append('status = "To Do"')
    jql = " AND ".join(jql_parts) + " ORDER BY key ASC"

    issues = get_todo_issues(jira_url, email, api_token, jql)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(issues, f, indent=2)
        print(f"Wrote {len(issues)} ticket(s) to {args.output}")
    else:
        with open(args.text, "w") as f:
            f.write(format_issues(issues, jira_url))
        print(f"Wrote {len(issues)} ticket(s) to {args.text}")


if __name__ == "__main__":
    main()
