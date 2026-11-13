#!/usr/bin/env python3
"""Local web UI for the Jira To Do / Done ticket views, plus a "Close MR" button.

    python3 app.py --setup-gitlab     # once: save GitLab URL + token (needed for Close MR)
    python3 app.py                    # then open http://127.0.0.1:8765

Jira credentials come from the same config as the CLI scripts. The server only
listens on localhost, and tokens never reach the browser.
"""

import argparse
import configparser
import datetime as dt
import getpass
import json
import os
import re
import stat
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

import get_done_tickets as done
import get_todo_tickets as todo

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = todo.CONFIG_PATH
MR_RE = re.compile(r"^https?://([^/]+)/(.+?)/-/merge_requests/(\d+)")

STATE = {"project": "TP", "port": 8765}


# ---------------------------------------------------------------------------
# GitLab config + MR closing
# ---------------------------------------------------------------------------

def setup_gitlab() -> None:
    url = input("GitLab URL (e.g. https://gitlab.com): ").strip().rstrip("/")
    token = getpass.getpass("GitLab personal access token, scope 'api' (hidden): ").strip()
    config = configparser.ConfigParser()
    config.read(CONFIG_PATH)
    config["gitlab"] = {"url": url, "token": token}
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        config.write(f)
    os.chmod(CONFIG_PATH, stat.S_IRUSR | stat.S_IWUSR)
    print("Saved GitLab settings to", CONFIG_PATH)


def gitlab_settings() -> tuple[str, str]:
    url = os.environ.get("GITLAB_URL", "")
    token = os.environ.get("GITLAB_TOKEN", "")
    if not (url and token) and os.path.exists(CONFIG_PATH):
        config = configparser.ConfigParser()
        config.read(CONFIG_PATH)
        if config.has_section("gitlab"):
            url = url or config["gitlab"].get("url", "")
            token = token or config["gitlab"].get("token", "")
    return url.rstrip("/"), token


def mr_api_url(mr_url: str, gl_url: str) -> str:
    m = MR_RE.match(mr_url)
    if not m:
        raise ValueError("Not a GitLab merge request URL.")
    host, project_path, iid = m.groups()
    # The URL comes from a Jira comment: never send the token to any other host.
    if host.lower() != urllib.parse.urlparse(gl_url).netloc.lower():
        raise ValueError(f"MR host {host} does not match configured GitLab host.")
    return f"{gl_url}/api/v4/projects/{urllib.parse.quote(project_path, safe='')}/merge_requests/{iid}"


def close_mr(mr_url: str) -> str:
    gl_url, token = gitlab_settings()
    if not (gl_url and token):
        raise ValueError("GitLab is not configured. Run `python3 app.py --setup-gitlab`.")
    r = requests.put(mr_api_url(mr_url, gl_url), headers={"PRIVATE-TOKEN": token}, json={"state_event": "close"}, timeout=30)
    if r.status_code >= 400:
        raise ValueError(f"GitLab returned {r.status_code}: {r.text[:200]}")
    state = r.json().get("state", "closed")
    cache_put(mr_url, state)
    return state


CACHE_PATH = os.path.join(os.path.dirname(CONFIG_PATH), "mr_state_cache.json")
# Merged MRs can never reopen, so they are cached forever (and saved to disk).
# Closed MRs rarely reopen: 1 hour. Open ones can change any time: 60 seconds.
MR_TTL = {"merged": None, "closed": 3600}
MR_TTL_DEFAULT = 60
MR_STATE_CACHE: dict[str, tuple[str, float]] = {}
_cache_lock = threading.Lock()


def _load_merged_cache() -> None:
    try:
        with open(CACHE_PATH) as f:
            for url in json.load(f):
                MR_STATE_CACHE[url] = ("merged", 0.0)
    except (OSError, ValueError):
        pass


def _save_merged_cache() -> None:
    try:
        merged = [u for u, (st, _) in MR_STATE_CACHE.items() if st == "merged"]
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        with open(CACHE_PATH, "w") as f:
            json.dump(merged, f)
    except OSError:
        pass


def cache_get(mr_url: str) -> str | None:
    entry = MR_STATE_CACHE.get(mr_url)
    if not entry:
        return None
    state, ts = entry
    ttl = MR_TTL.get(state, MR_TTL_DEFAULT)
    return state if ttl is None or time.time() - ts < ttl else None


def cache_put(mr_url: str, state: str) -> None:
    with _cache_lock:
        MR_STATE_CACHE[mr_url] = (state, time.time())
        if state == "merged":
            _save_merged_cache()


def fetch_mr_state(mr_url: str, gl_url: str, token: str) -> str:
    cached = cache_get(mr_url)
    if cached:
        return cached
    try:
        r = requests.get(mr_api_url(mr_url, gl_url), headers={"PRIVATE-TOKEN": token}, timeout=20)
        state = r.json().get("state", "unknown") if r.status_code == 200 else "unknown"
    except (ValueError, requests.RequestException):
        state = "unknown"
    if state != "unknown":
        cache_put(mr_url, state)
    return state


def add_mr_states(rows: list[dict]) -> None:
    """Annotate each row with the live GitLab state of its MR (opened/merged/closed/unknown)."""
    gl_url, token = gitlab_settings()
    urls = {r["mr"] for r in rows if r["mr"]}
    if not (gl_url and token and urls):
        for r in rows:
            r["mr_state"] = ""
        return
    with ThreadPoolExecutor(max_workers=10) as ex:
        states = dict(zip(urls, ex.map(lambda u: fetch_mr_state(u, gl_url, token), urls)))
    for r in rows:
        r["mr_state"] = states.get(r["mr"], "")


# ---------------------------------------------------------------------------
# Data builders
# ---------------------------------------------------------------------------

def jql_base(project: str) -> list[str]:
    parts = ["assignee = currentUser()"]
    if project:
        parts.append('project = "%s"' % project.replace('"', ""))
    return parts


def build_todo(project: str) -> list[dict]:
    jira_url, email, token = todo.load_credentials()
    jql = " AND ".join(jql_base(project) + ['status = "To Do"']) + " ORDER BY key ASC"
    rows = []
    for issue in todo.get_todo_issues(jira_url, email, token, jql):
        f = issue["fields"]
        desc = todo.parse_description_fields(f.get("description"))
        vuln = todo.extract_vulnerability_id(f["summary"])
        rows.append({
            "key": issue["key"],
            "url": f"{jira_url}/browse/{issue['key']}",
            "vuln_id": vuln,
            "ecosystem": desc.get("Ecosystem", ""),
            "package": todo.package_name(desc),
            "version": todo.vulnerable_version(desc),
            "patch": todo.has_patch_attachment(issue, vuln),
            "mr": todo.extract_mr_link(issue),
        })
    rows.sort(key=lambda r: (r["package"].lower(), r["version"], r["vuln_id"].lower(), todo.ticket_sort_key(r["url"])))
    add_mr_states(rows)
    return rows


def build_done(project: str, days: int) -> list[dict]:
    jira_url, email, token = done.load_credentials()
    jql = " AND ".join(
        jql_base(project) + ["statusCategory = Done", f"status changed AFTER -{days + 1}d"]
    ) + " ORDER BY key DESC"
    cutoff = dt.date.today() - dt.timedelta(days=days - 1)
    rows = []
    for issue in done.get_done_issues(jira_url, email, token, jql):
        raw = done.done_date(issue)
        try:
            when = dt.datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone()
        except ValueError:
            continue
        if when.date() < cutoff:
            continue
        desc = todo.parse_description_fields(issue["fields"].get("description"))
        rows.append({
            "key": issue["key"],
            "url": f"{jira_url}/browse/{issue['key']}",
            "resolved_by": done.resolved_by(issue, email),
            "mr": todo.extract_mr_link(issue),
            "vuln_id": todo.extract_vulnerability_id(issue["fields"]["summary"]),
            "ecosystem": desc.get("Ecosystem", ""),
            "package": todo.package_name(desc),
            "version": todo.vulnerable_version(desc),
            "status": (issue["fields"].get("status") or {}).get("name", ""),
            "done_at": when.isoformat(),
            "date": str(when.date()),
        })
    rows.sort(key=lambda r: r["done_at"], reverse=True)
    add_mr_states(rows)
    return rows


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("%s\n" % (fmt % args))

    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj).encode())

    def _host_ok(self) -> bool:
        # Blocks DNS-rebinding and cross-site requests against the localhost server.
        allowed = {f"127.0.0.1:{STATE['port']}", f"localhost:{STATE['port']}"}
        if self.headers.get("Host", "") not in allowed:
            return False
        origin = self.headers.get("Origin")
        return origin is None or urllib.parse.urlparse(origin).netloc in allowed

    def do_GET(self):
        if not self._host_ok():
            return self._json(403, {"error": "forbidden"})
        url = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(url.query)
        project = qs.get("project", [STATE["project"]])[0].strip()
        try:
            if url.path == "/":
                with open(os.path.join(HERE, "index.html"), "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            if url.path.startswith("/fonts/"):
                name = os.path.basename(url.path)  # basename blocks path traversal
                path = os.path.join(HERE, "fonts", name)
                if name.endswith((".woff2", ".css")) and os.path.isfile(path):
                    ctype = "font/woff2" if name.endswith(".woff2") else "text/css"
                    with open(path, "rb") as f:
                        return self._send(200, f.read(), ctype)
                return self._json(404, {"error": "not found"})
            if url.path == "/api/config":
                return self._json(200, {"project": STATE["project"], "gitlab": all(gitlab_settings())})
            if url.path == "/api/todo":
                return self._json(200, build_todo(project))
            if url.path == "/api/done":
                days = max(1, min(int(qs.get("days", ["1"])[0]), 90))
                return self._json(200, build_done(project, days))
        except (requests.RequestException, ValueError, SystemExit) as e:
            return self._json(502, {"error": str(e)})
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self._host_ok():
            return self._json(403, {"error": "forbidden"})
        if self.path != "/api/close-mr":
            return self._json(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            mr_url = json.loads(self.rfile.read(length))["url"]
            self._json(200, {"state": close_mr(mr_url)})
        except (ValueError, KeyError, requests.RequestException) as e:
            self._json(400, {"error": str(e)})


def main() -> None:
    p = argparse.ArgumentParser(description="Local web UI for Jira To Do / Done tickets.")
    p.add_argument("--project", default="TP", help="Default project key (default: TP)")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--setup-gitlab", action="store_true", help="Save GitLab URL + token and exit")
    args = p.parse_args()
    if args.setup_gitlab:
        return setup_gitlab()
    _load_merged_cache()
    STATE.update(project=args.project, port=args.port)
    print(f"Serving on http://127.0.0.1:{args.port}  (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
