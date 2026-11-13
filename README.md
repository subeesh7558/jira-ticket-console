# Jira Ticket Console

A small local website for your Jira vulnerability tickets.

- **To Do tab:** your open tickets with vulnerability ID, ecosystem, package, version, patch status and MR link.
- **Done tab:** recently resolved tickets, grouped by day, with who resolved them and the ticket status.
- **Close MR button:** closes a GitLab merge request from the page. It only shows for MRs that are still open.
- **Filters and export:** filter by ecosystem or search text, and export the current view to a `.txt` file.

It runs on your own machine and only listens on `localhost`. Your tokens stay on the server and are never sent to the browser.

## 1. Prerequisites

- Python 3.10 or newer (`python3 --version`)
- A Jira Cloud account with access to the project
- (Optional, only for **Close MR**) a GitLab account with Developer role or higher on the MR projects

## 2. Install

```bash
git clone https://github.com/subeesh7558/jira-ticket-console.git
cd jira-ticket-console
python3 -m pip install -r requirements.txt
```

## 3. One-time setup

### Jira credentials

Create an API token at <https://id.atlassian.com/manage-profile/security/api-tokens>, then run:

```bash
python3 get_todo_tickets.py --setup
```

It asks for your Jira URL (for example `https://yourcompany.atlassian.net`), your Jira email and the API token.

### GitLab token (only needed for Close MR)

1. In GitLab, go to **Preferences → Access tokens → Add new token**.
2. Give it the **`api`** scope and an expiry date.
3. Run:

```bash
python3 app.py --setup-gitlab
```

Enter your GitLab URL (for example `https://gitlab.com`) and paste the token. The input is hidden.

Both are saved to `~/.config/jira-pull-script/config`, readable only by you. Nothing is stored in the project folder. Without the GitLab token, the site still works and the Close MR button is hidden.

You can also use environment variables instead of the config file: `JIRA_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`, `GITLAB_URL`, `GITLAB_TOKEN`.

## 4. Run

```bash
python3 app.py
```

Open <http://127.0.0.1:8765>.

Options:

| Option | Default | Meaning |
|--------|---------|---------|
| `--project` | `TP` | Jira project key to load |
| `--port` | `8765` | Port to listen on |

Stop it with `Ctrl+C`. After you change any `.py` file, stop and start it again.

## 5. Using the page

- **Tabs:** switch between To Do and Done. The Done tab has a **Days** box for how far back to look (1 = today only).
- **Project:** change the project key in the top bar and the page reloads.
- **Ecosystem and search:** narrow down the table. The export uses whatever you are currently looking at.
- **Export TXT:** downloads the visible rows (without the MR link) as a text file.
- **Close MR:** asks you to confirm, then closes the merge request in GitLab without merging it. It does not change the Jira ticket. A closed MR can be reopened in GitLab.

MR states (open, merged, closed) are looked up in GitLab and cached. Merged MRs are remembered in `~/.config/jira-pull-script/mr_state_cache.json`. Delete that file to clear it.

## 6. Command-line scripts

The original scripts still work and write text files:

```bash
python3 get_todo_tickets.py --project TP        # writes issues.txt
python3 get_done_tickets.py --project TP 3      # last 3 days, writes done_issues.txt
```

## 7. Troubleshooting

| Problem | What to check |
|---------|---------------|
| `Missing credential(s)` | Run `python3 get_todo_tickets.py --setup` |
| Page shows an error loading tickets | Wrong Jira URL, email or token, or no access to the project |
| No **Close MR** buttons | Run `python3 app.py --setup-gitlab`, then restart the app |
| Close MR fails with 401 or 403 | Token expired, missing the `api` scope, or your role on that project is too low |
| Page looks unchanged after an update | Restart the app and hard-refresh the browser (Cmd+Shift+R) |
| Done tab is slow | Use fewer days. Each ticket needs its own Jira history lookup |
| `Address already in use` | Another copy is running. Stop it, or use `--port 8766` |

## 8. Files

| File | Purpose |
|------|---------|
| `app.py` | Local server and API (Jira, GitLab) |
| `index.html` | The web page |
| `fonts/` | Self-hosted fonts, so the page works offline |
| `get_todo_tickets.py`, `get_done_tickets.py` | Fetch and parse code, also usable as command-line scripts |
| `requirements.txt` | Python dependencies |

## Security notes

- Never commit tokens. They live in `~/.config/jira-pull-script/`, outside this folder.
- The server rejects requests whose `Host` or `Origin` is not localhost.
- The GitLab token is only ever sent to the GitLab host you configured, never to a host taken from a Jira comment.
