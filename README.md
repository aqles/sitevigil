# SiteVigil

**One command. A security audit of any website — scored, explained, and with the fix written out for you.**

```bash
sitevigil aqles.github.io
```

```
https://aqles.github.io
Score: 75/100  Grade: C  HTTP 200

[MEDIUM  ] Missing Content-Security-Policy header
           No CSP header; the page has no second line of defence against XSS.
           Fix: Add a CSP that fits your site, starting strict, e.g. Content-Security-Policy: default-src 'self'
[LOW     ] Missing X-Content-Type-Options: nosniff
           Header absent or not set to 'nosniff'.
           Fix: Add: X-Content-Type-Options: nosniff
[MEDIUM  ] No clickjacking protection
           Neither X-Frame-Options (DENY/SAMEORIGIN) nor CSP frame-ancestors is set.
           Fix: Add: X-Frame-Options: DENY (or SAMEORIGIN), or frame-ancestors 'none' in your CSP.
```

SiteVigil is a small Python tool with **zero dependencies** — standard library only. It runs the checks that turn up again and again when real websites get audited, it works as a plain CLI for humans, and it speaks MCP so AI coding agents (Claude Code, Cursor, …) can run the same audit and fix what it finds.

## Why not just use a free web checker?

Fair question — sites like SecurityHeaders or Mozilla Observatory grade a page for free, and for a one-off look they're fine. SiteVigil exists for everything around that moment:

- **It hands you the patch, not just the grade.** `--fix` generates a ready-to-commit config for your actual platform (Vercel, Netlify, Cloudflare Pages, nginx, Apache). On GitHub Pages it tells you plainly that headers are a platform limit and gives you the portable `_headers` file instead of a lecture.
- **It lives where you work.** Terminal, CI (`--fail-under`, `--baseline`), and inside your AI agent via MCP — a web page can't fail your deploy or re-check a fix.
- **It checks more than headers.** Exposed `.env`/`.git` (verified by content, not status codes), CORS reflection, cookie flags, mixed content, missing SRI, TRACE, TLS expiry, security.txt.
- **It remembers.** Save a report, come back next week, and `--baseline` shows exactly what regressed and what got fixed — web checkers have no memory of your last scan.

## What it checks

| Area | Checks |
| --- | --- |
| Transport | HTTPS in place, HTTP → HTTPS redirect, TLS protocol, certificate expiry |
| Security headers | HSTS, Content-Security-Policy (incl. `unsafe-inline` / `unsafe-eval` / wildcard sources), X-Content-Type-Options, clickjacking, Referrer-Policy, Permissions-Policy |
| Cookies | Secure, HttpOnly (on session-like cookies), SameSite |
| CORS | Arbitrary-origin reflection, `*` combined with credentials |
| Exposed files | `/.env`, `/.git/HEAD`, `/.git/config` |
| Page content | Mixed content (HTTP subresources on an HTTPS page), cross-origin scripts without Subresource Integrity |
| Methods & discovery | HTTP TRACE enabled, missing `/.well-known/security.txt` |
| Info disclosure | `Server`, `X-Powered-By` |

Every finding includes what was actually observed and a concrete fix — not just a warning label.

Two details that took real-world pain to learn:

- **No soft-404 false positives.** Many sites (SPAs, some hosts) answer `200` with their homepage for *every* path. SiteVigil only reports an exposed file when the response content actually matches a real `.env` / git file — a bare `200` is never enough.
- **Proxy-aware TLS.** If you sit behind a corporate proxy (`https_proxy`), the TLS check tunnels through it with `CONNECT` instead of dying with `WRONG_VERSION_NUMBER`.

## Install

```bash
pip install sitevigil        # once published to PyPI
# or straight from the repo:
pip install git+https://github.com/aqles/sitevigil
# or just run it from a clone, no install needed:
python -m sitevigil example.com
```

Requires Python 3.10+. That's it — nothing else gets installed.

## Use it

```bash
sitevigil example.com                  # human-readable report
sitevigil example.com --json           # structured output, for scripts and agents
sitevigil example.com --markdown       # a report you can paste into an issue
sitevigil example.com --html > report.html   # one self-contained HTML report
sitevigil a.com b.com c.com            # audit several sites, with a summary table
sitevigil example.com --fail-under 80  # CI mode: exit 1 if the score is below 80
sitevigil example.com --fix            # + a ready-to-commit header config for your platform
sitevigil example.com --json > monday.json          # save a baseline
sitevigil example.com --baseline monday.json        # next week: what regressed? (exit 1 on new findings)
```

Scoring starts at 100 and loses points per finding (critical 25, high 15, medium 8, low 3), ending in a grade from A to F.

## Let your AI agent use it

SiteVigil ships an MCP server (still stdlib-only — newline-delimited JSON-RPC over stdio):

```bash
sitevigil --mcp
```

MCP is a shared protocol, so **one server works with every MCP-compatible agent** — Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, Gemini CLI — no per-agent builds. Only the config file's location changes; ready-to-paste snippets for each agent live in [examples/mcp](examples/mcp/README.md). Interoperability is not just claimed: the server is tested against the official MCP Python SDK client (initialize → tool list → a real `audit_site` call).

Your agent gets two tools: `audit_site` (the full scored report) and `suggest_fix` (the audit plus a ready-to-commit, platform-specific header config). It can check a site before telling you it's "secure" — or audit the fix it just deployed.

## Honest limits

- It audits the response of the URL you give it (plus `/.env` / `/.git` probes). It is not a vulnerability scanner and it does not fuzz, brute-force, or log in anywhere.
- Only audit sites you own or have permission to test. The probes are read-only `GET`s, but scanning other people's property without permission is still a bad idea.
- A high score means these basics are in place. It is not a guarantee that a site is secure.

## Development

```bash
git clone https://github.com/aqles/sitevigil
cd sitevigil
PYTHONPATH=src python -m unittest discover -s tests -v
```

The test fixture is a local HTTP server that deliberately serves a soft-404 for unknown paths and a real-looking `.env` file — the audit has to catch one and ignore the other.

## License

MIT — see [LICENSE](LICENSE). Use it, fork it, ship it; just keep the copyright notice. If SiteVigil saves you from shipping a site with an exposed `.env`, a star is the going rate.
