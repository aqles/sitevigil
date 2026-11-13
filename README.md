# SiteVigil

```
     .      o                 .               o                       .
  ______  _____  _______  ______ __      __ _____   ______   _____  _
 / ____/ |_   _||__   __||  ____|\ \    / /|_   _| / ____/  |_   _|| |
| (___     | |     | |   | |__    \ \  / /   | |  | |  ___    | |  | |
 \___ \    | |     | |   |  __|    \ \/ /    | |  | | |_  |   | |  | |
 ____) |  _| |_    | |   | |____    \  /    _| |_ | |___| |  _| |_ | |____
|_____/  |_____|   |_|   |______|    \/    |_____| \_____/  |_____||______|
   |                                                |               |
   .                                                .              \___/
```

**One command. A security audit of any website — scored, explained, and with the fix written out for you.**

[![PyPI](https://img.shields.io/pypi/v/sitevigil)](https://pypi.org/project/sitevigil/)
[![Python](https://img.shields.io/pypi/pyversions/sitevigil)](https://pypi.org/project/sitevigil/)
[![CI](https://github.com/aqles/sitevigil/actions/workflows/test.yml/badge.svg)](https://github.com/aqles/sitevigil/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

```bash
pip install sitevigil
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
| Transport | HTTPS in place, HTTP → HTTPS redirect, TLS protocol, certificate expiry, redirect chains (downgrade hops, chains over 3 hops), main-page response time (flagged over 3 s) |
| Security headers | HSTS, Content-Security-Policy (incl. `unsafe-inline` / `unsafe-eval` / wildcard sources), X-Content-Type-Options, clickjacking, Referrer-Policy, Permissions-Policy |
| Cookies | Secure, HttpOnly (on session-like cookies), SameSite |
| CORS | Arbitrary-origin reflection, `*` combined with credentials |
| Exposed files | `/.env`, `/.git/HEAD`, `/.git/config` |
| Exposed services | Database ports open to the internet — MySQL/MariaDB (3306), PostgreSQL (5432), Redis (6379), MongoDB (27017), plain TCP connect |
| Page content | Mixed content (HTTP subresources on an HTTPS page), cross-origin scripts without Subresource Integrity |
| Methods & discovery | HTTP TRACE enabled, missing `/.well-known/security.txt` |
| Isolation | Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy, CSP hardening directives (object-src / base-uri) |
| Domain (via DNS) | SPF and DMARC (only when the domain receives mail), CAA |
| Known vulnerabilities | Software/version fingerprints (nginx, Apache, PHP, OpenSSL, IIS, WordPress, Drupal, Joomla) matched against NVD CVEs, verified against each CVE's vulnerable version ranges — plus jQuery and WordPress plugins (Elementor, WooCommerce, Contact Form 7, Akismet) fingerprinted from the page source |
| Info disclosure | `Server`, `X-Powered-By` |

The full catalog — 30+ checks, each with its reference — is one command away: `sitevigil --checks`. Checks are versioned as a **ruleset** (currently `2026.11`); every report names the ruleset that produced it, and changes land in [CHANGELOG.md](CHANGELOG.md), never silently. To keep a site up to date automatically, drop in the weekly GitHub Action from [examples/github-action](examples/github-action/sitevigil-weekly.yml): it re-audits on a schedule and fails on score drops or regressions.

Every finding includes what was actually observed and a concrete fix — not just a warning label.

Two details that took real-world pain to learn:

- **No soft-404 false positives.** Many sites (SPAs, some hosts) answer `200` with their homepage for *every* path. SiteVigil only reports an exposed file when the response content actually matches a real `.env` / git file — a bare `200` is never enough.
- **CVE matches are verified, not googled.** NVD search happily returns CVEs that only *mention* your software. SiteVigil re-checks every candidate against the CVE's own vulnerable configurations and version ranges before reporting it, scores it with NVD's primary CVSS, and prints the backport caveat next to every match — a version string alone never proves a server is unpatched.
- **Proxy-aware TLS.** If you sit behind a corporate proxy (`https_proxy`), the TLS check tunnels through it with `CONNECT` instead of dying with `WRONG_VERSION_NUMBER`.

## Install

```bash
pip install sitevigil
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
sitevigil example.com --crawl 10                    # audit up to 10 pages (sitemap.xml, else homepage links)
sitevigil example.com --badge > badge.svg           # an SVG score badge for your README
sitevigil example.com --no-cve                      # skip the CVE lookup (faster, fully offline)
sitevigil example.com --no-ports                    # skip the exposed-database-port check
sitevigil example.com --html --output report.html   # write any format straight to a file
```

Scoring starts at 100 and loses points per finding (critical 25, high 15, medium 8, low 3), ending in a grade from A to F.

In a terminal, output is coloured (severity tags, score, grade) and a spinner + progress bar walks through the eight audit phases while the scan runs — both switch off automatically for pipes, files, and `--json`/`--markdown`/`--html`, or with `--no-color` / `--no-progress` (`NO_COLOR` is honoured too). The HTML report is a dark theme with severity chips and a per-severity summary.

## Let your AI agent use it

SiteVigil ships an MCP server (still stdlib-only). Local agents use stdio; hosted agents can use the HTTP transport:

```bash
sitevigil --mcp                      # stdio, for desktop/CLI agents
sitevigil --mcp-http 8900            # HTTP on localhost, for hosted agents
```

MCP is a shared protocol, so **one server works with every MCP-compatible agent** — Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, Gemini CLI — no per-agent builds. Only the config file's location changes; ready-to-paste snippets for each agent live in [examples/mcp](examples/mcp/README.md). Interoperability is not just claimed: the server is tested against the official MCP Python SDK client (initialize → tool list → a real `audit_site` call).

Your agent gets two tools: `audit_site` (the full scored report) and `suggest_fix` (the audit plus a ready-to-commit, platform-specific header config). It can check a site before telling you it's "secure" — or audit the fix it just deployed.

## Honest limits

- It audits the response of the URL you give it (plus `/.env` / `/.git` probes). It is not a vulnerability scanner and it does not fuzz, brute-force, or log in anywhere.
- The database-port check is a plain TCP connect to four well-known ports: no banner grabbing, no login attempts. A firewalled port counts as closed — the check claims reachability, nothing more.
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
