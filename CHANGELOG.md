# Changelog

SiteVigil versions its audit ruleset separately (shown in every report
and via `sitevigil --checks`) so results stay comparable over time and
changes to what is checked are never silent.

## 0.9.0 — ruleset 2026.11

- Response time: every report now carries `response_time_ms` for the
  main document fetch (shown in text and Markdown output), and a main
  page that takes over 3 seconds end to end earns a `slow-response`
  finding. Latency was the one basic signal the audit did not measure.
- Exposed database ports: a plain TCP connect checks whether MySQL/
  MariaDB (3306), PostgreSQL (5432), Redis (6379) or MongoDB (27017)
  answer on the audited host's public interface — an open one is a
  high-severity `db-port-exposed` finding. Connect only: no banner
  grab, no login attempt. Runs once per host (crawl does not re-probe
  per page); `--no-ports` opts out. Ruleset grows to 42 checks.
  The connect reuses the proxy-aware path from the TLS check: behind
  an HTTP proxy a naive connect succeeds for every port (the proxy
  answers handshakes itself), so the verdict comes from the CONNECT
  response instead — the first live run without this reported four
  open database ports on a site that has none.

## 0.8.1 — ruleset 2026.11

- Packaging fix: the 0.8.0 PyPI metadata shipped without trove
  classifiers, so the Python-versions badge (and PyPI's own sidebar)
  had nothing to show. 0.8.1 declares the supported Python versions
  (3.10-3.13), license, audience and topics. No code or ruleset
  changes.

## 0.8.0 — ruleset 2026.11

- WordPress plugin CVE matching: Elementor, WooCommerce, Contact
  Form 7 and Akismet versions are fingerprinted from plugin asset
  URLs (`?ver=`), and matched against NVD. Every mapping was verified
  live first -- including the discovery that Elementor's NVD product
  is "website_builder"; a guessed name returns zero CVEs forever.
  Plugins whose assets disagree on the version are skipped.
- MCP over HTTP: `sitevigil --mcp-http PORT` serves the same tools to
  hosted/remote agents (stateless JSON-RPC POSTs to /mcp). Localhost
  by default; binding elsewhere prints a loud warning, because the
  tools fetch arbitrary URLs and there is no authentication.

## 0.7.0 — ruleset 2026.11

- CVE coverage grows: jQuery versions are now fingerprinted from the
  page source (script URLs such as jquery-1.12.4.min.js) and matched
  against NVD like server software. Bootstrap was probed and dropped:
  its CPE returns nothing in NVD under either vendor name, and this
  map only ships entries verified live.
- New info check: an HSTS policy that meets the browser preload
  requirements (max-age >= 1 year + includeSubDomains) but is missing
  the preload directive is called out, with the removal warning.
- `--output FILE` writes any report format to a file (banner-free).

## 0.6.0 — ruleset 2026.11

- Known-vulnerability check: SiteVigil fingerprints software and
  versions (Server / X-Powered-By headers, generator meta tags) for
  nginx, Apache, PHP, OpenSSL, IIS, WordPress, Drupal and Joomla, then
  matches them against the NVD database. Matches are verified
  client-side against each CVE's vulnerable CPE configurations and
  version ranges -- raw NVD search results also contain products that
  merely mention yours, and trusting them produces confident nonsense.
- CVE findings carry the NVD primary CVSS score (severity derives from
  it), the NVD link, and the standard caveat: distributions backport
  fixes without changing version strings, so verify before panicking.
- Results are cached on disk for 24 hours (NVD's no-key rate limit is
  5 requests per 30 seconds); `--no-cve` skips the lookup entirely.

## 0.5.0 — ruleset 2026.11

- Redirect-chain analysis on every audit: the full chain is recorded in
  the report, an HTTPS -> HTTP downgrade hop is a high finding, and a
  chain longer than 3 hops is flagged.
- `--crawl N`: audit up to N pages of one site, discovered from
  sitemap.xml (one index level) or, failing that, homepage links.
- `--badge`: print a shields.io-style SVG score badge for READMEs.
- `--fix` now also covers COOP and CORP findings.
- Check catalog completed (redirect checks, hsts-short,
  powered-by-header): 37 entries.

## 0.4.1

- Banner redrawn as outline graffiti tag art (hollow stroke letters,
  spray dots, paint drips) in the terminal and README.

## 0.4.0 — ruleset 2026.11

- New checks: Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy,
  CSP hardening directives (object-src / base-uri), deprecated TLS
  versions (RFC 8996), HTTP/2 via ALPN.
- New domain checks over DNS-over-HTTPS: SPF, DMARC (plus a monitor-only
  `p=none` note) and CAA — DMARC/SPF only fire when the domain actually
  receives mail. Answers are filtered by record type (a CNAME in an MX
  answer is not an MX record).
- `sitevigil --checks` lists the whole catalog with references.
- ASCII banner in text output (`--no-banner` to hide it).
- Example weekly GitHub Action in `examples/github-action/`.

## 0.3.0

- Platform detection (Vercel, Netlify, Cloudflare Pages, GitHub Pages,
  nginx, Apache, generic).
- `--fix`: ready-to-commit header config per platform; honest
  platform-limit note for GitHub Pages.
- `--baseline`: regression diff against a previous report.
- MCP: second tool, `suggest_fix`.

## 0.2.1

- MCP config examples for Claude Code/Desktop, Cursor, Windsurf,
  VS Code and Gemini CLI; interoperability verified against the
  official MCP SDK client.

## 0.2.0

- New checks: mixed content, missing SRI, TRACE, security.txt.
- Multi-URL scans with summary; `--html` self-contained reports.

## 0.1.0

- First release: headers, cookies, TLS, CORS, exposed files
  (content-verified), scoring, CLI + MCP (`audit_site`), MIT license.
