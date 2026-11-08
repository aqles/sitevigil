# Changelog

SiteVigil versions its audit ruleset separately (shown in every report
and via `sitevigil --checks`) so results stay comparable over time and
changes to what is checked are never silent.

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
