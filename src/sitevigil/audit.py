"""SiteVigil core audit. Standard library only.

Checks a live website for the misconfigurations that show up again and
again in real audits: missing security headers, weak cookies, TLS
problems, CORS reflection, and exposed sensitive files. Every finding
carries the observed value and a concrete fix.

Exposed-file checks require a content marker, never just HTTP 200 --
single-page apps often answer 200 with index.html for every path
(soft 404), and flagging those would be a false positive.
"""
from __future__ import annotations

import html
import json
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.client import IncompleteRead
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler

from . import __version__

USER_AGENT = f"SiteVigil/{__version__} (+https://github.com/aqles/sitevigil)"
WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
MAX_BODY = 65536

# The check catalog is versioned so a report can say which ruleset
# produced it. Bump this (and CHANGELOG.md) whenever checks change --
# that is what "always up to date" means in practice for this tool.
RULESET_VERSION = "2026.11"
CHECKS = [
    ("no-https", "critical", "Site is served over HTTPS", "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security"),
    ("http-no-redirect", "high", "HTTP redirects to HTTPS", "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security"),
    ("redirect-downgrade", "high", "Redirect chain never downgrades HTTPS to HTTP", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Redirections"),
    ("redirect-chain-long", "low", "Redirect chain is short (3 hops or fewer)", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Redirections"),
    ("hsts-short", "low", "HSTS max-age is at least 180 days", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security"),
    ("hsts-preload", "info", "HSTS preload status", "https://hstspreload.org/"),
    ("tls-expired", "critical", "TLS certificate is valid and not expiring", "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security"),
    ("tls-expiring", "high", "TLS certificate is valid and not expiring", "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security"),
    ("tls-untrusted", "high", "TLS certificate passes verification", "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security"),
    ("tls-error", "high", "TLS handshake succeeds", "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security"),
    ("csp-unsafe-inline", "low", "CSP does not allow inline scripts/styles", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP"),
    ("csp-unsafe-eval", "low", "CSP does not allow eval()", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP"),
    ("csp-wildcard", "low", "CSP does not use a wildcard source", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP"),
    ("tls-weak-protocol", "high", "TLS 1.2 or newer (no TLS 1.0/1.1)", "https://datatracker.ietf.org/doc/html/rfc8996"),
    ("http2-not-offered", "info", "HTTP/2 offered via ALPN", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/HTTP2"),
    ("hsts-missing", "medium", "Strict-Transport-Security header", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security"),
    ("csp-missing", "medium", "Content-Security-Policy header", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP"),
    ("csp-hardening", "low", "CSP includes object-src and base-uri restrictions", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP"),
    ("nosniff-missing", "low", "X-Content-Type-Options: nosniff", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options"),
    ("clickjacking", "medium", "Clickjacking protection (X-Frame-Options / frame-ancestors)", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP"),
    ("referrer-policy-missing", "low", "Referrer-Policy header", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy"),
    ("permissions-policy-missing", "low", "Permissions-Policy header", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy"),
    ("coop-missing", "low", "Cross-Origin-Opener-Policy header", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy"),
    ("corp-missing", "info", "Cross-Origin-Resource-Policy header", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Resource-Policy"),
    ("cookie-*", "medium/low", "Cookies carry Secure / HttpOnly / SameSite as appropriate", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies"),
    ("cors-reflect", "high", "CORS does not reflect arbitrary origins", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS"),
    ("mixed-content", "medium", "No HTTP subresources on HTTPS pages", "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"),
    ("sri-missing", "low", "Cross-origin scripts use Subresource Integrity", "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"),
    ("trace-enabled", "medium", "HTTP TRACE method disabled", "https://owasp.org/www-project-web-security-testing-guide/"),
    ("exposed/.env", "critical", "No exposed .env file", "https://owasp.org/www-project-web-security-testing-guide/"),
    ("exposed/.git/HEAD", "critical", "No exposed .git metadata", "https://owasp.org/www-project-web-security-testing-guide/"),
    ("security-txt-missing", "info", "security.txt published (RFC 9116)", "https://www.rfc-editor.org/rfc/rfc9116"),
    ("dmarc-missing", "medium", "DMARC record present when the domain receives mail", "https://dmarc.org/"),
    ("dmarc-monitor-only", "info", "DMARC policy enforces (not p=none forever)", "https://dmarc.org/"),
    ("spf-missing", "low", "SPF record present when the domain receives mail", "https://www.rfc-editor.org/rfc/rfc7208"),
    ("caa-missing", "info", "CAA record restricts certificate issuance", "https://www.rfc-editor.org/rfc/rfc8659"),
    ("server-header", "info", "Server / X-Powered-By do not disclose stack details", "https://owasp.org/www-project-web-security-testing-guide/"),
    ("powered-by-header", "info", "Server / X-Powered-By do not disclose stack details", "https://owasp.org/www-project-web-security-testing-guide/"),
    ("cve-*", "varies", "Known CVEs affecting the detected software version (NVD)", "https://nvd.nist.gov/"),
    ("cve-overflow", "info", "Total known-CVE count when more than 10 match a version", "https://nvd.nist.gov/"),
    ("slow-response", "low", "Main page responds within 3 seconds", "https://developer.mozilla.org/en-US/docs/Web/Performance"),
    ("db-port-exposed", "high", "Database ports (MySQL/PostgreSQL/Redis/MongoDB) are not open to the internet", "https://owasp.org/www-project-web-security-testing-guide/"),
    ("xss-reflected", "high", "User input is not reflected unencoded (reflected XSS probe)", "https://owasp.org/www-community/attacks/xss/"),
    ("open-redirect", "medium", "Redirect parameters do not point outside the site", "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"),
    ("sqli-error", "high", "Crafted input does not leak database errors", "https://owasp.org/www-community/attacks/SQL_Injection"),
    ("http-methods-dangerous", "medium", "PUT / DELETE are not advertised (OPTIONS Allow)", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/PUT"),
    ("sqli-blind", "high", "Time-delay SQL injection does not fire (aggressive mode only)", "https://owasp.org/www-community/attacks/Blind_SQL_Injection"),
    ("http-put-write", "critical", "PUT cannot write a file to the web root (aggressive mode only)", "https://owasp.org/www-project-web-security-testing-guide/"),
]

# Latency budget for the main document fetch, and the well-known database
# ports that should never be reachable from the public internet.
SLOW_RESPONSE_MS = 3000
DB_PORTS = {3306: "MySQL/MariaDB", 5432: "PostgreSQL",
            6379: "Redis", 27017: "MongoDB"}

# The audit's phases, in order, reported to a progress callback as
# progress(label, done, total). The CLI turns this into a spinner bar;
# library and MCP callers simply pass nothing and get no output.
AUDIT_PHASES = ["Fetching page", "Redirect chain", "TLS certificate",
                "Security headers", "Cookies, CORS & exposed files",
                "DNS records", "CVE lookup (NVD)", "Database ports",
                "Active probes"]

# ANSI colours for terminal output. Stdlib only, no colour library.
_ANSI = {"reset": "\x1b[0m", "bold": "\x1b[1m", "dim": "\x1b[2m",
         "red": "\x1b[31m", "green": "\x1b[32m", "yellow": "\x1b[33m",
         "blue": "\x1b[34m", "cyan": "\x1b[36m", "grey": "\x1b[90m",
         "bright_red": "\x1b[91m", "bright_yellow": "\x1b[93m"}
_SEV_COLOR = {"critical": "bright_red", "high": "yellow", "medium": "cyan",
              "low": "grey", "info": "grey"}


def _paint(text: str, colour: str, on: bool) -> str:
    return f"{_ANSI[colour]}{text}{_ANSI['reset']}" if on else text


def _score_colour(score: int) -> str:
    return ("green" if score >= 90 else "blue" if score >= 80
            else "yellow" if score >= 65 else "red")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _read_body(resp) -> bytes:
    """Read up to MAX_BODY bytes; a truncated body reads as what
    actually arrived. Some servers answer an error page with a chunked
    body and then close the connection mid-body: http.client raises
    IncompleteRead for that, and a failed body read must never kill
    the whole audit (it crashed a live run against ednasalam.com,
    whose 404 for a probed path is truncated)."""
    try:
        return resp.read(MAX_BODY)
    except IncompleteRead as e:
        return e.partial or b""
    except Exception:
        return b""


def _fetch(url: str, timeout: float, headers: dict | None = None,
           follow: bool = True, method: str = "GET",
           data: bytes | None = None):
    """Return (status, headers-as-dict-of-lists, body-bytes, final_url)."""
    req = Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})},
                  method=method, data=data)
    opener = build_opener() if follow else build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, _group(resp.headers), _read_body(resp), resp.geturl()
    except HTTPError as e:
        return e.code, _group(e.headers), _read_body(e), url


def _group(headers) -> dict:
    out: dict[str, list[str]] = {}
    if headers:
        for k, v in headers.items():
            out.setdefault(k.lower(), []).append(v)
    return out


def _first(headers: dict, name: str) -> str | None:
    values = headers.get(name.lower())
    return values[0] if values else None


def _redirect_chain(url: str, timeout: float, max_hops: int = 10) -> list[str]:
    """Follow redirects manually, returning every URL visited (start first)."""
    chain = [url]
    current = url
    for _ in range(max_hops):
        try:
            status, headers, _, _ = _fetch(current, timeout, follow=False)
        except (URLError, socket.timeout, OSError):
            break
        if status not in (301, 302, 303, 307, 308):
            break
        location = _first(headers, "location")
        if not location:
            break
        current = urljoin(current, location)
        chain.append(current)
    return chain


_SKIP_EXT = re.compile(
    r"\.(png|jpe?g|gif|svg|webp|ico|css|js|mjs|json|pdf|zip|gz|"
    r"woff2?|ttf|mp4|mp3|webmanifest)([?#]|$)", re.I)


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href)


def discover_urls(start_url: str, timeout: float = 10.0, limit: int = 5) -> list[str]:
    """Find pages to crawl: sitemap.xml first, homepage links as fallback.

    Same-origin HTML pages only, start URL first, capped at `limit`.
    """
    url = start_url if "://" in start_url else f"https://{start_url}"
    origin = urlparse(url)
    base = f"{origin.scheme}://{origin.netloc}"
    found: list[str] = []
    seen: set[str] = set()

    def push(candidate: str) -> None:
        candidate = candidate.split("#", 1)[0]
        p = urlparse(candidate)
        if p.scheme not in ("http", "https") or p.netloc != origin.netloc:
            return
        if _SKIP_EXT.search(p.path):
            return
        key = candidate.rstrip("/") or candidate
        if key not in seen:
            seen.add(key)
            found.append(candidate)

    push(url)
    # 1) Sitemap (one level of sitemap-index is enough in practice)
    try:
        _, _, sm_body, _ = _fetch(base + "/sitemap.xml", timeout)
        locs = re.findall(r"<loc>\s*([^<]+?)\s*</loc>",
                          sm_body.decode("utf-8", errors="ignore"))
        xml_children = [u for u in locs if u.endswith(".xml")]
        if xml_children:
            _, _, child_body, _ = _fetch(xml_children[0], timeout)
            locs = re.findall(r"<loc>\s*([^<]+?)\s*</loc>",
                              child_body.decode("utf-8", errors="ignore"))
        for u in locs:
            push(u)
    except (URLError, socket.timeout, OSError):
        pass
    # 2) Homepage links, if the sitemap did not fill the budget
    if len(found) < limit:
        try:
            _, _, body, final = _fetch(url, timeout)
            parser = _LinkParser()
            parser.feed(body.decode("utf-8", errors="ignore"))
            for href in parser.links:
                push(urljoin(final, href))
        except (URLError, socket.timeout, OSError, Exception):
            pass
    return found[:limit]


def to_badge(report: dict) -> str:
    """A shields.io-style SVG badge with the score, for READMEs and docs."""
    score = report.get("score", 0)
    grade = report.get("grade", "F")
    colour = ("#1a7f37" if score >= 90 else "#1f6feb" if score >= 80
              else "#bf8700" if score >= 65 else "#bc4c00" if score >= 50
              else "#cf222e")
    label, value = "sitevigil", f"{score}/100 · grade {grade}"
    lw = int(6.8 * len(label)) + 12
    vw = int(6.8 * len(value)) + 12
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{lw + vw}" height="20" '
        f'role="img" aria-label="{label}: {value}">'
        f"<title>{label}: {value}</title>"
        f'<rect width="{lw}" height="20" fill="#555"/>'
        f'<rect x="{lw}" width="{vw}" height="20" fill="{colour}"/>'
        f'<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{lw / 2}" y="14" text-anchor="middle">{label}</text>'
        f'<text x="{lw + vw / 2}" y="14" text-anchor="middle">{value}</text>'
        f"</g></svg>")


def _hsts_preload_ready(hsts: str) -> bool:
    """True when an HSTS value satisfies the browser preload requirements
    (max-age >= 1 year + includeSubDomains) but lacks the preload token."""
    low = hsts.lower()
    m = re.search(r"max-age=(\d+)", low)
    return bool(m and int(m.group(1)) >= 31536000
                and "includesubdomains" in low and "preload" not in low)


def _check_hsts(hsts: str | None, add) -> None:
    """HSTS findings for one Strict-Transport-Security header value."""
    if not hsts:
        add("hsts-missing", "medium", "Missing Strict-Transport-Security header",
            "No HSTS header on the HTTPS response.",
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains")
        return
    m = re.search(r"max-age=(\d+)", hsts)
    if not m:
        add("hsts-short", "low", "HSTS header has no max-age",
            f"HSTS is '{hsts}': without max-age browsers treat it "
            "as max-age=0, so the header does nothing.",
            "Set max-age explicitly, e.g. Strict-Transport-Security: "
            "max-age=31536000; includeSubDomains")
    elif int(m.group(1)) < 15552000:
        add("hsts-short", "low", "HSTS max-age is short",
            f"HSTS max-age is {m.group(1)} seconds (under 180 days).",
            "Raise max-age to at least 31536000 (one year).")
    elif _hsts_preload_ready(hsts):
        add("hsts-preload", "info",
            "HSTS meets browser preload requirements but is not preloaded",
            f"HSTS is '{hsts}': long max-age and includeSubDomains are "
            "set, but the preload directive is missing, so browsers "
            "still trust-on-first-use for a visitor's very first visit.",
            "Add '; preload' to the header and submit the domain at "
            "hstspreload.org. Only do this when every subdomain is "
            "HTTPS-ready: preload removal is slow.")


def _detect_platform(headers: dict) -> str:
    server = _first(headers, "server") or ""
    if _first(headers, "x-vercel-id") or server == "Vercel":
        return "Vercel"
    if _first(headers, "x-nf-request-id") or "netlify" in server.lower():
        return "Netlify"
    if server == "GitHub.com":
        return "GitHub Pages"
    if "cloudflare" in server.lower():
        return "Cloudflare Pages"
    if "nginx" in server:
        return "nginx"
    if "Apache" in server:
        return "Apache"
    return "generic"


class _PageParser(HTMLParser):
    """Collect subresources: (tag, absolute_url, has_integrity)."""

    def __init__(self, base: str):
        super().__init__()
        self.base = base
        self.resources: list[tuple[str, str, bool]] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        url = None
        if tag in ("script", "img", "iframe", "source", "video", "audio"):
            url = a.get("src")
        elif tag == "link" and "stylesheet" in (a.get("rel") or ""):
            url = a.get("href")
        if url and not url.startswith(("data:", "blob:", "#")):
            self.resources.append(
                (tag, urljoin(self.base, url), bool(a.get("integrity"))))


def audit(raw_url: str, timeout: float = 10.0, cve: bool = True,
          ports: bool = True, progress=None, kev: bool = True,
          probes: bool = True, pentest: str = "safe") -> dict:
    url = raw_url if "://" in raw_url else f"https://{raw_url}"
    parsed = urlparse(url)
    host = parsed.hostname or ""
    findings: list[dict] = []

    def add(fid, severity, title, detail, fix, extra=None):
        finding = {"id": fid, "severity": severity, "title": title,
                   "detail": detail, "fix": fix}
        if extra:
            finding.update(extra)
        findings.append(finding)

    def step(n: int) -> None:
        if progress is not None:
            progress(AUDIT_PHASES[n - 1], n, len(AUDIT_PHASES))

    # --- Reachability + main response -------------------------------------
    started = time.perf_counter()
    try:
        status, headers, body, final_url = _fetch(url, timeout)
    except (URLError, socket.timeout, OSError) as e:
        return {"url": url, "reachable": False, "error": str(e),
                "score": 0, "grade": "F", "findings": []}
    response_ms = round((time.perf_counter() - started) * 1000)
    is_https = urlparse(final_url).scheme == "https"

    if response_ms > SLOW_RESPONSE_MS:
        add("slow-response", "low", "Main page response is slow",
            f"Fetching {final_url} took {response_ms} ms end to end "
            f"(budget {SLOW_RESPONSE_MS} ms). A slow first response delays "
            "everything else on the page and usually means an overloaded "
            "origin, a cold cache, or a distant region.",
            "Profile where the time goes (origin CPU, database queries, "
            "cache misses); serve through a CDN/cache and from a region "
            "close to your users.")
    step(1)

    # --- Redirect chain -----------------------------------------------------
    chain = _redirect_chain(url, timeout)
    for a, b in zip(chain, chain[1:]):
        if urlparse(a).scheme == "https" and urlparse(b).scheme == "http":
            add("redirect-downgrade", "high", "Redirect chain downgrades HTTPS to HTTP",
                f"{a} redirects to {b}; anything sent between those hops "
                "travels unencrypted and can be tampered with.",
                "Make every hop in the chain HTTPS; never redirect back down to HTTP.")
            break
    if len(chain) - 1 > 3:
        add("redirect-chain-long", "low", "Redirect chain is long",
            f"{len(chain) - 1} redirects: " + " -> ".join(chain[:6])
            + (" -> ..." if len(chain) > 6 else ""),
            "Collapse the chain to at most 1-2 hops pointing straight at the "
            "final URL; each hop costs a round trip and can break HSTS coverage.")
    step(2)

    # --- HTTP -> HTTPS redirect -------------------------------------------
    # The host that matters is the one the audit actually landed on:
    # after a cross-host redirect the original host's HTTP behaviour
    # says nothing about the site being audited.
    final_host = urlparse(final_url).hostname or host
    if parsed.scheme == "https" or is_https:
        try:
            s2, _, _, final2 = _fetch(f"http://{final_host}", timeout, follow=True)
            if urlparse(final2).scheme != "https":
                add("http-no-redirect", "high", "HTTP does not redirect to HTTPS",
                    f"http://{host} answered with scheme {urlparse(final2).scheme} (status {s2}).",
                    "Redirect all HTTP traffic to HTTPS at the server or CDN level (301).")
        except (URLError, socket.timeout, OSError):
            pass  # HTTP port closed is acceptable

    if not is_https:
        add("no-https", "critical", "Site is not served over HTTPS",
            f"Final URL is {final_url}.",
            "Install a TLS certificate (e.g. Let's Encrypt) and serve the site over HTTPS only.")

    # --- TLS certificate ----------------------------------------------------
    tls: dict = {}
    if is_https:
        final_parsed = urlparse(final_url)
        tls = _check_tls(final_parsed.hostname or host,
                         final_parsed.port or 443, add, timeout=timeout)
        if tls.get("protocol") in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            add("tls-weak-protocol", "high", "Server negotiated a deprecated TLS version",
                f"Negotiated {tls['protocol']}; TLS 1.0/1.1 are deprecated (RFC 8996) "
                "and rejected by modern browsers.",
                "Disable TLS 1.0 and 1.1; serve TLS 1.2 and 1.3 only.")
        if tls and tls.get("alpn") != "h2":
            add("http2-not-offered", "info", "HTTP/2 was not negotiated",
                f"ALPN result: {tls.get('alpn') or 'none'}.",
                "Enable HTTP/2 at the server/CDN for faster, multiplexed loads.")

    step(3)

    # --- Security headers ---------------------------------------------------
    hsts = _first(headers, "strict-transport-security")
    if is_https:
        _check_hsts(hsts, add)

    csp = _first(headers, "content-security-policy")
    if not csp:
        add("csp-missing", "medium", "Missing Content-Security-Policy header",
            "No CSP header; the page has no second line of defence against XSS.",
            "Add a CSP that fits your site, starting strict, e.g. "
            "Content-Security-Policy: default-src 'self'")
    else:
        for token, fid, label in (
                ("'unsafe-inline'", "csp-unsafe-inline",
                 "allows inline scripts/styles ('unsafe-inline')"),
                ("'unsafe-eval'", "csp-unsafe-eval", "allows eval() ('unsafe-eval')"),
                ("*", "csp-wildcard", "uses a wildcard source (*)")):
            # '*' only counts as a standalone source token -- a subdomain
            # wildcard like https://*.example.com is a deliberate choice
            hit = token in csp if token != "*" else re.search(r"(?:^|[;\s])\*(?:[;\s]|$)", csp)
            if hit:
                add(fid, "low", "Content-Security-Policy is permissive",
                    f"CSP {label}: {csp[:160]}",
                    "Tighten the policy: replace wildcards/'unsafe-inline' with specific "
                    "sources and nonces or hashes where possible.")

    if (_first(headers, "x-content-type-options") or "").lower() != "nosniff":
        add("nosniff-missing", "low", "Missing X-Content-Type-Options: nosniff",
            "Header absent or not set to 'nosniff'.",
            "Add: X-Content-Type-Options: nosniff")

    xfo = (_first(headers, "x-frame-options") or "").upper()
    frame_ancestors = csp and "frame-ancestors" in csp
    if xfo not in ("DENY", "SAMEORIGIN") and not frame_ancestors:
        add("clickjacking", "medium", "No clickjacking protection",
            "Neither X-Frame-Options (DENY/SAMEORIGIN) nor CSP frame-ancestors is set.",
            "Add: X-Frame-Options: DENY (or SAMEORIGIN), or frame-ancestors 'none' in your CSP.")

    if not _first(headers, "referrer-policy"):
        add("referrer-policy-missing", "low", "Missing Referrer-Policy header",
            "Header absent; full URLs may leak to third parties via the Referer header.",
            "Add: Referrer-Policy: strict-origin-when-cross-origin")

    if not _first(headers, "permissions-policy"):
        add("permissions-policy-missing", "low", "Missing Permissions-Policy header",
            "Header absent; browser features (camera, mic, geolocation) are not restricted.",
            "Add a Permissions-Policy disabling features you do not use, e.g. "
            "Permissions-Policy: camera=(), microphone=(), geolocation=()")

    if not _first(headers, "cross-origin-opener-policy"):
        add("coop-missing", "low", "Missing Cross-Origin-Opener-Policy header",
            "Header absent; a malicious page that opens this site in a popup "
            "keeps a window reference to it (cross-origin isolation missing).",
            "Add: Cross-Origin-Opener-Policy: same-origin")

    if not _first(headers, "cross-origin-resource-policy"):
        add("corp-missing", "info", "Missing Cross-Origin-Resource-Policy header",
            "Header absent; other origins may embed this site's resources.",
            "Add: Cross-Origin-Resource-Policy: same-origin (or same-site if "
            "your subdomains must embed them).")

    if csp and ("object-src" not in csp or "base-uri" not in csp):
        missing = [d for d in ("object-src", "base-uri") if d not in csp]
        add("csp-hardening", "low", "Content-Security-Policy misses hardening directives",
            f"CSP does not set: {', '.join(missing)}.",
            "Add object-src 'none' and base-uri 'self' to the policy to close "
            "plugin-content and base-tag injection gaps.")

    # --- Info disclosure ------------------------------------------------------
    for name, fid in (("server", "server-header"), ("x-powered-by", "powered-by-header")):
        value = _first(headers, name)
        if value:
            add(fid, "info", f"{name} header discloses software details",
                f"{name}: {value}",
                f"Remove or genericise the {name} header so attackers learn less about your stack.")

    step(4)

    # --- Cookies ---------------------------------------------------------------
    for raw in headers.get("set-cookie", []):
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        if is_https and "secure" not in low:
            add(f"cookie-no-secure-{name}", "medium", f"Cookie '{name}' lacks the Secure flag",
                raw[:160], "Set the Secure attribute so the cookie is only sent over HTTPS.")
        if "httponly" not in low and re.search(r"sess|auth|token|login", name, re.I):
            add(f"cookie-no-httponly-{name}", "medium",
                f"Session-like cookie '{name}' lacks HttpOnly",
                raw[:160], "Set HttpOnly so JavaScript cannot read the session cookie.")
        if "samesite" not in low:
            add(f"cookie-no-samesite-{name}", "low", f"Cookie '{name}' lacks SameSite",
                raw[:160], "Set SameSite=Lax (or Strict) to limit cross-site sending.")

    # --- CORS reflection ---------------------------------------------------------
    evil = "https://evil.example"
    try:
        _, cors_headers, _, _ = _fetch(url, timeout, headers={"Origin": evil})
        acao = _first(cors_headers, "access-control-allow-origin")
        acac = (_first(cors_headers, "access-control-allow-credentials") or "").lower()
        if acao == evil or (acao == "*" and acac == "true"):
            add("cors-reflect", "high", "CORS reflects arbitrary origins",
                f"Access-Control-Allow-Origin answered '{acao}' to Origin: {evil}"
                + (" with credentials allowed." if acac == "true" else "."),
                "Only allowlist origins you trust; never reflect arbitrary Origin values, "
                "especially not with credentials.")
    except (URLError, socket.timeout, OSError):
        pass

    # --- Exposed sensitive files (content marker required) -----------------------
    _fin = urlparse(final_url)
    base = f"{_fin.scheme}://{_fin.netloc}"
    exposed = (
        ("/.env", lambda b: bool(re.search(rb"(?m)^[A-Z0-9_]*(KEY|SECRET|TOKEN|PASSWORD)\s*=", b)),
         "environment file with secrets"),
        ("/.git/HEAD", lambda b: b.lstrip().startswith(b"ref:"),
         "git repository metadata"),
        ("/.git/config", lambda b: b"[core]" in b or b"[remote" in b,
         "git configuration"),
    )
    for path, marker, label in exposed:
        try:
            s3, _, body3, _ = _fetch(base + path, timeout)
            if s3 == 200 and marker(body3):
                add(f"exposed{path}", "critical", f"Exposed {label} at {path}",
                    f"GET {path} returned 200 with content matching a real {label}.",
                    f"Block access to {path} at the server/CDN and rotate any secrets it contained.")
        except (URLError, socket.timeout, OSError):
            pass

    # --- Page content: mixed content + missing SRI --------------------------
    if is_https and body:
        parser = _PageParser(final_url)
        try:
            parser.feed(body.decode("utf-8", errors="ignore"))
        except Exception:
            pass
        mixed = [u for _, u, _ in parser.resources if u.startswith("http://")]
        if mixed:
            add("mixed-content", "medium", "Mixed content: HTTP subresources on an HTTPS page",
                f"{len(mixed)} subresource(s) load over plain HTTP, e.g. {mixed[0][:120]}",
                "Serve every subresource over HTTPS (or a protocol-relative URL) "
                "so the page cannot be tampered with in transit.")
        final_host = urlparse(final_url).hostname
        no_sri = [u for tag, u, integ in parser.resources
                  if tag == "script" and not integ
                  and urlparse(u).hostname != final_host]
        if no_sri:
            add("sri-missing", "low", "External scripts without Subresource Integrity",
                f"{len(no_sri)} cross-origin script(s) have no integrity attribute, "
                f"e.g. {no_sri[0][:120]}",
                "Add integrity=\"sha384-...\" (and crossorigin=\"anonymous\") to "
                "third-party script tags, or self-host the scripts.")

    # --- TRACE method ---------------------------------------------------------
    try:
        s4, _, body4, _ = _fetch(final_url, timeout, method="TRACE",
                                 headers={"X-SiteVigil-Probe": "1"})
        if s4 == 200 and b"x-sitevigil-probe" in body4.lower():
            add("trace-enabled", "medium", "HTTP TRACE method is enabled",
                "The server echoed a TRACE request back (Cross-Site Tracing risk).",
                "Disable the TRACE method on your server or CDN.")
    except (URLError, socket.timeout, OSError):
        pass

    # --- security.txt (presence requires a Contact: line, anti soft-404) ------
    try:
        s5, _, body5, _ = _fetch(base + "/.well-known/security.txt", timeout)
        if not (s5 == 200 and b"contact:" in body5.lower()):
            add("security-txt-missing", "info", "No security.txt",
                "/.well-known/security.txt is absent or has no Contact: line.",
                "Publish a security.txt (RFC 9116) so researchers can report "
                "vulnerabilities to you instead of posting them publicly.")
    except (URLError, socket.timeout, OSError):
        pass

    step(5)

    # --- Domain email / issuance records (DNS-over-HTTPS) -------------------
    _check_domain(host, add, timeout=timeout)
    step(6)

    # --- Known vulnerabilities for fingerprinted software -------------------
    body_text = body.decode("utf-8", errors="ignore") if body else ""
    software = _fingerprints(headers, body_text)
    if cve:
        kev_map = _kev_lookup() if (kev and software) else None
        for fp in software:
            hits = _cve_lookup(fp["product"], fp["version"])
            if not hits:
                continue
            for hit in hits[:10]:
                cvss = hit["cvss"]
                severity = ("critical" if cvss is not None and cvss >= 9 else
                            "high" if cvss is not None and cvss >= 7 else
                            "medium" if cvss is not None and cvss >= 4 else "low")
                kev_date = kev_map.get(hit["id"]) if kev_map else None
                title = (f"{fp['name']} {fp['version']} is affected by "
                         f"{hit['id']}"
                         + (f" (CVSS {cvss})" if cvss is not None else ""))
                detail = (f"Detected via {fp['via']}. {hit['description']} "
                          "Fingerprint-based match: distributions sometimes "
                          "backport security fixes without changing the "
                          "version string, so confirm against your package "
                          "changelog.")
                extra = None
                if kev_date:
                    title += (f" — KNOWN EXPLOITED (CISA KEV, added "
                              f"{kev_date})")
                    detail = (f"CISA lists {hit['id']} as known exploited "
                              f"in the wild (added to the KEV catalog "
                              f"{kev_date}). Patch this one first. " + detail)
                    extra = {"kev": True, "kev_date_added": kev_date}
                add(hit["id"].lower(), severity, title, detail,
                    f"Upgrade {fp['name']} to a release where {hit['id']} is "
                    f"fixed (https://nvd.nist.gov/vuln/detail/{hit['id']}), "
                    "or verify your distribution backported the patch.",
                    extra=extra)
            if len(hits) > 10:
                add("cve-overflow", "info",
                    f"{fp['name']} {fp['version']} has {len(hits)} known CVEs",
                    f"Only the 10 highest-CVSS matches are listed above; "
                    f"{len(hits)} CVEs in total match this version in NVD.",
                    f"Upgrade {fp['name']} to a supported release; the long "
                    "tail of old CVEs disappears with it.")

    step(7)

    # --- Exposed database ports --------------------------------------------
    open_db_ports: list[int] = []
    if ports:
        # TCP connects get the audit timeout, capped: a filtered port
        # must not burn the whole fetch budget four times over.
        open_db_ports = _check_db_ports(host, add, timeout=min(timeout, 2.5))
    step(8)

    # --- Active probes (non-destructive input tests) ---------------------
    if probes:
        _active_probes(final_url, timeout, add, pentest)
    step(9)

    score = max(0, 100 - sum(WEIGHTS[f["severity"]] for f in findings))
    grade = ("A" if score >= 90 else "B" if score >= 80 else
             "C" if score >= 65 else "D" if score >= 50 else "F")
    return {"url": url, "final_url": final_url, "status": status,
            "reachable": True, "platform": _detect_platform(headers),
            "ruleset": RULESET_VERSION, "redirect_chain": chain,
            "response_time_ms": response_ms, "open_db_ports": open_db_ports,
            "software": software,
            "tls": tls, "score": score, "grade": grade,
            "pentest_mode": pentest if probes else "off",
            "findings": findings}


# Finding id -> the response header that resolves it, where one exists.
HEADER_FIXES = {
    "hsts-missing": ("Strict-Transport-Security",
                     "max-age=31536000; includeSubDomains"),
    "hsts-short": ("Strict-Transport-Security",
                   "max-age=31536000; includeSubDomains"),
    "csp-missing": ("Content-Security-Policy",
                    "default-src 'self'; script-src 'self'; "
                    "style-src 'self' 'unsafe-inline'; "
                    "img-src 'self' data: https:; font-src 'self' data: https:; "
                    "connect-src 'self' https:; frame-ancestors 'none'; "
                    "base-uri 'self'; form-action 'self'"),
    "nosniff-missing": ("X-Content-Type-Options", "nosniff"),
    "clickjacking": ("X-Frame-Options", "DENY"),
    "referrer-policy-missing": ("Referrer-Policy",
                                "strict-origin-when-cross-origin"),
    "permissions-policy-missing": ("Permissions-Policy",
                                   "camera=(), microphone=(), geolocation=()"),
    "coop-missing": ("Cross-Origin-Opener-Policy", "same-origin"),
    "corp-missing": ("Cross-Origin-Resource-Policy", "same-origin"),
}


def needed_headers(report: dict) -> list[tuple[str, str]]:
    out, seen = [], set()
    for f in report.get("findings", []):
        fix = HEADER_FIXES.get(f["id"])
        if fix and fix[0] not in seen:
            seen.add(fix[0])
            out.append(fix)
    return out


def generate_fix(report: dict) -> dict:
    """Turn header findings into a ready-to-commit config for the platform.

    This is the step free web checkers stop short of: they grade you,
    SiteVigil hands you the patch.
    """
    platform = report.get("platform", "generic")
    headers = needed_headers(report)
    if not headers:
        return {"platform": platform, "filename": None,
                "content": "", "notes": "No header fixes needed."}
    if platform == "Vercel":
        content = json.dumps({"headers": [{
            "source": "/(.*)",
            "headers": [{"key": k, "value": v} for k, v in headers]}]}, indent=2)
        return {"platform": platform, "filename": "vercel.json",
                "content": content,
                "notes": "Merge this headers entry into vercel.json (or add the "
                         "same headers in next.config.js if the project has one), "
                         "then redeploy. Review the CSP first: tighten it to the "
                         "origins your site actually calls."}
    if platform in ("Netlify", "Cloudflare Pages"):
        lines = ["/*"] + [f"  {k}: {v}" for k, v in headers]
        return {"platform": platform, "filename": "_headers",
                "content": "\n".join(lines) + "\n",
                "notes": "Put _headers in your publish/output directory and redeploy. "
                         "Review the CSP first: tighten it to the origins your site "
                         "actually calls."}
    if platform == "GitHub Pages":
        lines = ["/*"] + [f"  {k}: {v}" for k, v in headers]
        return {"platform": platform, "filename": "_headers",
                "content": "\n".join(lines) + "\n",
                "notes": "GitHub Pages cannot set response headers at all -- this is "
                         "a platform limit, not a misconfiguration. The _headers file "
                         "above applies if you move the site to Cloudflare Pages or "
                         "Netlify, or put a Cloudflare proxy in front of Pages."}
    if platform == "nginx":
        lines = [f'add_header {k} "{v}" always;' for k, v in headers]
        return {"platform": platform, "filename": "sitevigil-headers.conf",
                "content": "\n".join(lines) + "\n",
                "notes": "Include this inside your server {} block and reload nginx."}
    if platform == "Apache":
        lines = (["<IfModule mod_headers.c>"] +
                 [f'Header set {k} "{v}"' for k, v in headers] +
                 ["</IfModule>"])
        return {"platform": platform, "filename": ".htaccess",
                "content": "\n".join(lines) + "\n",
                "notes": "Add this to .htaccess (requires mod_headers) and reload Apache."}
    lines = [f"{k}: {v}" for k, v in headers]
    return {"platform": platform, "filename": "headers.txt",
            "content": "\n".join(lines) + "\n",
            "notes": "Set these response headers in your server or framework config "
                     "for every route, then re-run SiteVigil to confirm."}


def compare_reports(baseline: dict, current: dict) -> dict:
    """Diff two reports: which findings are new, which were resolved."""
    base_ids = {f["id"] for f in baseline.get("findings", [])}
    cur = {f["id"]: f for f in current.get("findings", [])}
    return {
        "new": [f for fid, f in cur.items() if fid not in base_ids],
        "resolved": [fid for fid in base_ids if fid not in cur],
        "score_delta": current.get("score", 0) - baseline.get("score", 0),
        "baseline_score": baseline.get("score"),
        "current_score": current.get("score"),
    }


def _no_proxy_match(host: str, no_proxy: str) -> bool:
    """Standard no_proxy matching: comma-separated entries, each an
    exact host, a domain suffix (example.com also matches
    api.example.com), or '*' for everything. Entries are stripped and
    matching is case-insensitive; a bare exact `in` check misses all
    three cases."""
    host = host.lower()
    for entry in no_proxy.split(","):
        entry = entry.strip().lower().lstrip(".")
        if not entry:
            continue
        if entry == "*" or host == entry or host.endswith("." + entry):
            return True
    return False


def _tls_connect(host: str, port: int, timeout: float = 10):
    """TCP connection to host:port, honouring https_proxy (CONNECT) so the
    TLS check also works behind corporate proxies, where a direct socket
    would hit the proxy and fail with WRONG_VERSION_NUMBER."""
    import base64
    import os

    proxy = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
    no_proxy = os.environ.get("no_proxy") or os.environ.get("NO_PROXY") or ""
    if not proxy or _no_proxy_match(host, no_proxy):
        return socket.create_connection((host, port), timeout=timeout)
    p = urlparse(proxy)
    raw = socket.create_connection((p.hostname, p.port or 8080), timeout=timeout)
    auth = ""
    if p.username:
        creds = base64.b64encode(
            f"{p.username}:{p.password or ''}".encode()).decode()
        auth = f"Proxy-Authorization: Basic {creds}\r\n"
    raw.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                f"{auth}\r\n".encode())
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = raw.recv(4096)
        if not chunk:
            break
        response += chunk
    if b" 200 " not in response.split(b"\r\n", 1)[0] and \
            not response.startswith(b"HTTP/1.1 200"):
        raw.close()
        raise OSError(f"proxy CONNECT failed: {response[:80]!r}")
    return raw


_DNS_TYPES = {"MX": 15, "TXT": 16, "CAA": 257}


def _doh(name: str, rtype: str, timeout: float = 5.0) -> list[str]:
    """DNS-over-HTTPS lookup (Cloudflare), returning record data strings.

    Answers are filtered to the requested record type: for a hostname
    behind a CNAME, the resolver includes the CNAME record itself in the
    answer, and counting it as (say) an MX record once produced false
    'this domain receives mail' findings for plain website subdomains.
    """
    from urllib.request import urlopen

    req = Request(
        f"https://cloudflare-dns.com/dns-query?name={name}&type={rtype}",
        headers={"accept": "application/dns-json", "User-Agent": USER_AGENT})
    with urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read())
    want = _DNS_TYPES[rtype]
    return [str(a.get("data", "")) for a in data.get("Answer", [])
            if a.get("type") == want]


def _check_domain(host: str, add, timeout: float = 5.0) -> None:
    """Email-auth and issuance records for the site's domain.

    Only fires when the domain actually receives mail (has MX records):
    a site that sends no email is not told to invent DMARC records.
    All lookups fail silently -- DNS being unreachable must never break
    or falsify the web audit.
    """
    import ipaddress

    if not host or "." not in host:
        return
    try:
        ipaddress.ip_address(host)
        return  # bare IP: no domain records to check
    except ValueError:
        pass
    domain = host[4:] if host.startswith("www.") else host
    try:
        mx = _doh(domain, "MX", timeout=timeout)
        if mx:
            txt = _doh(domain, "TXT", timeout=timeout)
            if not any(t.strip('"').lower().startswith("v=spf1") for t in txt):
                add("spf-missing", "low", "No SPF record for a mail-receiving domain",
                    f"{domain} has MX records but no v=spf1 TXT record.",
                    "Publish an SPF TXT record listing the services allowed to "
                    "send mail for your domain.")
            dmarc = _doh(f"_dmarc.{domain}", "TXT", timeout=timeout)
            dmarc_rec = next((t for t in dmarc if "v=dmarc1" in t.lower()), None)
            if not dmarc_rec:
                add("dmarc-missing", "medium", "No DMARC record for a mail-receiving domain",
                    f"{domain} receives mail (MX present) but _dmarc.{domain} "
                    "has no DMARC policy; anyone can spoof mail from this domain.",
                    "Publish a DMARC TXT record at _dmarc (start with p=none to "
                    "monitor, then move to p=reject).")
            elif "p=none" in dmarc_rec.lower().replace(" ", ""):
                add("dmarc-monitor-only", "info", "DMARC policy is monitor-only (p=none)",
                    f"_dmarc.{domain} is set to p=none: spoofed mail is reported "
                    "but still delivered.",
                    "Once the DMARC reports look clean, step up to p=quarantine "
                    "and then p=reject so spoofed mail is actually blocked.")
        caa = _doh(domain, "CAA", timeout=timeout)
        if not caa:
            add("caa-missing", "info", "No CAA record",
                f"{domain} has no CAA records; any CA may issue certificates for it.",
                "Add CAA records naming only the CA(s) you actually use.")
    except Exception:
        pass


# --- Known-vulnerability (CVE) matching -----------------------------------
# Fingerprinted product -> (display name, NVD CPE vendor, NVD CPE product).
# nginx CVEs live under the f5 vendor in NVD since the F5 acquisition;
# querying the old nginx:nginx CPE silently returns nothing.
_CVE_PRODUCTS = {
    "nginx": ("nginx", "f5", "nginx"),
    "apache": ("Apache HTTP Server", "apache", "http_server"),
    "php": ("PHP", "php", "php"),
    "openssl": ("OpenSSL", "openssl", "openssl"),
    "iis": ("Microsoft IIS", "microsoft", "internet_information_services"),
    "wordpress": ("WordPress", "wordpress", "wordpress"),
    "drupal": ("Drupal", "drupal", "drupal"),
    "joomla": ("Joomla", "joomla", "joomla!"),
    # Only products whose NVD CPE was verified live belong in this map:
    # Bootstrap was probed under two vendors and returned nothing, so it
    # is deliberately absent rather than silently always-zero.
    "jquery": ("jQuery", "jquery", "jquery"),
    # WordPress plugins, keyed wp:<slug>. Every entry was verified live
    # against NVD before being added (dictionary CPE + a real CVE match
    # for an old version). Elementor's product is "website_builder" --
    # guessing "elementor" silently returns zero CVEs forever.
    "wp:elementor": ("Elementor (WordPress plugin)", "elementor", "website_builder"),
    "wp:woocommerce": ("WooCommerce (WordPress plugin)", "woocommerce", "woocommerce"),
    "wp:contact-form-7": ("Contact Form 7 (WordPress plugin)", "rocklobster", "contact_form_7"),
    "wp:akismet": ("Akismet (WordPress plugin)", "automattic", "akismet"),
}


def _fingerprints(headers: dict, body_text: str) -> list[dict]:
    """Detect software + version from headers and the page's generator tag.

    A version is required: without one there is nothing honest to match
    CVEs against, so unversioned banners are simply not reported.
    """
    found: dict[str, tuple[str, str]] = {}
    sources = [(_first(headers, "server") or "", "Server header"),
               (_first(headers, "x-powered-by") or "", "X-Powered-By header")]
    for text, source in sources:
        for pattern, key in ((r"nginx/([\d.]+)", "nginx"),
                             (r"Apache/([\d.]+)", "apache"),
                             (r"Microsoft-IIS/([\d.]+)", "iis"),
                             (r"PHP/([\d.]+)", "php"),
                             (r"OpenSSL/([\d.]+[a-z]?)", "openssl")):
            m = re.search(pattern, text, re.I)
            if m and key not in found:
                found[key] = (m.group(1), source)
    generator = None
    if body_text:
        m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)',
                      body_text, re.I) or \
            re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]*name=["\']generator["\']',
                      body_text, re.I)
        if m:
            generator = m.group(1)
    for text, source in ((generator, "meta generator tag"),
                         (_first(headers, "x-generator"), "X-Generator header")):
        if not text:
            continue
        for pattern, key in ((r"WordPress\s+([\d.]+)", "wordpress"),
                             (r"Drupal\s+([\d.]+)", "drupal"),
                             (r"Joomla!?\s+([\d.]+)", "joomla")):
            m = re.search(pattern, text, re.I)
            if m and key not in found:
                found[key] = (m.group(1), source)
    if body_text:
        for pattern in (r"jquery[-./]v?(\d+\.\d+\.\d+)",
                        r"jquery(?:\.min)?\.js\?ver=(\d+\.\d+\.\d+)"):
            m = re.search(pattern, body_text, re.I)
            if m and "jquery" not in found:
                found["jquery"] = (m.group(1), "page source")
                break
        # WordPress plugins: version comes from the ?ver= that WordPress
        # appends to each plugin's own asset URLs. If a plugin's assets
        # disagree about the version, the fingerprint is ambiguous and
        # the plugin is skipped -- no version, no claim.
        plugin_versions: dict[str, set[str]] = {}
        for slug, ver in re.findall(
                r"/wp-content/plugins/([a-z0-9\-_]+)/[^\"'\s<>]*?[?&]ver=([\d.]+)",
                body_text, re.I):
            plugin_versions.setdefault(slug.lower(), set()).add(ver)
        for slug, versions in plugin_versions.items():
            key = f"wp:{slug}"
            if key in _CVE_PRODUCTS and len(versions) == 1 and key not in found:
                found[key] = (next(iter(versions)),
                              "page source (WordPress plugin asset)")
    return [{"product": key, "name": _CVE_PRODUCTS[key][0],
             "version": version, "via": source}
            for key, (version, source) in found.items()]


def _vkey(version: str) -> list:
    parts = []
    for token in re.split(r"[.\-+_]", str(version).strip()):
        m = re.match(r"(\d*)([a-zA-Z]*)", token)
        parts.append((int(m.group(1)) if m.group(1) else 0, m.group(2)))
    return parts


def _vcmp(a: str, b: str) -> int:
    ka, kb = _vkey(a), _vkey(b)
    n = max(len(ka), len(kb))
    ka += [(0, "")] * (n - len(ka))
    kb += [(0, "")] * (n - len(kb))
    return (ka > kb) - (ka < kb)


def _cpe_match(match: dict, vendor: str, product: str, version: str) -> bool:
    """True only for a *vulnerable* CPE entry whose range covers `version`.

    NVD search results also contain CVEs that merely mention the product
    (running-on/with entries, negated matches); trusting the raw result
    set without this filter produces confident nonsense.
    """
    if not match.get("vulnerable"):
        return False
    parts = match.get("criteria", "").split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return False
    if (parts[3].replace("\\", "").lower(),
            parts[4].replace("\\", "").lower()) != (vendor, product):
        return False
    criteria_version = parts[5]
    if criteria_version not in ("*", "-"):
        return _vcmp(version, criteria_version) == 0
    if "versionStartIncluding" in match and \
            _vcmp(version, match["versionStartIncluding"]) < 0:
        return False
    if "versionStartExcluding" in match and \
            _vcmp(version, match["versionStartExcluding"]) <= 0:
        return False
    if "versionEndIncluding" in match and \
            _vcmp(version, match["versionEndIncluding"]) > 0:
        return False
    if "versionEndExcluding" in match and \
            _vcmp(version, match["versionEndExcluding"]) >= 0:
        return False
    return True


def _cve_matches(cve_obj: dict, vendor: str, product: str, version: str) -> bool:
    def walk(nodes) -> bool:
        for node in nodes or []:
            if any(_cpe_match(m, vendor, product, version)
                   for m in node.get("cpeMatch", [])):
                return True
            if walk(node.get("children")):
                return True
        return False

    return any(walk(cfg.get("nodes"))
               for cfg in cve_obj.get("configurations", []))


_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_last_nvd_call = [0.0]


def _nvd_query(vendor: str, product: str, version: str) -> dict:
    from urllib.parse import quote
    from urllib.request import urlopen

    match = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    url = (f"{_NVD_API}?virtualMatchString={quote(match, safe='')}"
           "&resultsPerPage=200")
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=20) as resp:
        return json.loads(resp.read())


def _cve_lookup(product_key: str, version: str) -> list[dict] | None:
    """CVEs affecting one product version, cached on disk for 24 hours.

    Returns None when NVD is unreachable (the audit then simply has no
    CVE section -- a network failure must never fail or falsify it).
    """
    import os
    import time

    _, vendor, product = _CVE_PRODUCTS[product_key]
    cache_dir = os.environ.get("SITEVIGIL_CACHE_DIR") or os.path.join(
        os.path.expanduser("~"), ".cache", "sitevigil")
    path = os.path.join(
        cache_dir, "cve", f"{vendor}-{product}-{version}.json".replace("/", "_"))
    try:
        if os.path.exists(path) and time.time() - os.path.getmtime(path) < 86400:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)["cves"]
    except Exception:
        pass
    # NVD without an API key allows 5 requests per 30 s; space ours out.
    wait = 6.5 - (time.time() - _last_nvd_call[0])
    if _last_nvd_call[0] and wait > 0:
        time.sleep(wait)
    _last_nvd_call[0] = time.time()
    try:
        data = _nvd_query(vendor, product, version)
    except Exception:
        return None
    out = []
    for item in data.get("vulnerabilities", []):
        cve_obj = item.get("cve", {})
        if not _cve_matches(cve_obj, vendor, product, version):
            continue
        metrics = cve_obj.get("metrics", {})
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            chosen = next((e for e in entries if e.get("type") == "Primary"),
                          entries[0] if entries else None)
            if chosen:
                cvss = (chosen.get("cvssData") or {}).get("baseScore")
                if cvss is not None:
                    break
        desc = next((d["value"] for d in cve_obj.get("descriptions", [])
                     if d.get("lang") == "en"), "")
        out.append({"id": cve_obj.get("id"), "cvss": cvss,
                    "description": desc[:280]})
    out.sort(key=lambda hit: hit["cvss"] or 0, reverse=True)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"cves": out}, fh)
    except Exception:
        pass
    return out


_KEV_FEED = ("https://www.cisa.gov/sites/default/files/feeds/"
              "known_exploited_vulnerabilities.json")


def _kev_lookup() -> dict[str, str] | None:
    """CVE ID -> KEV dateAdded, cached on disk for 24 hours.

    Returns None when the CISA feed is unreachable -- the audit then
    simply has no KEV tags, same as an unreachable NVD means no CVE
    section. A missing tag must never be read as "not exploited".
    """
    import os
    import time
    from urllib.request import urlopen

    cache_dir = os.environ.get("SITEVIGIL_CACHE_DIR") or os.path.join(
        os.path.expanduser("~"), ".cache", "sitevigil")
    path = os.path.join(cache_dir, "kev.json")
    try:
        if os.path.exists(path) and time.time() - os.path.getmtime(path) < 86400:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)["kev"]
    except Exception:
        pass
    try:
        req = Request(_KEV_FEED, headers={"User-Agent": USER_AGENT})
        with urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
        out = {v["cveID"]: v["dateAdded"]
               for v in data.get("vulnerabilities", [])
               if v.get("cveID") and v.get("dateAdded")}
    except Exception:
        return None
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"kev": out}, fh)
    except Exception:
        pass
    return out


# Probes that send crafted input and read the response: they never write,
# delete, log in, or extract data from the target. A probe that errors or
# times out is skipped silently -- a failed probe must never fail the audit.
_SQL_ERRORS = (
    "you have an error in your sql syntax", "warning: mysql_",
    "ora-01756", "ora-00933", "quoted string not properly terminated",
    "unclosed quotation mark", "microsoft ole db", "odbc sql server",
    "warning: pg_", "sqlite",
)
_REDIRECT_PARAMS = ("next", "url", "redirect", "return", "target", "continue")


def _with_param(base: str, name: str, value: str) -> str:
    from urllib.parse import parse_qsl, urlencode

    p = urlparse(base)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[name] = value
    return p._replace(query=urlencode(q)).geturl()


def _active_probes(base_url: str, timeout: float, add,
                   pentest: str = "safe") -> None:
    """Input probes. Safe mode is non-destructive: reflected XSS, open
    redirect, SQL error messages, dangerous HTTP methods. Aggressive
    mode adds two confirmation probes that touch the target harder --
    a time-delay blind SQL injection check and a canary file written
    with PUT and deleted again. Aggressive mode is opt-in only: run it
    solely against systems you own or have written permission to test.
    Each probe stops at the first hit; a probe that errors or times
    out is skipped silently and never fails the audit.
    """
    import secrets
    import time
    from urllib.parse import parse_qsl, quote, urlencode

    put_allowed = False
    sqli_found = False

    # --- Dangerous methods: does OPTIONS advertise PUT or DELETE? -------
    # Read-only: the Allow header is the evidence. No PUT is ever sent
    # in safe mode, so nothing is written to the target.
    try:
        status, headers, _, _ = _fetch(base_url, timeout, method="OPTIONS",
                                       follow=False)
        allow = {m.strip() for m in (_first(headers, "allow") or "").split(",")}
        dangerous = sorted(m for m in ("PUT", "DELETE") if m in allow)
        put_allowed = "PUT" in allow
        dav = _first(headers, "dav")
        if dangerous or dav:
            add("http-methods-dangerous", "medium",
                "PUT or DELETE advertised by the server",
                f"OPTIONS on {base_url} advertises: "
                f"{', '.join(sorted(allow)) or '(no Allow header)'}"
                + (f"; WebDAV enabled ({dav})" if dav else "") +
                ". A writable method on a public site is a foothold: "
                "uploaded files have led to full compromise.",
                "Disable PUT and DELETE (and WebDAV) unless the application "
                "genuinely needs them; restrict any upload endpoint to "
                "authenticated users and a safe directory.")
    except Exception:
        pass

    # --- Reflected XSS: is our canary echoed back unencoded? -----------
    canary = "svx" + secrets.token_hex(4) + "\"><'"
    try:
        for probe_url in (_with_param(base_url, "svxss", canary),
                          urljoin(base_url, "/" + quote(canary, safe="")),
                          _with_param(base_url, "q", canary)):
            try:
                _, _, body, _ = _fetch(probe_url, timeout)
            except Exception:
                continue
            text = body.decode("utf-8", errors="ignore")
            at = text.find(canary)
            if at < 0:
                continue
            snippet = " ".join(text[max(0, at - 40):at + len(canary) + 40].split())
            add("xss-reflected", "high",
                "User input is reflected unencoded in the page",
                f"The probe string {canary!r} came back verbatim in the "
                f"response: ...{snippet}... Unencoded reflection of "
                f"\"><' means an attacker can break out of the surrounding "
                "markup; confirm exploitability in that context, but treat "
                "any raw reflection as a real hole.",
                "Encode all user-controlled output for its context "
                "(HTML-encode in markup, attribute-encode in attributes); "
                "enforce a Content-Security-Policy as defence in depth.")
            break
    except Exception:
        pass

    # --- Open redirect: does a redirect parameter point outside? --------
    try:
        for name in _REDIRECT_PARAMS:
            probe_url = _with_param(base_url, name, "https://example.com")
            try:
                status, headers, _, _ = _fetch(probe_url, timeout, follow=False)
            except Exception:
                continue
            if status not in (301, 302, 303, 307, 308):
                continue
            target = _first(headers, "location") or ""
            if urlparse(target).netloc == "example.com":
                add("open-redirect", "medium",
                    f"Open redirect via the {name!r} parameter",
                    f"{probe_url} answers {status} to https://example.com. "
                    "An attacker can use the site's own domain to send "
                    "victims to a phishing page.",
                    "Allow only relative redirect targets or an explicit "
                    "allow-list of destinations; never redirect to a "
                    "raw user-supplied URL.")
                break
    except Exception:
        pass

    # --- SQL error: does a stray quote leak a database error? -----------
    try:
        p = urlparse(base_url)
        q = dict(parse_qsl(p.query, keep_blank_values=True))
        if q:
            first = next(iter(q))
            q[first] = q[first] + "'"
            probe_url = p._replace(query=urlencode(q)).geturl()
        else:
            probe_url = _with_param(base_url, "svsql", "1'")
        _, _, body, _ = _fetch(probe_url, timeout)
        text = body.decode("utf-8", errors="ignore").lower()
        hit = next((s for s in _SQL_ERRORS if s in text), None)
        if hit:
            sqli_found = True
            add("sqli-error", "high",
                "Database error message leaks from crafted input",
                f"A single quote in the request produced a database error "
                f"mentioning {hit!r}. The input reaches the database "
                "unsanitized: an error message alone does not prove data "
                "can be extracted, but it proves the injection point is "
                "real and tells the attacker which database runs behind it.",
                "Use parameterised queries (prepared statements) everywhere "
                "user input reaches SQL; turn database error details off "
                "in production responses.")
    except Exception:
        pass

    if pentest != "aggressive":
        return

    # --- Blind SQLi (aggressive): does a SLEEP payload delay the reply?
    # Skipped when the error probe already proved the injection point:
    # a second confirmation buys nothing and costs a 5 s database sleep.
    if not sqli_found:
        try:
            p = urlparse(base_url)
            q = dict(parse_qsl(p.query, keep_blank_values=True))
            base_q = dict(q)
            if q:
                first = next(iter(q))
            else:
                first = "svsql"
                base_q[first] = "1"
            t0 = time.perf_counter()
            _fetch(_with_param(base_url, first, base_q[first]), timeout)
            baseline = time.perf_counter() - t0
            for fn in ("SLEEP(5)", "pg_sleep(5)"):
                payload = base_q[first] + f"' AND {fn}-- "
                t0 = time.perf_counter()
                _fetch(_with_param(base_url, first, payload), timeout)
                took = time.perf_counter() - t0
                if took >= 4.0 and took >= baseline * 3:
                    add("sqli-blind", "high",
                        f"Time-delay SQL injection fires ({fn})",
                        f"The payload {payload!r} delayed the response to "
                        f"{took:.1f} s against a {baseline:.2f} s baseline. "
                        "The database executed the injected function: this "
                        "injection point is not just an error leak, it runs "
                        "attacker SQL.",
                        "Use parameterised queries (prepared statements) "
                        "everywhere user input reaches SQL; give the "
                        "database account the fewest privileges it needs.")
                    break
        except Exception:
            pass

    # --- PUT canary (aggressive): can a file actually be written? -------
    # Only when OPTIONS already advertised PUT. The canary is deleted
    # again immediately; if the delete fails the finding says so and
    # names the file left behind.
    if put_allowed:
        try:
            name = f"sv-{secrets.token_hex(4)}.txt"
            target = urljoin(base_url, "/" + name)
            body = b"sitevigil probe - delete me"
            status, _, _, _ = _fetch(
                target, timeout,
                headers={"Content-Type": "text/plain"},
                method="PUT", data=body)
            if status in (200, 201, 204):
                _, _, got, _ = _fetch(target, timeout)
                confirmed = got == body
                del_status, _, _, _ = _fetch(target, timeout, method="DELETE",
                                             follow=False)
                cleaned = del_status in (200, 202, 204, 404)
                detail = (f"PUT to {target} answered {status} and the file "
                          + ("came back readable" if confirmed else
                             "was not readable afterwards")
                          + (f"; DELETE answered {del_status}, file removed"
                             if cleaned else
                             f"; DELETE answered {del_status} -- the canary "
                             f"file {name} is STILL on the server, remove it "
                             "manually")
                          + ". The web root is writable from the internet: "
                          "an attacker can upload a shell the same way.")
                add("http-put-write", "critical",
                    "PUT wrote a file to the web root",
                    detail,
                    "Disable PUT and WebDAV unless the application genuinely "
                    "needs them; restrict any upload endpoint to "
                    "authenticated users and a safe directory.")
        except Exception:
            pass


def _check_db_ports(host: str, add, timeout: float = 2.5) -> list[int]:
    """TCP-connect to well-known database ports; an open one is a finding.

    A plain connect only -- no banner grab, no login attempt. A refused or
    timed-out connection counts as closed: a firewalled port is
    indistinguishable from a filtered drop, and either way the database is
    not reachable from outside, which is all this check claims.

    The connect goes through _tls_connect so it stays truthful behind an
    HTTP proxy: a proxy completes every handshake itself, so a naive
    direct connect behind one "succeeds" for every port on every host --
    the CONNECT response is the only honest signal there.
    """
    open_ports: list[int] = []
    for port, service in DB_PORTS.items():
        try:
            sock = _tls_connect(host, port, timeout=timeout)
            sock.close()
            open_ports.append(port)
            add("db-port-exposed", "high",
                f"{service} port {port} is open to the internet",
                f"A TCP connection to {host}:{port} succeeded from "
                "outside the network. Anyone on the internet can "
                "attempt to talk to this database service.",
                "Bind the database to localhost or a private network "
                "and firewall the port; application servers should "
                "reach it over a private interface or a tunnel, never "
                "the public internet.")
        except OSError:
            pass
    return open_ports


def _check_tls(host: str, port: int, add, timeout: float = 10.0) -> dict:
    info: dict = {}
    try:
        # Verified handshake first: getpeercert() only returns the parsed
        # certificate when verification is on. An unverified context gets {}.
        try:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            with _tls_connect(host, port, timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    info["protocol"] = tls_sock.version()
                    info["alpn"] = tls_sock.selected_alpn_protocol()
        except ssl.SSLCertVerificationError:
            ctx = ssl._create_unverified_context()
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            with _tls_connect(host, port, timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    info["protocol"] = tls_sock.version()
                    info["alpn"] = tls_sock.selected_alpn_protocol()
                    der = tls_sock.getpeercert(binary_form=True)
            cert = _decode_der(der) if der else {}
            add("tls-untrusted", "high", "TLS certificate fails verification",
                "The certificate is expired, self-signed, or does not match the hostname.",
                "Install a valid certificate for this hostname from a trusted CA.")
        except ssl.SSLError:
            raise
        not_after = cert.get("notAfter")
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc)
            days = (expiry - datetime.now(timezone.utc)).days
            info["expires_in_days"] = days
            if days < 0:
                add("tls-expired", "critical", "TLS certificate has expired",
                    f"Certificate expired {-days} day(s) ago ({not_after}).",
                    "Renew the certificate immediately.")
            elif days < 14:
                add("tls-expiring", "high", "TLS certificate expires soon",
                    f"Certificate expires in {days} day(s) ({not_after}).",
                    "Renew the certificate and check your auto-renewal is working.")
    except (ssl.SSLError, socket.timeout, OSError) as e:
        add("tls-error", "high", "TLS connection problem",
            str(e), "Check the certificate chain, hostname match and TLS configuration.")
    return info


def _decode_der(der: bytes) -> dict:
    """Parse a DER certificate with the stdlib's private test helper."""
    import os
    import tempfile

    try:
        from ssl import _ssl
    except ImportError:
        return {}
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(der)
        return _ssl._test_decode_cert(path)
    except Exception:
        return {}
    finally:
        os.unlink(path)


def to_markdown(report: dict) -> str:
    if not report.get("reachable"):
        return f"# SiteVigil report\n\n**{report['url']}** — unreachable: {report.get('error')}\n"
    lines = [f"# SiteVigil report — {report['final_url']}",
             "",
             f"**Score: {report['score']}/100 (grade {report['grade']})** · "
             f"HTTP {report['status']}"
             + (f" · response {report['response_time_ms']} ms"
                if "response_time_ms" in report else "")
             + (f" · TLS expires in {report['tls']['expires_in_days']} days"
                if "expires_in_days" in report.get("tls", {}) else ""),
             ""]
    if not report["findings"]:
        lines.append("No findings. Nice work.")
    for f in report["findings"]:
        lines += [f"## [{f['severity'].upper()}] {f['title']}",
                  "", f["detail"], "", f"**Fix:** {f['fix']}", ""]
    return "\n".join(lines)


def to_text(report: dict, color: bool = False) -> str:
    """Terminal report. Colour is off by default: the CLI turns it on only
    for a real terminal (never for pipes, files, or --json/--markdown)."""
    if not report.get("reachable"):
        return f"{report['url']} — UNREACHABLE: {report.get('error')}"
    score_c = _score_colour(report["score"])
    lines = [f"{report['final_url']}",
             f"Score: {_paint(str(report['score']), score_c, color)}/100  "
             f"Grade: {_paint(report['grade'], score_c, color)}  "
             f"HTTP {report['status']}"
             + (f"  Response: {report['response_time_ms']} ms"
                if "response_time_ms" in report else "")]
    if report.get("software"):
        lines.append("Software: " + ", ".join(
            f"{s['name']} {s['version']} (via {s['via']})"
            for s in report["software"]))
    lines.append("")
    if not report["findings"]:
        lines.append("No findings. Nice work.")
    for f in report["findings"]:
        tag = _paint(f"[{f['severity'].upper():8}]", _SEV_COLOR[f["severity"]], color)
        lines += [f"{tag} {_paint(f['title'], 'bold', color)}",
                  f"           {f['detail']}",
                  f"           Fix: {f['fix']}"]
    if report["findings"]:
        counts = {s: sum(1 for f in report["findings"] if f["severity"] == s)
                  for s in ("critical", "high", "medium", "low", "info")}
        parts = [_paint(f"{n} {s}", _SEV_COLOR[s], color)
                 for s, n in counts.items() if n]
        lines += ["", "Summary: " + "  ·  ".join(parts)]
    return "\n".join(lines)


def to_html(report: dict) -> str:
    """One self-contained HTML page (inline CSS, dark hacker theme)."""
    style = ("body{background:#0d1117;color:#e6edf3;font-family:system-ui,sans-serif;"
             "max-width:760px;margin:2rem auto;padding:0 1rem}"
             "a{color:#00ff41}.meta{color:#8b949e}"
             ".chip{display:inline-block;border:1px solid;border-radius:999px;"
             "padding:.15rem .6rem;margin:.2rem .25rem .2rem 0;font-size:.85rem}"
             "section{background:#161b22;border:1px solid #30363d;border-left:4px solid;"
             "border-radius:8px;padding:1rem;margin:1rem 0}"
             ".sev{font-size:.75rem;padding:.15rem .5rem;border-radius:999px;"
             "color:#0d1117;font-weight:700}h3{margin:.2rem 0}p{color:#c9d1d9}")
    if not report.get("reachable"):
        return (f"<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                f"<style>{style}</style></head>"
                f"<body><h1>SiteVigil</h1><p>{html.escape(report['url'])} — "
                f"unreachable: {html.escape(str(report.get('error')))}</p></body></html>")
    score_hex = ("#3fb950" if report["score"] >= 90 else "#58a6ff" if report["score"] >= 80
                 else "#d29922" if report["score"] >= 65 else "#f0883e" if report["score"] >= 50
                 else "#f85149")
    sev_hex = {"critical": "#f85149", "high": "#f0883e", "medium": "#d29922",
               "low": "#8b949e", "info": "#58a6ff"}
    counts = {s: sum(1 for f in report["findings"] if f["severity"] == s)
              for s in ("critical", "high", "medium", "low", "info")}
    chips = "".join(
        f"<span class='chip' style='border-color:{sev_hex[s]};color:{sev_hex[s]}'>"
        f"{n} {s}</span>" for s, n in counts.items() if n)
    meta = " · ".join([
        f"HTTP {report['status']}",
        f"Response {report.get('response_time_ms', '?')} ms",
        f"Platform: {report.get('platform', '?')}",
        f"Ruleset {report.get('ruleset', '?')}",
    ])
    rows = "".join(
        f"<section style='border-left-color:{sev_hex[f['severity']]}'>"
        f"<h3><span class='sev' style='background:{sev_hex[f['severity']]}'>"
        f"{f['severity'].upper()}</span> {html.escape(f['title'])}</h3>"
        f"<p>{html.escape(f['detail'])}</p>"
        f"<p><strong>Fix:</strong> {html.escape(f['fix'])}</p></section>"
        for f in report["findings"]) or "<p>No findings. Nice work.</p>"
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>SiteVigil — {html.escape(report['final_url'])}</title>
<style>{style}.score{{font-size:2.4rem;font-weight:700;color:{score_hex}}}</style></head>
<body><h1>SiteVigil report</h1>
<p>{html.escape(report['final_url'])}</p>
<p class="score">{report['score']}/100 — grade {report['grade']}</p>
<p class="meta">{html.escape(meta)}</p>
<p>{chips}</p>
{rows}
<footer><p class="meta">Generated by SiteVigil. A high score means these basics are in place, not that a site is invulnerable.</p></footer>
</body></html>"""


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)
