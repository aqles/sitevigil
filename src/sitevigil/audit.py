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
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler

USER_AGENT = "SiteVigil/0.5 (+https://github.com/aqles/sitevigil)"
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
]


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fetch(url: str, timeout: float, headers: dict | None = None,
           follow: bool = True, method: str = "GET"):
    """Return (status, headers-as-dict-of-lists, body-bytes, final_url)."""
    req = Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})},
                  method=method)
    opener = build_opener() if follow else build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, _group(resp.headers), resp.read(MAX_BODY), resp.geturl()
    except HTTPError as e:
        return e.code, _group(e.headers), e.read(MAX_BODY), url


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
        if any(u.endswith(".xml") for u in locs):
            for child in locs[:1]:
                _, _, child_body, _ = _fetch(child, timeout)
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


def audit(raw_url: str, timeout: float = 10.0) -> dict:
    url = raw_url if "://" in raw_url else f"https://{raw_url}"
    parsed = urlparse(url)
    host = parsed.hostname or ""
    findings: list[dict] = []

    def add(fid, severity, title, detail, fix):
        findings.append({"id": fid, "severity": severity, "title": title,
                         "detail": detail, "fix": fix})

    # --- Reachability + main response -------------------------------------
    try:
        status, headers, body, final_url = _fetch(url, timeout)
    except (URLError, socket.timeout, OSError) as e:
        return {"url": url, "reachable": False, "error": str(e),
                "score": 0, "grade": "F", "findings": []}
    is_https = urlparse(final_url).scheme == "https"

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

    # --- HTTP -> HTTPS redirect -------------------------------------------
    if parsed.scheme == "https" or is_https:
        try:
            s2, _, _, final2 = _fetch(f"http://{host}", timeout, follow=True)
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
        tls = _check_tls(host, parsed.port or 443, add)
        if tls.get("protocol") in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            add("tls-weak-protocol", "high", "Server negotiated a deprecated TLS version",
                f"Negotiated {tls['protocol']}; TLS 1.0/1.1 are deprecated (RFC 8996) "
                "and rejected by modern browsers.",
                "Disable TLS 1.0 and 1.1; serve TLS 1.2 and 1.3 only.")
        if tls and tls.get("alpn") != "h2":
            add("http2-not-offered", "info", "HTTP/2 was not negotiated",
                f"ALPN result: {tls.get('alpn') or 'none'}.",
                "Enable HTTP/2 at the server/CDN for faster, multiplexed loads.")

    # --- Security headers ---------------------------------------------------
    hsts = _first(headers, "strict-transport-security")
    if is_https:
        if not hsts:
            add("hsts-missing", "medium", "Missing Strict-Transport-Security header",
                "No HSTS header on the HTTPS response.",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains")
        else:
            m = re.search(r"max-age=(\d+)", hsts)
            if m and int(m.group(1)) < 15552000:
                add("hsts-short", "low", "HSTS max-age is short",
                    f"HSTS max-age is {m.group(1)} seconds (under 180 days).",
                    "Raise max-age to at least 31536000 (one year).")

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

    # --- Domain email / issuance records (DNS-over-HTTPS) -------------------
    _check_domain(host, add)

    score = max(0, 100 - sum(WEIGHTS[f["severity"]] for f in findings))
    grade = ("A" if score >= 90 else "B" if score >= 80 else
             "C" if score >= 65 else "D" if score >= 50 else "F")
    return {"url": url, "final_url": final_url, "status": status,
            "reachable": True, "platform": _detect_platform(headers),
            "ruleset": RULESET_VERSION, "redirect_chain": chain,
            "tls": tls, "score": score, "grade": grade,
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


def _tls_connect(host: str, port: int, timeout: float = 10):
    """TCP connection to host:port, honouring https_proxy (CONNECT) so the
    TLS check also works behind corporate proxies, where a direct socket
    would hit the proxy and fail with WRONG_VERSION_NUMBER."""
    import base64
    import os

    proxy = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
    no_proxy = (os.environ.get("no_proxy") or "").split(",")
    if not proxy or host in no_proxy:
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


def _check_domain(host: str, add) -> None:
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
        mx = _doh(domain, "MX")
        if mx:
            txt = _doh(domain, "TXT")
            if not any(t.strip('"').lower().startswith("v=spf1") for t in txt):
                add("spf-missing", "low", "No SPF record for a mail-receiving domain",
                    f"{domain} has MX records but no v=spf1 TXT record.",
                    "Publish an SPF TXT record listing the services allowed to "
                    "send mail for your domain.")
            dmarc = _doh(f"_dmarc.{domain}", "TXT")
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
        caa = _doh(domain, "CAA")
        if not caa:
            add("caa-missing", "info", "No CAA record",
                f"{domain} has no CAA records; any CA may issue certificates for it.",
                "Add CAA records naming only the CA(s) you actually use.")
    except Exception:
        pass


def _check_tls(host: str, port: int, add) -> dict:
    info: dict = {}
    try:
        # Verified handshake first: getpeercert() only returns the parsed
        # certificate when verification is on. An unverified context gets {}.
        try:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            with _tls_connect(host, port) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    info["protocol"] = tls_sock.version()
                    info["alpn"] = tls_sock.selected_alpn_protocol()
        except ssl.SSLCertVerificationError:
            ctx = ssl._create_unverified_context()
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            with _tls_connect(host, port) as sock:
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
             + (f" · TLS expires in {report['tls']['expires_in_days']} days"
                if "expires_in_days" in report.get("tls", {}) else ""),
             ""]
    if not report["findings"]:
        lines.append("No findings. Nice work.")
    for f in report["findings"]:
        lines += [f"## [{f['severity'].upper()}] {f['title']}",
                  "", f["detail"], "", f"**Fix:** {f['fix']}", ""]
    return "\n".join(lines)


def to_text(report: dict) -> str:
    if not report.get("reachable"):
        return f"{report['url']} — UNREACHABLE: {report.get('error')}"
    lines = [f"{report['final_url']}",
             f"Score: {report['score']}/100  Grade: {report['grade']}  HTTP {report['status']}",
             ""]
    if not report["findings"]:
        lines.append("No findings. Nice work.")
    for f in report["findings"]:
        lines += [f"[{f['severity'].upper():8}] {f['title']}",
                  f"           {f['detail']}",
                  f"           Fix: {f['fix']}"]
    return "\n".join(lines)


def to_html(report: dict) -> str:
    """One self-contained HTML page (inline CSS, no external assets)."""
    if not report.get("reachable"):
        return (f"<h1>SiteVigil</h1><p>{html.escape(report['url'])} — "
                f"unreachable: {html.escape(str(report.get('error')))}</p>")
    colour = ("#1a7f37" if report["score"] >= 90 else "#1f6feb" if report["score"] >= 80
              else "#bf8700" if report["score"] >= 65 else "#bc4c00" if report["score"] >= 50
              else "#cf222e")
    rows = "".join(
        f"<section><h3><span class='sev {f['severity']}'>{f['severity'].upper()}</span> "
        f"{html.escape(f['title'])}</h3><p>{html.escape(f['detail'])}</p>"
        f"<p><strong>Fix:</strong> {html.escape(f['fix'])}</p></section>"
        for f in report["findings"]) or "<p>No findings. Nice work.</p>"
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>SiteVigil — {html.escape(report['final_url'])}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;color:#1f2328}}
.score{{font-size:2.2rem;font-weight:700;color:{colour}}} section{{border:1px solid #d0d7de;border-radius:8px;padding:1rem;margin:1rem 0}}
.sev{{font-size:.75rem;padding:.15rem .5rem;border-radius:999px;background:#eaeef2}}
.sev.critical{{background:#cf222e;color:#fff}} .sev.high{{background:#bc4c00;color:#fff}}
.sev.medium{{background:#bf8700;color:#fff}} h3{{margin:.2rem 0}}</style></head>
<body><h1>SiteVigil report</h1>
<p>{html.escape(report['final_url'])}</p>
<p class="score">{report['score']}/100 — grade {report['grade']}</p>
{rows}
<footer><p>Generated by SiteVigil. A high score means these basics are in place, not that a site is invulnerable.</p></footer>
</body></html>"""


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)
