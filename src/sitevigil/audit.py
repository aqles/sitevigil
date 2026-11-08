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

import json
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler

USER_AGENT = "SiteVigil/0.1 (+https://github.com/aqles/sitevigil)"
WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
MAX_BODY = 65536


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fetch(url: str, timeout: float, headers: dict | None = None,
           follow: bool = True):
    """Return (status, headers-as-dict-of-lists, body-bytes, final_url)."""
    req = Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
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
        for token, label in (("'unsafe-inline'", "allows inline scripts/styles ('unsafe-inline')"),
                             ("'unsafe-eval'", "allows eval() ('unsafe-eval')"),
                             ("*", "uses a wildcard source (*)")):
            # '*' only counts as a standalone source token -- a subdomain
            # wildcard like https://*.example.com is a deliberate choice
            hit = token in csp if token != "*" else re.search(r"(?:^|[;\s])\*(?:[;\s]|$)", csp)
            if hit:
                add(f"csp-weak-{label[:12]}", "low", "Content-Security-Policy is permissive",
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

    score = max(0, 100 - sum(WEIGHTS[f["severity"]] for f in findings))
    grade = ("A" if score >= 90 else "B" if score >= 80 else
             "C" if score >= 65 else "D" if score >= 50 else "F")
    return {"url": url, "final_url": final_url, "status": status,
            "reachable": True, "tls": tls, "score": score, "grade": grade,
            "findings": findings}


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


def _check_tls(host: str, port: int, add) -> dict:
    info: dict = {}
    try:
        # Verified handshake first: getpeercert() only returns the parsed
        # certificate when verification is on. An unverified context gets {}.
        try:
            ctx = ssl.create_default_context()
            with _tls_connect(host, port) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    info["protocol"] = tls_sock.version()
        except ssl.SSLCertVerificationError:
            ctx = ssl._create_unverified_context()
            with _tls_connect(host, port) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    info["protocol"] = tls_sock.version()
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


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)
