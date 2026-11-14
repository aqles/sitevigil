"""Self-check: spin up a local HTTP server with known-bad responses.

Run: python -m unittest discover -s tests -v
The fixture mimics a soft-404 SPA (unknown paths answer 200 with the
index page) EXCEPT /.env, which serves a real-looking env file -- the
audit must flag /.env but must not flag /.git/HEAD, which returns the
soft-404 page here.
"""
import json
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sitevigil.audit import (  # noqa: E402
    CHECKS, _PageParser, audit, compare_reports, discover_urls,
    generate_fix, to_badge, to_html)
from sitevigil.mcp_server import handle  # noqa: E402

INDEX = (b'<html><body>spa index <a href="/page2">two</a>'
         b'<script src="/assets/jquery-1.12.4.min.js"></script>'
         b'<link rel="stylesheet" href="/wp-content/plugins/woocommerce/'
         b'assets/css/woocommerce.css?ver=5.4.0">'
         b'<script src="/wp-content/plugins/elementor/assets/js/'
         b'frontend.min.js?ver=3.5.5"></script>'
         b'</body></html>')


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.49"  # versioned banner -> CVE fingerprint
    sys_version = ""
    uploads: dict = {}  # path -> body, written by do_PUT, read by do_GET

    def log_message(self, *a):
        pass

    def do_PUT(self):
        length = int(self.headers.get("Content-Length") or 0)
        Handler.uploads[self.path] = self.rfile.read(length)
        self.send_response(201)
        self.end_headers()

    def do_DELETE(self):
        if self.path in Handler.uploads:
            del Handler.uploads[self.path]
            self.send_response(200)
        else:
            self.send_response(404)
        self.end_headers()

    def do_TRACE(self):
        body = ("\r\n".join(f"{k}: {v}" for k, v in self.headers.items())).encode()
        self._send(200, body, "message/http")

    def do_OPTIONS(self):
        if self.path == "/dav":
            self.send_response(200)
            self.send_header("Allow", "GET, HEAD, OPTIONS, PUT, DELETE")
            self.send_header("DAV", "1")
        else:
            self.send_response(200)
            self.send_header("Allow", "GET, HEAD, OPTIONS")
        self.end_headers()

    def do_GET(self):
        hops = {"/hop1": "/hop2", "/hop2": "/hop3", "/hop3": "/hop4",
                "/hop4": "/"}
        if self.path in hops:
            self.send_response(302)
            self.send_header("Location", hops[self.path])
            self.end_headers()
        elif self.path == "/sitemap.xml":
            host = self.headers.get("Host", "127.0.0.1")
            xml = ("<?xml version='1.0'?><urlset>"
                   f"<url><loc>http://{host}/</loc></url>"
                   f"<url><loc>http://{host}/page2</loc></url>"
                   f"<url><loc>http://{host}/page3</loc></url></urlset>")
            self._send(200, xml.encode(), "application/xml")
        elif self.path == "/.env":
            self._send(200, b"API_KEY=abc123\nDB_PASSWORD=hunter2\n", "text/plain")
        elif urlsplit(self.path).path == "/echo":
            q = parse_qs(urlsplit(self.path).query)
            value = (q.get("svxss") or q.get("q") or [""])[0]
            body = ("<html><body>results for " + value + "</body></html>").encode()
            self._send(200, body, "text/html")
        elif urlsplit(self.path).path == "/redir":
            q = parse_qs(urlsplit(self.path).query)
            target = (q.get("next") or [None])[0]
            if target:
                self.send_response(302)
                self.send_header("Location", target)
                self.end_headers()
            else:
                self._send(200, INDEX, "text/html")
        elif urlsplit(self.path).path == "/db":
            if "%27" in self.path or "'" in self.path:
                self._send(200, b"You have an error in your SQL syntax; "
                            b"check the manual that corresponds to your "
                            b"MySQL server version", "text/html")
            else:
                self._send(200, INDEX, "text/html")
        elif urlsplit(self.path).path == "/dbblind":
            import time
            vals = [v for vs in
                    parse_qs(urlsplit(self.path).query).values() for v in vs]
            if any("SLEEP(" in v or "pg_sleep(" in v for v in vals):
                time.sleep(5)  # blind injection point, no error leak
            self._send(200, INDEX, "text/html")
        elif self.path in Handler.uploads:
            self._send(200, Handler.uploads[self.path], "text/plain")
        elif self.path == "/":
            self.send_response(200)
            self.send_header("Set-Cookie", "sessionid=xyz; Path=/")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(INDEX)
        else:  # soft 404: everything else is the SPA index
            self._send(200, INDEX, "text/html")

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body)


def _canned_nvd(vendor, product, version):
    """Stand-in for the NVD API: one real match, two traps that must be
    filtered out (a range that starts above 2.4.49, a non-vulnerable entry)."""
    def entry(cid, cvss, match):
        return {"cve": {
            "id": cid,
            "descriptions": [{"lang": "en", "value": f"stub description for {cid}"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": cvss}}]},
            "configurations": [{"nodes": [{"cpeMatch": [match]}]}]}}

    if (vendor, product) == ("woocommerce", "woocommerce"):
        return {"vulnerabilities": [
            entry("CVE-2021-32790", 9.8, {
                "vulnerable": True,
                "criteria": "cpe:2.3:a:woocommerce:woocommerce:*:*:*:*:*:wordpress:*:*",
                "versionEndExcluding": "5.5.0"})]}
    if (vendor, product) == ("elementor", "website_builder"):
        return {"vulnerabilities": [
            entry("CVE-2022-29455", 5.4, {
                "vulnerable": True,
                "criteria": "cpe:2.3:a:elementor:website_builder:*:*:*:*:*:wordpress:*:*",
                "versionEndIncluding": "3.5.5"})]}
    if (vendor, product) == ("jquery", "jquery"):
        return {"vulnerabilities": [
            entry("CVE-2020-11023", 6.1, {
                "vulnerable": True,
                "criteria": "cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*",
                "versionEndExcluding": "3.5.0"})]}
    if (vendor, product) != ("apache", "http_server"):
        return {"vulnerabilities": []}

    return {"vulnerabilities": [
        entry("CVE-2021-41773", 7.5, {
            "vulnerable": True,
            "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}),
        entry("CVE-9999-0001", 9.8, {
            "vulnerable": True,
            "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "2.4.50"}),
        entry("CVE-9999-0002", 9.8, {
            "vulnerable": False,
            "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}),
    ]}


class AuditTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import os
        import tempfile

        import sitevigil.audit as audit_module
        os.environ["SITEVIGIL_CACHE_DIR"] = tempfile.mkdtemp()
        audit_module._nvd_query = _canned_nvd  # tests never touch real NVD
        # CVE-2021-41773 is in the real KEV catalog; jQuery's is not.
        cls._kev_lookup_real = audit_module._kev_lookup
        audit_module._kev_lookup = lambda: {"CVE-2021-41773": "2021-11-03"}
        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_findings(self):
        report = audit(self.base)
        ids = [f["id"] for f in report["findings"]]
        self.assertTrue(report["reachable"])
        self.assertIn("csp-missing", ids)
        self.assertIn("nosniff-missing", ids)
        self.assertIn("clickjacking", ids)
        # session cookie over http without flags is still checked for SameSite,
        # and the real .env must be caught
        self.assertTrue(any(i.startswith("exposed/.env") for i in ids), ids)
        # soft-404 trap: /.git/HEAD returns the SPA index, must NOT be flagged
        self.assertFalse(any("git" in i for i in ids), ids)
        self.assertLess(report["score"], 100)
        self.assertIn(report["grade"], "ABCDF")

    def test_v02_checks(self):
        report = audit(self.base)
        ids = [f["id"] for f in report["findings"]]
        self.assertIn("trace-enabled", ids)          # fixture echoes TRACE
        self.assertIn("security-txt-missing", ids)   # soft-404 page has no Contact:
        self.assertIn("/100", to_html(report))

    def test_page_parser(self):
        p = _PageParser("https://example.com/")
        p.feed('<img src="http://insecure.example/a.png">'
               '<script src="https://cdn.example/x.js"></script>'
               '<script src="/local.js" integrity="sha384-abc"></script>')
        urls = [u for _, u, _ in p.resources]
        self.assertIn("http://insecure.example/a.png", urls)
        scripts = {u: i for t, u, i in p.resources if t == "script"}
        self.assertFalse(scripts["https://cdn.example/x.js"])
        self.assertTrue(scripts["https://example.com/local.js"])

    def test_fix_and_compare(self):
        report = audit(self.base)
        fix = generate_fix(report)
        self.assertIn("X-Content-Type-Options", fix["content"])
        self.assertIn("Content-Security-Policy", fix["content"])
        same = compare_reports(report, report)
        self.assertEqual(same["new"], [])
        self.assertEqual(same["score_delta"], 0)
        worse = dict(report, findings=report["findings"] + [
            {"id": "brand-new", "severity": "high", "title": "t",
             "detail": "d", "fix": "f"}], score=report["score"] - 15)
        diff = compare_reports(report, worse)
        self.assertEqual([f["id"] for f in diff["new"]], ["brand-new"])
        self.assertEqual(diff["score_delta"], -15)

    def test_v04_checks_and_catalog(self):
        report = audit(self.base)
        ids = [f["id"] for f in report["findings"]]
        self.assertIn("coop-missing", ids)
        self.assertIn("corp-missing", ids)
        self.assertEqual(report["ruleset"], "2026.11")
        catalog = {c[0] for c in CHECKS}
        for fid in ids:  # every emitted finding must exist in the catalog
            base = ("cookie-*" if fid.startswith("cookie-")
                    else "cve-*" if fid.startswith("cve-") and fid != "cve-overflow"
                    else fid.split("-weak")[0] if fid.startswith("csp-weak") else fid)
            self.assertTrue(base in catalog or fid in catalog,
                            f"{fid} missing from CHECKS catalog")

    def test_v05_crawl_badge_redirects(self):
        report = audit(self.base + "/hop1")
        ids = [f["id"] for f in report["findings"]]
        self.assertIn("redirect-chain-long", ids)
        self.assertEqual(len(report["redirect_chain"]), 5)
        urls = discover_urls(self.base, limit=5)
        self.assertTrue(any(u.endswith("/page2") for u in urls), urls)
        self.assertTrue(any(u.endswith("/page3") for u in urls), urls)
        self.assertLessEqual(len(urls), 5)
        badge = to_badge(audit(self.base))
        self.assertIn("<svg", badge)
        self.assertIn("/100", badge)
        fix = generate_fix(audit(self.base))
        self.assertIn("Cross-Origin-Opener-Policy", fix["content"])

    def test_v06_cve(self):
        report = audit(self.base)
        self.assertTrue(any(s["product"] == "apache" and s["version"] == "2.4.49"
                            for s in report["software"]), report["software"])
        cve = [f for f in report["findings"] if f["id"].startswith("cve-")]
        apache = [f for f in cve if "41773" in f["id"]]
        self.assertEqual([f["id"] for f in apache], ["cve-2021-41773"], cve)
        self.assertEqual(apache[0]["severity"], "high")  # CVSS 7.5
        # the two canned traps (future range, non-vulnerable) must be gone
        self.assertFalse(any("9999" in f["id"] for f in cve), cve)
        off = audit(self.base, cve=False)
        self.assertFalse(any(f["id"].startswith("cve-")
                             for f in off["findings"]))

    def test_v07_jquery_preload_output(self):
        from sitevigil.audit import _hsts_preload_ready
        report = audit(self.base)
        self.assertTrue(any(s["product"] == "jquery" and s["version"] == "1.12.4"
                            for s in report["software"]), report["software"])
        jq = [f for f in report["findings"] if f["id"] == "cve-2020-11023"]
        self.assertEqual(len(jq), 1)
        self.assertEqual(jq[0]["severity"], "medium")  # CVSS 6.1
        self.assertTrue(_hsts_preload_ready(
            "max-age=63072000; includeSubDomains"))
        self.assertFalse(_hsts_preload_ready(
            "max-age=63072000; includeSubDomains; preload"))
        self.assertFalse(_hsts_preload_ready("max-age=1000; includeSubDomains"))
        import tempfile
        from pathlib import Path

        from sitevigil.cli import main
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "report.json"
            self.assertEqual(main([self.base, "--json", "--output", str(out)]), 0)
            saved = json.loads(out.read_text())
            self.assertIn("score", saved)

    def test_v08_wp_plugins_and_mcp_http(self):
        report = audit(self.base)
        sw = {s["product"]: s["version"] for s in report["software"]}
        self.assertEqual(sw.get("wp:woocommerce"), "5.4.0", sw)
        self.assertEqual(sw.get("wp:elementor"), "3.5.5", sw)
        ids = [f["id"] for f in report["findings"]]
        self.assertIn("cve-2021-32790", ids)
        self.assertIn("cve-2022-29455", ids)

        import threading
        from urllib.request import Request, urlopen

        from sitevigil.mcp_server import _make_http_server
        server = _make_http_server("127.0.0.1", 0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{server.server_port}/mcp"
        try:
            req = Request(url, data=json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode(),
                headers={"Content-Type": "application/json"})
            with urlopen(req, timeout=10) as resp:
                payload = json.loads(resp.read())
            names = [t["name"] for t in payload["result"]["tools"]]
            self.assertEqual(names, ["audit_site", "suggest_fix"])
            req = Request(url, data=json.dumps({
                "jsonrpc": "2.0", "method": "notifications/initialized"}).encode(),
                headers={"Content-Type": "application/json"})
            with urlopen(req, timeout=10) as resp:
                self.assertEqual(resp.status, 202)  # notification: no reply
        finally:
            server.shutdown()

    def test_v09_latency_and_db_ports(self):
        import socket as sock

        import sitevigil.audit as m

        # latency: the field rides along on every report; a fast local
        # fixture must not trip the slow finding; no db ports open here
        report = audit(self.base)
        self.assertIn("response_time_ms", report)
        self.assertIsInstance(report["response_time_ms"], int)
        ids = [f["id"] for f in report["findings"]]
        self.assertNotIn("slow-response", ids)
        self.assertEqual(report["open_db_ports"], [])
        self.assertNotIn("db-port-exposed", ids)

        # slow threshold: with a 0 ms budget any fetch counts as slow
        old_budget = m.SLOW_RESPONSE_MS
        m.SLOW_RESPONSE_MS = 0
        try:
            slow = audit(self.base, ports=False)
        finally:
            m.SLOW_RESPONSE_MS = old_budget
        self.assertIn("slow-response", [f["id"] for f in slow["findings"]])

        # exposed port: a real TCP listener standing in for a database
        listener = sock.socket()
        listener.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        fake_port = listener.getsockname()[1]
        old_ports = m.DB_PORTS
        m.DB_PORTS = {fake_port: "TestDB"}
        try:
            exposed = audit(self.base)
        finally:
            m.DB_PORTS = old_ports
            listener.close()
        self.assertEqual(exposed["open_db_ports"], [fake_port])
        hit = [f for f in exposed["findings"] if f["id"] == "db-port-exposed"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["severity"], "high")
        self.assertIn("TestDB", hit[0]["title"])

    def test_v09_db_ports_behind_proxy(self):
        # Behind an HTTP proxy a naive connect "succeeds" for every port
        # (the proxy answers the handshake itself). The check must trust
        # only the CONNECT verdict: 200 = open, anything else = closed.
        import os
        import socket as sock
        from unittest import mock

        import sitevigil.audit as m

        proxy = sock.socket()
        proxy.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
        proxy.bind(("127.0.0.1", 0))
        proxy.listen(5)
        proxy_port = proxy.getsockname()[1]

        def serve():
            for _ in range(2):
                conn, _ = proxy.accept()
                req = conn.recv(4096).decode("utf-8", "ignore")
                ok = ":1111 " in req  # only the fake-open port gets a 200
                conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n" if ok
                             else b"HTTP/1.1 403 Forbidden\r\n\r\n")
                conn.close()
            proxy.close()

        threading.Thread(target=serve, daemon=True).start()
        old_ports = m.DB_PORTS
        m.DB_PORTS = {1111: "OpenDB", 2222: "ShutDB"}
        env = dict(os.environ, https_proxy=f"http://127.0.0.1:{proxy_port}",
                   HTTPS_PROXY=f"http://127.0.0.1:{proxy_port}", no_proxy="")
        try:
            with mock.patch.dict(os.environ, env, clear=False):
                found: list = []
                opened = m._check_db_ports(
                    "dbtest.invalid", lambda *a: found.append(a[0]))
        finally:
            m.DB_PORTS = old_ports
        self.assertEqual(opened, [1111])
        self.assertEqual(found, ["db-port-exposed"])

    def test_v10_color_progress_html(self):
        from sitevigil.audit import AUDIT_PHASES, to_html, to_text

        report = audit(self.base)

        # colour: on when asked, never by default (pipes/files stay plain)
        self.assertNotIn("\x1b[", to_text(report))
        coloured = to_text(report, color=True)
        self.assertIn("\x1b[", coloured)
        self.assertIn("Summary:", coloured)

        # progress: every phase, in order, exactly once per audit
        seen: list = []
        audit(self.base, ports=False,
              progress=lambda label, done, total: seen.append((label, done, total)))
        self.assertEqual([s[0] for s in seen], AUDIT_PHASES)
        self.assertEqual([s[1] for s in seen], list(range(1, len(AUDIT_PHASES) + 1)))
        self.assertTrue(all(s[2] == len(AUDIT_PHASES) for s in seen))

        # HTML: dark theme, severity chips, response time in the meta line
        page = to_html(report)
        self.assertIn("#0d1117", page)
        self.assertIn("chip", page)
        self.assertIn("Response", page)
        self.assertNotIn("background:#eaeef2", page)  # old light theme

    def test_v12_probes(self):
        # reflected XSS: /echo returns the raw query value
        echo = audit(self.base + "/echo")
        xss = [f for f in echo["findings"] if f["id"] == "xss-reflected"]
        self.assertEqual(len(xss), 1, echo["findings"])
        self.assertEqual(xss[0]["severity"], "high")
        # open redirect: /redir 302s to the next parameter
        redir = audit(self.base + "/redir")
        od = [f for f in redir["findings"] if f["id"] == "open-redirect"]
        self.assertEqual(len(od), 1, redir["findings"])
        self.assertEqual(od[0]["severity"], "medium")
        # SQL error: /db leaks a MySQL error on a stray quote
        db = audit(self.base + "/db?id=1")
        sq = [f for f in db["findings"] if f["id"] == "sqli-error"]
        self.assertEqual(len(sq), 1, db["findings"])
        self.assertEqual(sq[0]["severity"], "high")
        # dangerous methods: /dav advertises PUT and DELETE
        dav = audit(self.base + "/dav")
        dm = [f for f in dav["findings"]
              if f["id"] == "http-methods-dangerous"]
        self.assertEqual(len(dm), 1, dav["findings"])
        self.assertEqual(dm[0]["severity"], "medium")
        # the plain index triggers none of the four
        plain = audit(self.base)
        self.assertFalse(any(f["id"] in ("xss-reflected", "open-redirect",
                                         "sqli-error", "http-methods-dangerous")
                            for f in plain["findings"]))
        # opt-out removes every probe
        off = audit(self.base + "/echo", probes=False)
        self.assertFalse(any(f["id"] == "xss-reflected"
                             for f in off["findings"]))
        # the catalog grew by four (plus two aggressive checks: 48 total)
        from sitevigil.audit import CHECKS
        self.assertEqual(len(CHECKS), 48)

    def test_v13_aggressive(self):
        # blind SQLi: /dbblind sleeps 5 s on SLEEP(), leaks nothing else
        safe = audit(self.base + "/dbblind?id=1")
        self.assertEqual(safe["pentest_mode"], "safe")
        self.assertFalse(any(f["id"] == "sqli-blind"
                             for f in safe["findings"]))
        aggr = audit(self.base + "/dbblind?id=1", pentest="aggressive")
        self.assertEqual(aggr["pentest_mode"], "aggressive")
        blind = [f for f in aggr["findings"] if f["id"] == "sqli-blind"]
        self.assertEqual(len(blind), 1, aggr["findings"])
        self.assertEqual(blind[0]["severity"], "high")
        # ...but never when the error probe already proved the point
        db = audit(self.base + "/db?id=1", pentest="aggressive")
        self.assertTrue(any(f["id"] == "sqli-error"
                            for f in db["findings"]))
        self.assertFalse(any(f["id"] == "sqli-blind"
                             for f in db["findings"]))
        # PUT canary: /dav accepts the file, the audit deletes it again
        Handler.uploads.clear()
        dav = audit(self.base + "/dav", pentest="aggressive")
        put = [f for f in dav["findings"] if f["id"] == "http-put-write"]
        self.assertEqual(len(put), 1, dav["findings"])
        self.assertEqual(put[0]["severity"], "critical")
        self.assertIn("file removed", put[0]["detail"])
        self.assertEqual(Handler.uploads, {})
        # safe mode on /dav: methods only, no canary ever written
        Handler.uploads.clear()
        dav_safe = audit(self.base + "/dav")
        self.assertFalse(any(f["id"] == "http-put-write"
                             for f in dav_safe["findings"]))
        self.assertEqual(Handler.uploads, {})
        # aggressive on a clean page: nothing fires, mode still recorded
        plain = audit(self.base, pentest="aggressive")
        self.assertFalse(any(f["id"] in ("sqli-blind", "http-put-write")
                            for f in plain["findings"]))
        off = audit(self.base + "/dbblind?id=1", probes=False)
        self.assertEqual(off["pentest_mode"], "off")

    def test_banner(self):
        import contextlib
        import io

        from sitevigil.cli import main
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main([self.base])
        self.assertIn("/ ____/", buf.getvalue())
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main([self.base, "--no-banner"])
        self.assertNotIn("SITEVIGIL", buf.getvalue().split("Score")[0])

    def test_mcp_tools(self):
        names = [t["name"] for t in handle({"method": "tools/list"})["tools"]]
        self.assertEqual(names, ["audit_site", "suggest_fix"])
        out = handle({"method": "tools/call", "params": {
            "name": "suggest_fix", "arguments": {"url": self.base}}})
        self.assertIn("fix", json.loads(out["content"][0]["text"]))
        out = handle({"method": "tools/call", "params": {
            "name": "audit_site", "arguments": {"url": self.base}}})
        parsed = json.loads(out["content"][0]["text"])
        self.assertIn("score", parsed)

    def test_v11_kev(self):
        report = audit(self.base)
        apache = [f for f in report["findings"] if f["id"] == "cve-2021-41773"]
        self.assertEqual(len(apache), 1)
        self.assertTrue(apache[0].get("kev"))
        self.assertEqual(apache[0].get("kev_date_added"), "2021-11-03")
        self.assertIn("KNOWN EXPLOITED", apache[0]["title"])
        self.assertIn("CISA", apache[0]["detail"])
        # a CVE outside KEV stays untagged
        jq = [f for f in report["findings"] if f["id"] == "cve-2020-11023"]
        self.assertEqual(len(jq), 1)
        self.assertNotIn("kev", jq[0])
        # opt-out removes every tag
        off = audit(self.base, kev=False)
        self.assertFalse(any(f.get("kev") for f in off["findings"]))
        # a failed KEV feed must not fail or falsify the audit
        import sitevigil.audit as audit_module
        old = audit_module._kev_lookup
        audit_module._kev_lookup = lambda: None
        try:
            report2 = audit(self.base)
        finally:
            audit_module._kev_lookup = old
        self.assertTrue(any(f["id"] == "cve-2021-41773"
                            for f in report2["findings"]))
        self.assertFalse(any(f.get("kev") for f in report2["findings"]))

    def test_v11_kev_lookup(self):
        import os
        import tempfile
        from unittest import mock
        from urllib.error import URLError

        # setUpClass stubbed the module name; the real function is on the
        # class (via the class, not the instance, so it stays unbound)
        _kev_lookup = type(self)._kev_lookup_real
        feed = {"vulnerabilities": [
            {"cveID": "CVE-2021-41773", "dateAdded": "2021-11-03"},
            {"cveID": "CVE-2020-11023", "dateAdded": "2020-07-28"}]}
        resp = mock.MagicMock()
        resp.read.return_value = json.dumps(feed).encode()
        resp.__enter__.return_value = resp
        with tempfile.TemporaryDirectory() as td:
            env = {"SITEVIGIL_CACHE_DIR": td}
            with mock.patch.dict(os.environ, env), \
                    mock.patch("urllib.request.urlopen",
                               return_value=resp) as get:
                self.assertEqual(_kev_lookup(), {
                    "CVE-2021-41773": "2021-11-03",
                    "CVE-2020-11023": "2020-07-28"})
                self.assertTrue(os.path.exists(
                    os.path.join(td, "kev.json")))
                # second call reads the cache: the feed is not re-fetched
                get.side_effect = URLError("down")
                self.assertEqual(_kev_lookup(), {
                    "CVE-2021-41773": "2021-11-03",
                    "CVE-2020-11023": "2020-07-28"})
            # no cache and a dead feed -> None, never an exception
            with tempfile.TemporaryDirectory() as td2, \
                    mock.patch.dict(os.environ, {"SITEVIGIL_CACHE_DIR": td2}), \
                    mock.patch("urllib.request.urlopen",
                               side_effect=URLError("down")):
                self.assertIsNone(_kev_lookup())


if __name__ == "__main__":
    unittest.main()
