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

    def log_message(self, *a):
        pass

    def do_TRACE(self):
        body = ("\r\n".join(f"{k}: {v}" for k, v in self.headers.items())).encode()
        self._send(200, body, "message/http")

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


if __name__ == "__main__":
    unittest.main()
