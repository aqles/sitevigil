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
    _PageParser, audit, compare_reports, generate_fix, to_html)
from sitevigil.mcp_server import handle  # noqa: E402

INDEX = b"<html><body>spa index</body></html>"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_TRACE(self):
        body = ("\r\n".join(f"{k}: {v}" for k, v in self.headers.items())).encode()
        self._send(200, body, "message/http")

    def do_GET(self):
        if self.path == "/.env":
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


class AuditTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
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
