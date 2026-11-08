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

from sitevigil.audit import audit  # noqa: E402
from sitevigil.mcp_server import handle  # noqa: E402

INDEX = b"<html><body>spa index</body></html>"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

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

    def test_mcp_tools(self):
        self.assertEqual(handle({"method": "tools/list"})["tools"][0]["name"],
                         "audit_site")
        out = handle({"method": "tools/call", "params": {
            "name": "audit_site", "arguments": {"url": self.base}}})
        parsed = json.loads(out["content"][0]["text"])
        self.assertIn("score", parsed)


if __name__ == "__main__":
    unittest.main()
