"""Minimal MCP server (stdio, JSON-RPC) exposing one tool: audit_site.

Standard library only -- MCP over stdio is newline-delimited JSON-RPC,
which does not need an SDK for a single read-only tool.
"""
import json
import sys

from .audit import audit, generate_fix

PROTOCOL = "2024-11-05"
_URL_SCHEMA = {
    "type": "object",
    "properties": {"url": {"type": "string",
                           "description": "Site to audit, e.g. https://example.com"}},
    "required": ["url"],
}
TOOLS = [
    {
        "name": "audit_site",
        "description": ("Audit a live website for security misconfigurations: "
                        "security headers, cookies, TLS, CORS, exposed files, and "
                        "known CVEs for the software versions it fingerprints. "
                        "Returns a 0-100 score and findings, each with a concrete fix."),
        "inputSchema": _URL_SCHEMA,
    },
    {
        "name": "suggest_fix",
        "description": ("Audit a site AND generate a ready-to-commit config that "
                        "fixes its missing security headers, tailored to its "
                        "hosting platform (Vercel vercel.json, Netlify/Cloudflare "
                        "_headers, nginx, Apache). For GitHub Pages it explains the "
                        "platform limit and returns the portable _headers file."),
        "inputSchema": _URL_SCHEMA,
    },
]


def handle(msg: dict) -> dict | None:
    method = msg.get("method")
    if method == "initialize":
        return {"protocolVersion": PROTOCOL,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "sitevigil", "version": "0.8.0"}}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        if name not in ("audit_site", "suggest_fix"):
            return {"content": [{"type": "text", "text": "unknown tool"}],
                    "isError": True}
        report = audit((params.get("arguments") or {}).get("url", ""))
        payload = report
        if name == "suggest_fix":
            payload = {"url": report.get("final_url") or report.get("url"),
                       "score": report.get("score"), "grade": report.get("grade"),
                       "fix": generate_fix(report)}
        return {"content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
                "isError": not report.get("reachable", False)}
    if method in ("ping",):
        return {}
    return None  # notifications and unknown methods: no reply


def _make_http_server(host: str, port: int):
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code: int, body: bytes, ctype: str = "application/json"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_GET(self):
            if self.path in ("/", "/mcp"):
                self._send(200, b"sitevigil MCP endpoint: POST JSON-RPC to /mcp\n",
                           "text/plain")
            else:
                self._send(404, b'{"error": "not found"}')

        def do_POST(self):
            if self.path != "/mcp":
                self._send(404, b'{"error": "not found"}')
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length > 1_000_000:
                self._send(413, b'{"error": "request too large"}')
                return
            try:
                msg = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._send(400, json.dumps({
                    "jsonrpc": "2.0", "id": None,
                    "error": {"code": -32700, "message": "parse error"}}).encode())
                return
            result = handle(msg)
            if result is None or "id" not in msg:
                self._send(202, b"")  # notification: accepted, no reply
                return
            self._send(200, json.dumps({"jsonrpc": "2.0", "id": msg["id"],
                                        "result": result}).encode())

    return HTTPServer((host, port), Handler)


def serve_http(port: int, host: str = "127.0.0.1") -> None:
    """Serve MCP over HTTP so hosted/remote agents can use SiteVigil too.

    Stateless request/response (one JSON-RPC message per POST), which is
    enough for remote agents and curl. Binds to localhost by default:
    the tools audit arbitrary URLs, so exposing this on a network
    interface means running an unauthenticated audit service -- the
    CLI prints a warning when asked to do that.
    """
    _make_http_server(host, port).serve_forever()


def serve(stdin=None, stdout=None) -> None:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        result = handle(msg)
        if result is not None and "id" in msg:
            stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"],
                                     "result": result}) + "\n")
            stdout.flush()
