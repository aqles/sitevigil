"""Minimal MCP server (stdio, JSON-RPC) exposing one tool: audit_site.

Standard library only -- MCP over stdio is newline-delimited JSON-RPC,
which does not need an SDK for a single read-only tool.
"""
import hmac
import json
import sys

from . import __version__
from .audit import audit, generate_fix

PROTOCOL = "2024-11-05"
_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
_URL_SCHEMA = {
    "type": "object",
    "properties": {"url": {"type": "string",
                           "description": "Site to audit, e.g. https://example.com"},
                   "allow_private": {"type": "boolean",
                                     "description": "Allow auditing private/loopback hosts (local development only; default false)."}},
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
                "serverInfo": {"name": "sitevigil", "version": __version__}}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        if name not in ("audit_site", "suggest_fix"):
            return {"content": [{"type": "text", "text": "unknown tool"}],
                    "isError": True}
        arguments = params.get("arguments") or {}
        url = arguments.get("url", "") if isinstance(arguments, dict) else ""
        if not isinstance(url, str) or not url:
            return {"content": [{"type": "text",
                                 "text": "tool arguments must include a url string"}],
                    "isError": True}
        allow_private = (arguments.get("allow_private", False)
                         if isinstance(arguments, dict) else False)
        if not isinstance(allow_private, bool):
            return {"content": [{"type": "text",
                                 "text": "allow_private must be a boolean"}],
                    "isError": True}
        report = audit(url, allow_private=allow_private)
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


def _make_http_server(host: str, port: int, token: str | None = None):
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
            # H2: when a token is configured, every POST to /mcp must
            # carry it -- the tools audit arbitrary URLs, so an
            # unauthenticated endpoint is an open SSRF service.
            if token is not None:
                auth = self.headers.get("Authorization") or ""
                if not hmac.compare_digest(auth, f"Bearer {token}"):
                    self._send(401, b'{"error": "unauthorized"}')
                    return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                self._send(400, b'{"error": "invalid Content-Length"}')
                return
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
            if not isinstance(msg, dict):
                self._send(400, json.dumps({
                    "jsonrpc": "2.0", "id": None,
                    "error": {"code": -32600, "message": "request must be an object"}}).encode())
                return
            try:
                result = handle(msg)
            except Exception as e:  # a malformed call must not drop the request
                self._send(200, json.dumps({
                    "jsonrpc": "2.0", "id": msg.get("id"),
                    "error": {"code": -32603,
                              "message": f"internal error: {e}"}}).encode())
                return
            if result is None or "id" not in msg:
                self._send(202, b"")  # notification: accepted, no reply
                return
            self._send(200, json.dumps({"jsonrpc": "2.0", "id": msg["id"],
                                        "result": result}).encode())

    return HTTPServer((host, port), Handler)


def serve_http(port: int, host: str = "127.0.0.1",
               allow_remote: bool = False, token: str | None = None) -> None:
    """Serve MCP over HTTP so hosted/remote agents can use SiteVigil too.

    Stateless request/response (one JSON-RPC message per POST), which is
    enough for remote agents and curl. Localhost-only by default (H2):
    a non-loopback bind is refused unless allow_remote is set, and
    then a bearer token is required and checked on every POST.
    """
    if host not in _LOOPBACK_HOSTS and not allow_remote:
        raise ValueError(
            f"refusing to bind MCP server to non-loopback host {host!r} "
            "without allow_remote")
    if host not in _LOOPBACK_HOSTS and not token:
        raise ValueError(
            "allow_remote requires a bearer token (SITEVIGIL_MCP_TOKEN)")
    _make_http_server(host, port, token=token).serve_forever()


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
        if not isinstance(msg, dict):
            continue
        try:
            result = handle(msg)
        except Exception as e:
            # M2: one bad call (a crashing audit, a malformed message)
            # must not kill the server -- answer a JSON-RPC internal
            # error and keep reading, like serve_http does.
            if "id" in msg:
                stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"],
                                         "error": {"code": -32603,
                                                   "message": f"internal error: {e}"}}) + "\n")
                stdout.flush()
            continue
        if result is not None and "id" in msg:
            stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"],
                                     "result": result}) + "\n")
            stdout.flush()
