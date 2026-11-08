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
                        "security headers, cookies, TLS, CORS and exposed files. "
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
                "serverInfo": {"name": "sitevigil", "version": "0.4.0"}}
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
