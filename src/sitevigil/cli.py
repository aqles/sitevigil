"""Command line interface: sitevigil <url> [--json|--markdown] [--fail-under N]"""
import argparse
import sys

from .audit import audit, to_json, to_markdown, to_text


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="sitevigil",
        description="One-command website security audit for humans and AI agents.")
    parser.add_argument("url", nargs="?", help="Site to audit, e.g. example.com")
    parser.add_argument("--json", action="store_true", help="Output JSON (agent-friendly)")
    parser.add_argument("--markdown", action="store_true", help="Output a Markdown report")
    parser.add_argument("--mcp", action="store_true",
                        help="Run as an MCP server on stdio (for Claude Code, Cursor, ...)")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--fail-under", type=int, default=None,
                        help="Exit 1 if the score is below N (for CI)")
    args = parser.parse_args(argv)

    if args.mcp:
        from .mcp_server import serve
        serve()
        return 0
    if not args.url:
        parser.error("url is required (or use --mcp)")

    report = audit(args.url, timeout=args.timeout)
    print(to_json(report) if args.json else
          to_markdown(report) if args.markdown else to_text(report))
    if args.fail_under is not None and report["score"] < args.fail_under:
        return 1
    return 0 if report.get("reachable") else 2


if __name__ == "__main__":
    sys.exit(main())
