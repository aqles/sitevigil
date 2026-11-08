"""Command line interface: sitevigil <url> [more urls] [--json|--markdown|--html]"""
import argparse
import json
import sys

from .audit import audit, to_html, to_json, to_markdown, to_text


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="sitevigil",
        description="One-command website security audit for humans and AI agents.")
    parser.add_argument("urls", nargs="*", metavar="url",
                        help="Site(s) to audit, e.g. example.com")
    parser.add_argument("--json", action="store_true", help="Output JSON (agent-friendly)")
    parser.add_argument("--markdown", action="store_true", help="Output a Markdown report")
    parser.add_argument("--html", action="store_true",
                        help="Output one self-contained HTML report per site")
    parser.add_argument("--mcp", action="store_true",
                        help="Run as an MCP server on stdio (for Claude Code, Cursor, ...)")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--fail-under", type=int, default=None,
                        help="Exit 1 if any score is below N (for CI)")
    args = parser.parse_args(argv)

    if args.mcp:
        from .mcp_server import serve
        serve()
        return 0
    if not args.urls:
        parser.error("at least one url is required (or use --mcp)")

    reports = [audit(u, timeout=args.timeout) for u in args.urls]
    if args.json:
        print(to_json(reports[0]) if len(reports) == 1 else
              json.dumps(reports, indent=2))
    elif args.html:
        print("\n".join(to_html(r) for r in reports))
    elif args.markdown:
        print("\n\n---\n\n".join(to_markdown(r) for r in reports))
    else:
        for r in reports:
            print(to_text(r))
            print()
        if len(reports) > 1:
            print("Summary:")
            for r in reports:
                state = (f"{r['score']}/100 ({r['grade']})" if r.get("reachable")
                         else "UNREACHABLE")
                print(f"  {state:14} {r['url']}")

    if any(not r.get("reachable") for r in reports):
        return 2
    if args.fail_under is not None and any(r["score"] < args.fail_under for r in reports):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
