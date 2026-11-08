"""Command line interface: sitevigil <url> [more urls] [--json|--markdown|--html]"""
import argparse
import json
import sys

from .audit import (audit, compare_reports, generate_fix, to_html, to_json,
                    to_markdown, to_text)


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
    parser.add_argument("--fix", action="store_true",
                        help="Also generate a ready-to-commit header config for the platform")
    parser.add_argument("--baseline", metavar="FILE",
                        help="Compare against a previous --json report; exit 1 on new findings")
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

    comparison = None
    if args.baseline:
        if len(reports) != 1:
            parser.error("--baseline works with exactly one url")
        with open(args.baseline, encoding="utf-8") as fh:
            base = json.load(fh)
        if isinstance(base, list):
            base = base[0]
        comparison = compare_reports(base, reports[0])

    if args.json:
        out = [dict(r) for r in reports]
        if args.fix:
            for o, r in zip(out, reports):
                o["fix"] = generate_fix(r)
        if comparison is not None:
            out[0]["comparison"] = comparison
        print(to_json(out[0]) if len(out) == 1 else json.dumps(out, indent=2))
    elif args.html:
        print("\n".join(to_html(r) for r in reports))
    elif args.markdown:
        print("\n\n---\n\n".join(to_markdown(r) for r in reports))
    else:
        for r in reports:
            print(to_text(r))
            print()
            if args.fix:
                fix = generate_fix(r)
                print(f"Suggested fix ({fix['platform']}"
                      + (f", {fix['filename']}" if fix["filename"] else "") + "):")
                print(fix["content"] or "  (nothing to change)")
                print(f"Note: {fix['notes']}")
                print()
        if len(reports) > 1:
            print("Summary:")
            for r in reports:
                state = (f"{r['score']}/100 ({r['grade']})" if r.get("reachable")
                         else "UNREACHABLE")
                print(f"  {state:14} {r['url']}")
        if comparison is not None:
            print(f"Baseline comparison: score {comparison['baseline_score']} -> "
                  f"{comparison['current_score']} ({comparison['score_delta']:+d})")
            for f in comparison["new"]:
                print(f"  NEW      [{f['severity']}] {f['title']}")
            for fid in comparison["resolved"]:
                print(f"  RESOLVED {fid}")

    if any(not r.get("reachable") for r in reports):
        return 2
    if comparison is not None and any(
            f["severity"] in ("critical", "high", "medium")
            for f in comparison["new"]):
        return 1
    if args.fail_under is not None and any(r["score"] < args.fail_under for r in reports):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
