"""Command line interface: sitevigil <url> [more urls] [--json|--markdown|--html]"""
import argparse
import json
import sys

from . import __version__
from .audit import (CHECKS, RULESET_VERSION, audit, compare_reports,
                    discover_urls, generate_fix, to_badge, to_html, to_json,
                    to_markdown, to_text)

BANNER = r"""
     .      o                 .               o                       .
  ______  _____  _______  ______ __      __ _____   ______   _____  _
 / ____/ |_   _||__   __||  ____|\ \    / /|_   _| / ____/  |_   _|| |
| (___     | |     | |   | |__    \ \  / /   | |  | |  ___    | |  | |
 \___ \    | |     | |   |  __|    \ \/ /    | |  | | |_  |   | |  | |
 ____) |  _| |_    | |   | |____    \  /    _| |_ | |___| |  _| |_ | |____
|_____/  |_____|   |_|   |______|    \/    |_____| \_____/  |_____||______|
   |                                                |               |
   .                                                .              \___/
""".strip("\n")


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
    parser.add_argument("--no-banner", action="store_true",
                        help="Hide the ASCII banner in text output")
    parser.add_argument("--checks", action="store_true",
                        help="List every check in the current ruleset and exit")
    parser.add_argument("--mcp", action="store_true",
                        help="Run as an MCP server on stdio (for Claude Code, Cursor, ...)")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--fix", action="store_true",
                        help="Also generate a ready-to-commit header config for the platform")
    parser.add_argument("--baseline", metavar="FILE",
                        help="Compare against a previous --json report; exit 1 on new findings")
    parser.add_argument("--fail-under", type=int, default=None,
                        help="Exit 1 if any score is below N (for CI)")
    parser.add_argument("--crawl", type=int, default=0, metavar="N",
                        help="Also audit up to N pages of the site "
                             "(from sitemap.xml or homepage links)")
    parser.add_argument("--badge", action="store_true",
                        help="Print an SVG score badge (for READMEs) and exit")
    args = parser.parse_args(argv)

    if args.checks:
        print(f"SiteVigil ruleset {RULESET_VERSION} — {len(CHECKS)} checks")
        for cid, severity, title, ref in CHECKS:
            print(f"  [{severity:9}] {cid:28} {title}")
            print(f"  {'':11} {'':28} {ref}")
        return 0
    if args.mcp:
        from .mcp_server import serve
        serve()
        return 0
    if not args.urls:
        parser.error("at least one url is required (or use --mcp / --checks)")

    if args.crawl:
        if len(args.urls) != 1:
            parser.error("--crawl works with exactly one url")
        args.urls = discover_urls(args.urls[0], timeout=args.timeout,
                                  limit=args.crawl)

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

    if args.badge:
        print(to_badge(reports[0]))
    elif args.json:
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
        if not args.no_banner:
            print(BANNER)
            print(f" v{__version__} — website security audit, ruleset {RULESET_VERSION}\n")
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
