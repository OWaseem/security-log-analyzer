import argparse
import sys
from pathlib import Path

from .detections import run_all
from .parsers import parse_auth, parse_web
from .report import to_json, to_markdown


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="loganalyzer", description="Detect suspicious activity in SSH auth and web access logs.")
    p.add_argument("--auth", type=Path, help="path to an OpenSSH syslog auth log")
    p.add_argument("--web", type=Path, help="path to an Apache/Nginx combined access log")
    p.add_argument("--year", type=int, default=2026, help="year for syslog timestamps (syslog omits it)")
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.add_argument("--out", type=Path, help="write the report to this file instead of stdout")
    args = p.parse_args(argv)
    if not args.auth and not args.web:
        p.error("provide at least one of --auth or --web")

    auth = list(parse_auth(args.auth.read_text().splitlines(), args.year)) if args.auth else []
    web = list(parse_web(args.web.read_text().splitlines())) if args.web else []
    alerts = run_all(auth, web)
    text = to_json(alerts) if args.format == "json" else to_markdown(alerts, len(auth), len(web))
    if args.out:
        args.out.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
