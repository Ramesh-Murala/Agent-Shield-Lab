"""CLI: python -m agentshield scan --text '...' / serve."""

import argparse
import json
import sys

from .scanner import scan_text


def main() -> None:
    parser = argparse.ArgumentParser(description="Explainable signals in untrusted agent input")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Scan --text or standard input")
    scan.add_argument("--text", help="Input text; omit to read standard input")
    serve = commands.add_parser("serve", help="Run local Python API and web UI")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if args.command == "scan":
        text = args.text if args.text is not None else sys.stdin.read()
        print(json.dumps(scan_text(text), indent=2, ensure_ascii=False))
    else:
        import uvicorn

        uvicorn.run("agentshield.web:app", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
