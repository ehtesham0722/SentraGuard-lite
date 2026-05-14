#!/usr/bin/env python3
"""
SentraGuard Lite CLI

Usage:
    python cli.py analyze --input sample_request.json --output out.json

Options:
    --input    Path to the JSON input file (required)
    --output   Path to write the JSON response (required)
    --api-url  API base URL (default: http://localhost:8000)
"""
import argparse
import json
import sys

import requests


def cmd_analyze(input_file: str, output_file: str, api_url: str) -> None:
    # ── 1. Read input JSON ──────────────────────────────────────────────────
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] Input file not found: {input_file}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"[ERROR] Invalid JSON in input file: {exc}", file=sys.stderr)
        sys.exit(1)

    # ── 2. Call POST /analyze ───────────────────────────────────────────────
    url = f"{api_url.rstrip('/')}/analyze"
    try:
        response = requests.post(url, json=payload, timeout=30)
        response.raise_for_status()
    except requests.exceptions.ConnectionError:
        print(
            f"[ERROR] Could not connect to API at {url}.\n"
            "Make sure the service is running: docker compose up  OR  uvicorn app.main:app",
            file=sys.stderr,
        )
        sys.exit(1)
    except requests.exceptions.HTTPError as exc:
        print(f"[ERROR] API returned an error: {exc}\n{response.text}", file=sys.stderr)
        sys.exit(1)

    result = response.json()

    # ── 3. Write output JSON ────────────────────────────────────────────────
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    # ── 4. Print summary to stdout ──────────────────────────────────────────
    decision = result.get("decision", "?")
    score = result.get("risk_score", "?")
    tags = ", ".join(result.get("risk_tags", [])) or "none"

    print(f"Decision   : {decision.upper()}")
    print(f"Risk Score : {score}/100")
    print(f"Risk Tags  : {tags}")
    print(f"Output     : {output_file}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="SentraGuard Lite — Guardrails Gateway CLI",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ── analyze sub-command ─────────────────────────────────────────────────
    analyze_parser = subparsers.add_parser(
        "analyze", help="Analyze a request JSON file against the running API"
    )
    analyze_parser.add_argument(
        "--input", required=True, metavar="FILE", help="Input JSON file path"
    )
    analyze_parser.add_argument(
        "--output", required=True, metavar="FILE", help="Output JSON file path"
    )
    analyze_parser.add_argument(
        "--api-url",
        default="http://localhost:8000",
        metavar="URL",
        help="API base URL (default: http://localhost:8000)",
    )

    args = parser.parse_args()

    if args.command == "analyze":
        cmd_analyze(args.input, args.output, args.api_url)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
