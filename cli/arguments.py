import argparse
import sys
from typing import List


def parse_arguments(argv: List[str] = None) -> argparse.Namespace:
    """Parse command-line arguments for SysVoidScan."""
    parser = argparse.ArgumentParser(
        prog="SysVoidScan",
        description="SysVoidScan v3.0.0 — Web Security Testing Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py -u https://example.com\n"
            "  python main.py -u https://example.com -o ./reports\n"
            "  python main.py -L targets.txt --batch\n"
            "  python main.py -u https://example.com -t 10 --timeout 30\n"
        ),
    )

    target_group = parser.add_argument_group("Target")
    target_group.add_argument(
        "-u", "--url",
        action="append",
        default=[],
        help="Target URL(s). Can be specified multiple times or comma-separated.",
    )
    target_group.add_argument(
        "-L", "--list",
        dest="target_list",
        default=None,
        help="File containing target URLs (one per line).",
    )

    mode_group = parser.add_argument_group("Mode")
    mode_group.add_argument(
        "-b", "--batch",
        action="store_true",
        default=False,
        help="Non-interactive batch mode (run all modules automatically).",
    )
    mode_group.add_argument(
        "-m", "--module",
        action="append",
        default=[],
        help="Run specific module(s) only. Can be specified multiple times.",
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-o", "--output",
        default="./reports",
        help="Output directory for reports (default: ./reports).",
    )
    output_group.add_argument(
        "-f", "--format",
        action="append",
        choices=["html", "dashboard", "json", "markdown", "txt", "csv"],
        default=[],
        help="Report format(s) to generate. Can be specified multiple times. Default: all.",
    )

    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument(
        "-t", "--threads",
        type=int,
        default=5,
        help="Number of concurrent threads (default: 5).",
    )
    scan_group.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP request timeout in seconds (default: 10).",
    )
    scan_group.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Delay between HTTP requests in seconds (default: 0).",
    )
    scan_group.add_argument(
        "--insecure",
        action="store_true",
        default=False,
        help="Disable TLS certificate verification.",
    )
    scan_group.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable colored output.",
    )
    scan_group.add_argument(
        "--no-autotests",
        action="store_true",
        default=False,
        help="Disable automatic pytest execution when main.py starts.",
    )
    scan_group.add_argument(
        "--smoke-tests",
        action="store_true",
        default=False,
        help="Run a lightweight subset of tests on startup instead of the full suite.",
    )

    proxy_group = parser.add_argument_group("Proxy & Network")
    proxy_group.add_argument(
        "--proxy",
        default=None,
        help="HTTP/SOCKS5 proxy (e.g., http://127.0.0.1:8080).",
    )
    proxy_group.add_argument(
        "--user-agent",
        default=None,
        help="Custom User-Agent string.",
    )

    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument(
        "--cookie",
        default=None,
        help="Cookie header value (e.g., 'session=abc123; token=xyz').",
    )
    auth_group.add_argument(
        "--header",
        action="append",
        default=[],
        help="Custom HTTP header(s) in 'Name: Value' format. Can be repeated.",
    )
    auth_group.add_argument(
        "--basic-auth",
        default=None,
        help="Basic authentication credentials (user:password).",
    )
    auth_group.add_argument(
        "--token",
        default=None,
        help="Bearer token for API authentication.",
    )

    plugin_group = parser.add_argument_group("Plugins")
    plugin_group.add_argument(
        "--plugin-dir",
        default=None,
        help="Directory containing plugins to load.",
    )
    plugin_group.add_argument(
        "--list-plugins",
        action="store_true",
        default=False,
        help="List available plugins and exit.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version="SysVoidScan 3.0.0",
    )

    args = parser.parse_args(argv)

    if args.url:
        expanded = []
        for u in args.url:
            for part in u.split(","):
                part = part.strip()
                if part:
                    expanded.append(part)
        args.url = expanded

    if args.target_list:
        try:
            with open(args.target_list, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        args.url.append(line)
        except FileNotFoundError:
            print(f"Error: Target list file not found: {args.target_list}")
            sys.exit(1)

    if not args.url and not args.batch and not args.list_plugins:
        args.interactive = True
    else:
        args.interactive = False

    if not args.format:
        args.format = ["html", "json", "markdown", "txt", "csv"]

    return args
