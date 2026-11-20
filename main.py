#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SysVoidScan v3.0 Sentinel — Web Security Testing Scanner
Main entry point with pipeline engine, OOB server, async HTTP, headless browser.
"""

import signal
import sys
import os
import threading
import time
import logging
from logging.handlers import RotatingFileHandler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.scanner import Scanner
from core.config import Config
from core.finding import FindingManager
from core.pipeline import ScanPipeline
from cli.arguments import parse_arguments
from cli.interactive import InteractiveMenu

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    pass


def configure_logging():
    """Configure root logging for console output and optional file rotation.

    Environment variables:
    - SYSVOID_LOG_LEVEL: logging level name (DEBUG/INFO/WARNING/ERROR/CRITICAL)
    - SYSVOID_LOG_FILE: optional path to a rotating log file
    - SYSVOID_LOG_FORMAT: custom formatter string
    - SYSVOID_DEBUG: convenience switch that enables DEBUG level when set to 1
    """
    debug_enabled = os.environ.get("SYSVOID_DEBUG", "0") == "1"
    level_name = os.environ.get("SYSVOID_LOG_LEVEL", "DEBUG" if debug_enabled else "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    log_format = os.environ.get("SYSVOID_LOG_FORMAT", "%(asctime)s %(levelname)s %(name)s: %(message)s")

    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()

    handlers = []
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(logging.Formatter(log_format))
    handlers.append(console_handler)

    log_file = os.environ.get("SYSVOID_LOG_FILE")
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setFormatter(logging.Formatter(log_format))
        handlers.append(file_handler)

    logging.basicConfig(level=level, format=log_format, handlers=handlers, force=True)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def _setup_signal_handlers(scanner, oob_server=None, scheduler=None):
    def signal_handler(sig, frame):
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user. Cleaning up...{Style.RESET_ALL}")
        try:
            if oob_server:
                oob_server.stop()
            if scheduler:
                scheduler.stop()
            scanner.close()
        except Exception:
            logging.exception("signal_handler: cleanup failed")
        sys.exit(0)
    try:
        signal.signal(signal.SIGINT, signal_handler)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, signal_handler)
    except (OSError, ValueError):
        pass


def _init_v3_components(scanner):
    """Initialize v3.0 Sentinel components: OOB server, async HTTP, headless browser, notifications, scheduler."""
    scheduler = None
    notifier = None
    try:
        scanner.oob_server.start()
    except Exception:
        logging.exception("_init_v3_components: oob_server failed to start")
    try:
        from core.async_http import AsyncHTTPEngine
        scanner.async_http = AsyncHTTPEngine()
    except Exception:
        logging.exception("_init_v3_components: AsyncHTTPEngine init failed")
    try:
        from core.headless_browser import HeadlessBrowser
        scanner.headless_browser = HeadlessBrowser()
    except Exception:
        logging.exception("_init_v3_components: HeadlessBrowser init failed")
    try:
        from notifications.notifier import Notifier
        notifier = Notifier.from_env()
        scanner.notifier = notifier
    except Exception:
        logging.exception("_init_v3_components: Notifier init failed")
    try:
        from scheduler.scan_scheduler import ScanScheduler
        scheduler = ScanScheduler()
        def _on_scheduled_scan(scheduled):
            target = scheduled.target
            scan_type = scheduled.scan_type
            scanner.config.target_url = target
            if scan_type == "full":
                scanner.run_full_pentest(target)
            else:
                scanner.run_module(scan_type, target)
            if notifier and scheduled.notifications:
                findings = scanner.finding_manager.get_all() if hasattr(scanner, "finding_manager") else []
                notifier.send_all(findings, target)
        scheduler.set_scan_callback(_on_scheduled_scan)
        scheduler.start()
    except Exception:
        logging.exception("_init_v3_components: ScanScheduler init failed")
    return scanner.oob_server, scheduler, notifier


def _apply_auth_to_session(session, auth_config, args):
    if not session:
        return
    if args.cookie:
        for part in args.cookie.split(";"):
            part = part.strip()
            if "=" in part:
                name, value = part.split("=", 1)
                session.cookies.set(name.strip(), value.strip())
    if args.basic_auth:
        try:
            user, password = args.basic_auth.split(":", 1)
            from requests.auth import HTTPBasicAuth
            session.auth = HTTPBasicAuth(user, password)
        except ValueError:
            pass
    if args.token:
        session.headers["Authorization"] = f"Bearer {args.token}"
    for header in args.header:
        if ":" in header:
            name, value = header.split(":", 1)
            session.headers[name.strip()] = value.strip()
    if auth_config:
        auth_type = auth_config.get("type", "none")
        creds = auth_config.get("credentials", {})
        if auth_type == "cookie" and "cookie" in creds:
            for part in creds["cookie"].split(";"):
                part = part.strip()
                if "=" in part:
                    name, value = part.split("=", 1)
                    session.cookies.set(name.strip(), value.strip())
        elif auth_type == "basic":
            from requests.auth import HTTPBasicAuth
            session.auth = HTTPBasicAuth(creds.get("username", ""), creds.get("password", ""))
        elif auth_type == "bearer" and "token" in creds:
            token_val = creds.get("token", "")
            if token_val:
                session.headers["Authorization"] = f"Bearer {token_val}"
        elif auth_type == "custom_headers":
            for name, value in creds.get("headers", {}).items():
                session.headers[name] = value


def main():
    configure_logging()
    args = parse_arguments()

    # Configure console encoding to avoid terminal write errors on Windows.
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        logging.exception("Failed to reconfigure stdout/stderr encoding")

    if args.list_plugins:
        from plugins.loader import PluginLoader
        loader = PluginLoader()
        loader.load_all()
        plugins = loader.list_plugins()
        if plugins:
            print(f"\n{Fore.CYAN}Available Plugins:{Style.RESET_ALL}")
            for p in plugins:
                print(f"  {Fore.GREEN}+{Style.RESET_ALL} {p['name']} v{p['version']} — {p['description']}")
        else:
            print(f"\n{Fore.YELLOW}No plugins found.{Style.RESET_ALL}")
        return

    scanner = Scanner()

    # Run the test suite now that the scanner and its artifact manager are available
    if not args.no_autotests:
        try:
            if os.environ.get("SYSVOID_AUTORUN_TESTS", "1") != "0":
                mode_label = "smoke tests" if args.smoke_tests else "test suite"
                pytest_cmd = [sys.executable, "-m", "pytest", "-q"]
                if args.smoke_tests:
                    pytest_cmd.extend([
                        "tests/test_cli",
                        "tests/test_core/test_artifact_manager.py",
                        "tests/test_core/test_config.py",
                        "tests/test_plugins/test_loader.py",
                        "tests/test_core/test_save_reports.py",
                    ])
                print(f"[sysvoid] Running {mode_label} ({' '.join(pytest_cmd[3:]) or 'python -m pytest -q'}) ...")
                import subprocess, datetime
                try:
                    res = subprocess.run(
                        pytest_cmd,
                        cwd=os.path.dirname(__file__),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        check=False,
                    )
                    output = res.stdout or ""
                except Exception as e:
                    output = f"pytest failed to run: {e}\n"
                    res = type("R", (), {"returncode": 1})()

                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                tr_dir = os.path.join(os.path.dirname(__file__), "test_runs")
                os.makedirs(tr_dir, exist_ok=True)
                suffix = "smoke" if args.smoke_tests else "full"
                out_path = os.path.join(tr_dir, f"pytest_{suffix}_run_{ts}.txt")
                try:
                    with open(out_path, "w", encoding="utf-8") as fh:
                        fh.write(output)
                    try:
                        rec = scanner.artifact_manager.register_file_artifact(
                            out_path,
                            kind="tests",
                            title=os.path.basename(out_path),
                            metadata={"runner": "pytest", "returncode": getattr(res, "returncode", -1), "generated_at": datetime.datetime.now().isoformat()},
                        )
                        scanner.scan_data.setdefault("artifacts", []).append(
                            {"title": rec.get("title"), "path": rec.get("path"), "kind": rec.get("kind"), "size_bytes": rec.get("size_bytes")}
                        )
                        print(f"[sysvoid] Test run registered as artifact: {rec.get('path')}")
                    except Exception as e:
                        print(f"[sysvoid] Failed to register test artifact: {e}")
                except Exception as e:
                    print(f"[sysvoid] Failed to write test run output: {e}")
        except Exception:
            logging.exception("main.py: exception")
            pass

    oob_server, scheduler, notifier = _init_v3_components(scanner)
    _setup_signal_handlers(scanner, oob_server, scheduler)

    if args.plugin_dir or args.interactive:
        from plugins.loader import PluginLoader
        loader = PluginLoader(args.plugin_dir)
        count = loader.load_all()
        loader.register_hooks(scanner)
        scanner.plugin_loader = loader
        if count > 0:
            from core.utils import print_good
            print_good(f"Loaded {count} plugin(s)")

    if args.no_color:
        import core.utils as utils
        utils.Fore = type('Fore', (), {attr: "" for attr in dir(utils.Fore) if not attr.startswith("_")})()
        utils.Style = type('Style', (), {attr: "" for attr in dir(utils.Style) if not attr.startswith("_")})()

    try:
        scanner.config.timeout = args.timeout
        scanner.config.threads = args.threads
        scanner.config.request_delay = args.delay
        scanner.config.verify_tls = not args.insecure

        from core.utils import get_session

        ua = args.user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        session = get_session(user_agent=ua, verify_tls=scanner.config.verify_tls, proxy=args.proxy)
        if session is None:
            print(f"{Fore.RED}[-] Could not create HTTP session.{Style.RESET_ALL}")
            sys.exit(1)

        _apply_auth_to_session(session, None, args)

        if args.interactive:
            menu = InteractiveMenu(plugin_loader=getattr(scanner, "plugin_loader", None))
            menu.show_banner(scanner)
            targets = args.url
            if not targets:
                targets = menu.prompt_target_selection()
            if not targets:
                print(f"{Fore.RED}[-] No targets specified.{Style.RESET_ALL}")
                sys.exit(1)
            authenticated = False
            auth_config = {}
            while True:
                choice = menu.show_menu(targets, authenticated=authenticated, scanner=scanner)
                if choice == "23":
                    break
                elif choice == "14":
                    auth_config = menu.prompt_auth_setup()
                    authenticated = auth_config.get("type", "none") != "none"
                    _apply_auth_to_session(session, auth_config, args)
                    continue
                for target in targets:
                    scanner.config.target_url = target
                    result = menu.dispatch(choice, target, session, scanner)
                if choice in ("19", "20"):
                    pass
                elif result is None:
                    break
        else:
            if args.batch:
                for target in args.url:
                    print(f"\n{Fore.CYAN}[*] Starting full pentest on: {target}{Style.RESET_ALL}")
                    scanner.config.target_url = target
                    scanner.run_full_pentest(target, session=session)
            else:
                for target in args.url:
                    scanner.config.target_url = target
                    if args.module:
                        for mod in args.module:
                            scanner.run_module(mod, target, session=session)
                    else:
                        scanner.run_full_pentest(target, session=session)

            if args.url:
                output_dir = args.output
                os.makedirs(output_dir, exist_ok=True)
                generated = scanner.save_reports(output_dir, formats=args.format)
                if generated:
                    from core.utils import print_good
                    print(f"\n{Fore.GREEN}[*] Reports generated:{Style.RESET_ALL}")
                    for path in generated:
                        print(f"    {Fore.GREEN}+{Style.RESET_ALL} {path}")

        if notifier and hasattr(scanner, "finding_manager"):
            findings = scanner.finding_manager.get_all()
            if findings and args.url:
                notifier.send_all(findings, args.url[0])

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Fatal error: {e}{Style.RESET_ALL}")
    finally:
        try:
            if oob_server:
                oob_server.stop()
            if scheduler:
                scheduler.stop()
        except Exception:
            logging.exception("main.py: exception")
            pass
        scanner.close()


if __name__ == "__main__":
    main()
