"""
FuzzingModule - Directory and virtual host fuzzing using ffuf or internal methods.

Supports directory brute-forcing, vhost discovery, and provides
an interactive prompt for selecting fuzzing mode.
"""

import os
import re
import json
import tempfile
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core.utils import (
    print_info,
    print_good,
    print_warning,
    print_error,
    get_session,
    normalize_url,
)
from lib.wordlists import Wordlists
from tools.ffuf_tool import FfufTool
import logging


class FuzzingModule:

    DEFAULT_DIR_WORDLIST = Wordlists.COMMON_DIRS

    LISTING_MARKERS = [
        "<title>index of",
        "<h1>index of",
        "directory listing for",
        "parent directory</a>",
        "index of /",
    ]

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.ffuf = FfufTool()
        self.wordlists = Wordlists()

    def run(self, target: str, session=None):
        print_info(f"Fuzzing module for {target}")
        print_info("Select fuzzing type:")
        print_info("  [1] Directory brute-force")
        print_info("  [2] Virtual host brute-force")
        print_info("  [3] Both")

        try:
            choice = input("\n> Choice (1/2/3): ").strip()
        except (KeyboardInterrupt, EOFError):
            choice = "1"

        results: Dict[str, Any] = {"target": target}

        if choice in ("1", "3"):
            results["directory"] = self.run_dirs(target, session)
        if choice in ("2", "3"):
            results["vhost"] = self.run_vhost(target, session)
        if choice not in ("1", "2", "3"):
            print_warning("Invalid choice. Running directory brute-force by default.")
            results["directory"] = self.run_dirs(target, session)

        self.scanner.scan_data["fuzzing"] = results
        return results

    def run_dirs(self, target: str, session=None) -> Dict[str, Any]:
        print_info("Starting directory brute-force...")
        wordlist = self._select_wordlist("dir")
        if not wordlist:
            print_warning("No wordlist available. Using built-in common directories.")
            wordlist = None

        results = self.dir_bruteforce(target, session, wordlist)
        return results

    def run_vhost(self, target: str, session=None) -> Dict[str, Any]:
        print_info("Starting virtual host brute-force...")
        parsed = urlparse(target)
        base_domain = parsed.hostname or ""
        if not base_domain:
            print_error("Could not extract domain from target.")
            return {"target": target, "hits": [], "total": 0}

        wordlist = self._select_wordlist("vhost")
        if not wordlist:
            print_warning("No wordlist available for vhost fuzzing.")
            return {"target": target, "hits": [], "total": 0}

        results = self.vhost_bruteforce(target, session, base_domain, wordlist)
        return results

    def dir_bruteforce(self, target: str, session=None, wordlist: str = None) -> Dict[str, Any]:
        if wordlist and self.ffuf.ensure_installed():
            return self._ffuf_dir_bruteforce(target, wordlist, session)
        return self._internal_dir_bruteforce(target, session)

    def vhost_bruteforce(self, target: str, session=None, base_domain: str = None, wordlist: str = None) -> Dict[str, Any]:
        if wordlist and self.ffuf.ensure_installed():
            return self._ffuf_vhost_bruteforce(target, wordlist, base_domain, session)
        return self._internal_vhost_bruteforce(target, base_domain, session)

    def _ffuf_dir_bruteforce(self, target: str, wordlist: str, session=None) -> Dict[str, Any]:
        print_info(f"Running ffuf directory scan: {target}")
        result = self.ffuf.run_fuzz(target, wordlist, mode="dir", session=session)
        hits = result.get("hits", [])

        for hit in hits:
            url = hit.get("url", "")
            status = hit.get("status", 0)
            length = hit.get("length", 0)
            self.scanner.findings.append(
                f"[FUZZ:DIR] {url} (HTTP {status}, {length} bytes)"
            )

        self.scanner.scan_data["directory_bruteforce"] = {
            "target": target,
            "wordlist": wordlist,
            "hits": hits,
            "total": len(hits),
        }
        print_good(f"Directory fuzzing found {len(hits)} result(s)")
        return {"target": target, "hits": hits, "total": len(hits)}

    def _ffuf_vhost_bruteforce(self, target: str, wordlist: str, base_domain: str, session=None) -> Dict[str, Any]:
        print_info(f"Running ffuf vhost scan on {base_domain}...")
        result = self.ffuf.run_fuzz(target, wordlist, mode="vhost", session=session, base_domain=base_domain)
        hits = result.get("hits", [])

        for hit in hits:
            url = hit.get("url", "")
            status = hit.get("status", 0)
            length = hit.get("length", 0)
            self.scanner.findings.append(
                f"[FUZZ:VHOST] {url} (HTTP {status}, {length} bytes)"
            )

        self.scanner.scan_data["vhosts"] = hits
        print_good(f"Vhost fuzzing found {len(hits)} result(s)")
        return {"target": target, "hits": hits, "total": len(hits)}

    def _internal_dir_bruteforce(self, target: str, session=None) -> Dict[str, Any]:
        print_info("Running internal directory brute-force...")
        if session is None:
            session = get_session()

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        hits: List[Dict[str, Any]] = []

        wordlist = self.wordlists.COMMON_DIRS

        for entry in wordlist:
            try:
                url = f"{base_url}/{entry}"
                resp = session.get(url, timeout=self.config.timeout, verify=self.config.verify_tls, allow_redirects=False)
                if resp.status_code not in (404, 405, 500, 502, 503):
                    body_lower = resp.text.lower()[:500] if resp.text else ""
                    is_listing = any(marker.lower() in body_lower for marker in self.LISTING_MARKERS)
                    hit = {
                        "url": url,
                        "status": resp.status_code,
                        "length": len(resp.content),
                        "directory_listing": is_listing,
                    }
                    hits.append(hit)

                    if resp.status_code in (200, 301, 302, 403):
                        print_info(f"  {resp.status_code} {url}")
                        self.scanner.findings.append(f"[FUZZ:DIR] {url} (HTTP {resp.status_code})")
                        if is_listing:
                            print_warning(f"  Directory listing detected: {url}")
                            self.scanner.findings.append(f"[FUZZ:DIR] Directory listing: {url}")
            except Exception:
                logging.exception("fuzzing.py: exception")
                continue
        self.scanner.scan_data["directory_bruteforce"] = {
            "target": target,
            "hits": hits,
            "total": len(hits),
        }
        print_good(f"Internal directory scan found {len(hits)} result(s)")
        return {"target": target, "hits": hits, "total": len(hits)}

    def _internal_vhost_bruteforce(self, target: str, base_domain: str, session=None) -> Dict[str, Any]:
        print_info(f"Running internal vhost brute-force on {base_domain}...")
        if session is None:
            session = get_session()

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        hits: List[Dict[str, Any]] = []

        subdomain_prefixes = [
            "admin", "api", "dev", "staging", "test", "internal", "portal",
            "mail", "ftp", "vpn", "remote", "webmail", "cpanel", "direct",
            "beta", "alpha", "demo", "sandbox", "uat", "preprod", "edge",
            "static", "cdn", "media", "assets", "img", "files", "backup",
        ]

        try:
            baseline_resp = session.get(base_url, timeout=self.config.timeout, verify=self.config.verify_tls)
            baseline_length = len(baseline_resp.content)
        except Exception:
            logging.exception("fuzzing.py: operation failed")
            baseline_length = 0

        for prefix in subdomain_prefixes:
            try:
                vhost = f"{prefix}.{base_domain}"
                headers = {"Host": vhost}
                resp = session.get(base_url, headers=headers, timeout=self.config.timeout, verify=self.config.verify_tls)
                length = len(resp.content)

                if resp.status_code not in (404, 500, 502, 503) and length != baseline_length:
                    hit = {
                        "vhost": vhost,
                        "status": resp.status_code,
                        "length": length,
                        "baseline_length": baseline_length,
                    }
                    hits.append(hit)
                    print_info(f"  {vhost} -> HTTP {resp.status_code} ({length} bytes)")
                    self.scanner.findings.append(f"[FUZZ:VHOST] {vhost} (HTTP {resp.status_code})")
            except Exception:
                logging.exception("fuzzing.py: exception")
                continue
        self.scanner.scan_data["vhosts"] = hits
        print_good(f"Internal vhost scan found {len(hits)} result(s)")
        return {"target": target, "hits": hits, "total": len(hits)}

    def _select_wordlist(self, mode: str) -> Optional[str]:
        if mode == "vhost":
            candidates = [
                self.wordlists.find_wordlist("subdomains-top1k-5000.txt"),
                self.wordlists.find_wordlist("subdomains-top1million-5000.txt"),
                self.wordlists.find_wordlist("subdomains-top1k-20000.txt"),
                self.wordlists.find_wordlist("subdomains-top1million-20000.txt"),
            ]
        else:
            candidates = [
                self.wordlists.find_wordlist("raft-small-directories.txt"),
                self.wordlists.find_wordlist("directory-list-lowercase-2.3-medium.txt"),
                self.wordlists.find_wordlist("common.txt"),
            ]

        for path in candidates:
            if path and os.path.isfile(path):
                return path
        return None
