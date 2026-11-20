"""
OpenRedirectModule - Open redirect vulnerability testing.

Tests discovered parameters for open redirect vulnerabilities
by injecting external redirect payloads and checking response behavior.
"""

import re
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


class OpenRedirectModule:

    CANARY_DOMAIN = "evil-redirect-test-9a7b3c.com"

    REDIRECT_PARAMS = [
        "url", "uri", "redirect", "redirect_url", "redirect_uri", "return",
        "return_url", "returnurl", "next", "continue", "dest", "destination",
        "goto", "go", "out", "view", "to", "target", "ref", "rurl",
        "callback", "redir", "redirect_to", "location",
    ]

    INTERNAL_MARKERS = ["login", "signin", "dashboard", "home", "index"]

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.payloads = Config.OPEN_REDIRECT

    def run(self, target: str, session=None):
        print_info(f"Running open redirect tests on {target}...")
        results: Dict[str, Any] = {
            "target": target,
            "vulnerable_params": [],
            "findings": [],
        }

        params = self._extract_params(target, session)
        if not params:
            print_info("No injectable parameters found for open redirect testing.")
            self.scanner.scan_data["open_redirect"] = results
            return results

        print_info(f"Testing {len(params)} parameter(s) for open redirect...")
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

        self.scanner.scan_data["open_redirect"] = results
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
            result = self.test_open_redirect(url, param_name, session, method)
            if result:
                findings.append(result)

        return findings

    def test_open_redirect(self, url: str, param: str, session, method: str = "GET") -> Optional[Dict[str, Any]]:
        print_info(f"    Open redirect test on '{param}'...")

        test_payloads = [
            f"https://{self.CANARY_DOMAIN}",
            f"//{self.CANARY_DOMAIN}",
            f"//{self.CANARY_DOMAIN}/path",
        ]

        for payload in test_payloads:
            try:
                resp = self._make_request(url, param, payload, method, session, allow_redirects=False)
                location = resp.headers.get("Location", "")

                if self.CANARY_DOMAIN in location:
                    finding = {
                        "type": "open_redirect",
                        "url": url,
                        "param": param,
                        "method": method,
                        "payload": payload,
                        "redirect_to": location,
                        "status_code": resp.status_code,
                        "detection": "header_redirect",
                    }
                    print_vuln(
                        f"Open redirect in '{param}' @ {url} | "
                        f"Payload: {payload} -> {location}"
                    )
                    self.scanner.findings.append(
                        f"[OPEN-REDIRECT] {url} param={param} payload='{payload}' -> {location}"
                    )
                    return finding
            except Exception:
                logging.exception("open_redirect.py: exception", exc_info=True)
                continue
        for payload in test_payloads:
            try:
                resp = self._make_request(url, param, payload, method, session, allow_redirects=True)
                final_url = resp.url

                if self.CANARY_DOMAIN in final_url and self.CANARY_DOMAIN not in url:
                    finding = {
                        "type": "open_redirect",
                        "url": url,
                        "param": param,
                        "method": method,
                        "payload": payload,
                        "redirect_to": final_url,
                        "status_code": resp.status_code,
                        "detection": "followed_redirect",
                    }
                    print_vuln(
                        f"Open redirect (followed) in '{param}' @ {url} | "
                        f"Payload: {payload} -> {final_url}"
                    )
                    self.scanner.findings.append(
                        f"[OPEN-REDIRECT] {url} param={param} payload='{payload}' -> {final_url} (followed)"
                    )
                    return finding
            except Exception:
                logging.exception("open_redirect.py: exception", exc_info=True)
                continue
        javascript_payloads = [
            "javascript:alert(1)",
            "javascript:alert(document.domain)",
            "data:text/html,<script>alert(1)</script>",
        ]

        for payload in javascript_payloads:
            try:
                resp = self._make_request(url, param, payload, method, session, allow_redirects=False)
                location = resp.headers.get("Location", "")

                if payload in location:
                    finding = {
                        "type": "open_redirect",
                        "url": url,
                        "param": param,
                        "method": method,
                        "payload": payload,
                        "redirect_to": location,
                        "status_code": resp.status_code,
                        "detection": "javascript_redirect",
                    }
                    print_vuln(
                        f"Open redirect (javascript:) in '{param}' @ {url} | "
                        f"Payload: {payload}"
                    )
                    self.scanner.findings.append(
                        f"[OPEN-REDIRECT:XSS] {url} param={param} payload='{payload}'"
                    )
                    return finding
            except Exception:
                logging.exception("open_redirect.py: exception", exc_info=True)
                continue
        print_info(f"    No open redirect found for '{param}'.")
        return None

    def _make_request(self, url: str, param: str, payload: str, method: str, session, allow_redirects: bool = True):
        kwargs = {
            "timeout": self.config.timeout,
            "verify": self.config.verify_tls,
            "allow_redirects": allow_redirects,
        }

        if method == "GET":
            test_url = self._inject_param(url, param, payload)
            return session.get(test_url, **kwargs)
        else:
            return session.post(url, data={param: payload}, **kwargs)

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
                pname = fp.get("name", "")
                if pname:
                    params.append({
                        "url": form_url,
                        "name": pname,
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

        all_params = []
        for p in params:
            if p["name"] in self.REDIRECT_PARAMS:
                all_params.append(p)

        if not all_params:
            all_params = params

        seen = set()
        unique_params = []
        for p in all_params:
            k = (p["url"], p["name"], p["method"])
            if k not in seen:
                seen.add(k)
                unique_params.append(p)

        return unique_params
