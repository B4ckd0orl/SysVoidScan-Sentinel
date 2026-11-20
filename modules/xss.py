"""
XSSModule - Cross-Site Scripting testing (reflected, contextual payloads).

Tests discovered parameters for XSS vulnerabilities using
context-aware payload injection and response reflection analysis.
"""

import re
import html
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


class XSSModule:

    CONTEXT_MARKERS = {
        "attribute": re.compile(r'''(\w+)=["']([^"']*?)''' , re.IGNORECASE),
        "javascript": re.compile(r"javascript\s*:", re.IGNORECASE),
        "event_handler": re.compile(r"\bon\w+\s*=", re.IGNORECASE),
        "html_tag": re.compile(r"<\w+[^>]*>", re.IGNORECASE),
    }

    REFLECTION_PATTERNS = [
        re.compile(r"alert\s*\(", re.IGNORECASE),
        re.compile(r"<script", re.IGNORECASE),
        re.compile(r"on\w+\s*=", re.IGNORECASE),
        re.compile(r"javascript\s*:", re.IGNORECASE),
        re.compile(r"<img[^>]+onerror", re.IGNORECASE),
        re.compile(r"<svg[^>]+onload", re.IGNORECASE),
    ]

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.payloads = Config.XSS_PAYLOADS

    def run(self, target: str, session=None):
        print_info(f"Running XSS tests on {target}...")
        results: Dict[str, Any] = {
            "target": target,
            "vulnerable_params": [],
            "findings": [],
        }

        params = self._extract_params(target, session)
        if not params:
            print_info("No injectable parameters found for XSS testing.")
            self.scanner.scan_data["xss"] = results
            return results

        print_info(f"Testing {len(params)} parameter(s) for XSS...")
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

        self.scanner.scan_data["xss"] = results
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
            result = self.test_reflected(url, param_name, session, method)
            if result:
                findings.append(result)

        return findings

    def test_reflected(self, url: str, param: str, session, method: str = "GET") -> Optional[Dict[str, Any]]:
        print_info(f"    Reflected XSS test on '{param}'...")

        marker = "xSsVeId9a7mK"
        try:
            baseline_resp = self._make_request(url, param, marker, method, session)
            baseline_body = baseline_resp.text or ""
            if marker not in baseline_body:
                print_info(f"    Marker not reflected in response for '{param}'.")
                return None
        except Exception as e:
            logging.exception("xss.py: operation failed")
            print_warning(f"    Baseline request failed: {e}")
            return None

        print_info(f"    Marker reflected in response. Testing payloads...")

        for payload in self.payloads:
            try:
                resp = self._make_request(url, param, payload, method, session)
                body = resp.text or ""

                if payload not in body:
                    continue

                context = self._detect_context(body, payload)
                decoded_payload = html.unescape(payload)

                if self._is_payload_effective(body, payload):
                    finding = {
                        "type": "reflected_xss",
                        "url": url,
                        "param": param,
                        "method": method,
                        "payload": payload,
                        "context": context,
                        "status_code": resp.status_code,
                    }
                    print_vuln(
                        f"XSS (reflected) in '{param}' @ {url} | "
                        f"Payload: {payload} | Context: {context}"
                    )
                    self.scanner.findings.append(
                        f"[XSS] {url} param={param} payload='{payload}' context={context}"
                    )
                    return finding
            except Exception:
                logging.exception("xss.py: exception", exc_info=True)
                continue
        print_info(f"    No XSS found for '{param}'.")
        return None

    def _detect_context(self, body: str, payload: str) -> str:
        escaped = re.escape(payload)
        html_match = re.search(rf"<[^>]*{escaped}[^>]*>", body, re.IGNORECASE)
        if html_match:
            tag = html_match.group(0)
            if re.search(r'''=\s*["'][^"']*{escaped}[^"']*["']''', tag, re.IGNORECASE):
                return "attribute"
            return "html_tag"

        attr_match = re.search(rf'\w+\s*=\s*["\'][^"\']*{escaped}[^"\']*["\']', body, re.IGNORECASE)
        if attr_match:
            return "attribute"

        js_match = re.search(rf"javascript\s*:\s*{escaped}", body, re.IGNORECASE)
        if js_match:
            return "javascript_uri"

        event_match = re.search(rf"on\w+\s*=\s*[^>]*{escaped}", body, re.IGNORECASE)
        if event_match:
            return "event_handler"

        return "text_node"

    def _is_payload_effective(self, body: str, payload: str) -> bool:
        if payload not in body:
            return False

        escaped_payload = html.escape(payload)
        if escaped_payload == payload:
            return True

        if escaped_payload in body:
            return False

        return True

    def _make_request(self, url: str, param: str, payload: str, method: str, session):
        if method == "GET":
            test_url = self._inject_param(url, param, payload)
            return session.get(test_url, timeout=self.config.timeout, verify=self.config.verify_tls)
        else:
            return session.post(url, data={param: payload}, timeout=self.config.timeout, verify=self.config.verify_tls)

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
