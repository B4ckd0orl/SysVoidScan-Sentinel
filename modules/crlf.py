import re
from urllib.parse import urlparse, parse_qs, urlencode, quote

from core.config import Config
from core.utils import (
    print_info, print_good, print_warning, print_error, print_vuln,
    print_phase, get_session, normalize_url,
)
from lib.payloads import Payloads
import logging


class CRLFModule:
    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.payloads = Payloads()

    def test_crlf(self, target, session):
        findings = []
        crlf_payloads = self.payloads.CRLF_PAYLOADS
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        path_payloads = []
        for payload in crlf_payloads:
            path_payloads.append(f"/{quote(payload.lstrip('/'), safe='')}")
            path_payloads.append(payload)

        print_info("Testing URL paths for CRLF injection...")
        for path_payload in path_payloads:
            test_url = f"{base}{path_payload}"
            try:
                resp = session.get(
                    test_url,
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                    allow_redirects=False,
                )

                for header_name, header_value in resp.headers.items():
                    lower_val = header_value.lower()
                    if "crlf_test" in lower_val or "x-crlf-test" in lower_val:
                        finding = {
                            "type": "crlf",
                            "severity": "high",
                            "url": target,
                            "injection_point": "path",
                            "payload": path_payload,
                            "injected_header": header_name,
                            "injected_value": header_value,
                        }
                        findings.append(finding)
                        print_vuln(
                            f"CRLF injection via path at {target}: "
                            f"header '{header_name}: {header_value}' injected"
                        )
                        break

                set_cookie_headers = [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]
                for sc in set_cookie_headers:
                    if "crlf_test" in sc.lower():
                        finding = {
                            "type": "crlf_cookie",
                            "severity": "high",
                            "url": target,
                            "injection_point": "path",
                            "payload": path_payload,
                            "injected_cookie": sc,
                        }
                        findings.append(finding)
                        print_vuln(
                            f"CRLF cookie injection via path at {target}: "
                            f"Set-Cookie: {sc}"
                        )

            except Exception:
                logging.exception("crlf.py: exception")
                continue
        params = parse_qs(parsed.query, keep_blank_values=True)
        if params:
            print_info(f"Testing {len(params)} URL parameters for CRLF injection...")
            for param in params:
                for payload in crlf_payloads:
                    test_params = dict(params)
                    test_params[param] = [payload]
                    new_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                    try:
                        resp = session.get(
                            test_url,
                            timeout=self.config.timeout,
                            verify=self.config.verify_tls,
                            allow_redirects=False,
                        )

                        for header_name, header_value in resp.headers.items():
                            lower_val = header_value.lower()
                            if "crlf_test" in lower_val or "x-crlf-test" in lower_val:
                                finding = {
                                    "type": "crlf",
                                    "severity": "high",
                                    "url": target,
                                    "injection_point": f"param:{param}",
                                    "payload": payload,
                                    "injected_header": header_name,
                                    "injected_value": header_value,
                                }
                                findings.append(finding)
                                print_vuln(
                                    f"CRLF injection via param '{param}' at {target}: "
                                    f"header '{header_name}: {header_value}' injected"
                                )
                                break

                        set_cookie_headers = [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]
                        for sc in set_cookie_headers:
                            if "crlf_test" in sc.lower():
                                finding = {
                                    "type": "crlf_cookie",
                                    "severity": "high",
                                    "url": target,
                                    "injection_point": f"param:{param}",
                                    "payload": payload,
                                    "injected_cookie": sc,
                                }
                                findings.append(finding)
                                print_vuln(
                                    f"CRLF cookie injection via param '{param}' at {target}: "
                                    f"Set-Cookie: {sc}"
                                )

                    except Exception:
                        logging.exception("crlf.py: exception")
                        continue
        header_inject_payloads = [
            "%0d%0aInjected-Header:SysVoid",
            "\r\nInjected-Header:SysVoid",
            "%0D%0AInjected-Header:%20SysVoid",
        ]

        print_info("Testing header-based CRLF injection...")
        for payload in header_inject_payloads:
            try:
                resp = session.get(
                    target,
                    headers={"Referer": f"{target}{payload}"},
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                    allow_redirects=False,
                )
                body = resp.text or ""
                if "Injected-Header" in body or "SysVoid" in body:
                    finding = {
                        "type": "crlf_header_reflection",
                        "severity": "medium",
                        "url": target,
                        "injection_point": "referer_header",
                        "payload": payload,
                    }
                    findings.append(finding)
                    print_vuln(
                        f"CRLF header reflection via Referer at {target}"
                    )
            except Exception:
                logging.exception("crlf.py: exception")
                continue
        return findings

    def run(self, target, session=None):
        print_phase("CRLF Injection Testing")
        self.config.target_url = normalize_url(target)

        if session is None:
            session = get_session()
        if session is None:
            print_error("Cannot proceed without a valid HTTP session.")
            return

        all_findings = self.test_crlf(target, session)

        self.config.scan_data["vulnerabilities"]["crlf"] = all_findings
        for f in all_findings:
            if f not in self.config.findings:
                self.config.findings.append(f)

        if all_findings:
            print_good(f"CRLF testing complete: {len(all_findings)} potential issue(s) found.")
        else:
            print_info("CRLF testing complete: no vulnerabilities found.")
