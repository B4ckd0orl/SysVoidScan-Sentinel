import re
import time
from urllib.parse import urlparse, parse_qs, urlencode

from core.config import Config
from core.utils import (
    print_info, print_good, print_warning, print_error, print_vuln,
    print_phase, get_session, normalize_url,
)
from lib.payloads import Payloads
import logging


class SSTIModule:
    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.payloads = Payloads()

    def test_ssti(self, url, param, session, method="GET"):
        findings = []
        probes = self.payloads.SSTI_PROBES
        error_markers = self.payloads.SSTI_ERROR_MARKERS

        parsed = urlparse(url)
        base_params = parse_qs(parsed.query, keep_blank_values=True)

        for probe, expected_result, engine in probes:
            try:
                if method.upper() == "GET":
                    test_params = dict(base_params)
                    test_params[param] = [probe]
                    new_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                    resp = session.get(test_url, timeout=self.config.timeout,
                                       verify=self.config.verify_tls)
                else:
                    test_url = url
                    data = {param: probe}
                    resp = session.post(url, data=data, timeout=self.config.timeout,
                                        verify=self.config.verify_tls)

                body = resp.text or ""

                if expected_result in body:
                    finding = {
                        "type": "ssti",
                        "severity": "critical",
                        "url": url,
                        "param": param,
                        "method": method,
                        "probe": probe,
                        "expected": expected_result,
                        "engine": engine,
                        "response_code": resp.status_code,
                    }
                    findings.append(finding)
                    print_vuln(
                        f"SSTI confirmed ({engine}) via param '{param}': "
                        f"probe '{probe}' returned {expected_result}"
                    )
                    return findings

                for marker in error_markers:
                    if marker.lower() in body.lower():
                        finding = {
                            "type": "ssti_error",
                            "severity": "high",
                            "url": url,
                            "param": param,
                            "method": method,
                            "probe": probe,
                            "error_marker": marker,
                            "engine": engine,
                            "response_code": resp.status_code,
                        }
                        findings.append(finding)
                        print_vuln(
                            f"SSTI error indicator ({engine}) via param '{param}': "
                            f"got '{marker}' in response"
                        )
                        return findings

                if resp.status_code == 500 and probe in body:
                    finding = {
                        "type": "ssti_500",
                        "severity": "medium",
                        "url": url,
                        "param": param,
                        "method": method,
                        "probe": probe,
                        "response_code": 500,
                    }
                    findings.append(finding)
                    print_warning(
                        f"Possible SSTI via param '{param}': "
                        f"probe reflected in 500 error response"
                    )

            except Exception:
                logging.exception("ssti.py: exception")
                continue
        return findings

    def run_on_params(self, target, params, session):
        all_findings = []
        for param, method in params:
            print_info(f"  Testing parameter '{param}' ({method}) for SSTI...")
            findings = self.test_ssti(target, param, session, method)
            all_findings.extend(findings)
            if findings:
                break
        return all_findings

    def run(self, target, session=None):
        print_phase("SSTI Testing")
        self.config.target_url = normalize_url(target)

        if session is None:
            session = get_session()
        if session is None:
            print_error("Cannot proceed without a valid HTTP session.")
            return

        all_findings = []
        parsed = urlparse(target)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if params:
            print_info(f"Found {len(params)} URL parameters, testing each for SSTI...")
            param_list = [(p, "GET") for p in params]
            findings = self.run_on_params(target, param_list, session)
            all_findings.extend(findings)

        try:
            resp = session.get(target, timeout=self.config.timeout,
                               verify=self.config.verify_tls)
            body = resp.text or ""

            form_pattern = re.compile(
                r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']?(post|get)["\']?',
                re.IGNORECASE | re.DOTALL,
            )
            forms = form_pattern.findall(body)

            input_pattern = re.compile(
                r'<input[^>]*name=["\']([^"\']+)["\']',
                re.IGNORECASE,
            )
            inputs = input_pattern.findall(body)

            if inputs and not params:
                print_info(f"Found {len(inputs)} form inputs, testing for SSTI...")
                for inp_name in inputs[:10]:
                    findings = self.test_ssti(target, inp_name, session, "POST")
                    all_findings.extend(findings)
                    if findings:
                        break
        except Exception:
            logging.exception("ssti.py: exception")
            pass
        content_type = resp.headers.get("Content-Type", "") if resp else ""
        if "json" in content_type:
            print_info("JSON response detected, testing JSON body for SSTI...")
            json_payloads = [
                '{"input": "{{1337*1337}}"}',
                '{"query": "${1337*1337}"}',
                '{"data": "<%= 1337*1337 %>"}',
                '{"value": "#{1337*1337}"}',
            ]
            for jp in json_payloads:
                try:
                    resp = session.post(
                        target,
                        data=jp,
                        headers={"Content-Type": "application/json"},
                        timeout=self.config.timeout,
                        verify=self.config.verify_tls,
                    )
                    if "1787569" in (resp.text or ""):
                        finding = {
                            "type": "ssti",
                            "severity": "critical",
                            "url": target,
                            "param": "json_body",
                            "method": "POST",
                            "probe": jp,
                            "expected": "1787569",
                            "engine": "JSON-injected template",
                            "response_code": resp.status_code,
                        }
                        all_findings.append(finding)
                        print_vuln("SSTI confirmed via JSON body injection")
                        break
                except Exception:
                    logging.exception("ssti.py: exception")
                    continue
        self.config.scan_data["vulnerabilities"]["template_injection"] = all_findings
        for f in all_findings:
            if f not in self.config.findings:
                self.config.findings.append(f)

        if all_findings:
            print_good(f"SSTI testing complete: {len(all_findings)} potential issue(s) found.")
        else:
            print_info("SSTI testing complete: no vulnerabilities found.")
