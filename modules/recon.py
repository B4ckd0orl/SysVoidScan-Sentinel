"""
ReconModule - Reconnaissance and information gathering for web targets.

Collects HTTP headers, cookies, security headers, robots/sitemap,
HTTP methods, information disclosure, directory listing, SSL/TLS info,
and advanced CORS testing.
"""

import re
import ssl
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from core.utils import (
    print_info,
    print_good,
    print_warning,
    print_error,
    print_vuln,
    normalize_url,
)
from lib.payloads import Payloads
from lib.wordlists import Wordlists
import logging


class ReconModule:

    SECURE_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
        "Feature-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
        "Cross-Origin-Embedder-Policy",
        "Cache-Control",
        "Pragma",
    ]

    COOKIE_FLAGS = ["Secure", "HttpOnly", "SameSite"]

    DISCLOSURE_PATTERNS = [
        ("email", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")),
        ("internal_ip", re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")),
        ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
        ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
        ("api_key_leak", re.compile(r"(?i)(?:api[_\-]?key|apikey|secret[_\-]?key|auth[_\-]?token)[\"'\s:=]{1,8}[\"']?([A-Za-z0-9\-_]{16,})")),
        ("sensitive_comment", re.compile(r"<!--[\s\S]{0,500}?(?:password|secret|api[_\-]?key|todo|fixme|hack|debug|deprecated|backdoor)[\s\S]{0,500}?-->", re.IGNORECASE)),
    ]

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config

    def run(self, target: str, session=None):
        print_info(f"Running reconnaissance on {target}...")
        results: Dict[str, Any] = {
            "target": target,
            "info": {},
            "robots": {},
            "http_methods": [],
            "security_headers": {},
            "cookie_security": [],
            "info_disclosure": [],
            "directory_listing": [],
            "ssl_tls": {},
            "cors": {},
        }

        try:
            resp_info = self.gather_info(target, session)
            results["info"] = resp_info
        except Exception as e:
            logging.exception("recon.py: operation failed")
            print_warning(f"Error gathering info: {e}")

        try:
            results["robots"] = self.check_robots_sitemap(target, session)
        except Exception as e:
            logging.exception("recon.py: operation failed")
            print_warning(f"Error checking robots/sitemap: {e}")

        try:
            results["http_methods"] = self.check_http_methods(target, session)
        except Exception as e:
            logging.exception("recon.py: operation failed")
            print_warning(f"Error checking HTTP methods: {e}")

        headers = results["info"].get("headers", {})
        if headers:
            results["security_headers"] = self.check_security_headers(headers)

        cookies = results["info"].get("cookies", [])
        if cookies:
            results["cookie_security"] = self.check_cookie_security(cookies)

        resp_text = results["info"].get("body", "")
        if resp_text:
            results["info_disclosure"] = self.check_info_disclosure(resp_text)

        try:
            results["directory_listing"] = self.check_directory_listing(target, session)
        except Exception as e:
            logging.exception("recon.py: operation failed")
            print_warning(f"Error checking directory listing: {e}")

        try:
            results["ssl_tls"] = self.check_ssl_tls(target)
        except Exception as e:
            logging.exception("recon.py: operation failed")
            print_warning(f"Error checking SSL/TLS: {e}")

        try:
            results["cors"] = self.test_cors_advanced(target, session)
        except Exception as e:
            logging.exception("recon.py: operation failed")
            print_warning(f"Error testing CORS: {e}")

        self.scanner.scan_data["recon"] = results
        print_good("Reconnaissance completed.")
        return results

    def gather_info(self, target: str, session=None) -> Dict[str, Any]:
        print_info("Gathering HTTP information...")
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        info: Dict[str, Any] = {
            "url": target,
            "status_code": 0,
            "headers": {},
            "cookies": [],
            "server": "",
            "title": "",
            "body": "",
            "content_length": 0,
            "redirect_chain": [],
        }

        try:
            if session is None:
                from core.utils import get_session
                session = get_session()

            resp = session.get(target, timeout=self.config.timeout, allow_redirects=True, verify=self.config.verify_tls)
            info["status_code"] = resp.status_code
            info["headers"] = dict(resp.headers)
            info["cookies"] = [
                {"name": c.name, "value": c.value, "domain": c.domain, "path": c.path}
                for c in resp.cookies
            ]
            info["server"] = resp.headers.get("Server", "")
            info["content_length"] = len(resp.content)

            title_match = re.search(r"<title[^>]*>([^<]+)</title>", resp.text, re.IGNORECASE)
            if title_match:
                info["title"] = title_match.group(1).strip()

            info["body"] = resp.text[:50000]

            if resp.history:
                info["redirect_chain"] = [
                    {"url": r.url, "status": r.status_code} for r in resp.history
                ]

            print_good(f"HTTP {resp.status_code} | Server: {info['server'] or 'N/A'} | Title: {info['title'] or 'N/A'}")

        except Exception as e:
            logging.exception("recon.py: operation failed")
            print_error(f"HTTP request failed: {e}")

        return info

    def check_robots_sitemap(self, target: str, session=None) -> Dict[str, Any]:
        print_info("Checking robots.txt and sitemap.xml...")
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        results: Dict[str, Any] = {"robots": {}, "sitemap": {}}

        if session is None:
            from core.utils import get_session
            session = get_session()

        robots_url = urljoin(base_url, "/robots.txt")
        try:
            resp = session.get(robots_url, timeout=self.config.timeout, verify=self.config.verify_tls)
            if resp.status_code == 200 and len(resp.text.strip()) > 0:
                results["robots"] = {"url": robots_url, "status": resp.status_code, "content": resp.text[:5000]}
                print_good(f"robots.txt found ({len(resp.text)} bytes)")
                paths = re.findall(r"(?:Allow|Disallow|Sitemap):\s*(.+)", resp.text, re.IGNORECASE)
                sensitive = [p for p in paths if any(k in p.lower() for k in ("admin", "config", "backup", ".env", "private", "secret"))]
                if sensitive:
                    print_vuln(f"Sensitive paths in robots.txt: {', '.join(sensitive[:5])}")
                    self.scanner.findings.append(f"[RECON] Sensitive paths exposed in robots.txt: {', '.join(sensitive[:5])}")
            else:
                print_info("robots.txt not found or empty.")
        except Exception as e:
            logging.exception("recon.py: operation failed")
            print_warning(f"Error fetching robots.txt: {e}")

        sitemap_url = urljoin(base_url, "/sitemap.xml")
        try:
            resp = session.get(sitemap_url, timeout=self.config.timeout, verify=self.config.verify_tls)
            if resp.status_code == 200 and len(resp.text.strip()) > 0:
                results["sitemap"] = {"url": sitemap_url, "status": resp.status_code, "content": resp.text[:10000]}
                print_good(f"sitemap.xml found ({len(resp.text)} bytes)")
        except Exception as e:
            logging.exception("recon.py: operation failed")
            print_warning(f"Error fetching sitemap.xml: {e}")

        return results

    def check_http_methods(self, target: str, session=None) -> List[Dict[str, Any]]:
        print_info("Checking HTTP methods (OPTIONS, TRACE)...")
        methods_found: List[Dict[str, Any]] = []

        if session is None:
            from core.utils import get_session
            session = get_session()

        try:
            resp = session.options(target, timeout=self.config.timeout, verify=self.config.verify_tls)
            allow = resp.headers.get("Allow", "")
            if allow:
                methods = [m.strip() for m in allow.split(",")]
                for m in methods:
                    methods_found.append({"method": m, "source": "OPTIONS", "status": resp.status_code})
                print_good(f"OPTIONS: {allow}")

                dangerous = [m for m in methods if m.upper() in ("TRACE", "TRACK", "DELETE", "PUT")]
                if dangerous:
                    print_vuln(f"Dangerous HTTP methods enabled: {', '.join(dangerous)}")
                    self.scanner.findings.append(f"[RECON] Dangerous HTTP methods: {', '.join(dangerous)}")
        except Exception as e:
            logging.exception("recon.py: operation failed")
            print_warning(f"OPTIONS request failed: {e}")

        try:
            resp = session.request("TRACE", target, timeout=self.config.timeout, verify=self.config.verify_tls)
            if resp.status_code == 200:
                methods_found.append({"method": "TRACE", "source": "TRACE", "status": resp.status_code})
                print_vuln("TRACE method enabled - potential XST vulnerability")
                self.scanner.findings.append("[RECON] TRACE method enabled (XST risk)")
        except Exception as e:
            logging.exception("recon.py: operation failed")
            pass

        return methods_found

    def check_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        print_info("Analyzing security headers...")
        results: Dict[str, Any] = {"missing": [], "present": [], "misconfigured": []}

        for header in self.SECURE_HEADERS:
            if header in headers:
                results["present"].append(header)
            else:
                results["missing"].append(header)
                print_warning(f"Missing security header: {header}")

        if results["missing"]:
            self.scanner.findings.append(f"[RECON] Missing security headers: {', '.join(results['missing'])}")

        hsts = headers.get("Strict-Transport-Security", "")
        if hsts:
            max_age_match = re.search(r"max-age=(\d+)", hsts)
            if max_age_match and int(max_age_match.group(1)) < 31536000:
                results["misconfigured"].append("Strict-Transport-Security max-age too low")
                print_warning("HSTS max-age is below 1 year")

        csp = headers.get("Content-Security-Policy", "")
        if csp and "unsafe-inline" in csp:
            results["misconfigured"].append("CSP contains unsafe-inline")

        xfo = headers.get("X-Frame-Options", "").upper()
        if xfo and xfo not in ("DENY", "SAMEORIGIN"):
            results["misconfigured"].append(f"X-Frame-Options unusual value: {xfo}")

        print_good(f"Security headers: {len(results['present'])} present, {len(results['missing'])} missing")
        return results

    def check_cookie_security(self, cookies: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        print_info("Analyzing cookie security flags...")
        results: List[Dict[str, Any]] = []

        for cookie in cookies:
            name = cookie.get("name", "")
            flags_missing = []

            cookie_str = str(cookie)
            for flag in self.COOKIE_FLAGS:
                if flag.lower() not in cookie_str.lower():
                    flags_missing.append(flag)

            entry = {"name": name, "flags_missing": flags_missing, "secure": len(flags_missing) == 0}
            results.append(entry)

            if flags_missing:
                print_warning(f"Cookie '{name}' missing flags: {', '.join(flags_missing)}")
                self.scanner.findings.append(f"[RECON] Cookie '{name}' missing: {', '.join(flags_missing)}")

        secure_count = sum(1 for r in results if r["secure"])
        print_good(f"Cookies analyzed: {secure_count}/{len(results)} fully secure")
        return results

    def check_info_disclosure(self, resp_text: str) -> List[Dict[str, str]]:
        print_info("Checking for information disclosure...")
        findings: List[Dict[str, str]] = []

        for disc_type, pattern in self.DISCLOSURE_PATTERNS:
            matches = pattern.findall(resp_text)
            if matches:
                unique_matches = list(set(matches))[:10]
                for match in unique_matches:
                    entry = {"type": disc_type, "match": str(match)[:200]}
                    findings.append(entry)
                    print_vuln(f"Info disclosure ({disc_type}): {str(match)[:100]}")
                    self.scanner.findings.append(f"[RECON] Info disclosure ({disc_type}): {str(match)[:100]}")

        print_good(f"Info disclosure checks: {len(findings)} findings")
        return findings

    def check_directory_listing(self, target: str, session=None) -> List[Dict[str, Any]]:
        print_info("Checking for directory listing...")
        findings: List[Dict[str, Any]] = []

        if session is None:
            from core.utils import get_session
            session = get_session()

        test_paths = ["/images/", "/uploads/", "/files/", "/backup/", "/static/", "/assets/"]
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        listing_markers = [
            "<title>Index of",
            "<h1>Index of",
            "Directory listing for",
            "Parent Directory</a>",
            "<pre>",
            "Index of /",
        ]

        for path in test_paths:
            try:
                url = urljoin(base_url, path)
                resp = session.get(url, timeout=self.config.timeout, verify=self.config.verify_tls)
                if resp.status_code == 200:
                    body_lower = resp.text.lower()
                    if any(marker.lower() in body_lower for marker in listing_markers):
                        entry = {"url": url, "status": resp.status_code}
                        findings.append(entry)
                        print_vuln(f"Directory listing found: {url}")
                        self.scanner.findings.append(f"[RECON] Directory listing exposed: {url}")
            except Exception:
                logging.exception("recon.py: exception", exc_info=True)
                continue
        if not findings:
            print_good("No directory listing found.")
        return findings

    def check_ssl_tls(self, target: str) -> Dict[str, Any]:
        print_info("Checking SSL/TLS configuration...")
        parsed = urlparse(target)
        hostname = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        ssl_info: Dict[str, Any] = {
            "valid": False,
            "issuer": "",
            "subject": "",
            "expiration": "",
            "protocol": "",
            "cipher": "",
            "san": [],
        }

        if not hostname:
            print_warning("Could not extract hostname for SSL check.")
            return ssl_info

        if parsed.scheme != "https":
            print_info("Target is not HTTPS, skipping SSL check.")
            return ssl_info

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.config.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info["valid"] = True
                    ssl_info["protocol"] = ssock.version()
                    ssl_info["cipher"] = ssock.cipher()[0] if ssock.cipher() else ""

                    issuer_parts = []
                    for rdn in cert.get("issuer", ()):
                        for attr in rdn:
                            if attr[0] in ("organizationName", "commonName"):
                                issuer_parts.append(attr[1])
                    ssl_info["issuer"] = " / ".join(issuer_parts)

                    subject_parts = []
                    for rdn in cert.get("subject", ()):
                        for attr in rdn:
                            if attr[0] == "commonName":
                                subject_parts.append(attr[1])
                    ssl_info["subject"] = " / ".join(subject_parts)

                    not_after = cert.get("notAfter", "")
                    ssl_info["expiration"] = not_after

                    san_entries = cert.get("subjectAltName", ())
                    ssl_info["san"] = [entry[1] for entry in san_entries[:20]]

                    print_good(f"SSL/TLS valid | Protocol: {ssl_info['protocol']} | Issuer: {ssl_info['issuer'][:60]}")

                    if not_after:
                        from datetime import datetime
                        try:
                            exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            from datetime import timezone
                            if exp_date.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
                                print_vuln("SSL certificate has expired!")
                                self.scanner.findings.append("[RECON] SSL certificate expired!")
                        except Exception:
                            logging.exception("recon.py: exception", exc_info=True)
                            pass
        except ssl.SSLCertVerificationError as e:
            print_warning(f"SSL certificate verification failed: {e}")
            ssl_info["valid"] = False
            self.scanner.findings.append(f"[RECON] SSL certificate issue: {e}")
        except Exception as e:
            logging.exception("recon.py: operation failed")
            print_warning(f"SSL check failed: {e}")

        return ssl_info

    def test_cors_advanced(self, target: str, session=None) -> Dict[str, Any]:
        print_info("Testing CORS configuration...")
        cors_results: Dict[str, Any] = {
            "wildcard": False,
            "origin_reflection": False,
            "preflight": False,
            "credentials": False,
            "details": [],
        }

        if session is None:
            from core.utils import get_session
            session = get_session()

        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            "https://" + (urlparse(target).hostname or "target.com") + ".evil.com",
        ]

        for origin in test_origins:
            try:
                headers = {"Origin": origin}
                resp = session.get(target, headers=headers, timeout=self.config.timeout, verify=self.config.verify_tls)
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                if acao:
                    detail = {"origin_sent": origin, "acao": acao, "acac": acac}
                    cors_results["details"].append(detail)

                    if acao == "*" and origin != "*":
                        cors_results["wildcard"] = True
                        print_vuln(f"CORS wildcard with origin: {origin} -> {acao}")
                        self.scanner.findings.append(f"[RECON] CORS wildcard: {origin}")

                    if acao == origin and origin in ("https://evil.com", "https://attacker.com", "null"):
                        cors_results["origin_reflection"] = True
                        print_vuln(f"CORS origin reflection: {origin} -> {acao}")
                        self.scanner.findings.append(f"[RECON] CORS origin reflection: {origin}")

                    if acac.lower() == "true" and acao != "*":
                        cors_results["credentials"] = True
                        print_vuln(f"CORS with credentials reflected: {origin}")
                        self.scanner.findings.append(f"[RECON] CORS credentials with reflected origin: {origin}")
            except Exception:
                logging.exception("recon.py: exception", exc_info=True)
                continue
        try:
            resp = session.options(
                target,
                headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "PUT",
                },
                timeout=self.config.timeout,
                verify=self.config.verify_tls,
            )
            if resp.headers.get("Access-Control-Allow-Methods"):
                cors_results["preflight"] = True
                print_info(f"CORS preflight responds with methods: {resp.headers.get('Access-Control-Allow-Methods')}")
        except Exception:
            logging.exception("recon.py: exception", exc_info=True)
            pass
        if not cors_results["wildcard"] and not cors_results["origin_reflection"]:
            print_good("CORS configuration appears restrictive.")
        return cors_results
