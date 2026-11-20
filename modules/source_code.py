import re
import time
from urllib.parse import urlparse, urljoin

from core.config import Config
from core.utils import (
    print_info, print_good, print_warning, print_error,
    print_phase, get_session, normalize_url,
)
from lib.constants import Constants
from lib.payloads import Payloads
import logging


class SourceCodeModule:
    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.payloads = Payloads()
        self.constants = Constants()

    def analyze_source_code(self, target, session, urls=None, max_urls=50, max_assets=100):
        findings = []
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        urls_to_scan = [target]
        if urls:
            urls_to_scan.extend(urls[:max_urls])

        crawled_urls = self.config.scan_data.get("crawl", {}).get("urls", [])
        if crawled_urls:
            for cu in crawled_urls[:max_urls]:
                if cu not in urls_to_scan:
                    urls_to_scan.append(cu)

        asset_urls = set()

        print_info(f"Analyzing source code from {len(urls_to_scan)} URL(s)...")

        for page_url in urls_to_scan[:max_urls]:
            try:
                resp = session.get(
                    page_url,
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                )

                content_type = resp.headers.get("Content-Type", "")
                if "text/html" not in content_type and "javascript" not in content_type:
                    continue

                body = resp.text or ""

                self._extract_asset_urls(body, page_url, base_url, asset_urls)

                page_findings = self._scan_content(body, page_url, "html")
                findings.extend(page_findings)

                time.sleep(self.config.request_delay)

            except Exception:
                logging.exception("source_code.py: exception")
                continue
        print_info(f"Found {len(asset_urls)} asset URLs to analyze...")

        scanned_assets = 0
        for asset_url in list(asset_urls)[:max_assets]:
            try:
                resp = session.get(
                    asset_url,
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                )

                asset_ct = resp.headers.get("Content-Type", "")
                asset_body = resp.text or ""

                asset_ext = urlparse(asset_url).path.lower()
                content_type_label = "javascript" if any(
                    ext in asset_ext for ext in [".js", ".mjs", ".jsx", ".ts"]
                ) else "asset"

                asset_findings = self._scan_content(asset_body, asset_url, content_type_label)
                findings.extend(asset_findings)

                scanned_assets += 1
                if scanned_assets % 20 == 0:
                    print_info(f"  Scanned {scanned_assets}/{len(asset_urls)} assets")

                time.sleep(self.config.request_delay)

            except Exception:
                logging.exception("source_code.py: exception")
                continue
        self.config.scan_data["vulnerabilities"]["info_disclosure"].extend(findings)
        for f in findings:
            if f not in self.config.findings:
                self.config.findings.append(f)

        return findings

    def _extract_asset_urls(self, html, page_url, base_url, asset_urls):
        src_pattern = re.compile(
            r'(?:src|href|action)=["\']([^"\']+)["\']',
            re.IGNORECASE,
        )
        url_pattern = re.compile(
            r'url\(["\']?([^"\')\s]+)["\']?\)',
            re.IGNORECASE,
        )
        import_pattern = re.compile(
            r'(?:import|from)\s+["\']([^"\']+)["\']',
            re.IGNORECASE,
        )
        srcmap_pattern = re.compile(
            r'//#\s*sourceMappingURL\s*=\s*([^\s"\']+)',
            re.IGNORECASE,
        )

        for pattern in [src_pattern, url_pattern, import_pattern, srcmap_pattern]:
            matches = pattern.findall(html)
            for match in matches:
                if not match or match.startswith("data:"):
                    continue

                absolute_url = urljoin(page_url, match)
                url_parsed = urlparse(absolute_url)

                if url_parsed.netloc and url_parsed.netloc != base_url.split("://")[1]:
                    continue

                path_lower = url_parsed.path.lower()
                asset_extensions = (
                    '.js', '.mjs', '.jsx', '.ts', '.tsx', '.json', '.map',
                    '.css', '.txt', '.xml', '.yml', '.yaml', '.env',
                    '.ts', '.tsx', '.vue', '.svelte',
                )

                if any(path_lower.endswith(ext) for ext in asset_extensions):
                    asset_urls.add(absolute_url)

    def _scan_content(self, content, url, content_type):
        findings = []

        for severity, name, pattern, group in self.constants._SOURCE_PATTERNS:
            matches = pattern.finditer(content)
            for match in matches:
                if group and match.lastindex:
                    evidence = match.group(1)
                else:
                    start = max(0, match.start() - 20)
                    end = min(len(content), match.end() + 20)
                    evidence = content[start:end].strip()

                evidence = evidence[:self.constants._SRC_SNIPPET_CHARS]

                finding = {
                    "type": "source_code_secret",
                    "severity": severity,
                    "url": url,
                    "secret_name": name,
                    "evidence": evidence,
                    "content_type": content_type,
                    "position": match.start(),
                }
                findings.append(finding)

                severity_label = severity.upper()
                print_warning(
                    f"[{severity_label}] {name} at {url}: "
                    f"{evidence[:80]}"
                )

        debug_patterns = [
            (re.compile(r'DEBUG\s*[=:]\s*(?:true|1|yes)', re.I), "Debug mode enabled"),
            (re.compile(r'NODE_ENV\s*[=:]\s*["\']?development', re.I), "Development environment"),
            (re.compile(r'APP_ENV\s*[=:]\s*["\']?local', re.I), "Local environment"),
            (re.compile(r'FLASK_DEBUG\s*[=:]\s*(?:1|true)', re.I), "Flask debug mode"),
            (re.compile(r'DJANGO_DEBUG\s*[=:]\s*(?:1|true)', re.I), "Django debug mode"),
        ]

        for pattern, name in debug_patterns:
            if pattern.search(content):
                finding = {
                    "type": "source_code_debug",
                    "severity": "medium",
                    "url": url,
                    "secret_name": name,
                    "evidence": name,
                    "content_type": content_type,
                }
                findings.append(finding)
                print_warning(f"[MEDIUM] {name} at {url}")

        config_patterns = [
            (re.compile(r'(?:mongodb|mysql|postgres(?:ql)?|redis|amqps?|mssql)://[^\s"\'<>]+', re.I),
             "Database connection string"),
            (re.compile(r'(?:aws[_\-]?(?:access[_\-]?)?(?:key|id)|AKIA[0-9A-Z]{16})', re.I),
             "AWS credential reference"),
            (re.compile(r'(?:api[_\-]?key|apikey|api[_\-]?secret)\s*[=:]\s*["\']([^"\']{8,})["\']', re.I),
             "API key"),
            (re.compile(r'(?:secret[_\-]?key|client[_\-]?secret)\s*[=:]\s*["\']([^"\']{8,})["\']', re.I),
             "Secret key"),
            (re.compile(r'(?:private[_\-]?key)\s*[=:]\s*["\']([^"\']{8,})["\']', re.I),
             "Private key reference"),
            (re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']', re.I),
             "Hardcoded password"),
        ]

        for pattern, name in config_patterns:
            matches = pattern.finditer(content)
            for match in matches:
                start = max(0, match.start() - 10)
                end = min(len(content), match.end() + 10)
                evidence = content[start:end].strip()[:self.constants._SRC_SNIPPET_CHARS]

                finding = {
                    "type": "source_code_credential",
                    "severity": "high",
                    "url": url,
                    "secret_name": name,
                    "evidence": evidence,
                    "content_type": content_type,
                }
                findings.append(finding)
                print_warning(f"[HIGH] {name} at {url}: {evidence[:80]}")

        api_endpoint_pattern = re.compile(
            r'["\'](/(?:api|rest|v1|v2|v3|graphql|gql|admin|internal)[^"\']*)["\']',
            re.I,
        )
        endpoints_found = set()
        for match in api_endpoint_pattern.finditer(content):
            endpoint = match.group(1)
            if endpoint not in endpoints_found:
                endpoints_found.add(endpoint)

        if endpoints_found:
            finding = {
                "type": "source_code_endpoints",
                "severity": "info",
                "url": url,
                "secret_name": "API endpoints in source",
                "evidence": f"Found {len(endpoints_found)} endpoints: {', '.join(list(endpoints_found)[:5])}",
                "content_type": content_type,
            }
            findings.append(finding)

        return findings

    def run(self, target, session=None):
        print_phase("Source Code Analysis")
        self.config.target_url = normalize_url(target)

        if session is None:
            session = get_session()
        if session is None:
            print_error("Cannot proceed without a valid HTTP session.")
            return

        all_findings = self.analyze_source_code(target, session)

        if all_findings:
            critical = [f for f in all_findings if f["severity"] == "critical"]
            high = [f for f in all_findings if f["severity"] == "high"]
            medium = [f for f in all_findings if f["severity"] == "medium"]
            info = [f for f in all_findings if f["severity"] == "info"]

            print_good(
                f"Source code analysis complete: "
                f"{len(critical)} critical, {len(high)} high, "
                f"{len(medium)} medium, {len(info)} info findings."
            )
        else:
            print_info("Source code analysis complete: no findings.")
