import random
import time
from urllib.parse import urlparse

from core.config import Config
from core.utils import (
    print_info, print_good, print_warning, print_error, print_vuln,
    print_phase, get_session, normalize_url,
)
from lib.payloads import Payloads
import logging


class CachePoisoningModule:
    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.payloads = Payloads()

    def test_cache_poisoning(self, target, session):
        findings = []
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        poison_headers = self.payloads.CACHE_POISON_HEADERS
        canary = f"sysvoid{random.randint(10000, 99999)}"

        print_info("Testing cache poisoning via non-standard headers...")

        normal_resp = None
        try:
            normal_resp = session.get(target, timeout=self.config.timeout,
                                      verify=self.config.verify_tls)
        except Exception:
            logging.exception("cache_poisoning.py: operation failed")
            print_error("Cannot fetch target for baseline response.")
            return findings

        normal_etag = normal_resp.headers.get("ETag", "")
        normal_last_modified = normal_resp.headers.get("Last-Modified", "")
        normal_cc = normal_resp.headers.get("Cache-Control", "")
        normal_via = normal_resp.headers.get("Via", "")
        normal_cf = normal_resp.headers.get("CF-Cache-Status", "")
        normal_age = normal_resp.headers.get("Age", "")

        is_cacheable = any([normal_etag, normal_last_modified, "max-age" in normal_cc.lower(),
                           normal_via, normal_cf in ("HIT", "MISS"), normal_age])

        if not is_cacheable:
            print_info("Target does not appear to have caching headers. Testing anyway...")

        for header_name, header_value_template in poison_headers:
            header_value = header_value_template.replace("{rand}", canary)

            poisoned_headers = {header_name: header_value}

            try:
                resp1 = session.get(
                    target,
                    headers=poisoned_headers,
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                )

                cache_status = resp1.headers.get("CF-Cache-Status", "")
                via = resp1.headers.get("Via", "")
                age = resp1.headers.get("Age", "")
                x_cache = resp1.headers.get("X-Cache", "")
                x_cache_lookup = resp1.headers.get("X-Cache-Lookup", "")

                time.sleep(1)

                try:
                    resp2 = session.get(
                        target,
                        timeout=self.config.timeout,
                        verify=self.config.verify_tls,
                    )

                    body2 = resp2.text or ""
                    headers2 = dict(resp2.headers)

                    poisoned_detected = False
                    evidence_parts = []

                    if canary.lower() in body2.lower():
                        poisoned_detected = True
                        evidence_parts.append(f"canary '{canary}' in response body")

                    for h_name, h_val in headers2.items():
                        if canary.lower() in h_val.lower():
                            poisoned_detected = True
                            evidence_parts.append(f"canary in header {h_name}: {h_val}")

                    if header_name.lower() == "x-forwarded-host":
                        host_header = resp2.headers.get("Host", "")
                        if canary in host_header:
                            poisoned_detected = True
                            evidence_parts.append(f"Host header poisoned to: {host_header}")

                    if poisoned_detected:
                        finding = {
                            "type": "cache_poisoning",
                            "severity": "high",
                            "url": target,
                            "poison_header": header_name,
                            "poison_value": header_value,
                            "cache_status": cache_status,
                            "via": via,
                            "evidence": "; ".join(evidence_parts),
                        }
                        findings.append(finding)
                        print_vuln(
                            f"Cache poisoning via '{header_name}': "
                            f"{'; '.join(evidence_parts)}"
                        )

                    elif cache_status or x_cache:
                        finding = {
                            "type": "cache_poisoning_candidate",
                            "severity": "medium",
                            "url": target,
                            "poison_header": header_name,
                            "poison_value": header_value,
                            "cache_status": cache_status,
                            "x_cache": x_cache,
                            "evidence": f"Cache header present: {cache_status or x_cache}",
                        }
                        findings.append(finding)
                        print_warning(
                            f"Cache poisoning candidate via '{header_name}': "
                            f"cache headers present ({cache_status or x_cache})"
                        )

                except Exception:
                    logging.exception("cache_poisoning.py: exception")
                    continue
            except Exception:
                logging.exception("cache_poisoning.py: exception")
                continue
        print_info("Testing cache poisoning via URL path manipulation...")
        path_poison_payloads = [
            f"/..;/{canary}",
            f"/{canary}%2f..%2f",
            f"/{canary}%0d%0a",
            f"/{canary}#",
            f"/{canary}?",
            f"/{canary}??",
        ]

        for path_payload in path_poison_payloads:
            test_url = f"{base}{path_payload}"
            try:
                resp = session.get(test_url, timeout=5,
                                   verify=self.config.verify_tls,
                                   allow_redirects=False)

                cache_status = resp.headers.get("CF-Cache-Status", "")
                x_cache = resp.headers.get("X-Cache", "")

                if cache_status == "HIT" or (x_cache and "HIT" in x_cache):
                    finding = {
                        "type": "cache_poisoning_path",
                        "severity": "high",
                        "url": target,
                        "path_payload": path_payload,
                        "cache_status": cache_status,
                        "evidence": f"Cache HIT on poisoned path: {path_payload}",
                    }
                    findings.append(finding)
                    print_vuln(
                        f"Cache poisoning via path: "
                        f"'{path_payload}' got cache HIT"
                    )

            except Exception:
                logging.exception("cache_poisoning.py: exception")
                continue
        print_info("Testing parameter cloaking cache poisoning...")
        cloaking_payloads = [
            f"{target}?utm_source={canary}",
            f"{target}?utm_medium={canary}",
            f"{target}?ref={canary}",
            f"{target}?callback={canary}",
        ]

        for cloaking_url in cloaking_payloads:
            try:
                poisoned_headers = {"X-Forwarded-Host": canary}
                resp = session.get(
                    cloaking_url,
                    headers=poisoned_headers,
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                )

                cache_status = resp.headers.get("CF-Cache-Status", "")
                if cache_status == "HIT":
                    time.sleep(0.5)
                    resp2 = session.get(cloaking_url, timeout=self.config.timeout,
                                        verify=self.config.verify_tls)
                    body2 = resp2.text or ""
                    if canary in body2:
                        finding = {
                            "type": "cache_poisoning_cloaking",
                            "severity": "critical",
                            "url": cloaking_url,
                            "poison_header": "X-Forwarded-Host",
                            "evidence": f"Parameter cloaking cache poisoning: canary in response",
                        }
                        findings.append(finding)
                        print_vuln(f"Cache poisoning via parameter cloaking at {cloaking_url}")

            except Exception:
                logging.exception("cache_poisoning.py: exception")
                continue
        return findings

    def run(self, target, session=None):
        print_phase("Cache Poisoning Testing")
        self.config.target_url = normalize_url(target)

        if session is None:
            session = get_session()
        if session is None:
            print_error("Cannot proceed without a valid HTTP session.")
            return

        all_findings = self.test_cache_poisoning(target, session)

        self.config.scan_data["vulnerabilities"]["cache_poisoning"] = all_findings
        for f in all_findings:
            if f not in self.config.findings:
                self.config.findings.append(f)

        if all_findings:
            print_good(f"Cache poisoning testing complete: {len(all_findings)} potential issue(s) found.")
        else:
            print_info("Cache poisoning testing complete: no vulnerabilities found.")
