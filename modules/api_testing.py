import re
import json
import time
import random
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

from core.config import Config
from core.utils import (
    print_info, print_good, print_warning, print_error, print_vuln,
    print_phase, print_table, get_session, normalize_url,
)
from lib.payloads import Payloads
from lib.wordlists import Wordlists
import logging


class APITestingModule:
    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.payloads = Payloads()
        self.wordlists = Wordlists()

    def discover_api_endpoints(self, target, session):
        found_endpoints = []
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        known_paths = self.wordlists.API_ENDPOINTS
        base_prefixes = self.wordlists.API_BASE_PREFIXES
        resources = self.wordlists.API_RESOURCES

        print_info(f"Probing {len(known_paths)} known API paths...")
        for path in known_paths:
            url = f"{base}{path}"
            try:
                resp = session.get(url, timeout=self.config.timeout,
                                   verify=self.config.verify_tls)
                if resp.status_code not in (404, 405, 406, 501, 503):
                    ct = resp.headers.get("Content-Type", "")
                    if any(kw in ct.lower() for kw in ["json", "xml", "text/plain"]) or resp.status_code == 200:
                        found_endpoints.append({
                            "path": path,
                            "url": url,
                            "status": resp.status_code,
                            "content_type": ct,
                            "methods": ["GET"],
                        })
                        print_info(f"  Found: {path} [{resp.status_code}] ({ct})")
            except Exception:
                logging.exception("api_testing.py: exception")
                continue
        print_info(f"Recursive fuzzing with {len(base_prefixes)} prefixes x {len(resources)} resources...")
        for prefix in base_prefixes:
            for resource in resources:
                url = f"{base}{prefix}/{resource}"
                try:
                    resp = session.get(url, timeout=5,
                                       verify=self.config.verify_tls)
                    if resp.status_code not in (404, 405, 406, 501):
                        ct = resp.headers.get("Content-Type", "")
                        existing = [e["path"] for e in found_endpoints]
                        path = f"{prefix}/{resource}"
                        if path not in existing:
                            found_endpoints.append({
                                "path": path,
                                "url": url,
                                "status": resp.status_code,
                                "content_type": ct,
                                "methods": ["GET"],
                            })
                            print_info(f"  Discovered: {path} [{resp.status_code}]")
                except Exception:
                    logging.exception("api_testing.py: exception")
                    continue
        for endpoint in found_endpoints[:50]:
            url = endpoint["url"]
            for method in ["POST", "PUT", "PATCH", "DELETE"]:
                try:
                    resp = session.request(method, url, timeout=5,
                                           verify=self.config.verify_tls)
                    if resp.status_code not in (404, 405, 501):
                        if method not in endpoint["methods"]:
                            endpoint["methods"].append(method)
                except Exception:
                    logging.exception("api_testing.py: exception")
                    continue
        self.config.scan_data["api"]["endpoints"] = found_endpoints
        print_good(f"Discovered {len(found_endpoints)} API endpoints.")
        return found_endpoints

    def test_cors(self, target, session):
        findings = []
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        evil_origins = [
            "https://evil.com",
            "https://null.sysvoid.test",
            f"https://{parsed.netloc}.evil.com",
            "https://subdomain." + parsed.netloc,
            "null",
            f"{parsed.scheme}://{parsed.netloc}",
        ]

        print_info("Testing CORS misconfiguration...")
        for origin in evil_origins:
            try:
                resp = session.get(
                    target,
                    headers={"Origin": origin},
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                )

                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                if acao:
                    if acao == "*" and acac.lower() == "true":
                        finding = {
                            "type": "cors_wildcard_credentials",
                            "severity": "high",
                            "url": target,
                            "origin": origin,
                            "acao": acao,
                            "acac": acac,
                            "evidence": "Wildcard ACAO with Allow-Credentials: true",
                        }
                        findings.append(finding)
                        print_vuln(f"CORS wildcard+credentials at {target}")

                    elif acao == origin and origin not in (f"{parsed.scheme}://{parsed.netloc}",):
                        finding = {
                            "type": "cors_reflected_origin",
                            "severity": "high",
                            "url": target,
                            "origin": origin,
                            "acao": acao,
                            "acac": acac,
                            "evidence": f"Origin '{origin}' reflected in ACAO",
                        }
                        findings.append(finding)
                        print_vuln(f"CORS reflected origin: '{origin}' accepted at {target}")

                    elif acao == "*" and origin != "*":
                        finding = {
                            "type": "cors_wildcard",
                            "severity": "medium",
                            "url": target,
                            "origin": origin,
                            "acao": acao,
                            "evidence": "Wildcard ACAO allows any origin",
                        }
                        findings.append(finding)
                        print_warning(f"CORS wildcard ACAO at {target}")

            except Exception:
                logging.exception("api_testing.py: exception")
                continue
        return findings

    def test_graphql(self, target, session):
        findings = []
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        graphql_paths = ["/graphql", "/gql", "/api/graphql", "/query", "/api/query", "/graphiql"]

        introspection_query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                types {
                    name
                    kind
                    fields {
                        name
                        type { name kind ofType { name kind } }
                        args { name type { name kind } }
                    }
                }
                directives { name locations args { name type { name } } }
            }
        }
        """

        print_info("Testing GraphQL endpoints...")
        for path in graphql_paths:
            url = f"{base}{path}"

            try:
                resp = session.post(
                    url,
                    json={"query": introspection_query},
                    headers={"Content-Type": "application/json"},
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                )

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "data" in data and "__schema" in data.get("data", {}):
                            schema = data["data"]["__schema"]
                            types_count = len(schema.get("types", []))
                            query_type = schema.get("queryType", {}).get("name", "")
                            mutation_type = schema.get("mutationType", {}).get("name", "")

                            finding = {
                                "type": "graphql_introspection",
                                "severity": "high",
                                "url": url,
                                "types_count": types_count,
                                "query_type": query_type,
                                "mutation_type": mutation_type,
                                "evidence": f"Introspection enabled: {types_count} types, query={query_type}",
                            }
                            findings.append(finding)
                            print_vuln(
                                f"GraphQL introspection enabled at {url}: "
                                f"{types_count} types exposed"
                            )

                            self.config.scan_data["vulnerabilities"]["graphql_introspection"].append(finding)

                    except (json.JSONDecodeError, KeyError):
                        pass

            except Exception:
                logging.exception("api_testing.py: exception")
                continue
            try:
                resp = session.get(url, timeout=self.config.timeout,
                                   verify=self.config.verify_tls)
                if resp.status_code == 200 and ("graphiql" in resp.text.lower() or "graphql" in resp.text.lower()):
                    finding = {
                        "type": "graphql_playground",
                        "severity": "medium",
                        "url": url,
                        "evidence": "GraphQL playground/introspection UI exposed",
                    }
                    findings.append(finding)
                    print_warning(f"GraphQL playground exposed at {url}")

            except Exception:
                logging.exception("api_testing.py: exception")
                continue
        return findings

    def test_jwt_tokens(self, target, session):
        findings = []

        print_info("Testing JWT vulnerabilities...")

        try:
            resp = session.get(target, timeout=self.config.timeout,
                               verify=self.config.verify_tls)
            cookies = dict(resp.cookies)
            auth_header = resp.request.headers.get("Authorization", "")

            jwt_tokens = []
            for name, value in cookies.items():
                if value.startswith("eyJ") and value.count(".") == 2:
                    jwt_tokens.append(value)
            if auth_header.startswith("eyJ") and auth_header.count(".") == 2:
                jwt_tokens.append(auth_header)

            body = resp.text or ""
            jwt_pattern = r'eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}'
            body_jwts = re.findall(jwt_pattern, body)
            jwt_tokens.extend(body_jwts)

        except Exception:
            logging.exception("api_testing.py: operation failed")
            jwt_tokens = []

        if not jwt_tokens:
            print_info("No JWT tokens found for testing.")
            return findings

        for token in jwt_tokens[:5]:
            parts = token.split(".")
            if len(parts) != 3:
                continue

            try:
                import base64
                header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
                header = json.loads(base64.urlsafe_b64decode(header_b64))
            except Exception:
                logging.exception("api_testing.py: exception")
                continue
            alg = header.get("alg", "")

            if alg == "none":
                finding = {
                    "type": "jwt_none_algorithm",
                    "severity": "critical",
                    "url": target,
                    "evidence": f"JWT uses 'none' algorithm",
                    "token_prefix": token[:30] + "...",
                }
                findings.append(finding)
                print_vuln(f"JWT 'none' algorithm detected at {target}")

                for none_alg in ["none", "None", "NONE", "nOnE"]:
                    tampered_header = header.copy()
                    tampered_header["alg"] = none_alg
                    try:
                        new_header = base64.urlsafe_b64encode(
                            json.dumps(tampered_header).encode()
                        ).rstrip(b"=").decode()
                        tampered_token = f"{new_header}.{parts[1]}."
                        test_headers = {"Authorization": f"Bearer {tampered_token}"}
                        resp = session.get(target, headers=test_headers,
                                           timeout=self.config.timeout,
                                           verify=self.config.verify_tls)
                        if resp.status_code not in (401, 403):
                            finding = {
                                "type": "jwt_none_bypass",
                                "severity": "critical",
                                "url": target,
                                "evidence": f"JWT none algorithm accepted (alg={none_alg})",
                            }
                            findings.append(finding)
                            print_vuln(f"JWT none algorithm bypass confirmed at {target}")
                            break
                    except Exception:
                        logging.exception("api_testing.py: exception")
                        continue
            elif alg in ("HS256", "HS384", "HS512"):
                finding = {
                    "type": "jwt_weak_algorithm",
                    "severity": "medium",
                    "url": target,
                    "algorithm": alg,
                    "evidence": f"JWT uses symmetric algorithm {alg}",
                    "token_prefix": token[:30] + "...",
                }
                findings.append(finding)
                print_warning(f"JWT uses symmetric algorithm {alg} (potential key confusion)")

            elif alg.startswith("RS") or alg.startswith("ES"):
                finding = {
                    "type": "jwt_asymmetric",
                    "severity": "info",
                    "url": target,
                    "algorithm": alg,
                    "evidence": f"JWT uses asymmetric algorithm {alg}",
                }
                findings.append(finding)
                print_info(f"JWT uses asymmetric algorithm {alg}")

        return findings

    def test_api_idor(self, found_endpoints, session):
        findings = []

        print_info("Testing for BOLA/IDOR vulnerabilities...")
        id_patterns = [
            (r'/(\d+)(?:/|$)', lambda x: [str(int(x) + 1), str(int(x) - 1), "0", "1", "999"]),
            (r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)',
             lambda x: ["00000000-0000-0000-0000-000000000001",
                        "00000000-0000-0000-0000-000000000002"]),
        ]

        for endpoint in found_endpoints:
            url = endpoint.get("url", "")
            for pattern, generator in id_patterns:
                match = re.search(pattern, url)
                if match:
                    original_id = match.group(1)
                    new_ids = generator(original_id)

                    for new_id in new_ids:
                        test_url = url.replace(original_id, new_id)
                        try:
                            resp = session.get(test_url, timeout=5,
                                               verify=self.config.verify_tls)
                            if resp.status_code == 200:
                                original_resp = session.get(url, timeout=5,
                                                            verify=self.config.verify_tls)
                                if (original_resp.status_code == 200 and
                                        len(resp.text) > 50 and
                                        len(resp.text) != len(original_resp.text)):
                                    finding = {
                                        "type": "idor",
                                        "severity": "high",
                                        "url": url,
                                        "test_url": test_url,
                                        "original_id": original_id,
                                        "tested_id": new_id,
                                        "evidence": f"Different data returned for different IDs",
                                    }
                                    findings.append(finding)
                                    print_vuln(
                                        f"IDOR at {url}: "
                                        f"accessed ID {new_id} (original: {original_id})"
                                    )
                                    break
                        except Exception:
                            logging.exception("api_testing.py: exception")
                            continue
        self.config.scan_data["vulnerabilities"]["idor"] = findings
        return findings

    def test_api_mass_assignment(self, found_endpoints, session):
        findings = []
        mass_fields = self.wordlists.MASS_ASSIGNMENT_FIELDS

        print_info("Testing for mass assignment vulnerabilities...")

        for endpoint in found_endpoints:
            url = endpoint.get("url", "")
            methods = endpoint.get("methods", ["GET"])

            if "POST" not in methods and "PUT" not in methods and "PATCH" not in methods:
                continue

            for mass_field in mass_fields:
                for method in ["POST", "PUT", "PATCH"]:
                    try:
                        test_data = {}
                        for key, value in mass_field.items():
                            test_data[key] = value

                        resp = session.request(
                            method, url,
                            json=test_data,
                            headers={"Content-Type": "application/json"},
                            timeout=5,
                            verify=self.config.verify_tls,
                        )

                        if resp.status_code in (200, 201):
                            body = resp.text or ""
                            for key, value in mass_field.items():
                                if str(value).lower() in body.lower():
                                    finding = {
                                        "type": "mass_assignment",
                                        "severity": "high",
                                        "url": url,
                                        "method": method,
                                        "field": key,
                                        "value": value,
                                        "evidence": f"Field '{key}={value}' accepted",
                                    }
                                    findings.append(finding)
                                    print_vuln(
                                        f"Mass assignment at {url}: "
                                        f"'{key}={value}' accepted via {method}"
                                    )
                                    break

                    except Exception:
                        logging.exception("api_testing.py: exception")
                        continue
        self.config.scan_data["vulnerabilities"]["mass_assignment"] = findings
        return findings

    def test_api_auth_bypass(self, found_endpoints, session):
        findings = []

        print_info("Testing for API authentication bypass...")

        bypass_headers = [
            {},
            {"Authorization": ""},
            {"Authorization": "Bearer null"},
            {"Authorization": "Bearer undefined"},
            {"Authorization": "Bearer test"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
        ]

        sensitive_endpoints = [
            ep for ep in found_endpoints
            if any(kw in ep.get("path", "").lower()
                   for kw in ["admin", "internal", "debug", "config",
                              "users", "user", "profile", "settings", "me"])
        ]

        for endpoint in sensitive_endpoints:
            url = endpoint.get("url", "")
            original_resp = None
            try:
                original_resp = session.get(url, timeout=5,
                                            verify=self.config.verify_tls)
            except Exception:
                logging.exception("api_testing.py: exception")
                continue
            if original_resp and original_resp.status_code in (401, 403):
                for headers in bypass_headers:
                    try:
                        resp = session.get(url, headers=headers, timeout=5,
                                           verify=self.config.verify_tls)
                        if resp.status_code not in (401, 403):
                            finding = {
                                "type": "auth_bypass",
                                "severity": "critical",
                                "url": url,
                                "bypass_headers": headers,
                                "response_code": resp.status_code,
                                "evidence": f"Authenticated access without credentials ({resp.status_code})",
                            }
                            findings.append(finding)
                            print_vuln(
                                f"Auth bypass at {url}: "
                                f"got {resp.status_code} with headers {headers}"
                            )
                            break
                    except Exception:
                        logging.exception("api_testing.py: exception")
                        continue
        self.config.scan_data["vulnerabilities"]["api_abuse"].extend(findings)
        return findings

    def test_api_verbose_errors(self, found_endpoints, session):
        findings = []
        error_patterns = [
            r"stack\s*trace",
            r"traceback",
            r"at\s+\w+\.\w+\(",
            r"File\s+\"[^\"]+\"",
            r"Exception\s+in",
            r"SQLSTATE\[:",
            r"ORA-\d{5}",
            r"PostgreSQL",
            r"MySQL",
            r"sqlite3\.",
            r"django\.db",
            r"Internal Server Error",
            r"DEBUG\s*=\s*True",
            r"stacktrace",
            r"java\.lang\.",
            r"com\.\w+\.\w+Exception",
        ]

        print_info("Testing for verbose error messages...")

        for endpoint in found_endpoints[:30]:
            url = endpoint.get("url", "")

            malformed_payloads = [
                ("POST", {"invalid": None, "data": "[{broken"}),
                ("POST", b"\x00\x01\x02\x03"),
                ("PUT", {"__proto__": {"admin": True}}),
                ("POST", '{"broken json'),
                ("GET", None),
            ]

            for method, payload in malformed_payloads:
                try:
                    if method == "GET":
                        resp = session.get(url, timeout=5,
                                           verify=self.config.verify_tls)
                    else:
                        if isinstance(payload, bytes):
                            resp = session.request(method, url, data=payload,
                                                   headers={"Content-Type": "application/octet-stream"},
                                                   timeout=5, verify=self.config.verify_tls)
                        else:
                            resp = session.request(method, url, json=payload,
                                                   timeout=5, verify=self.config.verify_tls)

                    body = resp.text or ""
                    for pattern in error_patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            snippet = body[:200].replace("\n", " ")
                            finding = {
                                "type": "verbose_error",
                                "severity": "medium",
                                "url": url,
                                "method": method,
                                "error_pattern": pattern,
                                "evidence": snippet[:140],
                            }
                            findings.append(finding)
                            print_warning(
                                f"Verbose error at {url} ({method}): "
                                f"matched '{pattern}'"
                            )
                            break

                except Exception:
                    logging.exception("api_testing.py: exception")
                    continue
        self.config.scan_data["vulnerabilities"]["info_disclosure"].extend(findings)
        return findings

    def test_api_rate_limiting(self, target, session):
        findings = []
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        login_endpoints = ["/api/login", "/api/auth/login", "/api/auth", "/login"]
        login_url = None
        for path in login_endpoints:
            try:
                resp = session.get(f"{base}{path}", timeout=5,
                                   verify=self.config.verify_tls)
                if resp.status_code != 404:
                    login_url = f"{base}{path}"
                    break
            except Exception:
                logging.exception("api_testing.py: exception")
                continue
        if not login_url:
            login_url = target

        print_info("Testing rate limiting...")
        rate_limit_triggered = False
        responses = []

        for i in range(15):
            try:
                resp = session.post(
                    login_url,
                    json={"username": f"testuser{i}", "password": "invalidpassword"},
                    headers={"Content-Type": "application/json"},
                    timeout=5,
                    verify=self.config.verify_tls,
                )
                responses.append(resp.status_code)
                if resp.status_code == 429:
                    rate_limit_triggered = True
                    finding = {
                        "type": "rate_limiting",
                        "severity": "info",
                        "url": login_url,
                        "evidence": f"Rate limiting triggered after {i + 1} requests",
                        "request_count": i + 1,
                    }
                    findings.append(finding)
                    print_good(f"Rate limiting detected at {login_url} after {i + 1} requests")
                    break
                time.sleep(0.1)
            except Exception:
                logging.exception("api_testing.py: exception")
                continue
        if not rate_limit_triggered:
            unique_status = set(responses)
            finding = {
                "type": "no_rate_limiting",
                "severity": "medium",
                "url": login_url,
                "evidence": f"No rate limiting after 15 rapid requests (statuses: {unique_status})",
            }
            findings.append(finding)
            print_warning(f"No rate limiting detected at {login_url} after 15 requests")

        self.config.scan_data["api"]["rate_limits"] = findings
        return findings

    def run(self, target, session=None):
        print_phase("API Testing")
        self.config.target_url = normalize_url(target)

        if session is None:
            session = get_session()
        if session is None:
            print_error("Cannot proceed without a valid HTTP session.")
            return

        endpoints = self.discover_api_endpoints(target, session)

        cors_findings = self.test_cors(target, session)
        graphql_findings = self.test_graphql(target, session)
        jwt_findings = self.test_jwt_tokens(target, session)
        idor_findings = self.test_api_idor(endpoints, session)
        mass_findings = self.test_api_mass_assignment(endpoints, session)
        auth_findings = self.test_api_auth_bypass(endpoints, session)
        error_findings = self.test_api_verbose_errors(endpoints, session)
        rate_findings = self.test_api_rate_limiting(target, session)

        all_findings = (
            cors_findings + graphql_findings + jwt_findings +
            idor_findings + mass_findings + auth_findings +
            error_findings + rate_findings
        )

        for f in all_findings:
            if f not in self.config.findings:
                self.config.findings.append(f)

        if all_findings:
            print_good(f"API testing complete: {len(all_findings)} issue(s) found.")
        else:
            print_info("API testing complete: no issues found.")
