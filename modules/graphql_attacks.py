"""
GraphQLAttacksModule - GraphQL API vulnerability testing.

Tests for introspection exposure, batching attacks, alias-based
rate limit bypass, mutation abuse, and directive injection.
"""

import re
import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from core.utils import (
    print_info,
    print_good,
    print_warning,
    print_error,
    print_vuln,
    get_session,
)
import logging


class GraphQLAttacksModule:

    INTROSPECTION_QUERY = '{"query":"{ __schema { types { name fields { name type { name kind ofType { name } } } } } }"}'

    INTROSPECTION_MARKERS = [
        "__schema", "__type", "types", "fields",
        "queryType", "mutationType", "subscriptionType",
        "enumValues", "inputFields", "possibleTypes",
    ]

    GRAPHQL_ERROR_MARKERS = [
        "errors", "message", "locations", "path",
        "extensions", "code", "exception",
    ]

    BATCH_PAYLOADS = [
        '[{"query":"{ __typename }"},{"query":"{ __typename }"}]',
        '[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]',
    ]

    ALIASE_PAYLOADS = [
        '{"a1: __typename": true, "a2: __typename": true, "a3: __typename": true}',
        '{"x1: __typename": true, "x2: __typename": true, "x3: __typename": true, "x4: __typename": true, "x5: __typename": true}',
    ]

    INTROSPECTION_DISABLED_MARKERS = [
        "introspection has been disabled",
        "schema introspection is not allowed",
        "introspection not available",
        "graphql introspection has been disabled",
        "introspection is disabled",
    ]

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config

    def run(self, target: str, session=None):
        print_info(f"Running GraphQL security tests on {target}...")
        results: Dict[str, Any] = {
            "target": target,
            "graphql_vulns": [],
        }

        if session is None:
            session = get_session()

        graphql_endpoints = self._detect_graphql_endpoints(target, session)
        if not graphql_endpoints:
            print_info("No GraphQL endpoints detected.")
            self.scanner.scan_data["graphql_attacks"] = results
            return results

        print_info(f"Found {len(graphql_endpoints)} GraphQL endpoint(s) to test...")

        for endpoint in graphql_endpoints:
            result = self.test_introspection(endpoint, session)
            if result:
                results["graphql_vulns"].append(result)

            result = self.test_batching(endpoint, session)
            if result:
                results["graphql_vulns"].append(result)

            result = self.test_alias_abuse(endpoint, session)
            if result:
                results["graphql_vulns"].append(result)

            result = self.test_mutation_abuse(endpoint, session)
            if result:
                results["graphql_vulns"].append(result)

            result = self.test_field_suggestion(endpoint, session)
            if result:
                results["graphql_vulns"].append(result)

            result = self.test_directive_injection(endpoint, session)
            if result:
                results["graphql_vulns"].append(result)

        self.scanner.scan_data["graphql_attacks"] = results
        return results

    def test_introspection(self, url: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    Testing GraphQL introspection on {url}...")

        try:
            headers = {"Content-Type": "application/json"}
            resp = session.post(
                url,
                data=self.INTROSPECTION_QUERY,
                headers=headers,
                timeout=self.config.timeout,
                verify=self.config.verify_tls,
            )

            body = resp.text or ""
            body_lower = body.lower()

            for disabled_marker in self.INTROSPECTION_DISABLED_MARKERS:
                if disabled_marker in body_lower:
                    print_info(f"    Introspection is disabled at {url}.")
                    return None

            has_introspection = False
            for marker in self.INTROSPECTION_MARKERS:
                if marker in body:
                    has_introspection = True
                    break

            if has_introspection and resp.status_code == 200:
                try:
                    data = json.loads(body)
                    if "data" in data:
                        schema = data["data"].get("__schema", {})
                        types = schema.get("types", [])
                        user_defined_types = [
                            t for t in types
                            if not t.get("name", "").startswith("__")
                        ]

                        type_names = [t.get("name", "") for t in user_defined_types]
                        query_type = schema.get("queryType", {}).get("name", "")
                        mutation_type = schema.get("mutationType", {})
                        mutation_name = mutation_type.get("name", "") if mutation_type else ""

                        finding = {
                            "type": "graphql_introspection_enabled",
                            "url": url,
                            "evidence": f"schema_exposed:{len(user_defined_types)}_types",
                            "type_count": len(user_defined_types),
                            "type_names": type_names[:20],
                            "query_type": query_type,
                            "mutation_type": mutation_name,
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"GraphQL introspection enabled @ {url} | "
                            f"Schema exposed with {len(user_defined_types)} user-defined types"
                        )
                        self.scanner.findings.append(
                            f"[GQL:INTROSPECT] {url} types={len(user_defined_types)} query={query_type}"
                        )
                        return finding
                except json.JSONDecodeError:
                    pass

            if resp.status_code == 200 and '"data"' in body:
                finding = {
                    "type": "graphql_introspection_enabled",
                    "url": url,
                    "evidence": "schema_data_present",
                    "status_code": resp.status_code,
                }
                print_vuln(
                    f"GraphQL introspection enabled @ {url} | "
                    f"Introspection query returned data"
                )
                self.scanner.findings.append(
                    f"[GQL:INTROSPECT] {url} data_in_response=true"
                )
                return finding

        except Exception as e:
            logging.exception("graphql_attacks.py: operation failed")
            print_warning(f"    Introspection test failed: {e}")

        print_info(f"    No GraphQL introspection exposure found at {url}.")
        return None

    def test_batching(self, url: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    Testing GraphQL batching attacks on {url}...")

        try:
            headers = {"Content-Type": "application/json"}

            single_resp = session.post(
                url,
                data='{"query":"{ __typename }"}',
                headers=headers,
                timeout=self.config.timeout,
                verify=self.config.verify_tls,
            )
            single_status = single_resp.status_code
            single_len = len(single_resp.text or "")
        except Exception as e:
            logging.exception("graphql_attacks.py: operation failed")
            print_warning(f"    Baseline request failed: {e}")
            return None

        for payload in self.BATCH_PAYLOADS:
            try:
                resp = session.post(
                    url,
                    data=payload,
                    headers=headers,
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                )

                body = resp.text or ""

                try:
                    data = json.loads(body)
                    if isinstance(data, list) and len(data) > 1:
                        success_count = sum(
                            1 for item in data
                            if "data" in item and "errors" not in item
                        )
                        if success_count > 1:
                            finding = {
                                "type": "graphql_batching_enabled",
                                "url": url,
                                "payload": payload,
                                "evidence": f"batch_processed:{success_count}_queries",
                                "query_count": success_count,
                                "status_code": resp.status_code,
                            }
                            print_vuln(
                                f"GraphQL batching attack @ {url} | "
                                f"Server processed {success_count} queries in single request"
                            )
                            self.scanner.findings.append(
                                f"[GQL:BATCH] {url} batch_queries={success_count}"
                            )
                            return finding
                except json.JSONDecodeError:
                    pass

                if resp.status_code == 200 and len(body) > single_len * 2:
                    finding = {
                        "type": "graphql_batching_enabled",
                        "url": url,
                        "payload": payload,
                        "evidence": f"response_size:{len(body)}>2*{single_len}",
                        "status_code": resp.status_code,
                    }
                    print_vuln(
                        f"GraphQL batching attack @ {url} | "
                        f"Response size indicates batch processing"
                    )
                    self.scanner.findings.append(
                        f"[GQL:BATCH] {url} size_diff=true"
                    )
                    return finding

            except Exception:
                logging.exception("graphql_attacks.py: exception")
                continue
        print_info(f"    No GraphQL batching vulnerability found at {url}.")
        return None

    def test_alias_abuse(self, url: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    Testing alias-based rate limit bypass on {url}...")

        try:
            headers = {"Content-Type": "application/json"}

            single_resp = session.post(
                url,
                data='{"query":"{ __typename }"}',
                headers=headers,
                timeout=self.config.timeout,
                verify=self.config.verify_tls,
            )
            single_status = single_resp.status_code
        except Exception as e:
            logging.exception("graphql_attacks.py: operation failed")
            print_warning(f"    Baseline request failed: {e}")
            return None

        for payload in self.ALIASE_PAYLOADS:
            try:
                resp = session.post(
                    url,
                    data=payload,
                    headers=headers,
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                )

                body = resp.text or ""
                body_lower = body.lower()

                rate_limited = any(
                    marker in body_lower
                    for marker in ["rate limit", "too many requests", "throttle", "slow down"]
                )

                if not rate_limited and resp.status_code == 200:
                    try:
                        data = json.loads(body)
                        if isinstance(data, dict):
                            data_keys = [k for k in data.keys() if k != "errors"]
                            if len(data_keys) > 1:
                                finding = {
                                    "type": "graphql_alias_rate_bypass",
                                    "url": url,
                                    "payload": payload,
                                    "evidence": f"alias_count:{len(data_keys)}_all_processed",
                                    "alias_count": len(data_keys),
                                    "status_code": resp.status_code,
                                }
                                print_vuln(
                                    f"GraphQL alias rate limit bypass @ {url} | "
                                    f"Server processed {len(data_keys)} aliased queries"
                                )
                                self.scanner.findings.append(
                                    f"[GQL:ALIAS] {url} aliases={len(data_keys)}"
                                )
                                return finding
                    except json.JSONDecodeError:
                        pass

            except Exception:
                logging.exception("graphql_attacks.py: exception")
                continue
        print_info(f"    No alias-based rate limit bypass found at {url}.")
        return None

    def test_mutation_abuse(self, url: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    Testing GraphQL mutation abuse on {url}...")

        introspection_query = self.INTROSPECTION_QUERY
        try:
            headers = {"Content-Type": "application/json"}
            resp = session.post(
                url,
                data=introspection_query,
                headers=headers,
                timeout=self.config.timeout,
                verify=self.config.verify_tls,
            )

            data = json.loads(resp.text or "{}")
            schema = data.get("data", {}).get("__schema", {})
            mutation_type = schema.get("mutationType")

            if not mutation_type:
                print_info("    No mutation type found in schema.")
                return None

            mutation_fields = mutation_type.get("fields", [])
            if not mutation_fields:
                print_info("    No mutation fields found.")
                return None

            sensitive_mutations = []
            for field in mutation_fields:
                name = field.get("name", "").lower()
                sensitive_keywords = [
                    "delete", "remove", "update", "create", "modify",
                    "change", "set", "reset", "admin", "role", "permission",
                    "user", "auth", "password", "grant", "revoke",
                ]
                if any(kw in name for kw in sensitive_keywords):
                    sensitive_mutations.append(field.get("name", ""))

            if sensitive_mutations:
                finding = {
                    "type": "graphql_sensitive_mutations",
                    "url": url,
                    "evidence": f"sensitive_mutations:{','.join(sensitive_mutations[:10])}",
                    "mutations": sensitive_mutations[:20],
                    "status_code": resp.status_code,
                }
                print_vuln(
                    f"GraphQL sensitive mutations exposed @ {url} | "
                    f"Found {len(sensitive_mutations)} sensitive mutation(s)"
                )
                self.scanner.findings.append(
                    f"[GQL:MUTATIONS] {url} count={len(sensitive_mutations)}"
                )
                return finding

        except Exception as e:
            logging.exception("graphql_attacks.py: operation failed")
            print_warning(f"    Mutation enumeration failed: {e}")

        print_info(f"    No GraphQL mutation abuse found at {url}.")
        return None

    def test_field_suggestion(self, url: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    Testing GraphQL field suggestion abuse on {url}...")

        suggestion_payloads = [
            '{"query":"{ uzer { id } }"}',
            '{"query":"{ admiin { id } }"}',
            '{"query":"{ users { id } }"}',
            '{"query":"{ admin { id } }"}',
            '{"query":"{ secret { id } }"}',
            '{"query":"{ internal { id } }"}',
        ]

        for payload in suggestion_payloads:
            try:
                headers = {"Content-Type": "application/json"}
                resp = session.post(
                    url,
                    data=payload,
                    headers=headers,
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                )

                body = (resp.text or "").lower()

                suggestion_markers = [
                    "did you mean", "suggestion", "similar field",
                    "did you mean", "field suggestion",
                ]

                for marker in suggestion_markers:
                    if marker in body:
                        finding = {
                            "type": "graphql_field_suggestion",
                            "url": url,
                            "payload": payload,
                            "evidence": f"suggestion_leak:{marker}",
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"GraphQL field suggestion abuse @ {url} | "
                            f"Server revealed field suggestions"
                        )
                        self.scanner.findings.append(
                            f"[GQL:SUGGESTION] {url} evidence='{marker}'"
                        )
                        return finding

                if "data" in body and "null" not in body.split('"data"')[1][:20]:
                    finding = {
                        "type": "graphql_field_enumeration",
                        "url": url,
                        "payload": payload,
                        "evidence": "data_present_in_error_response",
                        "status_code": resp.status_code,
                    }
                    print_vuln(
                        f"GraphQL field enumeration @ {url} | "
                        f"Server returned data for invalid query"
                    )
                    self.scanner.findings.append(
                        f"[GQL:ENUMERATE] {url}"
                    )
                    return finding

            except Exception:
                logging.exception("graphql_attacks.py: exception")
                continue
        print_info(f"    No GraphQL field suggestion abuse found at {url}.")
        return None

    def test_directive_injection(self, url: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    Testing GraphQL directive injection on {url}...")

        directive_payloads = [
            '{"query":"{ __typename @deprecated }"}',
            '{"query":"{ __typename @skip(if: true) }"}',
            '{"query":"{ __typename @include(if: false) }"}',
            '{"query":"{ admin @deprecated }"}',
            '{"query":"mutation { __typename @deprecated }"}',
        ]

        for payload in directive_payloads:
            try:
                headers = {"Content-Type": "application/json"}
                resp = session.post(
                    url,
                    data=payload,
                    headers=headers,
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                )

                body = resp.text or ""
                body_lower = body.lower()

                if resp.status_code == 200:
                    error_indicators = ["directive", "unknown directive", "not a valid directive"]
                    has_error = any(indicator in body_lower for indicator in error_indicators)

                    if not has_error:
                        finding = {
                            "type": "graphql_directive_accepted",
                            "url": url,
                            "payload": payload,
                            "evidence": "custom_directive_accepted",
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"GraphQL directive injection @ {url} | "
                            f"Server accepted directive in query"
                        )
                        self.scanner.findings.append(
                            f"[GQL:DIRECTIVE] {url}"
                        )
                        return finding

            except Exception:
                logging.exception("graphql_attacks.py: exception")
                continue
        print_info(f"    No GraphQL directive injection found at {url}.")
        return None

    def _detect_graphql_endpoints(self, target: str, session) -> List[str]:
        endpoints = []
        graphql_paths = [
            "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
            "/v2/graphql", "/query", "/api/query", "/gql",
            "/playground", "/altair", "/voyager",
        ]

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in graphql_paths:
            url = base + path
            try:
                probe_payload = '{"query":"{ __typename }"}'
                headers = {"Content-Type": "application/json"}
                resp = session.post(
                    url,
                    data=probe_payload,
                    headers=headers,
                    timeout=5,
                    verify=self.config.verify_tls,
                )

                ct = resp.headers.get("Content-Type", "")
                body = resp.text or ""

                is_graphql = False
                if "json" in ct:
                    try:
                        data = json.loads(body)
                        if "data" in data or "errors" in data:
                            is_graphql = True
                    except json.JSONDecodeError:
                        pass

                if is_graphql:
                    endpoints.append(url)
            except Exception:
                logging.exception("graphql_attacks.py: exception")
                continue
        try:
            resp = session.get(target, timeout=5, verify=self.config.verify_tls)
            body = resp.text or ""
            graphql_url_patterns = [
                r'graphql["\s]*[:=]\s*["\']([^"\']+)["\']',
                r'(https?://[^"\']+/graphql)',
                r'(wss?://[^"\']+/graphql)',
            ]
            for pattern in graphql_url_patterns:
                matches = re.findall(pattern, body)
                for match in matches:
                    if match.startswith("http"):
                        endpoints.append(match)
                    elif match.startswith("/"):
                        endpoints.append(base + match)
        except Exception:
            logging.exception("graphql_attacks.py: exception")
            pass
        return list(set(endpoints))
