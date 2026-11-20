"""
OAuthTestingModule - OAuth2/OIDC security testing.

Tests for OAuth2 and OpenID Connect vulnerabilities including
redirect URI manipulation, PKCE downgrade, token leakage, and more.
"""

import re
import json
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.utils import (
    print_info,
    print_good,
    print_warning,
    print_error,
    print_vuln,
    get_session,
)
import logging


class OAuthTestingModule:

    REDIRECT_URI_MARKERS = [
        "redirect_uri", "redirect_url", "return_to", "callback",
        "continue", "next", "returnurl",
    ]

    TOKEN_MARKERS = [
        "access_token", "id_token", "refresh_token",
        "token_type", "expires_in", "bearer",
    ]

    STATE_MARKERS = [
        "state", "csrf", "nonce", "session_state",
    ]

    PKCE_MARKERS = [
        "code_challenge", "code_verifier", "code_challenge_method",
        "S256", "plain",
    ]

    ERROR_MARKERS = [
        "invalid_grant", "invalid_request", "unauthorized_client",
        "invalid_client", "access_denied", "unsupported_response_type",
        "invalid_scope", "server_error", "temporarily_unavailable",
    ]

    REDIRECT_URI_PAYLOADS = [
        "https://evil.com",
        "https://evil.com/callback",
        "https://evil.com%00.example.com",
        "https://evil.com@example.com",
        "https://evil.com%23.example.com",
        "http://localhost",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "https://evil.com/.example.com",
        "https://evil.com\\@.example.com",
        "https://evil.com%0d%0aLocation:%20https://evil.com",
    ]

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config

    def run(self, target: str, session=None):
        print_info(f"Running OAuth/OIDC security tests on {target}...")
        results: Dict[str, Any] = {
            "target": target,
            "oauth_vulns": [],
        }

        if session is None:
            session = get_session()

        oauth_endpoints = self._detect_oauth_endpoints(target, session)
        if not oauth_endpoints:
            print_info("No OAuth/OIDC endpoints detected.")
            self.scanner.scan_data["oauth_testing"] = results
            return results

        print_info(f"Found {len(oauth_endpoints)} OAuth endpoint(s) to test...")

        for endpoint in oauth_endpoints:
            endpoint_url = endpoint.get("url", "")
            endpoint_type = endpoint.get("type", "")

            result = self.test_redirect_uri_manipulation(endpoint_url, session)
            if result:
                results["oauth_vulns"].append(result)

            result = self.test_state_parameter_bypass(endpoint_url, session)
            if result:
                results["oauth_vulns"].append(result)

            result = self.test_pkce_downgrade(endpoint_url, session)
            if result:
                results["oauth_vulns"].append(result)

            result = self.test_token_leakage(endpoint_url, session)
            if result:
                results["oauth_vulns"].append(result)

            result = self.test_scope_escalation(endpoint_url, session)
            if result:
                results["oauth_vulns"].append(result)

            result = self.test_token_substitution(endpoint_url, session)
            if result:
                results["oauth_vulns"].append(result)

        self.scanner.scan_data["oauth_testing"] = results
        return results

    def test_redirect_uri_manipulation(self, url: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    Testing redirect URI manipulation on {url}...")

        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)

        original_redirect = None
        for marker in self.REDIRECT_URI_MARKERS:
            if marker in qs:
                original_redirect = qs[marker][0]
                break

        if not original_redirect:
            print_info("    No redirect_uri parameter found in URL.")
            return None

        for payload in self.REDIRECT_URI_PAYLOADS:
            try:
                test_qs = dict(qs)
                test_qs["redirect_uri"] = [payload]
                new_query = urlencode(test_qs, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                resp = session.get(
                    test_url,
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                    allow_redirects=False,
                )

                location = resp.headers.get("Location", "")

                if payload in location:
                    finding = {
                        "type": "oauth_redirect_uri_bypass",
                        "url": url,
                        "original_redirect": original_redirect,
                        "payload": payload,
                        "redirect_location": location,
                        "evidence": f"redirect_to:{payload}",
                        "status_code": resp.status_code,
                    }
                    print_vuln(
                        f"OAuth redirect URI bypass @ {url} | "
                        f"Payload: {payload} | Redirects to: {location}"
                    )
                    self.scanner.findings.append(
                        f"[OAUTH:REDIRECT] {url} payload='{payload}' redirect='{location}'"
                    )
                    return finding

                if resp.status_code == 200 and payload in (resp.text or ""):
                    finding = {
                        "type": "oauth_redirect_uri_reflection",
                        "url": url,
                        "original_redirect": original_redirect,
                        "payload": payload,
                        "evidence": "redirect_uri_reflected_in_response",
                        "status_code": resp.status_code,
                    }
                    print_vuln(
                        f"OAuth redirect URI reflection @ {url} | "
                        f"Payload: {payload} reflected in response"
                    )
                    self.scanner.findings.append(
                        f"[OAUTH:REDIRECT_REFLECT] {url} payload='{payload}'"
                    )
                    return finding

            except Exception:
                logging.exception("oauth_testing.py: exception")
                continue
        print_info("    No redirect URI bypass found.")
        return None

    def test_state_parameter_bypass(self, url: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    Testing OAuth state parameter bypass on {url}...")

        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)

        has_state = any(marker in qs for marker in self.STATE_MARKERS)

        if not has_state:
            finding = {
                "type": "oauth_missing_state",
                "url": url,
                "evidence": "no_state_parameter_in_auth_request",
                "status_code": 200,
            }
            print_vuln(
                f"OAuth missing state parameter @ {url} | "
                f"Authentication request lacks state/CSRF parameter"
            )
            self.scanner.findings.append(
                f"[OAUTH:NO_STATE] {url} missing_state=true"
            )
            return finding

        state_param = None
        for marker in self.STATE_MARKERS:
            if marker in qs:
                state_param = marker
                break

        try:
            test_qs = dict(qs)
            test_qs[state_param] = [""]
            new_query = urlencode(test_qs, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            resp = session.get(
                test_url,
                timeout=self.config.timeout,
                verify=self.config.verify_tls,
                allow_redirects=False,
            )

            if resp.status_code in (200, 302, 301):
                location = resp.headers.get("Location", "")
                if "code=" in location or resp.status_code == 200:
                    finding = {
                        "type": "oauth_state_bypass",
                        "url": url,
                        "evidence": f"accepted_empty_state_param:{state_param}",
                        "status_code": resp.status_code,
                    }
                    print_vuln(
                        f"OAuth state parameter bypass @ {url} | "
                        f"Server accepted empty state parameter"
                    )
                    self.scanner.findings.append(
                        f"[OAUTH:NO_STATE_BYPASS] {url} empty_state_accepted=true"
                    )
                    return finding
        except Exception:
            logging.exception("oauth_testing.py: exception")
            pass
        print_info("    State parameter appears to be enforced.")
        return None

    def test_pkce_downgrade(self, url: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    Testing PKCE downgrade attack on {url}...")

        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)

        has_pkce = any(marker in qs for marker in self.PKCE_MARKERS)

        if not has_pkce:
            print_info("    No PKCE parameters found (may not use PKCE).")
            return None

        challenge_param = None
        for marker in ["code_challenge"]:
            if marker in qs:
                challenge_param = marker
                break

        if not challenge_param:
            return None

        try:
            test_qs = dict(qs)
            del test_qs[challenge_param]
            if "code_challenge_method" in test_qs:
                del test_qs["code_challenge_method"]
            new_query = urlencode(test_qs, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            resp = session.get(
                test_url,
                timeout=self.config.timeout,
                verify=self.config.verify_tls,
                allow_redirects=False,
            )

            location = resp.headers.get("Location", "")
            if resp.status_code in (301, 302) and "code=" in location:
                finding = {
                    "type": "oauth_pkce_downgrade",
                    "url": url,
                    "evidence": "auth_code_issued_without_pkce_challenge",
                    "status_code": resp.status_code,
                }
                print_vuln(
                    f"OAuth PKCE downgrade @ {url} | "
                    f"Server issued authorization code without code_challenge"
                )
                self.scanner.findings.append(
                    f"[OAUTH:PKCE_DOWNGRADE] {url} pkce_bypassed=true"
                )
                return finding

            if resp.status_code == 200 and "code=" in (resp.text or ""):
                finding = {
                    "type": "oauth_pkce_downgrade",
                    "url": url,
                    "evidence": "code_in_response_without_pkce",
                    "status_code": resp.status_code,
                }
                print_vuln(
                    f"OAuth PKCE downgrade @ {url} | "
                    f"Authorization code present without PKCE"
                )
                self.scanner.findings.append(
                    f"[OAUTH:PKCE_DOWNGRADE] {url} code_without_pkce=true"
                )
                return finding

        except Exception:
            logging.exception("oauth_testing.py: exception")
            pass
        print_info("    PKCE downgrade not successful.")
        return None

    def test_token_leakage(self, url: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    Testing for token leakage @ {url}...")

        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)

        token_in_url = False
        for marker in self.TOKEN_MARKERS:
            if marker in qs:
                token_in_url = True
                break

        if token_in_url:
            finding = {
                "type": "oauth_token_in_url",
                "url": url,
                "evidence": "token_parameter_in_url_query",
                "status_code": 200,
            }
            print_vuln(
                f"OAuth token leakage in URL @ {url} | "
                f"Token found in URL query string"
            )
            self.scanner.findings.append(
                f"[OAUTH:TOKEN_URL] {url} token_in_query=true"
            )
            return finding

        try:
            resp = session.get(
                url,
                timeout=self.config.timeout,
                verify=self.config.verify_tls,
            )
            body = resp.text or ""

            for marker in self.TOKEN_MARKERS:
                pattern = rf'{marker}\s*[=:]\s*["\']?([A-Za-z0-9\-_\.]+)["\']?'
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    token_value = match.group(1)
                    if len(token_value) >= 20:
                        finding = {
                            "type": "oauth_token_leakage_in_page",
                            "url": url,
                            "evidence": f"token_found:{marker}",
                            "token_preview": token_value[:10] + "...",
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"OAuth token leakage @ {url} | "
                            f"Token found in page content: {marker}"
                        )
                        self.scanner.findings.append(
                            f"[OAUTH:TOKEN_LEAK] {url} marker='{marker}'"
                        )
                        return finding

            referer = resp.headers.get("Referer", "")
            if referer:
                for marker in self.TOKEN_MARKERS:
                    if marker in referer.lower():
                        finding = {
                            "type": "oauth_token_in_referer",
                            "url": url,
                            "evidence": f"token_in_referer_header:{marker}",
                            "referer": referer,
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"OAuth token in Referer @ {url} | "
                            f"Token found in Referer header"
                        )
                        self.scanner.findings.append(
                            f"[OAUTH:TOKEN_REFERER] {url} referer='{referer}'"
                        )
                        return finding

        except Exception:
            logging.exception("oauth_testing.py: exception")
            pass
        print_info("    No token leakage detected.")
        return None

    def test_scope_escalation(self, url: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    Testing OAuth scope escalation on {url}...")

        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)

        scope_param = None
        original_scope = None
        for marker in ["scope", "scope"]:
            if marker in qs:
                scope_param = marker
                original_scope = qs[marker][0]
                break

        if not scope_param:
            print_info("    No scope parameter found.")
            return None

        admin_scopes = [
            "admin", "administrator", "superuser", "full_access",
            "manage", "write", "delete", "root", "privilege",
        ]

        for admin_scope in admin_scopes:
            try:
                test_qs = dict(qs)
                test_qs[scope_param] = [admin_scope]
                new_query = urlencode(test_qs, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                resp = session.get(
                    test_url,
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                    allow_redirects=False,
                )

                location = resp.headers.get("Location", "")
                if "code=" in location:
                    finding = {
                        "type": "oauth_scope_escalation",
                        "url": url,
                        "original_scope": original_scope,
                        "escalated_scope": admin_scope,
                        "evidence": f"code_issued_with_admin_scope:{admin_scope}",
                        "status_code": resp.status_code,
                    }
                    print_vuln(
                        f"OAuth scope escalation @ {url} | "
                        f"Code issued with scope: {admin_scope}"
                    )
                    self.scanner.findings.append(
                        f"[OAUTH:SCOPE] {url} scope='{admin_scope}'"
                    )
                    return finding
            except Exception:
                logging.exception("oauth_testing.py: exception")
                continue
        print_info("    No scope escalation found.")
        return None

    def test_token_substitution(self, url: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    Testing OAuth token substitution on {url}...")

        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)

        has_code = "code" in qs
        has_token = any(marker in qs for marker in self.TOKEN_MARKERS)

        if not has_code and not has_token:
            print_info("    No code/token parameters found for substitution test.")
            return None

        fake_tokens = [
            str(uuid.uuid4()),
            "AAAA" * 10,
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test",
        ]

        for param_name in ["code", "access_token", "id_token", "token"]:
            if param_name not in qs:
                continue

            for fake_token in fake_tokens:
                try:
                    test_qs = dict(qs)
                    test_qs[param_name] = [fake_token]
                    new_query = urlencode(test_qs, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))

                    resp = session.get(
                        test_url,
                        timeout=self.config.timeout,
                        verify=self.config.verify_tls,
                        allow_redirects=False,
                    )

                    body = (resp.text or "").lower()
                    if resp.status_code == 200:
                        success_indicators = ["success", "dashboard", "welcome", "profile"]
                        if any(indicator in body for indicator in success_indicators):
                            finding = {
                                "type": "oauth_token_substitution",
                                "url": url,
                                "param": param_name,
                                "evidence": f"accepted_fake_token:{param_name}",
                                "status_code": resp.status_code,
                            }
                            print_vuln(
                                f"OAuth token substitution @ {url} | "
                                f"Server accepted fake token in '{param_name}'"
                            )
                            self.scanner.findings.append(
                                f"[OAUTH:SUBSTITUTION] {url} param={param_name}"
                            )
                            return finding
                except Exception:
                    logging.exception("oauth_testing.py: exception")
                    continue
        print_info("    No token substitution vulnerability found.")
        return None

    def _detect_oauth_endpoints(self, target: str, session) -> List[Dict[str, str]]:
        endpoints = []
        oauth_paths = [
            "/oauth/authorize", "/oauth/authorize", "/oauth2/authorize",
            "/auth/authorize", "/auth/realms/master/protocol/openid-connect/auth",
            "/oauth/consent", "/authorize", "/auth/authorize",
            "/.well-known/openid-configuration", "/openid-configuration",
            "/oauth/token", "/oauth2/token", "/auth/token",
        ]

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in oauth_paths:
            url = base + path
            try:
                resp = session.get(url, timeout=5, verify=self.config.verify_tls)
                ct = resp.headers.get("Content-Type", "")
                body = (resp.text or "").lower()

                is_oauth = False
                if "authorize" in body or "redirect_uri" in body or "client_id" in body:
                    is_oauth = True
                if "access_token" in body or "grant_type" in body:
                    is_oauth = True
                if "openid" in body or "oidc" in body:
                    is_oauth = True

                if is_oauth or resp.status_code in (302, 301):
                    endpoint_type = "auth" if "authorize" in path else "token"
                    endpoints.append({
                        "url": url,
                        "type": endpoint_type,
                        "status_code": resp.status_code,
                    })
            except Exception:
                logging.exception("oauth_testing.py: exception")
                continue
        if not endpoints:
            for marker in self.REDIRECT_URI_MARKERS:
                if marker in target.lower():
                    endpoints.append({
                        "url": target,
                        "type": "auth",
                        "status_code": 200,
                    })
                    break

        return endpoints
