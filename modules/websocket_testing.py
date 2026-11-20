"""
WebSocketTestingModule - WebSocket security testing.

Tests for WebSocket endpoint detection, Cross-Site WebSocket Hijacking,
message injection, and authentication/authorization bypass.
"""

import re
import json
import ssl
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


class WebSocketTestingModule:

    WS_HANDSHAKE_HEADERS = [
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Key:",
        "Sec-WebSocket-Version: 13",
    ]

    CSWSH_PAYLOADS = [
        {"type": "subscribe", "channel": "admin"},
        {"type": "message", "to": "all", "body": "test"},
        {"type": "query", "table": "users", "action": "select"},
        {"type": "execute", "command": "ls -la"},
        {"type": "auth", "token": ""},
        {"type": "join", "room": "admin"},
    ]

    MESSAGE_INJECTION_PAYLOADS = [
        '{"type":"admin","action":"delete_user","user_id":1}',
        '{"type":"subscribe","channel":"*"}',
        '{"type":"auth","role":"admin"}',
        '{"cmd":"whoami"}',
        '{"action":"escalate","role":"admin"}',
    ]

    AUTH_BYPASS_PAYLOADS = [
        '{"type":"auth","token":"test"}',
        '{"type":"auth","token":""}',
        '{"type":"auth","token":null}',
        '{"type":"auth","token":"admin"}',
        '{"type":"subscribe","channel":"admin","auth":false}',
    ]

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config

    def run(self, target: str, session=None):
        print_info(f"Running WebSocket security tests on {target}...")
        results: Dict[str, Any] = {
            "target": target,
            "websocket_vulns": [],
        }

        if session is None:
            session = get_session()

        ws_endpoints = self.detect_websockets(target, session)
        if not ws_endpoints:
            print_info("No WebSocket endpoints detected.")
            self.scanner.scan_data["websocket_testing"] = results
            return results

        print_info(f"Found {len(ws_endpoints)} WebSocket endpoint(s) to test...")

        for ws_url in ws_endpoints:
            result = self.test_cswh(ws_url, session)
            if result:
                results["websocket_vulns"].append(result)

            result = self.test_message_injection(ws_url, session)
            if result:
                results["websocket_vulns"].append(result)

            result = self.test_auth_bypass(ws_url, session)
            if result:
                results["websocket_vulns"].append(result)

            result = self.test_cross_origin_policy(ws_url, session)
            if result:
                results["websocket_vulns"].append(result)

            result = self.test_origin_validation(ws_url, target, session)
            if result:
                results["websocket_vulns"].append(result)

        self.scanner.scan_data["websocket_testing"] = results
        return results

    def detect_websockets(self, url: str, session) -> List[str]:
        print_info(f"    Detecting WebSocket endpoints at {url}...")
        ws_endpoints = []

        parsed = urlparse(url)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        base_ws = f"{ws_scheme}://{parsed.netloc}"

        try:
            resp = session.get(url, timeout=self.config.timeout, verify=self.config.verify_tls)
            body = resp.text or ""

            ws_patterns = [
                r'ws://[^"\'\s<>]+',
                r'wss://[^"\'\s<>]+',
                r'WebSocket\s*\(\s*["\']([^"\']+)["\']',
                r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
                r'websocket_url\s*[=:]\s*["\']([^"\']+)["\']',
                r'socket_url\s*[=:]\s*["\']([^"\']+)["\']',
            ]

            for pattern in ws_patterns:
                matches = re.findall(pattern, body, re.IGNORECASE)
                for match in matches:
                    if match.startswith("ws://") or match.startswith("wss://"):
                        ws_endpoints.append(match)
                    elif match.startswith("/"):
                        ws_endpoints.append(base_ws + match)
                    elif match.startswith("ws"):
                        ws_endpoints.append(match)

            common_ws_paths = [
                "/ws", "/websocket", "/socket", "/api/ws",
                "/api/websocket", "/ws/", "/socket.io/",
                "/signalr", "/hub", "/graphql-ws",
            ]

            for path in common_ws_paths:
                ws_url = base_ws + path
                try:
                    ws_resp = session.get(
                        urljoin(url, path),
                        headers={"Upgrade": "websocket", "Connection": "Upgrade"},
                        timeout=5,
                        verify=self.config.verify_tls,
                        allow_redirects=False,
                    )
                    if ws_resp.status_code == 101:
                        ws_endpoints.append(ws_url)
                    ct = ws_resp.headers.get("Content-Type", "")
                    if "websocket" in ct.lower() or "upgrade" in ws_resp.headers.get("Connection", "").lower():
                        ws_endpoints.append(ws_url)
                except Exception:
                    logging.exception("websocket_testing.py: exception")
                    continue
        except Exception as e:
            logging.exception("websocket_testing.py: operation failed")
            print_warning(f"    WebSocket detection failed: {e}")

        ws_endpoints = list(set(ws_endpoints))

        if ws_endpoints:
            print_info(f"    Found {len(ws_endpoints)} WebSocket endpoint(s).")
        else:
            print_info("    No WebSocket endpoints detected.")

        return ws_endpoints

    def test_cswh(self, ws_url: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    Testing Cross-Site WebSocket Hijacking on {ws_url}...")

        try:
            parsed = urlparse(ws_url)
            http_url = f"{'https' if parsed.scheme == 'wss' else 'http'}://{parsed.netloc}{parsed.path}"

            try:
                ws_response = session.get(
                    http_url,
                    headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                        "Sec-WebSocket-Version": "13",
                        "Sec-WebSocket-Protocol": "chat, superchat",
                    },
                    timeout=5,
                    verify=self.config.verify_tls,
                    allow_redirects=False,
                )

                if ws_response.status_code == 101:
                    finding = {
                        "type": "websocket_no_origin_check",
                        "url": ws_url,
                        "evidence": "handshake_succeeded_without_origin",
                        "status_code": ws_response.status_code,
                    }
                    print_vuln(
                        f"WebSocket hijacking possible @ {ws_url} | "
                        f"Handshake succeeded without origin validation"
                    )
                    self.scanner.findings.append(
                        f"[WS:CSWSH] {ws_url} no_origin_check=true"
                    )
                    return finding
            except Exception:
                logging.exception("websocket_testing.py: exception")
                pass
            for payload in self.CSWSH_PAYLOADS:
                try:
                    ws_resp = session.post(
                        http_url,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        timeout=self.config.timeout,
                        verify=self.config.verify_tls,
                    )

                    if ws_resp.status_code in (200, 201):
                        body = (ws_resp.text or "").lower()
                        if "unauthorized" not in body and "forbidden" not in body:
                            finding = {
                                "type": "websocket_cswsh_possible",
                                "url": ws_url,
                                "payload": json.dumps(payload),
                                "evidence": f"accepted_cross_origin:{payload.get('type', '')}",
                                "status_code": ws_resp.status_code,
                            }
                            print_vuln(
                                f"WebSocket CSWSH @ {ws_url} | "
                                f"Accepted cross-origin request: {json.dumps(payload)}"
                            )
                            self.scanner.findings.append(
                                f"[WS:CSWSH] {ws_url} type='{payload.get('type', '')}'"
                            )
                            return finding
                except Exception:
                    logging.exception("websocket_testing.py: exception")
                    continue
        except Exception as e:
            logging.exception("websocket_testing.py: operation failed")
            print_warning(f"    CSWSH test failed: {e}")

        print_info(f"    No CSWSH vulnerability found at {ws_url}.")
        return None

    def test_message_injection(self, ws_url: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    Testing WebSocket message injection on {ws_url}...")

        try:
            parsed = urlparse(ws_url)
            http_url = f"{'https' if parsed.scheme == 'wss' else 'http'}://{parsed.netloc}{parsed.path}"

            for payload in self.MESSAGE_INJECTION_PAYLOADS:
                try:
                    resp = session.post(
                        http_url,
                        data=payload,
                        headers={
                            "Content-Type": "application/json",
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                        },
                        timeout=self.config.timeout,
                        verify=self.config.verify_tls,
                        allow_redirects=False,
                    )

                    body = (resp.text or "").lower()

                    if resp.status_code == 200:
                        injection_indicators = [
                            "admin", "success", "executed", "deleted",
                            "updated", "created", "subscribed",
                        ]
                        if any(indicator in body for indicator in injection_indicators):
                            finding = {
                                "type": "websocket_message_injection",
                                "url": ws_url,
                                "payload": payload,
                                "evidence": f"injection_accepted:{body[:100]}",
                                "status_code": resp.status_code,
                            }
                            print_vuln(
                                f"WebSocket message injection @ {ws_url} | "
                                f"Payload: {payload[:80]}"
                            )
                            self.scanner.findings.append(
                                f"[WS:INJECT] {ws_url} payload='{payload[:60]}'"
                            )
                            return finding

                except Exception:
                    logging.exception("websocket_testing.py: exception")
                    continue
            try:
                resp = session.get(http_url, timeout=5, verify=self.config.verify_tls)
                ws_key = resp.headers.get("Sec-WebSocket-Key", "")
                ws_protocol = resp.headers.get("Sec-WebSocket-Protocol", "")

                if resp.status_code == 101 or ws_key:
                    finding = {
                        "type": "websocket_upgrade_available",
                        "url": ws_url,
                        "evidence": "upgrade_endpoint_responds",
                        "status_code": resp.status_code,
                    }
                    print_info(
                        f"WebSocket upgrade available @ {ws_url} | "
                        f"Endpoint accepts upgrade requests"
                    )
            except Exception:
                logging.exception("websocket_testing.py: exception")
                pass
        except Exception as e:
            logging.exception("websocket_testing.py: operation failed")
            print_warning(f"    Message injection test failed: {e}")

        print_info(f"    No WebSocket message injection found at {ws_url}.")
        return None

    def test_auth_bypass(self, ws_url: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    Testing WebSocket authentication bypass on {ws_url}...")

        try:
            parsed = urlparse(ws_url)
            http_url = f"{'https' if parsed.scheme == 'wss' else 'http'}://{parsed.netloc}{parsed.path}"

            try:
                no_auth_resp = session.get(
                    http_url,
                    headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                        "Sec-WebSocket-Version": "13",
                    },
                    timeout=5,
                    verify=self.config.verify_tls,
                    allow_redirects=False,
                )

                if no_auth_resp.status_code == 101:
                    finding = {
                        "type": "websocket_no_auth_required",
                        "url": ws_url,
                        "evidence": "handshake_succeeded_without_auth",
                        "status_code": no_auth_resp.status_code,
                    }
                    print_vuln(
                        f"WebSocket no auth required @ {ws_url} | "
                        f"Handshake succeeded without authentication"
                    )
                    self.scanner.findings.append(
                        f"[WS:NO_AUTH] {ws_url}"
                    )
                    return finding
            except Exception:
                logging.exception("websocket_testing.py: exception")
                pass
            for payload in self.AUTH_BYPASS_PAYLOADS:
                try:
                    resp = session.post(
                        http_url,
                        data=json.dumps(payload),
                        headers={"Content-Type": "application/json"},
                        timeout=self.config.timeout,
                        verify=self.config.verify_tls,
                        allow_redirects=False,
                    )

                    body = (resp.text or "").lower()

                    if resp.status_code == 200:
                        auth_success = [
                            "connected", "authenticated", "welcome",
                            "success", "authorized",
                        ]
                        if any(indicator in body for indicator in auth_success):
                            finding = {
                                "type": "websocket_auth_bypass",
                                "url": ws_url,
                                "payload": json.dumps(payload),
                                "evidence": f"auth_success:{body[:80]}",
                                "status_code": resp.status_code,
                            }
                            print_vuln(
                                f"WebSocket auth bypass @ {ws_url} | "
                                f"Payload: {json.dumps(payload)}"
                            )
                            self.scanner.findings.append(
                                f"[WS:AUTH_BYPASS] {ws_url} payload='{json.dumps(payload)[:60]}'"
                            )
                            return finding

                        auth_fail = ["unauthorized", "forbidden", "denied", "invalid token"]
                        if not any(fail in body for fail in auth_fail):
                            finding = {
                                "type": "websocket_weak_auth",
                                "url": ws_url,
                                "payload": json.dumps(payload),
                                "evidence": f"no_auth_error:{body[:80]}",
                                "status_code": resp.status_code,
                            }
                            print_vuln(
                                f"WebSocket weak auth @ {ws_url} | "
                                f"No auth error for invalid credentials"
                            )
                            self.scanner.findings.append(
                                f"[WS:WEAK_AUTH] {ws_url}"
                            )
                            return finding

                except Exception:
                    logging.exception("websocket_testing.py: exception")
                    continue
        except Exception as e:
            logging.exception("websocket_testing.py: operation failed")
            print_warning(f"    Auth bypass test failed: {e}")

        print_info(f"    No WebSocket auth bypass found at {ws_url}.")
        return None

    def test_cross_origin_policy(self, ws_url: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    Testing WebSocket cross-origin policy on {ws_url}...")

        try:
            parsed = urlparse(ws_url)
            http_url = f"{'https' if parsed.scheme == 'wss' else 'http'}://{parsed.netloc}{parsed.path}"

            try:
                resp = session.options(
                    http_url,
                    headers={
                        "Origin": "https://evil.com",
                        "Access-Control-Request-Method": "GET",
                    },
                    timeout=5,
                    verify=self.config.verify_tls,
                )

                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                if acao == "*" or "evil.com" in acao:
                    finding = {
                        "type": "websocket_permissive_cors",
                        "url": ws_url,
                        "evidence": f"acao:{acao}",
                        "status_code": resp.status_code,
                    }
                    print_vuln(
                        f"WebSocket permissive CORS @ {ws_url} | "
                        f"Access-Control-Allow-Origin: {acao}"
                    )
                    self.scanner.findings.append(
                        f"[WS:CORS] {ws_url} acao='{acao}'"
                    )
                    return finding
            except Exception:
                logging.exception("websocket_testing.py: exception")
                pass
            try:
                resp = session.get(
                    http_url,
                    headers={
                        "Origin": "https://evil.com",
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                        "Sec-WebSocket-Version": "13",
                    },
                    timeout=5,
                    verify=self.config.verify_tls,
                    allow_redirects=False,
                )

                if resp.status_code == 101:
                    finding = {
                        "type": "websocket_no_origin_validation",
                        "url": ws_url,
                        "evidence": "accepted_cross_origin_handshake",
                        "status_code": resp.status_code,
                    }
                    print_vuln(
                        f"WebSocket no origin validation @ {ws_url} | "
                        f"Accepted connection from evil.com origin"
                    )
                    self.scanner.findings.append(
                        f"[WS:NO_ORIGIN] {ws_url}"
                    )
                    return finding
            except Exception:
                logging.exception("websocket_testing.py: exception")
                pass
        except Exception as e:
            logging.exception("websocket_testing.py: operation failed")
            print_warning(f"    Cross-origin policy test failed: {e}")

        print_info(f"    Cross-origin policy appears enforced at {ws_url}.")
        return None

    def test_origin_validation(self, ws_url: str, original_url: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    Testing WebSocket origin validation on {ws_url}...")

        try:
            parsed = urlparse(ws_url)
            http_url = f"{'https' if parsed.scheme == 'wss' else 'http'}://{parsed.netloc}{parsed.path}"
            original_parsed = urlparse(original_url)

            origins_to_test = [
                f"{original_parsed.scheme}://{original_parsed.netloc}",
                "https://evil.com",
                "http://localhost",
                "null",
                "",
            ]

            for origin in origins_to_test:
                try:
                    headers = {
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                        "Sec-WebSocket-Version": "13",
                    }
                    if origin:
                        headers["Origin"] = origin

                    resp = session.get(
                        http_url,
                        headers=headers,
                        timeout=5,
                        verify=self.config.verify_tls,
                        allow_redirects=False,
                    )

                    if resp.status_code == 101 and origin != f"{original_parsed.scheme}://{original_parsed.netloc}":
                        finding = {
                            "type": "websocket_origin_bypass",
                            "url": ws_url,
                            "origin_tested": origin,
                            "evidence": f"accepted_origin:{origin}",
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"WebSocket origin bypass @ {ws_url} | "
                            f"Accepted connection from origin: {origin}"
                        )
                        self.scanner.findings.append(
                            f"[WS:ORIGIN_BYPASS] {ws_url} origin='{origin}'"
                        )
                        return finding

                except Exception:
                    logging.exception("websocket_testing.py: exception")
                    continue
        except Exception as e:
            logging.exception("websocket_testing.py: operation failed")
            print_warning(f"    Origin validation test failed: {e}")

        print_info(f"    Origin validation appears enforced at {ws_url}.")
        return None
