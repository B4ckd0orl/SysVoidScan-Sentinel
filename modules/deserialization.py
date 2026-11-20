"""
DeserializationModule - Insecure deserialization testing.

Tests for Java, PHP, Python pickle, and .NET deserialization vulnerabilities
via error message detection and response anomaly analysis.
"""

import re
import json
import base64
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


class DeserializationModule:

    JAVA_ERROR_MARKERS = [
        "java.io.ObjectInputStream",
        "java.io.InvalidClassException",
        "ClassNotFoundException",
        "NotSerializableException",
        "StreamCorruptedException",
        "ObjectStreamException",
        "java.io.ObjectOutput",
        "java.io.ObjectInput",
        "java.io.Serializable",
        "readObject",
        "writeObject",
        "readResolve",
        "java.io.ByteArrayInputStream",
        "java.io.ObjectOutputStream",
    ]

    PHP_ERROR_MARKERS = [
        "__wakeup",
        "__destruct",
        "__toString",
        "unserialize()",
        "Serializable",
        "Warning: unserialize",
        "Fatal error: Uncaught",
        "__autoload",
        "O:",
        "C:",
        "allowed_classes",
    ]

    PYTHON_ERROR_MARKERS = [
        "__reduce__",
        "__getstate__",
        "__setstate__",
        "pickle",
        "cPickle",
        "_pickle",
        "UnpicklingError",
        "Unpickler",
        "pickle.Unpickler",
        "import builtins",
        "__builtins__",
    ]

    DOTNET_ERROR_MARKERS = [
        "BinaryFormatter",
        "ObjectStateFormatter",
        "LosFormatter",
        "SoapFormatter",
        "NetDataContractSerializer",
        "System.Runtime.Serialization",
        "SerializationException",
        "SecurityException",
        "DeserializationException",
        "__type",
        "$type",
        "TypeFilterLevel",
    ]

    JAVA_PAYLOADS = [
        b"\xac\xed\x00\x05",
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        b"\xac\xed\x00\x05\x73\x72",
    ]

    PHP_PAYLOADS = [
        'O:8:"stdClass":0:{}',
        'a:1:{s:1:"x";s:3:"y";}',
        'C:8:"Exception":0:{}',
        'O:9:"Exception":7:{s:10:"*message";s:3:"x";s:13:"*previous";O:0:"":0:{}s:17:"exception.string";s:3:"x";s:26:"*trace";a:0:{}s:19:"*previousAsString";s:0:"";s:17:"exception.trace";a:0:{}}',
        'O:11:"ArrayObject":0:{}',
    ]

    PYTHON_PICKLE_PAYLOADS = [
        b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00\x8c\x01x\x94.",
        b"\x80\x03\x63pickle\nUnpickler\n\x85\x94.",
    ]

    DOTNET_PAYLOADS = [
        '{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework"}',
        '{"$type":"System.Diagnostics.Process, System"}',
    ]

    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config

    def run(self, target: str, session=None):
        print_info(f"Running deserialization tests on {target}...")
        results: Dict[str, Any] = {
            "target": target,
            "deserialization": [],
        }

        if session is None:
            session = get_session()

        params = self._extract_params(target, session)
        if not params:
            print_info("No injectable parameters found for deserialization testing.")
            self.scanner.scan_data["deserialization"] = results
            return results

        print_info(f"Testing {len(params)} parameter(s) for deserialization...")
        for param_info in params:
            url = param_info.get("url", target)
            param_name = param_info.get("name", "")
            method = param_info.get("method", "POST")

            if not param_name:
                continue

            print_info(f"  Testing parameter '{param_name}' on {url}")

            result = self.test_java_deserialization(url, param_name, session)
            if result:
                results["deserialization"].append(result)
                continue

            result = self.test_php_deserialization(url, param_name, session)
            if result:
                results["deserialization"].append(result)
                continue

            result = self.test_python_pickle(url, param_name, session)
            if result:
                results["deserialization"].append(result)
                continue

            result = self.test_dotnet_deserialization(url, param_name, session)
            if result:
                results["deserialization"].append(result)

        self.scanner.scan_data["deserialization"] = results
        return results

    def test_java_deserialization(self, url: str, param: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    Java deserialization test on '{param}'...")

        for payload_bytes in self.JAVA_PAYLOADS:
            try:
                b64_payload = base64.b64encode(payload_bytes).decode()
                resp = session.post(
                    url,
                    data={param: b64_payload},
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                )
                body = (resp.text or "").lower()

                for marker in self.JAVA_ERROR_MARKERS:
                    if marker.lower() in body:
                        finding = {
                            "type": "java_deserialization",
                            "url": url,
                            "param": param,
                            "payload": b64_payload,
                            "evidence": marker,
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"Java deserialization in '{param}' @ {url} | "
                            f"Marker: {marker}"
                        )
                        self.scanner.findings.append(
                            f"[DESER:JAVA] {url} param={param} evidence='{marker}'"
                        )
                        return finding

                resp_raw = resp.content
                if resp_raw and b"java" in resp_raw.lower() and any(
                    marker.lower().encode() in resp_raw.lower() for marker in self.JAVA_ERROR_MARKERS
                ):
                    finding = {
                        "type": "java_deserialization",
                        "url": url,
                        "param": param,
                        "payload": b64_payload,
                        "evidence": "binary_java_error",
                        "status_code": resp.status_code,
                    }
                    print_vuln(
                        f"Java deserialization in '{param}' @ {url} | "
                        f"Marker: binary java error detected"
                    )
                    self.scanner.findings.append(
                        f"[DESER:JAVA] {url} param={param} evidence='binary_java_error'"
                    )
                    return finding

            except Exception:
                logging.exception("deserialization.py: exception")
                continue
        json_payloads = [
            '{"$type":"java.lang.String"}',
            '{"@class":"java.lang.String"}',
            '{"type":"java.lang.Runtime"}',
            '["java.lang.Runtime","exec",["calc"]]',
        ]

        for payload in json_payloads:
            try:
                resp = session.post(
                    url,
                    data={param: payload},
                    headers={"Content-Type": "application/json"},
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                )
                body = (resp.text or "").lower()

                for marker in self.JAVA_ERROR_MARKERS:
                    if marker.lower() in body:
                        finding = {
                            "type": "java_deserialization_json",
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "evidence": marker,
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"Java deserialization (JSON) in '{param}' @ {url} | "
                            f"Marker: {marker}"
                        )
                        self.scanner.findings.append(
                            f"[DESER:JAVA:JSON] {url} param={param} evidence='{marker}'"
                        )
                        return finding
            except Exception:
                logging.exception("deserialization.py: exception")
                continue
        print_info(f"    No Java deserialization found for '{param}'.")
        return None

    def test_php_deserialization(self, url: str, param: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    PHP object injection test on '{param}'...")

        for payload in self.PHP_PAYLOADS:
            try:
                resp = session.post(
                    url,
                    data={param: payload},
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                )
                body = (resp.text or "").lower()

                for marker in self.PHP_ERROR_MARKERS:
                    if marker.lower() in body:
                        severity = "high" if "__wakeup" in body or "__destruct" in body else "medium"
                        finding = {
                            "type": "php_deserialization",
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "evidence": marker,
                            "severity": severity,
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"PHP object injection in '{param}' @ {url} | "
                            f"Payload: {payload} | Marker: {marker} | Severity: {severity}"
                        )
                        self.scanner.findings.append(
                            f"[DESER:PHP] {url} param={param} payload='{payload}' evidence='{marker}'"
                        )
                        return finding

                if resp.status_code == 500:
                    body_text = resp.text or ""
                    if "exception" in body_text.lower() or "error" in body_text.lower():
                        finding = {
                            "type": "php_error_disclosure",
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "evidence": "500_with_error_on_serialize_payload",
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"PHP error disclosure (deserialization) in '{param}' @ {url} | "
                            f"Payload: {payload}"
                        )
                        self.scanner.findings.append(
                            f"[DESER:PHP:ERROR] {url} param={param} payload='{payload}'"
                        )
                        return finding

            except Exception:
                logging.exception("deserialization.py: exception")
                continue
        print_info(f"    No PHP object injection found for '{param}'.")
        return None

    def test_python_pickle(self, url: str, param: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    Python pickle deserialization test on '{param}'...")

        for payload_bytes in self.PYTHON_PICKLE_PAYLOADS:
            try:
                b64_payload = base64.b64encode(payload_bytes).decode()
                resp = session.post(
                    url,
                    data={param: b64_payload},
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                )
                body = (resp.text or "").lower()

                for marker in self.PYTHON_ERROR_MARKERS:
                    if marker.lower() in body:
                        finding = {
                            "type": "python_pickle_deserialization",
                            "url": url,
                            "param": param,
                            "payload": b64_payload,
                            "evidence": marker,
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f"Python pickle deserialization in '{param}' @ {url} | "
                            f"Marker: {marker}"
                        )
                        self.scanner.findings.append(
                            f"[DESER:PYTHON] {url} param={param} evidence='{marker}'"
                        )
                        return finding

            except Exception:
                logging.exception("deserialization.py: exception")
                continue
        pickle_content_markers = [
            b"\x80\x04\x95", b"\x80\x03",
            b"cos\nsystem\n", b"builtins\n__import__\n",
            b"__reduce__", b"__getstate__",
        ]

        try:
            resp = session.get(url, timeout=self.config.timeout, verify=self.config.verify_tls)
            for marker in pickle_content_markers:
                if marker in resp.content:
                    finding = {
                        "type": "python_pickle_content_detected",
                        "url": url,
                        "param": "",
                        "payload": "",
                        "evidence": marker.decode("utf-8", errors="replace"),
                        "status_code": resp.status_code,
                    }
                    print_vuln(
                        f"Pickle content detected @ {url} | "
                        f"Marker: {marker.decode('utf-8', errors='replace')}"
                    )
                    self.scanner.findings.append(
                        f"[DESER:PYTHON:CONTENT] {url} evidence='{marker.decode('utf-8', errors='replace')}'"
                    )
                    return finding
        except Exception:
            logging.exception("deserialization.py: exception")
            pass
        print_info(f"    No Python pickle deserialization found for '{param}'.")
        return None

    def test_dotnet_deserialization(self, url: str, param: str, session) -> Optional[Dict[str, Any]]:
        print_info(f"    .NET deserialization test on '{param}'...")

        for payload in self.DOTNET_PAYLOADS:
            try:
                resp = session.post(
                    url,
                    data={param: payload},
                    headers={"Content-Type": "application/json"},
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                )
                body = (resp.text or "").lower()

                for marker in self.DOTNET_ERROR_MARKERS:
                    if marker.lower() in body:
                        finding = {
                            "type": "dotnet_deserialization",
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "evidence": marker,
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f".NET deserialization in '{param}' @ {url} | "
                            f"Payload: {payload} | Marker: {marker}"
                        )
                        self.scanner.findings.append(
                            f"[DESER:DOTNET] {url} param={param} payload='{payload}' evidence='{marker}'"
                        )
                        return finding

            except Exception:
                logging.exception("deserialization.py: exception")
                continue
        b64_dotnet_payloads = []
        for payload in self.DOTNET_PAYLOADS:
            try:
                b64 = base64.b64encode(payload.encode()).decode()
                b64_dotnet_payloads.append(b64)
            except Exception:
                logging.exception("deserialization.py: exception")
                continue
        for b64_payload in b64_dotnet_payloads:
            try:
                resp = session.post(
                    url,
                    data={param: b64_payload},
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                )
                body = (resp.text or "").lower()

                for marker in self.DOTNET_ERROR_MARKERS:
                    if marker.lower() in body:
                        finding = {
                            "type": "dotnet_deserialization_b64",
                            "url": url,
                            "param": param,
                            "payload": b64_payload,
                            "evidence": marker,
                            "status_code": resp.status_code,
                        }
                        print_vuln(
                            f".NET deserialization (base64) in '{param}' @ {url} | "
                            f"Marker: {marker}"
                        )
                        self.scanner.findings.append(
                            f"[DESER:DOTNET:B64] {url} param={param} evidence='{marker}'"
                        )
                        return finding
            except Exception:
                logging.exception("deserialization.py: exception")
                continue
        print_info(f"    No .NET deserialization found for '{param}'.")
        return None

    def _extract_params(self, target: str, session=None) -> List[Dict[str, Any]]:
        params: List[Dict[str, Any]] = []

        crawl_data = self.scanner.scan_data.get("crawl", {})
        forms = crawl_data.get("forms", [])
        for form in forms:
            form_url = form.get("url", target)
            for fp in form.get("params", []):
                params.append({
                    "url": form_url,
                    "name": fp.get("name", ""),
                    "method": form.get("method", "POST"),
                })

        parsed = urlparse(target)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for key in qs:
            params.append({
                "url": target,
                "name": key,
                "method": "GET",
            })

        seen = set()
        unique_params = []
        for p in params:
            k = (p["url"], p["name"], p["method"])
            if k not in seen:
                seen.add(k)
                unique_params.append(p)

        return unique_params
