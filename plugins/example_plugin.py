import time
from typing import Any, Dict, List, Optional

from plugins.loader import Plugin


class ExamplePlugin(Plugin):
    """Example plugin demonstrating the SysVoidScan plugin system.

    This plugin performs a basic HTTP check on the target and reports
    security-relevant HTTP headers. It serves as a reference implementation
    for developing custom plugins.
    """

    name = "example-plugin"
    version = "1.0.0"
    description = "Example plugin that checks HTTP security headers on the target"

    SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
        "Cross-Origin-Embedder-Policy",
    ]

    def register(self, scanner) -> None:
        """Register hooks with the scanner."""
        if not hasattr(scanner, "_plugin_hooks"):
            scanner._plugin_hooks = {}
        scanner._plugin_hooks[self.name] = [
            {"event": "before_scan", "handler": self._on_before_scan},
            {"event": "after_scan", "handler": self._on_after_scan},
        ]

    def _on_before_scan(self, target: str, **kwargs):
        """Called before a scan starts."""
        pass

    def _on_after_scan(self, target: str, results: Dict = None, **kwargs):
        """Called after a scan completes."""
        pass

    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run the security header check against the target."""
        results = {
            "target": target,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "present_headers": [],
            "missing_headers": [],
            "findings": [],
        }

        try:
            import requests
            session = requests.Session()
            session.headers["User-Agent"] = (
                "SysVoidScan/2.0 ExamplePlugin"
            )
            session.verify = True

            if options and not options.get("verify_tls", True):
                session.verify = False
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            response = session.get(target, timeout=10, allow_redirects=True)
            response_headers = {k.lower(): v for k, v in response.headers.items()}

            for header in self.SECURITY_HEADERS:
                header_lower = header.lower()
                if header_lower in response_headers:
                    results["present_headers"].append({
                        "name": header,
                        "value": response_headers[header_lower],
                    })
                else:
                    results["missing_headers"].append(header)
                    results["findings"].append({
                        "severity": "medium",
                        "title": f"Missing security header: {header}",
                        "detail": f"The HTTP response does not include the {header} header.",
                        "module": "example-plugin",
                    })

            server = response_headers.get("server", "")
            if server:
                results["server"] = server
                if any(v in server.lower() for v in ("apache/2.2", "apache/2.3", "nginx/1.0")):
                    results["findings"].append({
                        "severity": "low",
                        "title": f"Outdated web server detected: {server}",
                        "detail": "The server header reveals the web server version, which may help attackers identify known vulnerabilities.",
                        "module": "example-plugin",
                    })

            x_powered_by = response_headers.get("x-powered-by", "")
            if x_powered_by:
                results["x_powered_by"] = x_powered_by
                results["findings"].append({
                    "severity": "info",
                    "title": f"X-Powered-By header disclosed: {x_powered_by}",
                    "detail": "The X-Powered-By header reveals technology information.",
                    "module": "example-plugin",
                })

            results["status_code"] = response.status_code

        except ImportError:
            results["error"] = "requests library not installed"
        except Exception as e:
            results["error"] = str(e)

        return results

    def report(self, results: Dict[str, Any]) -> str:
        """Return a summary string of the plugin results."""
        present = len(results.get("present_headers", []))
        missing = len(results.get("missing_headers", []))
        findings = len(results.get("findings", []))
        return (
            f"Security Header Check: {present} present, {missing} missing, "
            f"{findings} findings"
        )
