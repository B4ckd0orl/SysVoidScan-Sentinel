import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from modules.recon import ReconModule


class MockScanner:
    def __init__(self):
        self.config = MockConfig()
        self.findings = []
        self.scan_data = {"recon": {}}


class MockConfig:
    timeout = 10
    verify_tls = True


class TestSecurityHeadersPresent:
    def _make_module(self):
        scanner = MockScanner()
        return ReconModule(scanner)

    def test_all_headers_present(self):
        mod = self._make_module()
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            "Feature-Policy": "camera 'none'",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        }
        result = mod.check_security_headers(headers)
        assert len(result["missing"]) == 0
        assert len(result["present"]) == len(ReconModule.SECURE_HEADERS)

    def test_no_headers_present(self):
        mod = self._make_module()
        result = mod.check_security_headers({})
        assert len(result["missing"]) == len(ReconModule.SECURE_HEADERS)
        assert len(result["present"]) == 0

    def test_partial_headers(self):
        mod = self._make_module()
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
        }
        result = mod.check_security_headers(headers)
        assert "Content-Security-Policy" in result["present"]
        assert "X-Frame-Options" in result["present"]
        assert "Strict-Transport-Security" in result["missing"]

    def test_hsts_low_max_age(self):
        mod = self._make_module()
        headers = {"Strict-Transport-Security": "max-age=100"}
        result = mod.check_security_headers(headers)
        assert "Strict-Transport-Security max-age too low" in result["misconfigured"]

    def test_hsts_good_max_age(self):
        mod = self._make_module()
        headers = {"Strict-Transport-Security": "max-age=63072000"}
        result = mod.check_security_headers(headers)
        assert len(result["misconfigured"]) == 0

    def test_csp_unsafe_inline(self):
        mod = self._make_module()
        headers = {"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"}
        result = mod.check_security_headers(headers)
        assert "CSP contains unsafe-inline" in result["misconfigured"]

    def test_xfo_invalid_value(self):
        mod = self._make_module()
        headers = {"X-Frame-Options": "ALLOW-FROM evil.com"}
        result = mod.check_security_headers(headers)
        assert any("X-Frame-Options" in m for m in result["misconfigured"])


class TestSecurityHeadersMissing:
    def _make_module(self):
        scanner = MockScanner()
        return ReconModule(scanner)

    def test_all_missing(self):
        mod = self._make_module()
        result = mod.check_security_headers({})
        assert len(result["missing"]) == len(ReconModule.SECURE_HEADERS)

    def test_missing_adds_finding(self):
        scanner = MockScanner()
        mod = ReconModule(scanner)
        mod.check_security_headers({})
        assert len(scanner.findings) > 0
        assert any("Missing security headers" in f for f in scanner.findings)

    def test_present_not_in_missing(self):
        mod = self._make_module()
        headers = {"Content-Security-Policy": "default-src 'self'"}
        result = mod.check_security_headers(headers)
        assert "Content-Security-Policy" not in result["missing"]


class TestCookieSecurityCheck:
    def _make_module(self):
        scanner = MockScanner()
        return ReconModule(scanner)

    def test_secure_cookie(self):
        mod = self._make_module()
        cookies = [{"name": "session", "value": "abc", "domain": ".example.com", "path": "/"}]
        result = mod.check_cookie_security(cookies)
        assert len(result) == 1

    def test_cookie_missing_flags(self):
        mod = self._make_module()
        cookies = [{"name": "session", "value": "abc", "domain": ".example.com", "path": "/"}]
        result = mod.check_cookie_security(cookies)
        assert len(result) == 1
        assert len(result[0]["flags_missing"]) > 0

    def test_multiple_cookies(self):
        mod = self._make_module()
        cookies = [
            {"name": "c1", "value": "v1"},
            {"name": "c2", "value": "v2"},
            {"name": "c3", "value": "v3"},
        ]
        result = mod.check_cookie_security(cookies)
        assert len(result) == 3

    def test_cookie_missing_flags_adds_finding(self):
        scanner = MockScanner()
        mod = ReconModule(scanner)
        cookies = [{"name": "insecure_cookie", "value": "val"}]
        mod.check_cookie_security(cookies)
        assert any("insecure_cookie" in f for f in scanner.findings)

    def test_empty_cookies(self):
        mod = self._make_module()
        result = mod.check_cookie_security([])
        assert result == []
