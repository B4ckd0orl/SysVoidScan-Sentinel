import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.config import Config


class TestConfigDefaults:
    def test_version(self):
        cfg = Config()
        assert cfg.VERSION == "2.0.0"

    def test_default_timeout(self):
        cfg = Config()
        assert cfg.DEFAULT_TIMEOUT == 10

    def test_default_threads(self):
        cfg = Config()
        assert cfg.THREADS == 5

    def test_default_max_redirects(self):
        cfg = Config()
        assert cfg.MAX_REDIRECTS == 10

    def test_default_verify_tls(self):
        cfg = Config()
        assert cfg.VERIFY_TLS is True

    def test_default_http_retries(self):
        cfg = Config()
        assert cfg.HTTP_RETRIES == 2

    def test_default_http_pool_size(self):
        cfg = Config()
        assert cfg.HTTP_POOL_SIZE == 50

    def test_default_request_delay(self):
        cfg = Config()
        assert cfg.REQUEST_DELAY == 0.0

    def test_instance_attributes_after_init(self):
        cfg = Config()
        assert cfg.target_url == ""
        assert cfg.output_file is None
        assert cfg.findings == []
        assert cfg.authenticated is False
        assert cfg.auth_session is None


class TestConfigReset:
    def test_reset_clears_findings(self):
        cfg = Config()
        cfg.findings.append("test finding")
        cfg.reset()
        assert cfg.findings == []

    def test_reset_restores_target_url(self):
        cfg = Config()
        cfg.target_url = "http://evil.com"
        cfg.reset()
        assert cfg.target_url == ""

    def test_reset_restores_timeout(self):
        cfg = Config()
        cfg.timeout = 999
        cfg.reset()
        assert cfg.timeout == cfg.DEFAULT_TIMEOUT

    def test_reset_restores_threads(self):
        cfg = Config()
        cfg.threads = 999
        cfg.reset()
        assert cfg.threads == cfg.THREADS

    def test_reset_creates_fresh_scan_data(self):
        cfg = Config()
        cfg.scan_data["recon"]["whois"]["registrar"] = "modified"
        cfg.reset()
        assert cfg.scan_data["recon"]["whois"] == {}

    def test_reset_sets_start_time(self):
        cfg = Config()
        old_time = cfg.start_time
        import time
        time.sleep(0.01)
        cfg.reset()
        assert cfg.start_time >= old_time


class TestConfigSnapshotRestore:
    def test_snapshot_returns_dict(self):
        cfg = Config()
        snap = cfg.snapshot()
        assert isinstance(snap, dict)

    def test_snapshot_contains_all_keys(self):
        cfg = Config()
        snap = cfg.snapshot()
        expected_keys = [
            "target_url", "output_file", "findings", "scan_data",
            "authenticated", "timeout", "max_redirects", "threads",
            "http_retries", "http_pool_size", "request_delay",
            "verify_tls", "start_time",
        ]
        for key in expected_keys:
            assert key in snap, f"Missing key: {key}"

    def test_snapshot_is_deep_copy(self):
        cfg = Config()
        snap = cfg.snapshot()
        cfg.findings.append("mutated")
        assert "mutated" not in snap["findings"]

    def test_restore_recovers_state(self):
        cfg = Config()
        cfg.target_url = "http://test.example.com"
        cfg.threads = 99
        cfg.findings.append("finding1")
        snap = cfg.snapshot()

        cfg.reset()
        assert cfg.target_url == ""
        assert cfg.threads == 5

        cfg.restore(snap)
        assert cfg.target_url == "http://test.example.com"
        assert cfg.threads == 99
        assert cfg.findings == ["finding1"]

    def test_restore_with_empty_snapshot(self):
        cfg = Config()
        cfg.target_url = "http://test.example.com"
        cfg.restore({})
        assert cfg.target_url == ""


class TestFreshScanDataStructure:
    def test_has_all_top_level_sections(self):
        cfg = Config()
        data = cfg._fresh_scan_data()
        expected_sections = [
            "target", "recon", "crawl", "directory_bruteforce",
            "subdomain_enum", "parameter_discovery", "header_security",
            "ssl_tls", "authentication", "vulnerabilities", "api", "scan_info",
        ]
        for section in expected_sections:
            assert section in data, f"Missing section: {section}"

    def test_target_section_structure(self):
        cfg = Config()
        data = cfg._fresh_scan_data()
        target = data["target"]
        assert "url" in target
        assert "domain" in target
        assert "ip" in target
        assert "status" in target
        assert "title" in target
        assert "server" in target
        assert "technologies" in target
        assert "headers" in target
        assert "cookies" in target
        assert "redirect_chain" in target

    def test_vulnerabilities_section_structure(self):
        cfg = Config()
        data = cfg._fresh_scan_data()
        vulns = data["vulnerabilities"]
        expected_vuln_types = [
            "sqli", "xss", "ssrf", "lfi", "rfi", "rce", "cors", "csrf",
            "open_redirect", "info_disclosure", "misconfig", "cve",
        ]
        for vtype in expected_vuln_types:
            assert vtype in vulns, f"Missing vulnerability type: {vtype}"
            assert isinstance(vulns[vtype], list)

    def test_scan_info_has_version(self):
        cfg = Config()
        data = cfg._fresh_scan_data()
        assert data["scan_info"]["scanner_version"] == Config.VERSION

    def test_recon_section_structure(self):
        cfg = Config()
        data = cfg._fresh_scan_data()
        recon = data["recon"]
        assert "whois" in recon
        assert "dns" in recon
        assert "subdomains" in recon
        assert "ports" in recon
        assert "services" in recon

    def test_crawl_section_structure(self):
        cfg = Config()
        data = cfg._fresh_scan_data()
        crawl = data["crawl"]
        assert "urls" in crawl
        assert "forms" in crawl
        assert "links" in crawl
        assert "scripts" in crawl
        assert "hidden_fields" in crawl

    def test_api_section_structure(self):
        cfg = Config()
        data = cfg._fresh_scan_data()
        api = data["api"]
        assert "endpoints" in api
        assert "methods" in api
        assert "schemas" in api
        assert "authentication" in api

    def test_payload_lists_are_non_empty(self):
        assert len(Config.SQL_PAYLOADS) > 0
        assert len(Config.XSS_PAYLOADS) > 0
        assert len(Config.PATH_TRAVERSAL) > 0
        assert len(Config.COMMAND_INJECT) > 0
        assert len(Config.OPEN_REDIRECT) > 0

    def test_api_endpoints_list_is_non_empty(self):
        assert len(Config.API_ENDPOINTS) > 0
        assert "/api" in Config.API_ENDPOINTS

    def test_login_paths_list_is_non_empty(self):
        assert len(Config.LOGIN_PATHS) > 0
        assert "/login" in Config.LOGIN_PATHS

    def test_mass_assignment_fields_non_empty(self):
        assert len(Config.MASS_ASSIGNMENT_FIELDS) > 0
        assert "admin" in Config.MASS_ASSIGNMENT_FIELDS

    def test_banner_is_string(self):
        assert isinstance(Config.BANNER, str)
        assert "SysVoidScan" in Config.BANNER or "_____" in Config.BANNER
