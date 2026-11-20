import sys
import os
import json
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reports.json_report import JSONReport


class TestJsonReportGeneration:
    def _make_report(self, tmpdir):
        scan_data = {
            "target": {"url": "http://example.com"},
            "scan_info": {"duration": "00:05:30", "modules_run": ["recon", "sqli"]},
        }
        findings = [
            {"severity": "high", "title": "SQL Injection", "module": "sqli"},
            {"severity": "medium", "title": "XSS", "module": "xss"},
            {"severity": "low", "title": "Info Leak", "module": "recon"},
        ]
        return JSONReport(scan_data, findings, "http://example.com", tmpdir)

    def test_generate_returns_filepath(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report = self._make_report(tmpdir)
            filepath = report.generate()
            assert os.path.isfile(filepath)

    def test_generate_creates_json_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report = self._make_report(tmpdir)
            filepath = report.generate()
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert "report" in data
            assert "summary" in data
            assert "findings" in data

    def test_report_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report = self._make_report(tmpdir)
            filepath = report.generate()
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert data["report"]["scanner"] == "SysVoidScan"
            assert data["report"]["version"] == "2.0.0"
            assert data["report"]["target"] == "http://example.com"

    def test_summary_severity_counts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report = self._make_report(tmpdir)
            filepath = report.generate()
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            counts = data["summary"]["severity_counts"]
            assert counts["high"] == 1
            assert counts["medium"] == 1
            assert counts["low"] == 1

    def test_summary_risk_score(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report = self._make_report(tmpdir)
            filepath = report.generate()
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            score = data["summary"]["risk_score"]
            assert isinstance(score, int)
            assert score > 0

    def test_findings_in_report(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report = self._make_report(tmpdir)
            filepath = report.generate()
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert len(data["findings"]) == 3

    def test_empty_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report = JSONReport({}, [], "http://example.com", tmpdir)
            filepath = report.generate()
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert data["summary"]["total_findings"] == 0
            assert data["summary"]["risk_score"] == 0

    def test_filename_format(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report = self._make_report(tmpdir)
            filepath = report.generate()
            assert filepath.endswith("_report.json")


class TestJsonSerialization:
    def test_set_serialized(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_data = {"scan_info": {}}
            findings = [{"severity": "high", "tags": {"a", "b", "c"}}]
            report = JSONReport(scan_data, findings, "http://example.com", tmpdir)
            filepath = report.generate()
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            tags = data["findings"][0]["tags"]
            assert isinstance(tags, list)

    def test_bytes_serialized(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_data = {"scan_info": {}}
            findings = [{"severity": "low", "data": b"binary content"}]
            report = JSONReport(scan_data, findings, "http://example.com", tmpdir)
            filepath = report.generate()
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert data["findings"][0]["data"] == "binary content"

    def test_datetime_serialized(self):
        from datetime import datetime
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_data = {"scan_info": {}}
            findings = [{"severity": "info", "ts": datetime(2024, 1, 1)}]
            report = JSONReport(scan_data, findings, "http://example.com", tmpdir)
            filepath = report.generate()
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert "2024-01-01" in data["findings"][0]["ts"]

    def test_non_string_serialized(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_data = {"scan_info": {}}
            findings = [{"severity": "info", "count": 42}]
            report = JSONReport(scan_data, findings, "http://example.com", tmpdir)
            filepath = report.generate()
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert data["findings"][0]["count"] == 42

    def test_unicode_handling(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_data = {"scan_info": {}}
            findings = [{"severity": "info", "note": "日本語テスト émojis"}]
            report = JSONReport(scan_data, findings, "http://example.com", tmpdir)
            filepath = report.generate()
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert "日本語テスト" in data["findings"][0]["note"]
