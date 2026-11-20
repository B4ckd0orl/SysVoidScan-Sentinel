import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.scanner import Scanner


def test_save_reports_generates_dashboard_and_json(tmp_path):
    scanner = Scanner()
    scanner.config.target_url = "http://example.com"
    scanner.scan_data["target"] = {"url": "http://example.com"}
    scanner.findings = [
        {"severity": "high", "title": "Test", "module": "example", "detail": "Detail"},
    ]

    output_dir = str(tmp_path / "reports")
    generated = scanner.save_reports(output_dir, formats=["dashboard", "json"])

    assert len(generated) == 2
    assert any(path.endswith("_report.html") for path in generated)
    assert any(path.endswith("_report.json") for path in generated)
    for path in generated:
        assert os.path.isfile(path)
