import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.database import Database


class TestInitDb:
    def test_creates_tables(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                cursor = db.conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
                tables = {row[0] for row in cursor.fetchall()}
                assert "scans" in tables
                assert "findings" in tables
                assert "technologies" in tables
                assert "services" in tables
                assert "subdomains" in tables
                assert "urls" in tables
                assert "cache" in tables
        finally:
            os.unlink(db_path)

    def test_init_idempotent(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                db.init_db()
                db.init_db()
                cursor = db.conn.execute(
                    "SELECT count(*) FROM sqlite_master WHERE type='table'"
                )
                count = cursor.fetchone()[0]
                assert count >= 7
        finally:
            os.unlink(db_path)


class TestCreateAndGetScan:
    def test_create_scan_returns_id(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                scan_id = db.create_scan("http://example.com")
                assert isinstance(scan_id, int)
                assert scan_id > 0
        finally:
            os.unlink(db_path)

    def test_get_scan_returns_dict(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                scan_id = db.create_scan("http://example.com")
                scan = db.get_scan(scan_id)
                assert isinstance(scan, dict)
                assert scan["target"] == "http://example.com"
                assert scan["status"] == "running"
        finally:
            os.unlink(db_path)

    def test_get_nonexistent_scan_returns_none(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                scan = db.get_scan(9999)
                assert scan is None
        finally:
            os.unlink(db_path)

    def test_update_scan(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                scan_id = db.create_scan("http://example.com")
                db.update_scan(scan_id, status="completed")
                scan = db.get_scan(scan_id)
                assert scan["status"] == "completed"
                assert scan["end_time"] is not None
        finally:
            os.unlink(db_path)

    def test_get_scans_returns_list(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                db.create_scan("http://a.com")
                db.create_scan("http://b.com")
                scans = db.get_scans()
                assert len(scans) == 2
        finally:
            os.unlink(db_path)

    def test_get_scans_by_target(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                db.create_scan("http://a.com")
                db.create_scan("http://b.com")
                scans = db.get_scans(target="http://a.com")
                assert len(scans) == 1
                assert scans[0]["target"] == "http://a.com"
        finally:
            os.unlink(db_path)


class TestAddFinding:
    def test_add_finding(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                scan_id = db.create_scan("http://example.com")
                db.add_finding(scan_id, "sqli", "high", "SQL Injection", "Found sqli in param")
                findings = db.get_findings(scan_id)
                assert len(findings) == 1
                assert findings[0]["module"] == "sqli"
                assert findings[0]["severity"] == "high"
                assert findings[0]["title"] == "SQL Injection"
        finally:
            os.unlink(db_path)

    def test_add_finding_with_evidence(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                scan_id = db.create_scan("http://example.com")
                db.add_finding(scan_id, "xss", "medium", "XSS", "Reflected XSS", evidence="<script>alert(1)</script>")
                findings = db.get_findings(scan_id)
                assert findings[0]["evidence"] == "<script>alert(1)</script>"
        finally:
            os.unlink(db_path)

    def test_get_findings_by_severity(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                scan_id = db.create_scan("http://example.com")
                db.add_finding(scan_id, "sqli", "high", "SQLi High", "detail")
                db.add_finding(scan_id, "xss", "low", "XSS Low", "detail")
                high_findings = db.get_findings(scan_id, severity="high")
                assert len(high_findings) == 1
                assert high_findings[0]["severity"] == "high"
        finally:
            os.unlink(db_path)

    def test_multiple_findings(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                scan_id = db.create_scan("http://example.com")
                for i in range(5):
                    db.add_finding(scan_id, "test", "info", f"Finding {i}", f"Detail {i}")
                findings = db.get_findings(scan_id)
                assert len(findings) == 5
        finally:
            os.unlink(db_path)


class TestAddTechnology:
    def test_add_technology(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                scan_id = db.create_scan("http://example.com")
                db.add_technology(scan_id, "nginx", "1.18.0", "Web server")
                cursor = db.conn.execute("SELECT * FROM technologies WHERE scan_id=?", (scan_id,))
                rows = cursor.fetchall()
                assert len(rows) == 1
                assert dict(rows[0])["name"] == "nginx"
                assert dict(rows[0])["version"] == "1.18.0"
        finally:
            os.unlink(db_path)


class TestCompareScans:
    def test_compare_scans_new_findings(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                scan1 = db.create_scan("http://a.com")
                scan2 = db.create_scan("http://a.com")
                db.add_finding(scan1, "sqli", "high", "Old Finding", "detail")
                db.add_finding(scan2, "sqli", "high", "Old Finding", "detail")
                db.add_finding(scan2, "xss", "medium", "New Finding", "detail")
                result = db.compare_scans(scan1, scan2)
                assert len(result["new"]) == 1
                assert result["new"][0]["title"] == "New Finding"
        finally:
            os.unlink(db_path)

    def test_compare_scans_removed_findings(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                scan1 = db.create_scan("http://a.com")
                scan2 = db.create_scan("http://a.com")
                db.add_finding(scan1, "sqli", "high", "Removed Finding", "detail")
                db.add_finding(scan2, "xss", "medium", "New Finding", "detail")
                result = db.compare_scans(scan1, scan2)
                assert len(result["removed"]) == 1
                assert result["removed"][0]["title"] == "Removed Finding"
        finally:
            os.unlink(db_path)

    def test_compare_scans_changed_severity(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                scan1 = db.create_scan("http://a.com")
                scan2 = db.create_scan("http://a.com")
                db.add_finding(scan1, "sqli", "low", "Same Finding", "detail")
                db.add_finding(scan2, "sqli", "high", "Same Finding", "detail")
                result = db.compare_scans(scan1, scan2)
                assert len(result["changed"]) == 1
                assert result["changed"][0]["old_severity"] == "low"
                assert result["changed"][0]["new_severity"] == "high"
        finally:
            os.unlink(db_path)

    def test_compare_identical_scans(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                scan1 = db.create_scan("http://a.com")
                scan2 = db.create_scan("http://a.com")
                db.add_finding(scan1, "sqli", "high", "Finding", "detail")
                db.add_finding(scan2, "sqli", "high", "Finding", "detail")
                result = db.compare_scans(scan1, scan2)
                assert len(result["new"]) == 0
                assert len(result["removed"]) == 0
                assert len(result["changed"]) == 0
        finally:
            os.unlink(db_path)


class TestCacheResult:
    def test_cache_and_retrieve(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                data = {"status": 200, "headers": {"Server": "nginx"}}
                db.cache_result("nmap", "http://example.com", "hash123", data)
                cached = db.get_cached_result("nmap", "http://example.com", "hash123")
                assert cached == data
        finally:
            os.unlink(db_path)

    def test_cache_miss_returns_none(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                cached = db.get_cached_result("nmap", "http://example.com", "nonexistent")
                assert cached is None
        finally:
            os.unlink(db_path)

    def test_cache_overwrite(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                db.cache_result("nmap", "http://example.com", "hash1", {"v": 1})
                db.cache_result("nmap", "http://example.com", "hash1", {"v": 2})
                cached = db.get_cached_result("nmap", "http://example.com", "hash1")
                assert cached["v"] == 2
        finally:
            os.unlink(db_path)

    def test_cache_string_data(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                db.cache_result("test", "target", "hash", "raw string data")
                cached = db.get_cached_result("test", "target", "hash")
                assert cached == "raw string data"
        finally:
            os.unlink(db_path)

    def test_different_tools_same_target(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            with Database(db_path) as db:
                db.cache_result("tool1", "http://example.com", "h1", {"a": 1})
                db.cache_result("tool2", "http://example.com", "h1", {"b": 2})
                c1 = db.get_cached_result("tool1", "http://example.com", "h1")
                c2 = db.get_cached_result("tool2", "http://example.com", "h1")
                assert c1 == {"a": 1}
                assert c2 == {"b": 2}
        finally:
            os.unlink(db_path)
