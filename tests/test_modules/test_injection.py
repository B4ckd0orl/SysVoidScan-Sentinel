import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.config import Config
from lib.payloads import Payloads


class TestSqlPayloadsExist:
    def test_config_has_sql_payloads(self):
        assert hasattr(Config, "SQL_PAYLOADS")
        assert isinstance(Config.SQL_PAYLOADS, list)
        assert len(Config.SQL_PAYLOADS) > 0

    def test_payloads_class_has_sql_payloads(self):
        p = Payloads()
        assert len(p.SQL_PAYLOADS) > 0

    def test_sql_payloads_contain_union(self):
        union_payloads = [p for p in Config.SQL_PAYLOADS if "UNION" in p.upper()]
        assert len(union_payloads) > 0

    def test_sql_payloads_contain_comment(self):
        comment_payloads = [p for p in Config.SQL_PAYLOADS if "--" in p or "#" in p]
        assert len(comment_payloads) > 0

    def test_sql_payloads_contain_sleep(self):
        sleep_payloads = [p for p in Config.SQL_PAYLOADS if "SLEEP" in p.upper() or "WAITFOR" in p.upper()]
        assert len(sleep_payloads) > 0

    def test_sql_payloads_contain_or_1_eq_1(self):
        classic = [p for p in Config.SQL_PAYLOADS if "'1'='1" in p or "OR 1=1" in p]
        assert len(classic) > 0


class TestXssPayloadsExist:
    def test_config_has_xss_payloads(self):
        assert hasattr(Config, "XSS_PAYLOADS")
        assert isinstance(Config.XSS_PAYLOADS, list)
        assert len(Config.XSS_PAYLOADS) > 0

    def test_payloads_class_has_xss_payloads(self):
        p = Payloads()
        assert len(p.XSS_PAYLOADS) > 0

    def test_xss_payloads_contain_script_tag(self):
        script_payloads = [p for p in Config.XSS_PAYLOADS if "<script" in p.lower()]
        assert len(script_payloads) > 0

    def test_xss_payloads_contain_alert(self):
        alert_payloads = [p for p in Config.XSS_PAYLOADS if "alert" in p.lower()]
        assert len(alert_payloads) > 0

    def test_xss_payloads_contain_event_handlers(self):
        event_payloads = [p for p in Config.XSS_PAYLOADS if "onerror" in p.lower() or "onload" in p.lower() or "onfocus" in p.lower()]
        assert len(event_payloads) > 0

    def test_xss_payloads_contain_javascript_uri(self):
        js_payloads = [p for p in Config.XSS_PAYLOADS if "javascript:" in p.lower()]
        assert len(js_payloads) > 0


class TestPathTraversalPayloadsExist:
    def test_config_has_path_traversal(self):
        assert hasattr(Config, "PATH_TRAVERSAL")
        assert isinstance(Config.PATH_TRAVERSAL, list)
        assert len(Config.PATH_TRAVERSAL) > 0

    def test_payloads_class_has_path_traversal(self):
        p = Payloads()
        assert len(p.PATH_TRAVERSAL) > 0

    def test_payloads_target_etc_passwd(self):
        etc_payloads = [p for p in Config.PATH_TRAVERSAL if "etc/passwd" in p.lower()]
        assert len(etc_payloads) > 0

    def test_payloads_target_windows(self):
        win_payloads = [p for p in Config.PATH_TRAVERSAL if "windows" in p.lower() or "win.ini" in p.lower() or "boot.ini" in p.lower()]
        assert len(win_payloads) > 0

    def test_payloads_contain_dot_dot_slash(self):
        traversal = [p for p in Config.PATH_TRAVERSAL if ".." in p]
        assert len(traversal) > 0

    def test_payloads_contain_encoded_variants(self):
        encoded = [p for p in Config.PATH_TRAVERSAL if "%2f" in p.lower() or "%2e" in p.lower() or "%5c" in p.lower()]
        assert len(encoded) > 0

    def test_payloads_contain_null_byte(self):
        null_payloads = [p for p in Config.PATH_TRAVERSAL if "%00" in p]
        assert len(null_payloads) > 0

    def test_command_inject_payloads_exist(self):
        assert len(Config.COMMAND_INJECT) > 0
        pipe_payloads = [p for p in Config.COMMAND_INJECT if "|" in p or ";" in p or "$(" in p or "`" in p]
        assert len(pipe_payloads) > 0
