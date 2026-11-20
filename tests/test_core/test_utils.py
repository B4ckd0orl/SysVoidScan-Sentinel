import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.utils import (
    normalize_url,
    safe_filename_from_url,
    _append_finding_once,
    _format_external_command,
    _strip_ansi,
    print_table,
)
import core.utils as utils_module


class TestNormalizeUrl:
    def test_adds_http_scheme(self):
        assert normalize_url("example.com") == "http://example.com"

    def test_preserves_http_scheme(self):
        assert normalize_url("http://example.com") == "http://example.com"

    def test_preserves_https_scheme(self):
        assert normalize_url("https://example.com") == "https://example.com"

    def test_root_slash_preserved(self):
        assert normalize_url("http://example.com/") == "http://example.com/"

    def test_non_root_trailing_slash_stripped(self):
        assert normalize_url("http://example.com/foo/") == "http://example.com/foo"

    def test_preserves_path(self):
        assert normalize_url("http://example.com/foo/bar") == "http://example.com/foo/bar"

    def test_strips_trailing_slash_from_path(self):
        assert normalize_url("http://example.com/foo/bar/") == "http://example.com/foo/bar"

    def test_preserves_query_string(self):
        assert normalize_url("http://example.com?q=1") == "http://example.com?q=1"

    def test_preserves_fragment(self):
        assert normalize_url("http://example.com#section") == "http://example.com#section"

    def test_strips_whitespace(self):
        assert normalize_url("  http://example.com  ") == "http://example.com"

    def test_empty_string(self):
        assert normalize_url("") == ""

    def test_none_returns_none(self):
        assert normalize_url(None) is None

    def test_complex_url(self):
        result = normalize_url("https://example.com/path/to/page?foo=bar&baz=qux#top")
        assert result == "https://example.com/path/to/page?foo=bar&baz=qux#top"


class TestSafeFilenameFromUrl:
    def test_simple_domain(self):
        result = safe_filename_from_url("http://example.com")
        assert result == "example_com"

    def test_with_port(self):
        result = safe_filename_from_url("http://example.com:8080")
        assert "example_com" in result

    def test_with_path(self):
        result = safe_filename_from_url("http://example.com/foo/bar")
        assert "example_com" in result
        assert "foo" in result
        assert "bar" in result

    def test_replaces_dots(self):
        result = safe_filename_from_url("http://sub.domain.example.com")
        assert "." not in result

    def test_replaces_slashes_in_path(self):
        result = safe_filename_from_url("http://example.com/a/b/c")
        assert "/" not in result

    def test_truncates_long_names(self):
        long_url = "http://" + "a" * 200 + ".com"
        result = safe_filename_from_url(long_url)
        assert len(result) <= 100

    def test_strips_special_chars(self):
        result = safe_filename_from_url('http://example.com/<test>')
        assert "<" not in result
        assert ">" not in result

    def test_root_url(self):
        result = safe_filename_from_url("http://example.com/")
        assert result == "example_com"


class TestAppendFindingOnceDedup:
    def setup_method(self):
        utils_module._FINDINGS_SET.clear()

    def test_first_append_returns_true(self):
        result = _append_finding_once("test finding 1")
        assert result is True

    def test_duplicate_returns_false(self):
        _append_finding_once("test finding 2")
        result = _append_finding_once("test finding 2")
        assert result is False

    def test_case_insensitive_dedup(self):
        _append_finding_once("Case Insensitive Test")
        result = _append_finding_once("case insensitive test")
        assert result is False

    def test_whitespace_normalization(self):
        _append_finding_once("  spaced finding  ")
        result = _append_finding_once("spaced finding")
        assert result is False

    def test_different_findings_allowed(self):
        _append_finding_once("finding A")
        result = _append_finding_once("finding B")
        assert result is True


class TestFormatExternalCommandMasksSecrets:
    def test_masks_password(self):
        cmd = ["tool", "--password", "supersecret123"]
        result = _format_external_command(cmd)
        assert "supersecret123" not in result
        assert "***" in result

    def test_masks_token_flag(self):
        cmd = ["tool", "--session_token", "abc123def456ghij"]
        result = _format_external_command(cmd)
        assert "--session_token" not in result
        assert "***" in result

    def test_masks_secret(self):
        cmd = ["tool", "secret_key", "mysecretvalue"]
        result = _format_external_command(cmd)
        assert "mysecretvalue" not in result

    def test_preserves_non_sensitive(self):
        cmd = ["nmap", "-sV", "example.com"]
        result = _format_external_command(cmd)
        assert "nmap" in result
        assert "-sV" in result
        assert "example.com" in result

    def test_short_values_not_masked(self):
        cmd = ["tool", "--key", "abc"]
        result = _format_external_command(cmd)
        assert "abc" in result

    def test_masks_auth(self):
        cmd = ["tool", "--authorization", "bearer xyztoken12345"]
        result = _format_external_command(cmd)
        assert "xyztoken12345" not in result


class TestStripAnsi:
    def test_strips_color_codes(self):
        text = "\x1b[31mRed Text\x1b[0m"
        result = _strip_ansi(text)
        assert result == "Red Text"

    def test_strips_bold_code(self):
        text = "\x1b[1mBold\x1b[0m"
        result = _strip_ansi(text)
        assert result == "Bold"

    def test_plain_text_unchanged(self):
        text = "No color codes here"
        result = _strip_ansi(text)
        assert result == text

    def test_empty_string(self):
        assert _strip_ansi("") == ""

    def test_multiple_sequences(self):
        text = "\x1b[32mGreen\x1b[0m and \x1b[34mBlue\x1b[0m"
        result = _strip_ansi(text)
        assert result == "Green and Blue"

    def test_strips_complex_sequence(self):
        text = "\x1b[38;5;196mBright red\x1b[0m"
        result = _strip_ansi(text)
        assert result == "Bright red"


class TestPrintTable:
    def test_prints_with_data(self, capsys):
        headers = ["Name", "Value"]
        rows = [["foo", "1"], ["bar", "2"]]
        print_table(headers, rows)
        captured = capsys.readouterr()
        assert "foo" in captured.out
        assert "bar" in captured.out

    def test_prints_no_data_message(self, capsys):
        print_table(["Col1"], [])
        captured = capsys.readouterr()
        assert "No data" in captured.out

    def test_prints_with_title(self, capsys):
        print_table(["A"], [["1"]], title="My Table")
        captured = capsys.readouterr()
        assert "My Table" in captured.out

    def test_prints_with_footer(self, capsys):
        print_table(["A"], [["1"]], footer="Total: 1")
        captured = capsys.readouterr()
        assert "Total: 1" in captured.out

    def test_alignment_right(self, capsys):
        print_table(["A"], [["1"]], alignments=[">"])
        captured = capsys.readouterr()
        assert "1" in captured.out

    def test_alignment_center(self, capsys):
        print_table(["A"], [["1"]], alignments=["^"])
        captured = capsys.readouterr()
        assert "1" in captured.out
