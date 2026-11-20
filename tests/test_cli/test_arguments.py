from cli.arguments import parse_arguments


def test_parse_arguments_includes_no_autotests_flag():
    args = parse_arguments(["--no-autotests", "-u", "https://example.com"])
    assert args.no_autotests is True
    assert args.url == ["https://example.com"]


def test_parse_arguments_default_is_autotests_enabled():
    args = parse_arguments(["-u", "https://example.com"])
    assert args.no_autotests is False
    assert args.interactive is False
    assert "html" in args.format


def test_parse_arguments_includes_smoke_tests_flag():
    args = parse_arguments(["--smoke-tests", "-u", "https://example.com"])
    assert args.smoke_tests is True
    assert args.url == ["https://example.com"]
