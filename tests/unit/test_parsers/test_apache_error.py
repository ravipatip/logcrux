import pytest

from logcrux.models import Severity
from logcrux.parsers.apache_error import ApacheErrorParser


@pytest.fixture
def parser():
    return ApacheErrorParser()


@pytest.mark.parametrize("line,expected_severity", [
    (
        "[Mon Jun 16 03:41:00.123456 2026] [error] [pid 1234] "
        "[client 10.0.1.52:43210] File does not exist: /var/www/html/favicon.ico",
        Severity.ERROR,
    ),
    (
        "[Mon Jun 16 03:42:00.345678 2026] [crit] [pid 1236] "
        "[client 10.0.1.54:43212] SSL handshake failed",
        Severity.CRITICAL,
    ),
    (
        "[Mon Jun 16 03:42:01.456789 2026] [warn] [pid 1237] "
        "mod_fcgid: read data timeout in 45 seconds",
        Severity.WARNING,
    ),
])
def test_parse_severity_mapping(parser, line, expected_severity):
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.severity == expected_severity


def test_extracts_client_ip(parser):
    line = (
        "[Mon Jun 16 03:41:00.123456 2026] [error] [pid 1234] "
        "[client 10.0.1.52:43210] File does not exist"
    )
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.extra.get("client_ip") == "10.0.1.52"


def test_malformed_returns_none(parser):
    assert parser.parse_line("random garbage", 1) is None


def test_stream_fixture(parser, fixtures_dir):
    with open(fixtures_dir / "apache_error.log", errors="replace") as f:
        events = list(parser.parse_stream(f))
    assert len(events) == 5


@pytest.mark.parametrize("level_token,expected_severity", [
    ("core:error", Severity.ERROR),
    ("ssl:warn", Severity.WARNING),
    ("proxy_fcgi:error", Severity.ERROR),
    ("mpm_event:notice", Severity.INFO),
    ("core:crit", Severity.CRITICAL),
])
def test_apache24_module_prefixed_levels(parser, level_token, expected_severity):
    line = (
        f"[Mon Jun 16 03:41:00.123456 2026] [{level_token}] [pid 1234] "
        "mod_proxy: SSL backend handshake failed"
    )
    event = parser.parse_line(line, 1)
    assert event is not None, f"parse_line returned None for level '{level_token}'"
    assert event.severity == expected_severity, (
        f"level '{level_token}' → {event.severity}, expected {expected_severity}"
    )


@pytest.mark.parametrize("trace_n", range(1, 9))
def test_trace_levels_are_debug(parser, trace_n):
    line = (
        f"[Mon Jun 16 03:41:00.000000 2026] [trace{trace_n}] [pid 99] "
        "backtrace line here"
    )
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.severity == Severity.DEBUG
