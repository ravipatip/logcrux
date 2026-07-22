import pytest

from logcrux.models import Severity
from logcrux.parsers.apache_access import ApacheAccessParser


@pytest.fixture
def parser():
    return ApacheAccessParser()


VALID_LINE = (
    '10.0.1.50 - - [16/Jun/2026:03:41:00 +0000] "GET /index.html HTTP/1.1" '
    '200 1234 "-" "Mozilla/5.0"'
)
ERROR_LINE = (
    '10.0.1.52 - - [16/Jun/2026:03:41:02 +0000] "GET /api/data HTTP/1.1" '
    '503 0 "-" "python-requests/2.31"'
)


def test_parse_200_is_info(parser):
    event = parser.parse_line(VALID_LINE, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.extra["status_code"] == 200
    assert event.extra["method"] == "GET"
    assert event.extra["path"] == "/index.html"
    assert event.extra["client_ip"] == "10.0.1.50"


def test_parse_503_is_error(parser):
    event = parser.parse_line(ERROR_LINE, 2)
    assert event is not None
    assert event.severity == Severity.ERROR
    assert event.extra["status_code"] == 503


def test_parse_malformed_returns_none(parser):
    assert parser.parse_line("not an access log line", 1) is None


def test_stream_parses_fixture(parser, apache_access_path):
    with open(apache_access_path, errors="replace") as f:
        events = list(parser.parse_stream(f))
    assert len(events) == 8
    errors = [e for e in events if e.severity in (Severity.ERROR, Severity.WARNING)]
    assert len(errors) >= 4
