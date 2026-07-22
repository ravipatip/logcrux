import pytest

from logcrux.models import Severity
from logcrux.parsers.nginx_access import NginxAccessParser


@pytest.fixture
def parser():
    return NginxAccessParser()


def test_parse_200(parser):
    line = (
        '10.0.1.50 - - [16/Jun/2026:03:41:00 +0000] "GET /index.html HTTP/1.1" '
        '200 1234 "-" "Mozilla/5.0" 0.002'
    )
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.extra["status_code"] == 200
    assert float(event.extra["request_time"]) == pytest.approx(0.002)


def test_parse_502_is_error(parser):
    line = (
        '10.0.1.52 - - [16/Jun/2026:03:41:02 +0000] "GET /api/data HTTP/1.1" '
        '502 0 "-" "python-requests/2.31" 30.001'
    )
    event = parser.parse_line(line, 2)
    assert event is not None
    assert event.severity == Severity.ERROR


def test_stream_fixture(parser, fixtures_dir):
    with open(fixtures_dir / "nginx_access.log", errors="replace") as f:
        events = list(parser.parse_stream(f))
    assert len(events) == 5
    assert all(e.timestamp is not None for e in events)
    # Fixture has two 502 lines → ERROR, three 200 lines → INFO
    assert sum(1 for e in events if e.severity == Severity.ERROR) == 2
    assert sum(1 for e in events if e.severity == Severity.INFO) == 3
    assert all("status_code" in e.extra for e in events)
