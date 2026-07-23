import pytest

from logcrux.models import Severity
from logcrux.parsers.nginx_error import NginxErrorParser


@pytest.fixture
def parser():
    return NginxErrorParser()


def test_parse_error_line(parser):
    line = "2026/06/16 03:41:00 [error] 456#456: *101 connect() failed (111: Connection refused)"
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.severity == Severity.ERROR
    assert "connect() failed" in event.message


def test_parse_crit_line(parser):
    line = "2026/06/16 03:42:00 [crit] 456#456: *104 SSL_do_handshake() failed"
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.severity == Severity.CRITICAL


def test_stream_fixture(parser, nginx_error_path):
    with open(nginx_error_path, errors="replace") as f:
        events = list(parser.parse_stream(f))
    assert len(events) == 4
    # Fixture: two [error], one [warn], one [crit]
    severities = [e.severity for e in events]
    assert severities.count(Severity.ERROR) == 2
    assert severities.count(Severity.WARNING) == 1
    assert severities.count(Severity.CRITICAL) == 1
