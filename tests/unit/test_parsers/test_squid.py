from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.squid import SquidParser


@pytest.fixture
def parser():
    return SquidParser()


def test_parse_native_tcp_miss(parser):
    line = "1750000000.000   82 10.0.1.1 TCP_MISS/200 1234 GET http://example.com/ - DIRECT/1.2.3.4 text/html"
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.extra["result_code"] == "TCP_MISS"
    assert event.extra["status_code"] == 200
    assert event.extra["method"] == "GET"
    assert event.extra["parser"] == "squid"
    assert event.timestamp is not None


def test_parse_native_tcp_denied_is_warning(parser):
    line = "1750000000.000   10 10.0.1.2 TCP_DENIED/403 0 GET http://blocked.com/ - NONE/- text/html"
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.extra["result_code"] == "TCP_DENIED"


def test_parse_native_status_5xx_is_error(parser):
    line = "1750000000.000   10 10.0.1.2 TCP_MISS/503 0 GET http://example.com/ - DIRECT/1.2.3.4 text/html"
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.severity == Severity.ERROR


def test_parse_native_status_407_is_warning(parser):
    line = "1750000000.000    5 10.0.1.4 NONE/407 1234 GET http://example.com/ - NONE/- text/html"
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.extra["status_code"] == 407


def test_parse_native_connect_extracts_port(parser):
    line = "1750000000.000 5000 10.0.1.3 TCP_TUNNEL/200 0 CONNECT badserver.com:22 - DIRECT/1.2.3.4 -"
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.extra["method"] == "CONNECT"
    assert event.extra["connect_port"] == 22


def test_parse_native_connect_port_443_not_flagged(parser):
    line = "1750000000.000  100 10.0.1.3 TCP_TUNNEL/200 0 CONNECT secure.example.com:443 - DIRECT/1.2.3.4 -"
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.extra["connect_port"] == 443


def test_parse_clf_line(parser):
    line = '10.0.1.10 - - [16/Jun/2026:10:00:00 +0000] "GET http://example.com/ HTTP/1.1" 200 1234'
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.extra["status_code"] == 200
    assert event.extra["parser"] == "squid"
    assert event.extra["result_code"] is None
    assert event.severity == Severity.INFO


def test_parse_clf_404_is_warning(parser):
    line = '10.0.1.10 - - [16/Jun/2026:10:00:00 +0000] "GET http://example.com/missing HTTP/1.1" 404 512'
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.severity == Severity.WARNING


def test_parse_clf_connect_extracts_port(parser):
    # CLF CONNECT tunnels must populate connect_port so tunnel-anomaly
    # detection works on proxy access logs, not just native-format logs.
    line = '10.0.1.10 - - [16/Jun/2026:10:00:00 +0000] "CONNECT badhost.com:4444 HTTP/1.1" 200 0'
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.extra["method"] == "CONNECT"
    assert event.extra["connect_port"] == 4444


def test_can_parse_clf_proxy_content():
    line = '10.0.1.10 - - [16/Jun/2026:10:00:00 +0000] "GET http://example.com/ HTTP/1.1" 200 1234'
    assert SquidParser.can_parse(None, [line])


def test_can_parse_by_squid_path():
    assert SquidParser.can_parse(Path("/var/log/squid/access.log"), [])


def test_can_parse_by_proxy_path():
    assert SquidParser.can_parse(Path("/var/log/proxy/access.log"), [])


def test_can_parse_by_native_content():
    sample = ["1750000000.000   82 10.0.1.1 TCP_MISS/200 1234 GET http://example.com/ - DIRECT/1.2.3.4 text/html"]
    assert SquidParser.can_parse(None, sample)


def test_cannot_parse_syslog_content():
    sample = ["Jun 16 03:41:00 prod-web01 sshd[2001]: Failed password for root"]
    assert not SquidParser.can_parse(None, sample)


def test_parse_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None


def test_stream_skips_malformed(parser):
    lines = [
        "1750000000.000   82 10.0.1.1 TCP_MISS/200 1234 GET http://example.com/ - DIRECT/1.2.3.4 text/html\n",
        "this is garbage that should be skipped\n",
        "1750000001.000   50 10.0.1.2 TCP_HIT/200 500 GET http://example.com/js - DIRECT/1.2.3.4 application/javascript\n",
    ]
    events = list(parser.parse_stream(iter(lines)))
    assert len(events) == 2


def test_stream_parses_native_fixture(parser):
    fixture = Path("tests/fixtures/squid_native.log")
    with open(fixture) as f:
        events = list(parser.parse_stream(f))
    assert len(events) == 19
    denied = [e for e in events if e.extra.get("result_code") == "TCP_DENIED"]
    assert len(denied) == 12
