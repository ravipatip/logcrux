from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.haproxy import HAProxyParser


@pytest.fixture
def parser():
    return HAProxyParser()


_HTTP_LINE = (
    "Jun 19 10:00:01 web01 haproxy[1234]: 10.0.1.5:52341 "
    "[19/Jun/2026:10:00:01.123] http-in backend/srv1 "
    "0/0/1/5/6 200 1234 - - ---- 3/3/0/0/0 0/0 \"GET /api/status HTTP/1.1\""
)
_HTTP_500 = (
    "Jun 19 10:00:03 web01 haproxy[1234]: 10.0.1.7:52343 "
    "[19/Jun/2026:10:00:03.789] http-in backend/srv1 "
    "0/0/1/150/151 500 256 - - ---- 3/3/0/0/0 0/0 \"POST /api/data HTTP/1.1\""
)
_HTTP_404 = (
    "Jun 19 10:00:02 web01 haproxy[1234]: 10.0.1.6:52342 "
    "[19/Jun/2026:10:00:02.456] http-in backend/srv2 "
    "0/0/1/8/9 404 512 - - ---- 3/3/0/0/0 0/0 \"GET /missing HTTP/1.1\""
)
_TCP_LINE = (
    "Jun 19 10:00:05 web01 haproxy[1234]: 10.0.1.9:52345 "
    "[19/Jun/2026:10:00:05.345] tcp-in db-backend/db1 5/10/3000 9876 --"
)


def test_parse_http_200(parser):
    event = parser.parse_line(_HTTP_LINE, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.extra["status_code"] == 200
    assert event.extra["client_ip"] == "10.0.1.5"
    assert event.extra["backend"] == "backend"
    assert event.source == "haproxy"


def test_parse_http_500_is_error(parser):
    event = parser.parse_line(_HTTP_500, 1)
    assert event is not None
    assert event.severity == Severity.ERROR
    assert event.extra["status_code"] == 500


def test_parse_http_404_is_warning(parser):
    event = parser.parse_line(_HTTP_404, 1)
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.extra["status_code"] == 404


def test_parse_tcp_line(parser):
    event = parser.parse_line(_TCP_LINE, 1)
    assert event is not None
    assert event.source == "haproxy"
    assert event.extra["client_ip"] == "10.0.1.9"
    assert event.extra["bytes"] == 9876


def test_parse_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None


def test_can_parse_by_path():
    assert HAProxyParser.can_parse(Path("/var/log/haproxy.log"), [])


def test_can_parse_by_content():
    assert HAProxyParser.can_parse(None, [_HTTP_LINE])


def test_cannot_parse_syslog():
    assert not HAProxyParser.can_parse(None, ["Jun 19 10:00:01 host sshd[123]: message"])


def test_fixture(parser):
    fixture = Path("tests/fixtures/haproxy.log")
    with open(fixture) as f:
        events = list(parser.parse_stream(f))
    assert len(events) >= 3
    errors = [e for e in events if e.severity == Severity.ERROR]
    assert len(errors) >= 1


# --- Admin / state-change lines (the root-cause lines of an outage) ---
_SERVER_DOWN = (
    "Jun 19 10:01:00 web01 haproxy[1234]: Server backend/srv1 is DOWN, reason: "
    "Layer4 connection problem, info: \"Connection refused\", check duration: 0ms. "
    "0 active and 0 backup servers left."
)
_NO_SERVER = "Jun 19 10:01:05 web01 haproxy[1234]: backend backend has no server available!"
_SERVER_UP = (
    "Jun 19 10:05:00 web01 haproxy[1234]: Server backend/srv1 is UP, reason: "
    "Layer4 check passed, check duration: 1ms. 1 active and 0 backup servers online."
)
_PROXY_STARTED = "Jun 19 09:00:00 web01 haproxy[1234]: Proxy http-in started."


def test_parse_server_down_is_error(parser):
    event = parser.parse_line(_SERVER_DOWN, 1)
    assert event is not None
    assert event.severity == Severity.ERROR
    assert event.extra["kind"] == "admin"
    assert "is DOWN" in event.message


def test_parse_no_server_available_is_error(parser):
    event = parser.parse_line(_NO_SERVER, 1)
    assert event is not None
    assert event.severity == Severity.ERROR


def test_parse_server_up_is_info(parser):
    event = parser.parse_line(_SERVER_UP, 1)
    assert event is not None
    assert event.severity == Severity.INFO


def test_parse_proxy_started_is_info(parser):
    event = parser.parse_line(_PROXY_STARTED, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.timestamp is not None
