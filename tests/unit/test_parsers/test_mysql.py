from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.mysql import MySQLParser


@pytest.fixture
def parser():
    return MySQLParser()


_ERROR_LINE = "2026-06-19T10:00:03.345678Z 1 [ERROR] [MY-000067] [Server] unknown variable 'query_cache_size=0'"
_WARN_LINE = "2026-06-19T10:00:02.234567Z 0 [Warning] [MY-010075] [Server] No existing UUID has been found"
_SYSTEM_LINE = "2026-06-19T10:00:01.123456Z 0 [System] [MY-013169] [Server] /usr/sbin/mysqld starting"
_SLOW_USER = "# User@Host: appuser[appuser] @ 10.0.1.5 []"
_SLOW_TIME_SLOW = "# Query_time: 8.456789  Lock_time: 0.001234 Rows_sent: 1  Rows_examined: 5000000"
_SLOW_TIME_FAST = "# Query_time: 3.123456  Lock_time: 0.000123 Rows_sent: 1000  Rows_examined: 2000000"


def test_parse_error_line(parser):
    event = parser.parse_line(_ERROR_LINE, 1)
    assert event is not None
    assert event.severity == Severity.ERROR
    assert event.source == "mysql"
    assert "unknown variable" in event.message


def test_parse_warning_line(parser):
    event = parser.parse_line(_WARN_LINE, 1)
    assert event is not None
    assert event.severity == Severity.WARNING


def test_parse_system_line(parser):
    event = parser.parse_line(_SYSTEM_LINE, 1)
    assert event is not None
    assert event.severity == Severity.INFO


def test_slow_query_emits_error_when_very_slow(parser):
    parser.parse_line(_SLOW_USER, 1)
    event = parser.parse_line(_SLOW_TIME_SLOW, 2)
    assert event is not None
    assert event.severity == Severity.ERROR
    assert event.extra["query_time"] == pytest.approx(8.456789)
    assert event.extra["rows_examined"] == 5000000
    assert "appuser" in event.extra["user"]


def test_slow_query_emits_warning_when_moderate(parser):
    parser.parse_line(_SLOW_USER, 1)
    event = parser.parse_line(_SLOW_TIME_FAST, 2)
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.extra["query_time"] == pytest.approx(3.123456)


def test_set_timestamp_skipped(parser):
    assert parser.parse_line("SET timestamp=1701683100;", 1) is None


def test_can_parse_by_path():
    assert MySQLParser.can_parse(Path("/var/log/mysql/error.log"), [])


def test_can_parse_by_content():
    assert MySQLParser.can_parse(None, [_ERROR_LINE])


def test_fixture_error_log(parser):
    fixture = Path("tests/fixtures/mysql_error.log")
    with open(fixture) as f:
        events = list(parser.parse_stream(f))
    assert len(events) >= 3
    errors = [e for e in events if e.severity == Severity.ERROR]
    assert len(errors) >= 2


def test_fixture_slow_log():
    p = MySQLParser()
    fixture = Path("tests/fixtures/mysql_slow.log")
    with open(fixture) as f:
        events = list(p.parse_stream(f))
    slow_events = [e for e in events if "Slow query" in e.message]
    assert len(slow_events) == 2


def test_slow_log_min_coverage_set():
    # Regression: MySQLParser had no MIN_COVERAGE override, so the slow query
    # log triggered a generic fallback (only 2 events from 10 lines = 20%).
    # The CLI uses parser.MIN_COVERAGE to decide whether to fall back; the
    # mysql parser must declare a low threshold to stay as the active parser.
    assert MySQLParser.MIN_COVERAGE <= 0.25, (
        f"MySQLParser.MIN_COVERAGE={MySQLParser.MIN_COVERAGE} is too high; "
        "slow query logs emit ~1 event per 5 lines and would trigger the "
        "generic fallback at >= 0.6"
    )
