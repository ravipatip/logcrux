from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.postgresql import PostgreSQLParser


@pytest.fixture
def parser():
    return PostgreSQLParser()


_LOG_LINE = "2026-06-19 10:00:01.123 UTC [1234] LOG:  database system is ready to accept connections"
_ERROR_LINE = "2026-06-19 10:00:03.345 UTC [1236] appuser@myapp ERROR:  syntax error at or near \"SELCT\" at character 1"
_FATAL_LINE = "2026-06-19 10:00:04.456 UTC [1237] root@postgres FATAL:  password authentication failed for user \"hacker\""
_PANIC_LINE = "2026-06-19 10:00:08.890 UTC [1241] appuser@myapp PANIC:  could not write to file \"pg_wal/000000\": No space left on device"
_WARN_LINE = "2026-06-19 10:00:05.567 UTC [1238] appuser@myapp WARNING:  there is no unique constraint matching given keys"


def test_parse_log_info(parser):
    event = parser.parse_line(_LOG_LINE, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.source == "postgresql"
    assert "ready to accept connections" in event.message


def test_parse_error(parser):
    event = parser.parse_line(_ERROR_LINE, 1)
    assert event is not None
    assert event.severity == Severity.ERROR
    assert event.extra["user"] == "appuser"
    assert event.extra["db"] == "myapp"


def test_parse_fatal_is_critical(parser):
    event = parser.parse_line(_FATAL_LINE, 1)
    assert event is not None
    assert event.severity == Severity.CRITICAL


def test_parse_panic_is_critical(parser):
    event = parser.parse_line(_PANIC_LINE, 1)
    assert event is not None
    assert event.severity == Severity.CRITICAL


def test_parse_warning(parser):
    event = parser.parse_line(_WARN_LINE, 1)
    assert event is not None
    assert event.severity == Severity.WARNING


def test_parse_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None


def test_can_parse_by_path():
    assert PostgreSQLParser.can_parse(Path("/var/log/postgresql/postgresql-14-main.log"), [])


def test_can_parse_by_content():
    assert PostgreSQLParser.can_parse(None, [_LOG_LINE])


def test_fixture(parser):
    fixture = Path("tests/fixtures/postgresql.log")
    with open(fixture) as f:
        events = list(parser.parse_stream(f))
    assert len(events) >= 6
    criticals = [e for e in events if e.severity == Severity.CRITICAL]
    assert len(criticals) >= 2
