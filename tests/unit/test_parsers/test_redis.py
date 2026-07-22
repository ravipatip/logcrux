from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.redis import RedisParser


@pytest.fixture
def parser():
    return RedisParser()


_NOTICE = "1:M 19 Jun 2026 10:00:02.456 * Ready to accept connections tcp"
_WARNING = "1:M 19 Jun 2026 10:01:00.567 # WARNING overcommit_memory is set to 0! Background save may fail under low memory condition."
_OOM_ERROR = "1:M 19 Jun 2026 10:07:00.012 # Can't save in background: fork: Cannot allocate memory"
_REPLICA = "1:S 19 Jun 2026 10:06:00.901 * REPLICAOF 10.0.1.10:6379 enabled"
_OLD_FORMAT = "[4018] 14 Nov 07:01:22.119 * Background saving terminated with success"


def test_parse_notice_is_info(parser):
    event = parser.parse_line(_NOTICE, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.source == "redis"
    assert event.extra["role"] == "master"
    assert event.extra["symbol"] == "*"


def test_parse_warning_symbol(parser):
    event = parser.parse_line(_WARNING, 1)
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.extra["symbol"] == "#"


def test_parse_oom_error(parser):
    event = parser.parse_line(_OOM_ERROR, 1)
    assert event is not None
    assert event.severity == Severity.ERROR


def test_parse_replica_role(parser):
    event = parser.parse_line(_REPLICA, 1)
    assert event is not None
    assert event.extra["role"] == "replica"


def test_parse_old_format(parser):
    event = parser.parse_line(_OLD_FORMAT, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.extra["symbol"] == "*"
    assert "role" not in event.extra


def test_parse_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None


def test_can_parse_by_path():
    assert RedisParser.can_parse(Path("/var/log/redis/redis-server.log"), [])


def test_can_parse_by_content():
    assert RedisParser.can_parse(None, [_NOTICE])


def test_fixture(parser):
    fixture = Path("tests/fixtures/redis.log")
    with open(fixture) as f:
        events = list(parser.parse_stream(f))
    assert len(events) >= 8
    warnings = [e for e in events if e.severity in (Severity.WARNING, Severity.ERROR)]
    assert len(warnings) >= 3
