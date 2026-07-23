from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.cron import CronParser

_CMD = "May 19 10:15:01 web01 CROND[12345]: (root) CMD (run-parts /etc/cron.hourly)"
_BAD = "May 19 10:20:01 web01 crond[1234]: (CRON) bad minute (/etc/crontab)"
_ERR = "May 19 10:30:01 web01 crond[1234]: cannot stat /etc/cron.d/legacy: No such file or directory"


@pytest.fixture
def parser():
    return CronParser()


def test_cmd_extracts_fields(parser):
    event = parser.parse_line(_CMD, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.source == "cron"
    assert event.extra["user"] == "root"
    assert event.extra["action"] == "CMD"
    assert event.extra["command"] == "run-parts /etc/cron.hourly"


def test_bad_minute_is_warning(parser):
    event = parser.parse_line(_BAD, 1)
    assert event is not None
    assert event.severity == Severity.WARNING


def test_cannot_stat_is_error(parser):
    event = parser.parse_line(_ERR, 1)
    assert event is not None
    assert event.severity == Severity.ERROR


def test_can_parse_by_path():
    assert CronParser.can_parse(Path("/var/log/cron"), [])


def test_can_parse_by_content():
    assert CronParser.can_parse(None, [_CMD])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
