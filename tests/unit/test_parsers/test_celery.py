from __future__ import annotations

import pytest

from logcrux.models import Severity
from logcrux.parsers.celery import CeleryParser

_INFO = "[2026-06-20 10:23:45,123: INFO/MainProcess] Connected to redis://localhost:6379/0"
_WARN = "[2026-06-20 10:23:47,789: WARNING/MainProcess] Substantial drift may mean clocks are out of sync"
_TASK = "[2026-06-20 10:23:48,012: INFO/ForkPoolWorker-2] Task app.tasks.add[abc-123] succeeded in 0.012s: 4"
_ERR = "[2026-06-20 10:23:49,345: ERROR/ForkPoolWorker-3] Task app.tasks.div[def-456] raised unexpected: ZeroDivisionError"
_CRIT = "[2026-06-20 10:23:50,678: CRITICAL/MainProcess] Unrecoverable error: WorkerLostError"


@pytest.fixture
def parser():
    return CeleryParser()


def test_info(parser):
    e = parser.parse_line(_INFO, 1)
    assert e.severity == Severity.INFO
    assert e.extra["process"] == "MainProcess"


def test_warn(parser):
    assert parser.parse_line(_WARN, 1).severity == Severity.WARNING


def test_task_fields(parser):
    e = parser.parse_line(_TASK, 1)
    assert e.extra["task"] == "app.tasks.add"
    assert e.extra["task_id"] == "abc-123"


def test_error(parser):
    assert parser.parse_line(_ERR, 1).severity == Severity.ERROR


def test_critical(parser):
    assert parser.parse_line(_CRIT, 1).severity == Severity.CRITICAL


def test_can_parse_by_content():
    assert CeleryParser.can_parse(None, [_INFO])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
