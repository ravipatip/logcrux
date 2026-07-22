from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.supervisor import SupervisorParser

_SPAWN = "2026-06-20 10:23:46,456 INFO spawned: 'web' with pid 1234"
_WARN = "2026-06-20 10:23:48,012 WARN received SIGTERM indicating exit request"
_FATAL = "2026-06-20 10:23:50,678 INFO gave up: web entered FATAL state, too many start retries too quickly"
_CRIT = "2026-06-20 10:23:51,000 CRIT could not write pidfile /var/run/supervisord.pid"


@pytest.fixture
def parser():
    return SupervisorParser()


def test_spawn_info(parser):
    assert parser.parse_line(_SPAWN, 1).severity == Severity.INFO


def test_warn(parser):
    assert parser.parse_line(_WARN, 1).severity == Severity.WARNING


def test_gave_up_elevated_to_error(parser):
    # an INFO line announcing FATAL/gave up is a crash-loop signal -> error
    assert parser.parse_line(_FATAL, 1).severity == Severity.ERROR


def test_crit(parser):
    assert parser.parse_line(_CRIT, 1).severity == Severity.CRITICAL


def test_can_parse_by_content():
    assert SupervisorParser.can_parse(None, [_SPAWN])
    # a generic "<ts> INFO message" line without supervisor vocab is not claimed
    assert not SupervisorParser.can_parse(None, ["2026-06-20 10:23:46,456 INFO hello world"])


def test_can_parse_by_path():
    assert SupervisorParser.can_parse(Path("/var/log/supervisor/supervisord.log"), [])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
