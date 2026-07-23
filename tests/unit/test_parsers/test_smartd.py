from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.smartd import SmartdParser

_OPENED = "Jun 20 10:23:45 h smartd[1234]: Device: /dev/sda [SAT], opened"
_PENDING = "Jun 20 10:23:47 h smartd[1234]: Device: /dev/sda [SAT], 5 Currently unreadable (pending) sectors"
_FAILED = "Jun 20 10:23:48 h smartd[1234]: Device: /dev/sdb [SAT], FAILED SMART self-check. BACK UP DATA NOW!"


@pytest.fixture
def parser():
    return SmartdParser()


def test_opened_is_info(parser):
    e = parser.parse_line(_OPENED, 1)
    assert e.severity == Severity.INFO
    assert e.extra["device"] == "/dev/sda"


def test_pending_sectors_is_warning(parser):
    assert parser.parse_line(_PENDING, 1).severity == Severity.WARNING


def test_failed_selfcheck_is_error(parser):
    e = parser.parse_line(_FAILED, 1)
    assert e.severity == Severity.ERROR
    assert e.extra["device"] == "/dev/sdb"


def test_can_parse_by_path():
    assert SmartdParser.can_parse(Path("/var/log/smartd.log"), [])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
