from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.cups import CupsParser

_INFO = "I [20/Jun/2026:10:23:45 +0000] Listening to 127.0.0.1:631 (IPv4)"
_WARN = "W [20/Jun/2026:10:23:47 +0000] CreateProfile failed: AlreadyExists"
_ERR = "E [20/Jun/2026:10:23:48 +0000] Unable to open listen socket - Address already in use"
_CRIT = "C [20/Jun/2026:10:23:49 +0000] Scheduler shutting down due to program error"


@pytest.fixture
def parser():
    return CupsParser()


def test_info(parser):
    e = parser.parse_line(_INFO, 1)
    assert e.severity == Severity.INFO
    assert e.timestamp is not None


def test_warning(parser):
    assert parser.parse_line(_WARN, 1).severity == Severity.WARNING


def test_error(parser):
    assert parser.parse_line(_ERR, 1).severity == Severity.ERROR


def test_critical(parser):
    assert parser.parse_line(_CRIT, 1).severity == Severity.CRITICAL


def test_can_parse_by_content(parser):
    assert CupsParser.can_parse(None, [_INFO])


def test_can_parse_by_path():
    assert CupsParser.can_parse(Path("/var/log/cups/error_log"), [])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
