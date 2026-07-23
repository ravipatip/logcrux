from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.chrony import ChronyParser

_SELECTED = "May 19 10:15:01 host chronyd[1234]: Selected source 192.168.1.1 (pool.ntp.org)"
_UNREACH = "May 19 10:15:10 host chronyd[1234]: Source 10.0.0.5 unreachable"
_NOSERVERS = "May 19 10:15:20 host ntpd[2345]: no servers reachable"


@pytest.fixture
def parser():
    return ChronyParser()


def test_selected_source_is_info(parser):
    event = parser.parse_line(_SELECTED, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.source == "chronyd"
    assert event.extra["source_ip"] == "192.168.1.1"


def test_unreachable_is_warning(parser):
    event = parser.parse_line(_UNREACH, 1)
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.extra["source_ip"] == "10.0.0.5"


def test_no_servers_is_error(parser):
    event = parser.parse_line(_NOSERVERS, 1)
    assert event is not None
    assert event.severity == Severity.ERROR
    assert event.source == "ntpd"


def test_can_parse_by_path():
    assert ChronyParser.can_parse(Path("/var/log/chrony/chrony.log"), [])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
