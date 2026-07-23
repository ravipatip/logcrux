from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.dhcpd import DhcpdParser

_ACK = "May 19 10:15:01 gw01 dhcpd[1234]: DHCPACK on 10.0.0.50 to 00:0c:29:aa:bb:cc via eth0"
_NAK = "May 19 10:15:05 gw01 dhcpd[1234]: DHCPNAK on 10.0.0.99 to 00:0c:29:dd:ee:ff via eth0"
_NOFREE = "May 19 10:15:10 gw01 dhcpd[1234]: no free leases on subnet 10.0.0.0/24"


@pytest.fixture
def parser():
    return DhcpdParser()


def test_ack_is_info(parser):
    event = parser.parse_line(_ACK, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.source == "dhcpd"
    assert event.extra["msg_type"] == "DHCPACK"
    assert event.extra["mac"] == "00:0c:29:aa:bb:cc"


def test_nak_is_warning(parser):
    event = parser.parse_line(_NAK, 1)
    assert event is not None
    assert event.severity == Severity.WARNING


def test_no_free_leases_is_error(parser):
    event = parser.parse_line(_NOFREE, 1)
    assert event is not None
    assert event.severity == Severity.ERROR


def test_can_parse_by_path():
    assert DhcpdParser.can_parse(Path("/var/log/dhcpd.log"), [])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
