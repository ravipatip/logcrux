from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.strongswan import StrongSwanParser

_ESTABLISHED = "Jun 20 10:23:49 gw charon[1234]: 07[IKE] CHILD_SA net{2} established with SPIs c1/c2"
_RETRANSMIT = "Jun 20 10:23:48 gw charon[1234]: 11[IKE] retransmit 3 of request with message ID 0"
_FAILED = "Jun 20 10:23:47 gw charon[1234]: 09[IKE] establishing IKE_SA failed, peer not responding"


@pytest.fixture
def parser():
    return StrongSwanParser()


def test_established_is_info(parser):
    e = parser.parse_line(_ESTABLISHED, 1)
    assert e.severity == Severity.INFO
    assert e.extra["subsystem"] == "IKE"
    # the "07[IKE]" bookkeeping is stripped from the body
    assert e.message.startswith("CHILD_SA")


def test_retransmit_is_warning(parser):
    assert parser.parse_line(_RETRANSMIT, 1).severity == Severity.WARNING


def test_failed_is_error(parser):
    assert parser.parse_line(_FAILED, 1).severity == Severity.ERROR


def test_can_parse_by_path():
    assert StrongSwanParser.can_parse(Path("/var/log/charon.log"), [])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
