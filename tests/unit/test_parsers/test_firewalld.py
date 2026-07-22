from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.firewalld import FirewalldParser

_INFO = "Jun 20 10:23:45 h firewalld[1234]: INFO: Reloading firewall rules."
_WARN = "Jun 20 10:23:46 h firewalld[1234]: WARNING: ZONE_ALREADY_SET: public"
_ERR = "Jun 20 10:23:48 h firewalld[1234]: ERROR: COMMAND_FAILED: '/usr/sbin/iptables ...' failed"


@pytest.fixture
def parser():
    return FirewalldParser()


def test_info(parser):
    e = parser.parse_line(_INFO, 1)
    assert e.severity == Severity.INFO
    assert e.message == "Reloading firewall rules."


def test_warning(parser):
    assert parser.parse_line(_WARN, 1).severity == Severity.WARNING


def test_error(parser):
    assert parser.parse_line(_ERR, 1).severity == Severity.ERROR


def test_can_parse_by_path():
    assert FirewalldParser.can_parse(Path("/var/log/firewalld"), [])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
