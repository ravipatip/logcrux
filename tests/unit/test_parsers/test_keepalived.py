from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.keepalived import KeepalivedParser

_START = "Jun 20 10:23:45 lb1 Keepalived[1230]: Starting Keepalived v2.2.4"
_MASTER = "Jun 20 10:23:47 lb1 Keepalived_vrrp[1234]: VRRP_Instance(VI_1) Entering MASTER STATE"
_CHECK = "Jun 20 10:23:48 lb1 Keepalived_healthcheckers[1235]: Check failed for [10.0.0.5]:80"
_FAULT = "Jun 20 10:23:49 lb1 Keepalived_vrrp[1234]: VRRP_Instance(VI_1) Entering FAULT STATE"


@pytest.fixture
def parser():
    return KeepalivedParser()


def test_startup_info(parser):
    assert parser.parse_line(_START, 1).severity == Severity.INFO


def test_master_transition_is_warning(parser):
    e = parser.parse_line(_MASTER, 1)
    assert e.severity == Severity.WARNING
    assert e.extra["vrrp_instance"] == "VI_1"


def test_check_failed_is_error(parser):
    assert parser.parse_line(_CHECK, 1).severity == Severity.ERROR


def test_fault_state_is_error(parser):
    assert parser.parse_line(_FAULT, 1).severity == Severity.ERROR


def test_can_parse_by_path():
    assert KeepalivedParser.can_parse(Path("/var/log/keepalived.log"), [])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
