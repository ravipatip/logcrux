from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.networkmanager import NetworkManagerParser

_INFO = "Jun 20 10:23:45 h NetworkManager[789]: <info>  [1623.4] device (eth0): state change: config -> ip-config (reason 'none')"
_WARN = "Jun 20 10:23:47 h NetworkManager[789]: <warn>  [1623.7] dhcp4 (eth0): request timed out"
_ERR = "Jun 20 10:23:48 h NetworkManager[789]: <error> [1623.9] device (eth0): Activation: failed for connection 'Wired'"


@pytest.fixture
def parser():
    return NetworkManagerParser()


def test_info_level(parser):
    e = parser.parse_line(_INFO, 1)
    assert e.severity == Severity.INFO
    # marker + timer prefix stripped from message body
    assert e.message.startswith("device (eth0): state change")


def test_warn_level(parser):
    e = parser.parse_line(_WARN, 1)
    assert e.severity == Severity.WARNING


def test_error_activation_failure(parser):
    e = parser.parse_line(_ERR, 1)
    assert e.severity == Severity.ERROR


def test_can_parse_by_path():
    assert NetworkManagerParser.can_parse(Path("/var/log/NetworkManager.log"), [])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
