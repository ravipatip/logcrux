from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.ufw import UFWParser


@pytest.fixture
def parser():
    return UFWParser()


_BLOCK = (
    "Jun 19 10:00:01 server kernel: [12345.678901] [UFW BLOCK] "
    "IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:08:00 "
    "SRC=1.2.3.4 DST=10.0.0.1 LEN=52 TOS=0x00 PREC=0x00 TTL=54 "
    "ID=12345 DF PROTO=TCP SPT=59876 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0"
)
_ALLOW = (
    "Jun 19 10:00:03 server kernel: [12347.234567] [UFW ALLOW] "
    "IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:08:00 "
    "SRC=192.168.1.100 DST=10.0.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 "
    "ID=11111 DF PROTO=TCP SPT=54321 DPT=443 WINDOW=65535 RES=0x00 SYN URGP=0"
)


def test_parse_block(parser):
    event = parser.parse_line(_BLOCK, 1)
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.extra["action"] == "BLOCK"
    assert event.extra["src_ip"] == "1.2.3.4"
    assert event.extra["dst_port"] == "22"
    assert event.extra["proto"] == "TCP"
    assert event.source == "ufw"


def test_parse_allow(parser):
    event = parser.parse_line(_ALLOW, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.extra["action"] == "ALLOW"
    assert event.extra["dst_port"] == "443"


def test_parse_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None


def test_parse_non_ufw_returns_none(parser):
    assert parser.parse_line("Jun 19 10:00:01 host sshd[123]: message", 1) is None


def test_can_parse_by_path():
    assert UFWParser.can_parse(Path("/var/log/ufw.log"), [])


def test_can_parse_by_content():
    assert UFWParser.can_parse(None, [_BLOCK])


def test_fixture(parser):
    fixture = Path("tests/fixtures/ufw.log")
    with open(fixture) as f:
        events = list(parser.parse_stream(f))
    assert len(events) == 5
    blocks = [e for e in events if e.extra.get("action") == "BLOCK"]
    assert len(blocks) == 4
