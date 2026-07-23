from __future__ import annotations

import pytest

from logcrux.models import Severity
from logcrux.parsers.coredns import CoreDNSParser

_RELOAD = "[INFO] plugin/reload: Running configuration MD5 = abc123"
_QUERY = '[INFO] 10.0.0.5:5353 - 12345 "A IN example.com. udp 30 false 512" NOERROR qr,rd,ra 56 0.001s'
_ERR = "[ERROR] plugin/errors: 2 example.com. A: read udp 10.0.0.2:53->8.8.8.8:53: i/o timeout"
_TS = "2026-06-20T10:23:45.123Z [WARNING] plugin/health: Local health request took more than 1s"


@pytest.fixture
def parser():
    return CoreDNSParser()


def test_reload_info(parser):
    assert parser.parse_line(_RELOAD, 1).severity == Severity.INFO


def test_query_extracts_fields(parser):
    e = parser.parse_line(_QUERY, 1)
    assert e.extra["query_type"] == "A"
    assert e.extra["query_name"] == "example.com."


def test_error(parser):
    assert parser.parse_line(_ERR, 1).severity == Severity.ERROR


def test_timestamped_warning(parser):
    e = parser.parse_line(_TS, 1)
    assert e.severity == Severity.WARNING
    assert e.timestamp is not None


def test_can_parse_by_content():
    assert CoreDNSParser.can_parse(None, [_RELOAD])
    # a bare "[INFO] foo" application line must NOT be claimed
    assert not CoreDNSParser.can_parse(None, ["[INFO] application started"])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
