from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.named import NamedParser

_DENIED = "May 19 10:15:02 ns01 named[1234]: client @0x7f1a 1.2.3.4#54321 (evil.com): query (cache) 'evil.com/A/IN' denied"
_SERVFAIL = "May 19 10:15:05 ns01 named[1234]: client 5.6.7.8#1234 (x.com): query failed (SERVFAIL) for x.com/IN/A"
_LOADED = "May 19 10:15:01 ns01 named[1234]: zone example.com/IN: loaded serial 2024051901"
_NATIVE_ERR = "19-May-2024 10:15:05.345 general: error: zone db.broken/IN: loading from master file failed: file not found"
_NATIVE_INFO = "19-May-2024 10:15:01.123 general: info: zone example.com/IN: loaded serial 2024051901"


@pytest.fixture
def parser():
    return NamedParser()


def test_denied_query_is_warning(parser):
    event = parser.parse_line(_DENIED, 1)
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.source == "named"
    assert event.extra["client_ip"] == "1.2.3.4"


def test_servfail_is_error(parser):
    event = parser.parse_line(_SERVFAIL, 1)
    assert event is not None
    assert event.severity == Severity.ERROR
    assert event.extra["client_ip"] == "5.6.7.8"


def test_zone_loaded_is_info(parser):
    event = parser.parse_line(_LOADED, 1)
    assert event is not None
    assert event.severity == Severity.INFO


def test_native_error_severity(parser):
    event = parser.parse_line(_NATIVE_ERR, 1)
    assert event is not None
    assert event.severity == Severity.ERROR
    assert event.extra["category"] == "general"


def test_native_info_severity(parser):
    event = parser.parse_line(_NATIVE_INFO, 1)
    assert event is not None
    assert event.severity == Severity.INFO


def test_can_parse_by_path_and_native():
    assert NamedParser.can_parse(Path("/var/log/named/named.log"), [])
    assert NamedParser.can_parse(None, [_NATIVE_INFO])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
