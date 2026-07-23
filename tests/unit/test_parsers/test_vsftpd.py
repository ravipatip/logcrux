from __future__ import annotations

import pytest

from logcrux.models import Severity
from logcrux.parsers.vsftpd import VsftpdParser

_LOGIN = 'May 19 10:15:02 ftp01 vsftpd[1234]: [alice] OK LOGIN: Client "10.0.0.5"'
_FAIL = 'May 19 10:15:03 ftp01 vsftpd[1235]: [anonymous] FAIL LOGIN: Client "5.6.7.8"'
_DOWNLOAD = 'May 19 10:15:05 ftp01 vsftpd[1234]: [alice] OK DOWNLOAD: Client "10.0.0.5", "/pub/report.pdf", 1048576 bytes, 5.21Kbyte/sec'


@pytest.fixture
def parser():
    return VsftpdParser()


def test_login_is_info(parser):
    event = parser.parse_line(_LOGIN, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.source == "vsftpd"
    assert event.extra["user"] == "alice"
    assert event.extra["status"] == "OK"
    assert event.extra["client_ip"] == "10.0.0.5"


def test_fail_login_is_warning(parser):
    event = parser.parse_line(_FAIL, 1)
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.extra["status"] == "FAIL"
    assert event.extra["user"] == "anonymous"


def test_download_event(parser):
    event = parser.parse_line(_DOWNLOAD, 1)
    assert event is not None
    assert event.extra["event"] == "DOWNLOAD"
    assert event.extra["client_ip"] == "10.0.0.5"


def test_can_parse_by_content():
    assert VsftpdParser.can_parse(None, [_LOGIN])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
