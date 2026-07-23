from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.ftp import FTPParser


@pytest.fixture
def parser():
    return FTPParser()


_CONNECT = 'Mon Jun 19 10:00:01 2026 [pid 1234] CONNECT: Client "192.168.1.100"'
_OK_LOGIN = 'Mon Jun 19 10:00:02 2026 [pid 1234] [bob] OK LOGIN: Client "192.168.1.100"'
_FAIL_LOGIN = 'Mon Jun 19 10:00:04 2026 [pid 1235] [anonymous] FAIL LOGIN: Client "10.0.1.5"'
_XFER = "Mon Jun 19 10:00:13 2026 1 192.168.1.100 551 /path/to/file.tgz b _ o r username ftp 0 * c"
_XFER_INTERRUPTED = "Mon Jun 19 10:00:13 2026 5 192.168.1.100 1024 /upload/data.csv a _ i r bob ftp 0 * i"


def test_parse_connect(parser):
    event = parser.parse_line(_CONNECT, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.extra["client_ip"] == "192.168.1.100"
    assert event.source == "vsftpd"


def test_parse_ok_login(parser):
    event = parser.parse_line(_OK_LOGIN, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.extra["user"] == "bob"
    assert event.extra["status"] == "OK"


def test_parse_fail_login_is_warning(parser):
    event = parser.parse_line(_FAIL_LOGIN, 1)
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.extra["status"] == "FAIL"


def test_parse_xferlog_download(parser):
    event = parser.parse_line(_XFER, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.extra["direction"] == "download"
    assert event.extra["filesize"] == 551
    assert event.extra["completed"] is True
    assert event.source == "ftp"


def test_parse_xferlog_interrupted_is_warning(parser):
    event = parser.parse_line(_XFER_INTERRUPTED, 1)
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.extra["completed"] is False
    assert event.extra["direction"] == "upload"


def test_parse_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None


def test_can_parse_by_path_vsftpd():
    assert FTPParser.can_parse(Path("/var/log/vsftpd.log"), [])


def test_can_parse_by_path_xferlog():
    assert FTPParser.can_parse(Path("/var/log/xferlog"), [])


def test_can_parse_by_content():
    assert FTPParser.can_parse(None, [_CONNECT])


def test_fixture(parser):
    fixture = Path("tests/fixtures/vsftpd.log")
    with open(fixture) as f:
        events = list(parser.parse_stream(f))
    assert len(events) >= 6
    fails = [e for e in events if e.extra.get("status") == "FAIL"]
    assert len(fails) >= 2
