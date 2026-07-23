from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.samba import SambaParser

_OK = "May 19 10:15:01 fs01 smbd[1234]:   Auth: user [WORKGROUP]\\[alice] status [NT_STATUS_OK]"
_WRONG_PW = "May 19 10:15:02 fs01 smbd[1235]:   Auth: user [WORKGROUP]\\[bob] status [NT_STATUS_WRONG_PASSWORD]"
_LOGON_FAIL = "May 19 10:15:03 fs01 smbd[1236]:   Auth: user [WORKGROUP]\\[administrator] status [NT_STATUS_LOGON_FAILURE]"
_PANIC = "May 19 10:15:09 fs01 smbd[1244]: PANIC: internal error in smbd_smb2_request_error"
_NATIVE = "[2024/05/19 10:15:01.123456,  0] ../source3/auth/auth.c:319(auth_check_password) NT_STATUS_LOGON_FAILURE"


@pytest.fixture
def parser():
    return SambaParser()


def test_ok_auth_is_info(parser):
    event = parser.parse_line(_OK, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.source == "smbd"
    assert event.extra["nt_status"] == "NT_STATUS_OK"


def test_wrong_password_is_warning(parser):
    event = parser.parse_line(_WRONG_PW, 1)
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.extra["nt_status"] == "NT_STATUS_WRONG_PASSWORD"


def test_logon_failure_is_warning(parser):
    event = parser.parse_line(_LOGON_FAIL, 1)
    assert event is not None
    assert event.severity == Severity.WARNING


def test_panic_is_critical(parser):
    event = parser.parse_line(_PANIC, 1)
    assert event is not None
    assert event.severity == Severity.CRITICAL


def test_native_format(parser):
    event = parser.parse_line(_NATIVE, 1)
    assert event is not None
    assert event.source == "samba"
    assert event.extra["debug_level"] == 0
    assert event.extra["nt_status"] == "NT_STATUS_LOGON_FAILURE"


def test_can_parse_by_path_and_native():
    assert SambaParser.can_parse(Path("/var/log/samba/log.smbd"), [])
    assert SambaParser.can_parse(None, [_NATIVE])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
