from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.auditd import AuditdParser

_AUTH_FAIL = 'type=USER_AUTH msg=audit(1716113702.001:457): pid=1234 acct="root" addr=1.2.3.4 terminal=ssh res=failed'
_AVC = 'type=AVC msg=audit(1716113704.700:459): avc:  denied  { read } for  pid=999 comm="nginx" name="shadow"'
_ANOM = 'type=ANOM_LOGIN_FAILURES msg=audit(1716113705.900:460): pid=1236 acct="root" addr=9.9.9.9 res=failed'
_OK = 'type=SYSCALL msg=audit(1716113701.123:456): arch=c000003e syscall=59 success=yes exit=0 comm="bash"'


@pytest.fixture
def parser():
    return AuditdParser()


def test_auth_failure_is_warning(parser):
    event = parser.parse_line(_AUTH_FAIL, 1)
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.source == "auditd"
    assert event.extra["record_type"] == "USER_AUTH"
    assert event.extra["acct"] == "root"
    assert event.extra["addr"] == "1.2.3.4"
    assert event.extra["result"] == "failed"


def test_avc_denied_is_warning(parser):
    event = parser.parse_line(_AVC, 1)
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.extra["record_type"] == "AVC"


def test_anomaly_is_error(parser):
    event = parser.parse_line(_ANOM, 1)
    assert event is not None
    assert event.severity == Severity.ERROR


def test_success_syscall_is_info(parser):
    event = parser.parse_line(_OK, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.timestamp is not None


def test_can_parse_by_path_and_content():
    assert AuditdParser.can_parse(Path("/var/log/audit/audit.log"), [])
    assert AuditdParser.can_parse(None, [_AUTH_FAIL])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
