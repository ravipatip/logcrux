from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.dovecot import DovecotParser

_LOGIN = "May 19 10:15:01 mail01 dovecot: imap-login: Login: user=<alice>, method=PLAIN, rip=10.0.0.5, lip=10.0.0.1, TLS"
_FAIL = "May 19 10:15:02 mail01 dovecot: imap-login: Disconnected (auth failed, 1 attempts in 3 secs): user=<bob>, method=PLAIN, rip=5.6.7.8"
_FATAL = "May 19 10:15:09 mail01 dovecot: auth: Fatal: Error reading configuration: dict file not found"


@pytest.fixture
def parser():
    return DovecotParser()


def test_login_is_info(parser):
    event = parser.parse_line(_LOGIN, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.source == "dovecot"
    assert event.extra["service"] == "imap-login"
    assert event.extra["user"] == "alice"
    assert event.extra["client_ip"] == "10.0.0.5"


def test_auth_failed_is_warning(parser):
    event = parser.parse_line(_FAIL, 1)
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.extra["user"] == "bob"
    assert event.extra["client_ip"] == "5.6.7.8"


def test_fatal_is_error(parser):
    event = parser.parse_line(_FATAL, 1)
    assert event is not None
    assert event.severity == Severity.ERROR


def test_can_parse_by_path():
    assert DovecotParser.can_parse(Path("/var/log/dovecot.log"), [])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None


@pytest.mark.parametrize("ip", ["2001:db8::1", "::1", "::ffff:192.0.2.1", "fe80::1"])
def test_ipv6_rip_extracted(parser, ip):
    line = (
        f"May 19 10:15:02 mail01 dovecot: imap-login: Disconnected (auth failed): "
        f"user=<eve>, rip={ip}, lip=::1"
    )
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.extra.get("client_ip") == ip, (
        f"IPv6 rip={ip} not extracted, got {event.extra.get('client_ip')!r}"
    )
