from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.fail2ban import Fail2BanParser


@pytest.fixture
def parser():
    return Fail2BanParser()


_BAN = "2026-06-19 10:00:07,305 fail2ban.actions [8765]: WARNING  [sshd] Ban 192.168.1.100"
_UNBAN = "2026-06-19 10:05:00,128 fail2ban.actions [8765]: WARNING  [sshd] Unban 192.168.1.100"
_FOUND = "2026-06-19 10:00:01,305 fail2ban.actions [8765]: INFO     [sshd] Found 192.168.1.100 - 2026-06-19 10:00:01"


def test_parse_ban(parser):
    event = parser.parse_line(_BAN, 1)
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.extra["action"] == "ban"
    assert event.extra["ip"] == "192.168.1.100"
    assert event.extra["jail"] == "sshd"
    assert event.source == "fail2ban"


def test_parse_unban(parser):
    event = parser.parse_line(_UNBAN, 1)
    assert event is not None
    assert event.extra["action"] == "unban"
    assert event.extra["ip"] == "192.168.1.100"


def test_parse_found_is_info(parser):
    event = parser.parse_line(_FOUND, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.extra["action"] == "found"


def test_parse_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None


def test_can_parse_by_path():
    assert Fail2BanParser.can_parse(Path("/var/log/fail2ban.log"), [])


def test_can_parse_by_content():
    assert Fail2BanParser.can_parse(None, [_BAN])


def test_fixture(parser):
    fixture = Path("tests/fixtures/fail2ban.log")
    with open(fixture) as f:
        events = list(parser.parse_stream(f))
    assert len(events) >= 6
    bans = [e for e in events if e.extra.get("action") == "ban"]
    assert len(bans) == 3


# --- NOTICE level + jail-less server lines (real fail2ban output) ---
# fail2ban logs Ban/Unban at NOTICE, and fail2ban.server lines carry no [jail].
_NOTICE_BAN = "2026-06-19 10:10:00,305 fail2ban.actions        [8765]: NOTICE  [sshd] Ban 203.0.113.66"
_SERVER_LINE = "2026-06-19 09:59:59,101 fail2ban.server         [8765]: INFO    Starting Fail2ban v1.0.2"


def test_parse_notice_ban(parser):
    event = parser.parse_line(_NOTICE_BAN, 1)
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.extra["action"] == "ban"
    assert event.extra["jail"] == "sshd"
    assert event.extra["level"] == "NOTICE"


def test_parse_server_line_without_jail(parser):
    event = parser.parse_line(_SERVER_LINE, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert "jail" not in event.extra
    assert event.message == "Starting Fail2ban v1.0.2"
