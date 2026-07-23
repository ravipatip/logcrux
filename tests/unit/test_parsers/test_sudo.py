from __future__ import annotations

import pytest

from logcrux.models import Severity
from logcrux.parsers.sudo import SudoParser

_OK = "May 19 10:15:01 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"
_INCORRECT = "May 19 10:16:01 web01 sudo:      bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/cat /etc/shadow"
_NOT_SUDOER = "May 19 10:16:30 web01 sudo:      eve : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/eve ; USER=root ; COMMAND=/bin/bash"


@pytest.fixture
def parser():
    return SudoParser()


def test_successful_command(parser):
    event = parser.parse_line(_OK, 1)
    assert event is not None
    assert event.severity == Severity.INFO
    assert event.source == "sudo"
    assert event.extra["user"] == "alice"
    assert event.extra["target_user"] == "root"
    assert event.extra["command"] == "/usr/bin/apt update"


def test_incorrect_password_is_warning(parser):
    event = parser.parse_line(_INCORRECT, 1)
    assert event is not None
    assert event.severity == Severity.WARNING
    assert event.extra["user"] == "bob"


def test_not_in_sudoers_is_warning(parser):
    event = parser.parse_line(_NOT_SUDOER, 1)
    assert event is not None
    assert event.severity == Severity.WARNING


def test_can_parse_by_content():
    assert SudoParser.can_parse(None, [_OK])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
