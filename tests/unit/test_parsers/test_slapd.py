from __future__ import annotations

from pathlib import Path

import pytest

from logcrux.models import Severity
from logcrux.parsers.slapd import SlapdParser

_BIND_OK = 'Jun 20 10:23:45 h slapd[1234]: conn=1001 op=0 RESULT tag=97 err=0 text='
_BIND_FAIL = 'Jun 20 10:23:46 h slapd[1234]: conn=1002 op=0 RESULT tag=97 err=49 text='
_NO_CONN = 'Jun 20 10:23:47 h slapd[1234]: connection_read(14): no connection!'
_SIZELIMIT = 'Jun 20 10:23:48 h slapd[1234]: conn=1003 op=1 SEARCH RESULT err=4 text=size limit exceeded'


@pytest.fixture
def parser():
    return SlapdParser()


def test_err0_is_info(parser):
    e = parser.parse_line(_BIND_OK, 1)
    assert e is not None and e.severity == Severity.INFO
    assert e.extra["err"] == "0"
    assert e.extra["conn"] == "1001"


def test_err49_invalid_creds_is_warning(parser):
    e = parser.parse_line(_BIND_FAIL, 1)
    assert e.severity == Severity.WARNING
    assert e.extra["err"] == "49"


def test_no_connection_is_error(parser):
    e = parser.parse_line(_NO_CONN, 1)
    assert e.severity == Severity.ERROR


def test_size_limit_is_warning(parser):
    e = parser.parse_line(_SIZELIMIT, 1)
    assert e.severity == Severity.WARNING


def test_can_parse_by_path():
    assert SlapdParser.can_parse(Path("/var/log/slapd.log"), [])


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
