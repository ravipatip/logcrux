from __future__ import annotations

import pytest

from logcrux.models import Severity
from logcrux.parsers.traefik import TraefikParser

_INFO = '{"level":"info","msg":"Configuration loaded from file","time":"2026-06-20T10:23:45Z"}'
_WARN = '{"level":"warning","msg":"No domain found in rule Host()","time":"2026-06-20T10:23:47Z"}'
_ERR = '{"level":"error","error":"dial tcp 10.0.0.7:8080: connect: connection refused","msg":"Error while creating client","time":"2026-06-20T10:23:48Z"}'


@pytest.fixture
def parser():
    return TraefikParser()


def test_info(parser):
    e = parser.parse_line(_INFO, 1)
    assert e.severity == Severity.INFO
    assert e.timestamp is not None


def test_warn(parser):
    assert parser.parse_line(_WARN, 1).severity == Severity.WARNING


def test_error(parser):
    e = parser.parse_line(_ERR, 1)
    assert e.severity == Severity.ERROR
    assert "connection refused" in e.extra["error"]


def test_can_parse_by_content():
    assert TraefikParser.can_parse(None, [_INFO])
    # caddy (has "logger"/"ts") and etcd (has "caller") must not be claimed
    assert not TraefikParser.can_parse(
        None, ['{"level":"info","ts":1718880225.1,"logger":"http","msg":"x"}']
    )


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
    assert parser.parse_line("plain text", 1) is None
