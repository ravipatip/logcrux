from __future__ import annotations

import pytest

from logcrux.models import Severity
from logcrux.parsers.caddy import CaddyParser

_INFO = '{"level":"info","ts":1718880225.123,"logger":"http.log","msg":"server running","address":":443"}'
_WARN = '{"level":"warn","ts":1718880228.012,"logger":"http","msg":"could not get certificate"}'
_ERR = '{"level":"error","ts":1718880227.789,"logger":"http.log.error","msg":"dial tcp: connection refused","request":{"method":"GET","uri":"/api"},"status":502}'
_ACCESS5XX = '{"level":"info","ts":1718880229.3,"logger":"http.log.access","msg":"handled request","request":{"method":"GET","uri":"/x"},"status":503}'


@pytest.fixture
def parser():
    return CaddyParser()


def test_info(parser):
    e = parser.parse_line(_INFO, 1)
    assert e.severity == Severity.INFO
    assert e.timestamp is not None
    assert e.extra["logger"] == "http.log"


def test_warn(parser):
    assert parser.parse_line(_WARN, 1).severity == Severity.WARNING


def test_error_with_request(parser):
    e = parser.parse_line(_ERR, 1)
    assert e.severity == Severity.ERROR
    assert e.extra["method"] == "GET"
    assert e.extra["status"] == 502


def test_5xx_access_log_elevated_to_error(parser):
    # an info-level access line with a 5xx status surfaces as an error
    assert parser.parse_line(_ACCESS5XX, 1).severity == Severity.ERROR


def test_can_parse_by_content():
    assert CaddyParser.can_parse(None, [_INFO])
    # etcd (has "caller") must not be claimed
    assert not CaddyParser.can_parse(
        None, ['{"level":"info","ts":"2026-06-20T10:23:45Z","caller":"x.go:1","msg":"y"}']
    )


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
