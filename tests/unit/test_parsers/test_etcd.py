from __future__ import annotations

import pytest

from logcrux.models import Severity
from logcrux.parsers.etcd import EtcdParser

_INFO = '{"level":"info","ts":"2026-06-20T10:23:45.123Z","caller":"embed/serve.go:98","msg":"ready to serve client requests"}'
_WARN = '{"level":"warn","ts":"2026-06-20T10:23:46.456Z","caller":"etcdserver/util.go:163","msg":"apply request took too long","took":"200ms"}'
_ERR = '{"level":"error","ts":"2026-06-20T10:23:48.012Z","caller":"etcdserver/server.go:2042","msg":"failed to publish local member","error":"context deadline exceeded"}'


@pytest.fixture
def parser():
    return EtcdParser()


def test_info(parser):
    e = parser.parse_line(_INFO, 1)
    assert e.severity == Severity.INFO
    assert e.timestamp is not None
    assert e.extra["caller"].startswith("embed/")


def test_warn_with_attrs(parser):
    e = parser.parse_line(_WARN, 1)
    assert e.severity == Severity.WARNING
    assert e.extra["took"] == "200ms"


def test_error(parser):
    e = parser.parse_line(_ERR, 1)
    assert e.severity == Severity.ERROR
    assert "deadline" in e.extra["error"]


def test_can_parse_by_content():
    assert EtcdParser.can_parse(None, [_INFO])
    # mongodb JSON must not be claimed
    assert not EtcdParser.can_parse(
        None, ['{"t":{"$date":"2024-06-20T10:23:45.123+00:00"},"s":"I","msg":"x"}']
    )


def test_empty_returns_none(parser):
    assert parser.parse_line("", 1) is None
    assert parser.parse_line("not json", 1) is None
