from __future__ import annotations

import pytest

from logcrux.models import Severity
from logcrux.parsers.etcd import EtcdParser
from logcrux.parsers.klogjson import KlogJsonParser
from logcrux.parsers.registry import detect_parser


@pytest.fixture
def parser():
    return KlogJsonParser()


_INFO = '{"ts":1718000014.047,"caller":"server/server.go:120","msg":"Starting controller","v":0}'
_ERROR = (
    '{"ts":1718000062.551,"caller":"controller/sync.go:88","msg":"Reconciler error",'
    '"err":"connection refused"}'
)


def test_info_record(parser):
    ev = parser.parse_line(_INFO, 1)
    assert ev is not None
    assert ev.severity == Severity.INFO
    assert ev.message == "Starting controller"
    assert ev.source == "klog"
    assert ev.timestamp is not None
    assert ev.timestamp.year == 2024
    assert ev.extra["caller"] == "server/server.go:120"


def test_error_record_appends_err(parser):
    ev = parser.parse_line(_ERROR, 1)
    assert ev is not None
    assert ev.severity == Severity.ERROR
    assert "connection refused" in ev.message
    assert ev.timestamp is not None


def test_rfc3339_string_ts(parser):
    line = '{"ts":"2024-06-10T08:00:14Z","caller":"x.go:1","msg":"hi","v":2}'
    ev = parser.parse_line(line, 1)
    assert ev is not None
    assert ev.timestamp is not None


def test_zap_with_level_not_claimed(parser):
    # etcd/otel zap records carry a "level" field — must NOT be read as klog JSON.
    zap = '{"level":"info","ts":"2024-06-10T08:00:14Z","caller":"x.go:1","msg":"hi"}'
    assert parser.parse_line(zap, 1) is None
    assert not KlogJsonParser.can_parse(None, [zap])


def test_non_klog_returns_none(parser):
    assert parser.parse_line('{"foo":"bar"}', 1) is None
    assert parser.parse_line("plain text", 1) is None
    assert parser.parse_line("", 1) is None


def test_detect_klog_json():
    assert isinstance(detect_parser(None, [_INFO, _ERROR]), KlogJsonParser)


def test_etcd_zap_still_detected_not_klog():
    zap = '{"level":"warn","ts":"2024-06-10T08:00:14Z","caller":"util.go:1","msg":"slow"}'
    assert isinstance(detect_parser(None, [zap]), EtcdParser)
