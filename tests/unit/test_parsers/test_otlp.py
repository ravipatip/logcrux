from __future__ import annotations

import pytest

from logcrux.models import Severity
from logcrux.parsers.otlp import OTLPParser
from logcrux.parsers.registry import detect_parser


@pytest.fixture
def parser():
    return OTLPParser()


_INFO = (
    '{"timeUnixNano":"1718000014000000000","severityNumber":9,"severityText":"INFO",'
    '"body":{"stringValue":"server started on :8080"},"traceId":"abc123",'
    '"resource":{"service.name":"checkout"}}'
)
_ERROR = (
    '{"timeUnixNano":"1718000062000000000","severityNumber":17,"severityText":"ERROR",'
    '"body":{"stringValue":"connect failed: connection refused"}}'
)
_FATAL = (
    '{"timeUnixNano":"1718000063000000000","severityNumber":21,'
    '"body":{"stringValue":"out of memory: killed"}}'
)


def test_info_record(parser):
    ev = parser.parse_line(_INFO, 1)
    assert ev is not None
    assert ev.severity == Severity.INFO
    assert ev.message == "server started on :8080"
    assert ev.timestamp is not None
    assert ev.timestamp.year == 2024
    assert ev.source == "checkout"
    assert ev.extra["trace_id"] == "abc123"


def test_severity_number_mapping(parser):
    assert parser.parse_line(_ERROR, 1).severity == Severity.ERROR
    assert parser.parse_line(_FATAL, 1).severity == Severity.CRITICAL


@pytest.mark.parametrize("num,expected", [
    (1, Severity.DEBUG), (5, Severity.DEBUG), (9, Severity.INFO),
    (13, Severity.WARNING), (17, Severity.ERROR), (21, Severity.CRITICAL),
    (24, Severity.CRITICAL),
])
def test_severity_scale(parser, num, expected):
    line = f'{{"severityNumber":{num},"body":{{"stringValue":"x"}}}}'
    assert parser.parse_line(line, 1).severity == expected


def test_falls_back_to_severity_text(parser):
    # No severityNumber — must map from severityText.
    line = '{"severityText":"WARN","body":{"stringValue":"slow"}}'
    assert parser.parse_line(line, 1).severity == Severity.WARNING


def test_bare_string_body(parser):
    line = '{"severityNumber":9,"body":"plain message"}'
    assert parser.parse_line(line, 1).message == "plain message"


def test_snake_case_fields(parser):
    line = (
        '{"time_unix_nano":"1718000014000000000","severity_number":17,'
        '"body":{"stringValue":"err"}}'
    )
    ev = parser.parse_line(line, 1)
    assert ev.severity == Severity.ERROR
    assert ev.timestamp is not None


def test_non_otlp_returns_none(parser):
    assert parser.parse_line('{"level":"info","msg":"x"}', 1) is None
    assert parser.parse_line("plain text", 1) is None
    assert parser.parse_line("", 1) is None


def test_detect_otlp():
    assert isinstance(detect_parser(None, [_INFO, _ERROR]), OTLPParser)
