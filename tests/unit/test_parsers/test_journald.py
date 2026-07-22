import pytest

from logcrux.models import Severity
from logcrux.parsers.journald import JournaldParser


@pytest.fixture
def parser():
    return JournaldParser()


def test_parse_priority_3_is_error(parser):
    line = (
        '{"__REALTIME_TIMESTAMP":"1750038060000000","PRIORITY":"3",'
        '"SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for root"}'
    )
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.severity == Severity.ERROR
    assert event.source == "sshd"
    assert "Failed password" in event.message


def test_parse_priority_0_is_critical(parser):
    line = (
        '{"__REALTIME_TIMESTAMP":"1750038120000000","PRIORITY":"0",'
        '"SYSLOG_IDENTIFIER":"kernel","MESSAGE":"Out of memory: Killed process 12345"}'
    )
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.severity == Severity.CRITICAL


def test_parse_timestamp_from_microseconds(parser):
    line = (
        '{"__REALTIME_TIMESTAMP":"1750038060000000","PRIORITY":"6",'
        '"SYSLOG_IDENTIFIER":"systemd","MESSAGE":"Started session"}'
    )
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.timestamp is not None
    assert event.timestamp.year == 2025


def test_malformed_json_returns_none(parser):
    assert parser.parse_line("{not valid json", 1) is None


def test_binary_message_decoded(parser):
    # journald encodes non-UTF8 kernel messages as byte-integer arrays
    import json
    payload = list(b"oom-killer invoked")
    line = json.dumps({
        "__REALTIME_TIMESTAMP": "1750038060000000",
        "PRIORITY": "2",
        "SYSLOG_IDENTIFIER": "kernel",
        "MESSAGE": payload,
    })
    event = parser.parse_line(line, 1)
    assert event is not None
    assert event.message == "oom-killer invoked", (
        f"Binary MESSAGE not decoded, got: {event.message!r}"
    )
    assert event.severity == Severity.CRITICAL


def test_stream_fixture(parser, journald_path):
    with open(journald_path, errors="replace") as f:
        events = list(parser.parse_stream(f))
    assert len(events) == 4
    # Fixture: PRIORITY 3, 3, 6, 0 → ERROR, ERROR, INFO, CRITICAL
    severities = [e.severity for e in events]
    assert severities.count(Severity.ERROR) == 2
    assert severities.count(Severity.INFO) == 1
    assert severities.count(Severity.CRITICAL) == 1
    assert all(e.timestamp is not None for e in events)
